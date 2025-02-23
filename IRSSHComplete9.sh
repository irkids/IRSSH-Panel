#!/bin/bash

# IRSSH Panel Installation Script
# Version: 3.5.2

# Base directory structure
SCRIPT_PATH=$(readlink -f "${BASH_SOURCE[0]}")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")

# Core directories
PANEL_DIR="/opt/irssh-panel"
CONFIG_DIR="/etc/enhanced_ssh"
LOG_DIR="/var/log/irssh"
BACKUP_DIR="/opt/irssh-backups"
TEMP_DIR="/tmp/irssh-install"

# Protocol configuration
declare -A PROTOCOLS=(
    ["SSH"]=true
    ["L2TP"]=true
    ["IKEV2"]=true
    ["CISCO"]=true
    ["WIREGUARD"]=true
    ["SINGBOX"]=true
)

# Port configuration
declare -A PORTS=(
    ["SSH"]=22
    ["SSH_TLS"]=443
    ["L2TP"]=1701
    ["IKEV2"]=500
    ["CISCO"]=443
    ["WIREGUARD"]=51820
    ["SINGBOX"]=1080
    ["WEB"]=8080
)

# Logging functions
log() {
    local level=$1
    local message=$2
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message"
    echo "[$timestamp] [$level] $message" >> "$LOG_DIR/installation.log"
}

info() {
    log "INFO" "$1"
}

error() {
    log "ERROR" "$1"
    if [[ "${2:-}" != "no-exit" ]]; then
        cleanup
        exit 1
    fi
}

# Installation module function
install_module() {
    local module_name=$1
    local module_script="$SCRIPT_DIR/modules/$module_name/install.sh"
    
    if [[ ! -f "$module_script" ]]; then
        error "Module installation script not found: $module_script"
        return 1
    }
    
    info "Installing module: $module_name"
    bash "$module_script"
    local result=$?
    
    if [[ $result -ne 0 ]]; then
        error "Failed to install module: $module_name"
        return 1
    fi
    
    info "Successfully installed module: $module_name"
    return 0
}

# Protocol installation functions
install_ssh() {
    info "Installing SSH protocol..."
    
    # Install SSH packages
    apt-get install -y openssh-server stunnel4 || error "Failed to install SSH packages"
    
    # Configure SSH
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    cat > /etc/ssh/sshd_config << EOL
Port ${PORTS[SSH]}
PermitRootLogin yes
PasswordAuthentication yes
X11Forwarding yes
PrintMotd no

MaxAuthTries 6
LoginGraceTime 30
PermitEmptyPasswords no
ClientAliveInterval 300
ClientAliveCountMax 3

SyslogFacility AUTH
LogLevel INFO
EOL

    # Configure stunnel for SSL
    mkdir -p /etc/stunnel
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/stunnel/stunnel.pem \
        -out /etc/stunnel/stunnel.pem \
        -subj "/CN=localhost"
    
    chmod 600 /etc/stunnel/stunnel.pem
    
    cat > /etc/stunnel/stunnel.conf << EOL
pid = /var/run/stunnel4/stunnel.pid
setuid = stunnel4
setgid = stunnel4
cert = /etc/stunnel/stunnel.pem
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh-tls]
client = no
accept = ${PORTS[SSH_TLS]}
connect = 127.0.0.1:${PORTS[SSH]}
EOL

    systemctl restart ssh
    systemctl enable stunnel4
    systemctl restart stunnel4
}

install_l2tp() {
    info "Installing L2TP/IPsec..."
    
    apt-get install -y strongswan xl2tpd || error "Failed to install L2TP packages"
    
    # Generate PSK
    PSK=$(openssl rand -base64 32)
    
    # Configure strongSwan
    cat > /etc/ipsec.conf << EOL
config setup
    charondebug="ike 2, knl 2"
    uniqueids=no

conn L2TP-PSK
    authby=secret
    auto=add
    keyingtries=3
    rekey=no
    ikelifetime=8h
    keylife=1h
    type=transport
    left=%defaultroute
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
EOL

    echo ": PSK \"$PSK\"" > /etc/ipsec.secrets
    chmod 600 /etc/ipsec.secrets
    
    systemctl restart strongswan
    systemctl enable strongswan
}

install_wireguard() {
    info "Installing WireGuard..."
    
    apt-get install -y wireguard || error "Failed to install WireGuard"
    
    # Generate keys
    wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
    chmod 600 /etc/wireguard/server_private.key
    
    # Configure WireGuard
    cat > /etc/wireguard/wg0.conf << EOL
[Interface]
PrivateKey = $(cat /etc/wireguard/server_private.key)
Address = 10.66.66.1/24
ListenPort = ${PORTS[WIREGUARD]}
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
EOL

    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
}

install_singbox() {
    info "Installing Sing-Box..."
    
    local ARCH="amd64"
    local VERSION="1.7.0"
    local URL="https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box-${VERSION}-linux-${ARCH}.tar.gz"
    
    wget "$URL" -O /tmp/sing-box.tar.gz || error "Failed to download Sing-Box"
    tar -xzf /tmp/sing-box.tar.gz -C /usr/local/bin/
    chmod +x /usr/local/bin/sing-box
    
    # Configure Sing-Box
    mkdir -p /etc/sing-box
    cat > /etc/sing-box/config.json << EOL
{
    "log": {
        "level": "info",
        "output": "/var/log/sing-box.log"
    },
    "inbounds": [
        {
            "type": "mixed",
            "listen": "::",
            "listen_port": ${PORTS[SINGBOX]}
        }
    ]
}
EOL

    systemctl enable sing-box
    systemctl start sing-box
}

# Setup monitoring
setup_monitoring() {
    if [ "$ENABLE_MONITORING" != "y" ]; then
        return 0
    fi
    
    apt-get install -y prometheus-node-exporter collectd || error "Failed to install monitoring tools"
    
    mkdir -p /var/log/irssh/metrics
    
    # Configure node exporter
    cat > /etc/systemd/system/node-exporter.service << EOL
[Unit]
Description=Prometheus Node Exporter
After=network.target

[Service]
Type=simple
User=node_exporter
ExecStart=/usr/bin/node_exporter
Restart=always

[Install]
WantedBy=multi-user.target
EOL

    systemctl enable node-exporter
    systemctl start node-exporter
}

# Main setup function
setup_panel() {
    info "Setting up IRSSH Panel..."
    
    # Create directories
    mkdir -p "$PANEL_DIR"/{frontend,backend,config}
    
    # Setup backend
    cd "$PANEL_DIR/backend" || error "Failed to access backend directory"
    npm install
    
    # Setup frontend
    cd "$PANEL_DIR/frontend" || error "Failed to access frontend directory"
    npm install
    npm run build
    
    # Configure nginx
    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen ${PORTS[WEB]};
    server_name _;
    
    root $PANEL_DIR/frontend/dist;
    index index.html;
    
    location /api {
        proxy_pass http://localhost:3000;
    }
}
EOL

    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
    systemctl restart nginx
}

# Main installation function
main() {
    info "Starting IRSSH Panel installation..."
    
    # Initial setup
    mkdir -p "$LOG_DIR"
    mkdir -p "$CONFIG_DIR"
    
    # Install base requirements
    apt-get update
    apt-get install -y nginx nodejs npm postgresql || error "Failed to install base requirements"
    
    # Install protocols
    for protocol in "${!PROTOCOLS[@]}"; do
        if [ "${PROTOCOLS[$protocol]}" = true ]; then
            "install_${protocol,,}" || error "Failed to install $protocol"
        fi
    done
    
    # Setup panel
    setup_panel
    
    # Setup monitoring if enabled
    setup_monitoring
    
    info "Installation completed successfully!"
}

# Run main installation
main
