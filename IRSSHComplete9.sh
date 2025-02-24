#!/bin/bash

# IRSSH Panel Complete Installation Script
# Version: 3.5.2

# Base directories
PANEL_DIR="/opt/irssh-panel"
CONFIG_DIR="/etc/enhanced_ssh"
LOG_DIR="/var/log/irssh"
BACKUP_DIR="/opt/irssh-backups"
TEMP_DIR="/tmp/irssh-install"
SSL_DIR="/etc/nginx/ssl"

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
    ["SSH_TLS"]=444
    ["WEBSOCKET"]=2082
    ["L2TP"]=1701
    ["IKEV2"]=500
    ["CISCO"]=85
    ["WIREGUARD"]=51820
    ["SINGBOX"]=1080
    ["UDPGW"]=7300
)

# User Configuration
ADMIN_USER=""
ADMIN_PASS=""
ENABLE_MONITORING="n"
SERVER_IPv4=""
SERVER_IPv6=""
DB_NAME="irssh"
REPO_URL="https://github.com/irkids/IRSSH-Panel.git"

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

cleanup() {
    info "Performing cleanup..."
    rm -rf "$TEMP_DIR"
}

get_server_ip() {
    SERVER_IPv4=$(curl -s4 ifconfig.me)
    if [ -z "$SERVER_IPv4" ]; then
        SERVER_IPv4=$(ip -4 route get 8.8.8.8 | awk '{print $7; exit}')
    fi

    SERVER_IPv6=$(curl -s6 ifconfig.me)

    if [ -z "$SERVER_IPv4" ] && [ -z "$SERVER_IPv6" ]; then
        error "Could not determine server IP address"
    fi
}

get_config() {
    info "Getting initial configuration..."
    
    read -p "Enter admin username: " ADMIN_USER
    while [ -z "$ADMIN_USER" ]; do
        read -p "Username cannot be empty. Enter admin username: " ADMIN_USER
    done
    
    read -s -p "Enter admin password: " ADMIN_PASS
    echo
    while [ -z "$ADMIN_PASS" ]; do
        read -s -p "Password cannot be empty. Enter admin password: " ADMIN_PASS
        echo
    done

    while true; do
        read -p "Enter web panel port (4-5 digits) or press Enter for random port: " WEB_PORT
        if [ -z "$WEB_PORT" ]; then
            WEB_PORT=$(shuf -i 1234-65432 -n 1)
            info "Generated random port: $WEB_PORT"
            break
        elif [[ "$WEB_PORT" =~ ^[0-9]{4,5}$ ]] && [ "$WEB_PORT" -ge 1234 ] && [ "$WEB_PORT" -le 65432 ]; then
            break
        else
            error "Invalid port number. Must be between 1234 and 65432" "no-exit"
        fi
    done
    PORTS["WEB"]=$WEB_PORT
    
    read -p "Enable monitoring? (y/N): " ENABLE_MONITORING
    ENABLE_MONITORING=${ENABLE_MONITORING,,}
}

setup_dependencies() {
    info "Installing system dependencies..."
    
    # Update system
    apt-get update || error "Failed to update package lists"
    
    # Remove old Node.js completely
    apt-get remove -y nodejs npm node-*
    apt-get purge -y nodejs npm
    apt-get autoremove -y
    rm -rf /usr/local/lib/node_modules
    rm -rf /usr/local/bin/node
    rm -rf /usr/local/bin/npm
    rm -rf /etc/apt/sources.list.d/nodesource.list*
    
    # Install required packages
    apt-get install -y \
        nginx \
        postgresql \
        postgresql-contrib \
        git \
        curl \
        build-essential \
        python3 \
        python3-pip \
        || error "Failed to install dependencies"
    
    # Install Node.js 20.x
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
    
    # Install development tools
    npm install -g npm@latest
    npm install -g pm2
    
    info "Dependencies installation completed"
}

setup_database() {
    info "Setting up database..."
    
    # Start PostgreSQL if not running
    systemctl start postgresql
    systemctl enable postgresql
    
    # Switch to postgres home directory to avoid permission warnings
    cd /var/lib/postgresql || error "Failed to access PostgreSQL directory"
    
    # Check if database exists and create if needed
    if ! sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
        info "Creating new database: $DB_NAME"
        sudo -u postgres createdb "$DB_NAME" || error "Failed to create database"
        
        # Create user and grant privileges
        sudo -u postgres psql -c "CREATE USER ${ADMIN_USER} WITH PASSWORD '${ADMIN_PASS}';" || error "Failed to create database user"
        sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${ADMIN_USER};" || error "Failed to grant privileges"
    else
        info "Database '$DB_NAME' already exists"
        
        # Update user password if it exists, create if it doesn't
        sudo -u postgres psql -c "DO \$\$
        BEGIN
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = '${ADMIN_USER}') THEN
                ALTER USER ${ADMIN_USER} WITH PASSWORD '${ADMIN_PASS}';
            ELSE
                CREATE USER ${ADMIN_USER} WITH PASSWORD '${ADMIN_PASS}';
            END IF;
        END
        \$\$;" || error "Failed to update database user"
        
        sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${ADMIN_USER};" || error "Failed to grant privileges"
    fi
    
    info "Database setup completed"
}

setup_web_server() {
    info "Setting up web server..."
    
    # Clone repository
    git clone "$REPO_URL" "$TEMP_DIR/repo" || error "Failed to clone repository"
    
    # Setup frontend
    mkdir -p "$PANEL_DIR/frontend"
    cp -r "$TEMP_DIR/repo/frontend/"* "$PANEL_DIR/frontend/"
    
    cd "$PANEL_DIR/frontend" || error "Failed to access frontend directory"

# Install frontend dependencies
npm install || error "Failed to install frontend dependencies"

# Make the build script executable
chmod +x build-frontend.sh

# Build frontend using the new build script and custom tsconfig.build.json
bash build-frontend.sh || error "Failed to build frontend"
    
    # Setup backend
    mkdir -p "$PANEL_DIR/backend"
    cp -r "$TEMP_DIR/repo/backend/"* "$PANEL_DIR/backend/"
    
    cd "$PANEL_DIR/backend" || error "Failed to access backend directory"
    
    # Create backend environment file
    cat > .env << EOL
NODE_ENV=production
PORT=3000
DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$ADMIN_USER
DB_PASS=$ADMIN_PASS
JWT_SECRET=$(openssl rand -base64 32)
EOL
    
    # Install backend dependencies
    npm install || error "Failed to install backend dependencies"
    
    # Initialize database schema
    npm run migrate || error "Failed to initialize database schema"
    
    # Create admin user in database
    HASHED_PASSWORD=$(node -e "console.log(require('bcrypt').hashSync('${ADMIN_PASS}', 10))")
    psql -U "$ADMIN_USER" "$DB_NAME" -c "INSERT INTO users (username, password, role) VALUES ('${ADMIN_USER}', '${HASHED_PASSWORD}', 'admin');"
    
    # Configure nginx
    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen ${PORTS[WEB]};
    listen [::]:${PORTS[WEB]};
    
    server_name _;
    
    root $PANEL_DIR/frontend/dist;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ /index.html;
    }
    
    location /api {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOL

    # Setup backend service
    cat > /etc/systemd/system/irssh-api.service << EOL
[Unit]
Description=IRSSH Panel API Server
After=network.target postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=$PANEL_DIR/backend
ExecStart=/usr/bin/npm start
Restart=always
Environment=NODE_ENV=production
Environment=PORT=3000

[Install]
WantedBy=multi-user.target
EOL

    # Enable and start services
    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    systemctl daemon-reload
    systemctl enable irssh-api
    systemctl start irssh-api
    systemctl restart nginx
    systemctl enable nginx
    
    # Set permissions
    chown -R www-data:www-data "$PANEL_DIR/frontend"
    chmod -R 755 "$PANEL_DIR/frontend"
    
    info "Web server setup completed"
}

install_ssh() {
    info "Installing SSH protocol..."
    
    apt-get install -y openssh-server stunnel4 || error "Failed to install SSH packages"
    
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

    cat > /etc/systemd/system/websocket.service << EOL
[Unit]
Description=WebSocket for SSH
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/websocat -t --binary-protocol ws-l:0.0.0.0:${PORTS[WEBSOCKET]} tcp:127.0.0.1:${PORTS[SSH]}
Restart=always

[Install]
WantedBy=multi-user.target
EOL

    systemctl daemon-reload
    systemctl restart ssh
    systemctl enable stunnel4
    systemctl restart stunnel4
    systemctl enable websocket
    systemctl start websocket
    
    info "SSH installation completed"
}

install_l2tp() {
    info "Installing L2TP/IPsec..."
    
    apt-get install -y strongswan xl2tpd || error "Failed to install L2TP packages"
    
    PSK=$(openssl rand -base64 32)
    
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
    dpddelay=30
    dpdtimeout=120
    dpdaction=clear
EOL

    echo ": PSK \"$PSK\"" > /etc/ipsec.secrets
    chmod 600 /etc/ipsec.secrets
    
    cat > /etc/xl2tpd/xl2tpd.conf << EOL
[global]
ipsec saref = yes
port = ${PORTS[L2TP]}

[lns default]
ip range = 10.10.10.100-10.10.10.200
local ip = 10.10.10.1
require chap = yes
refuse pap = yes
require authentication = yes
name = L2TP-VPN
ppp debug = yes
length bit = yes
EOL

    systemctl restart strongswan
    systemctl enable strongswan
    systemctl restart xl2tpd
    systemctl enable xl2tpd
    
    info "L2TP installation completed"
}

install_ikev2() {
    info "Installing IKEv2..."
    
    apt-get install -y strongswan strongswan-pki || error "Failed to install IKEv2 packages"
    
    mkdir -p /etc/ipsec.d/{private,cacerts,certs}
    
    ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/ca-key.pem
    chmod 600 /etc/ipsec.d/private/ca-key.pem
    
    ipsec pki --self --ca --lifetime 3650 \
        --in /etc/ipsec.d/private/ca-key.pem \
        --type rsa --dn "CN=VPN CA" \
        --outform pem > /etc/ipsec.d/cacerts/ca-cert.pem
    
    ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/server-key.pem
    chmod 600 /etc/ipsec.d/private/server-key.pem
    
    ipsec pki --pub --in /etc/ipsec.d/private/server-key.pem --type rsa \
        | ipsec pki --issue --lifetime 1825 \
            --cacert /etc/ipsec.d/cacerts/ca-cert.pem \
            --cakey /etc/ipsec.d/private/ca-key.pem \
            --dn "CN=vpn.server.com" \
            --san "vpn.server.com" \
            --flag serverAuth --flag ikeIntermediate \
            --outform pem > /etc/ipsec.d/certs/server-cert.pem
    
    cat > /etc/ipsec.conf << EOL
config setup
    charondebug="ike 2, knl 2, cfg 2, net 2, esp 2"

conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%any
    leftid=@vpn.server.com
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
   right=%any
   rightauth=eap-mschapv2
   rightsourceip=10.20.20.0/24
   rightdns=8.8.8.8,8.8.4.4
EOL

   systemctl restart strongswan
   systemctl enable strongswan
   
   info "IKEv2 installation completed"
}

install_cisco() {
   info "Installing OpenConnect (Cisco AnyConnect)..."
   
   apt-get install -y ocserv gnutls-bin || error "Failed to install OpenConnect packages"
   
   mkdir -p /etc/ocserv/ssl
   cd /etc/ocserv/ssl || error "Failed to access OpenConnect SSL directory"
   
   certtool --generate-privkey --outfile ca-key.pem
   
   cat > ca.tmpl << EOL
cn = "VPN CA"
organization = "IRSSH Panel"
serial = 1
expiration_days = 3650
ca
signing_key
cert_signing_key
crl_signing_key
EOL

   certtool --generate-self-signed --load-privkey ca-key.pem \
       --template ca.tmpl --outfile ca-cert.pem
   
   certtool --generate-privkey --outfile server-key.pem
   
   cat > server.tmpl << EOL
cn = "VPN Server"
organization = "IRSSH Panel"
expiration_days = 3650
signing_key
encryption_key
tls_www_server
EOL

   certtool --generate-certificate --load-privkey server-key.pem \
       --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem \
       --template server.tmpl --outfile server-cert.pem
   
   cat > /etc/ocserv/ocserv.conf << EOL
auth = "plain[passwd=/etc/ocserv/ocpasswd]"
tcp-port = ${PORTS[CISCO]}
udp-port = ${PORTS[CISCO]}
run-as-user = nobody
run-as-group = daemon
server-cert = /etc/ocserv/ssl/server-cert.pem
server-key = /etc/ocserv/ssl/server-key.pem
ca-cert = /etc/ocserv/ssl/ca-cert.pem
socket-file = /var/run/ocserv-socket
isolate-workers = true
max-clients = 128
max-same-clients = 2
keepalive = 32400
dpd = 90
mobile-dpd = 1800
try-mtu-discovery = true
server-stats-reset-time = 604800
EOL

   systemctl restart ocserv
   systemctl enable ocserv
   
   info "OpenConnect installation completed"
}

install_wireguard() {
   info "Installing WireGuard..."
   
   apt-get install -y wireguard || error "Failed to install WireGuard"
   
   mkdir -p /etc/wireguard
   cd /etc/wireguard || error "Failed to access WireGuard directory"
   
   wg genkey | tee server_private.key | wg pubkey > server_public.key
   chmod 600 server_private.key
   
   cat > /etc/wireguard/wg0.conf << EOL
[Interface]
PrivateKey = $(cat server_private.key)
Address = 10.66.66.1/24
ListenPort = ${PORTS[WIREGUARD]}
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

MTU = 1420
Table = off
PreUp = sysctl -w net.ipv4.ip_forward=1
EOL

   systemctl enable wg-quick@wg0
   systemctl start wg-quick@wg0
   
   info "WireGuard installation completed"
}

install_singbox() {
   info "Installing Sing-Box..."
   
   local ARCH="amd64"
   local VERSION="1.7.0"
   local URL="https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box-${VERSION}-linux-${ARCH}.tar.gz"
   
   mkdir -p /tmp/sing-box
   wget "$URL" -O /tmp/sing-box.tar.gz || error "Failed to download Sing-Box"
   tar -xzf /tmp/sing-box.tar.gz -C /tmp/sing-box --strip-components=1
   
   cp /tmp/sing-box/sing-box /usr/local/bin/
   chmod +x /usr/local/bin/sing-box || error "Failed to set permissions for sing-box"
   
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
           "listen_port": ${PORTS[SINGBOX]},
           "sniff": true,
           "sniff_override_destination": false
       }
   ],
   "outbounds": [
       {
           "type": "direct",
           "tag": "direct"
       }
   ]
}
EOL

   cat > /etc/systemd/system/sing-box.service << EOL
[Unit]
Description=Sing-Box Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=always

[Install]
WantedBy=multi-user.target
EOL

   systemctl daemon-reload
   systemctl enable sing-box
   systemctl start sing-box
   
   info "Sing-Box installation completed"
}

setup_monitoring() {
   if [ "$ENABLE_MONITORING" != "y" ]; then
       info "Monitoring system disabled, skipping..."
       return 0
   fi
   
   info "Setting up monitoring system..."
   
   apt-get install -y prometheus-node-exporter collectd vnstat || error "Failed to install monitoring tools"
   
   mkdir -p /var/log/irssh/metrics
   
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

   cat > /etc/collectd/collectd.conf << EOL
LoadPlugin cpu
LoadPlugin memory
LoadPlugin network
LoadPlugin interface
LoadPlugin load
LoadPlugin disk

<Plugin interface>
   Interface "eth0"
   IgnoreSelected false
</Plugin>

<Plugin network>
   Server "localhost" "25826"
</Plugin>
EOL

   systemctl daemon-reload
   systemctl enable node-exporter
   systemctl start node-exporter
   systemctl enable collectd
   systemctl start collectd
   
   info "Monitoring setup completed"
}

main() {
   info "Starting IRSSH Panel installation..."
   
   mkdir -p "$LOG_DIR"
   mkdir -p "$CONFIG_DIR"
   mkdir -p "$PANEL_DIR"
   mkdir -p "$TEMP_DIR"
   
   get_server_ip
   get_config
   setup_dependencies
   setup_database
   setup_web_server
   
   for protocol in "${!PROTOCOLS[@]}"; do
       if [ "${PROTOCOLS[$protocol]}" = true ]; then
           info "Installing ${protocol}..."
           install_${protocol,,} || error "Failed to install $protocol"
       fi
   done
   
   setup_monitoring
   cleanup
   
   info "Installation completed successfully!"
   
   cat << EOL

IRSSH Panel Installation Summary
-------------------------------
Panel Version: 3.5.2
Web Interface:
$([ ! -z "$SERVER_IPv4" ] && echo "IPv4: http://${SERVER_IPv4}:${PORTS[WEB]}")
$([ ! -z "$SERVER_IPv6" ] && echo "IPv6: http://${SERVER_IPv6}:${PORTS[WEB]}")

Admin Credentials:
Username: ${ADMIN_USER}
Password: (As specified during installation)

Enabled Protocols:
$(for protocol in "${!PROTOCOLS[@]}"; do
   if [ "${PROTOCOLS[$protocol]}" = true ]; then
       echo "- $protocol (Port: ${PORTS[$protocol]})"
   fi
done)

Additional Features:
- Monitoring: ${ENABLE_MONITORING}

For more information, please check:
- Logs: ${LOG_DIR}
- Configuration: ${CONFIG_DIR}
EOL
}

main
