#!/bin/bash

# IRSSH Panel Complete Installation Script
# Version: 3.5.2
# This script includes all original functionality plus improvements and fixes

# Base Configuration
###########################################
# Base directories
PANEL_DIR="/opt/irssh-panel"
CONFIG_DIR="/etc/enhanced_ssh"
LOG_DIR="/var/log/irssh"
BACKUP_DIR="/opt/irssh-backups"
TEMP_DIR="/tmp/irssh-install"
SSL_DIR="/etc/nginx/ssl"

# Protocol Installation Modes
declare -A PROTOCOLS=(
    ["SSH"]=true
    ["DROPBEAR"]=true
    ["L2TP"]=true
    ["IKEV2"]=true
    ["CISCO"]=true
    ["WIREGUARD"]=true
    ["SINGBOX"]=true
)

# Protocol Ports
declare -A PORTS=(
    ["SSH"]=22
    ["DROPBEAR"]=22722
    ["WEBSOCKET"]=2082
    ["SSH_TLS"]=443
    ["L2TP"]=1701
    ["IKEV2"]=500
    ["CISCO"]=443
    ["WIREGUARD"]=51820
    ["SINGBOX"]=1080
    ["BADVPN"]=7300
    ["WEB"]=443
)

# Version Information
VERSION="3.5.2"
MIN_NODE_VERSION=16
MIN_PYTHON_VERSION="3.8"
REQUIRED_MEMORY=1024
REQUIRED_DISK=5120

# Colors for output
declare -A COLORS=(
    ["GREEN"]='\033[0;32m'
    ["RED"]='\033[0;31m'
    ["YELLOW"]='\033[1;33m'
    ["BLUE"]='\033[0;34m'
    ["NC"]='\033[0m'
)

# Utility Functions
###########################################
# Enhanced logging system
log() {
    local level=$1
    local message=$2
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    local color_code="${COLORS[${level}]:-${COLORS[NC]}}"
    
    # Create log directory if it doesn't exist
    mkdir -p "$LOG_DIR"
    
    # Console output with color
    echo -e "${color_code}[$timestamp] [$level] $message${COLORS[NC]}"
    
    # File output without color codes
    echo "[$timestamp] [$level] $message" >> "$LOG_DIR/installation.log"
    
    # Special handling for errors
    if [[ "$level" == "ERROR" ]]; then
        echo "[$timestamp] [$level] $message" >> "$LOG_DIR/error.log"
    fi
}

error() {
    log "ERROR" "$1"
    if [[ "${2:-}" != "no-exit" ]]; then
        cleanup
        exit 1
    fi
}

warn() {
    log "WARN" "$1"
}

info() {
    log "INFO" "$1"
}

debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        log "DEBUG" "$1"
    fi
}

# Backup function with compression
backup_data() {
    local backup_name="irssh-backup-$(date +%Y%m%d-%H%M%S)"
    local backup_path="$BACKUP_DIR/$backup_name.tar.gz"
    
    info "Creating backup: $backup_name"
    
    mkdir -p "$BACKUP_DIR"
    
    # Backup configuration
    if [ -d "$CONFIG_DIR" ]; then
        tar -czf "$backup_path" -C "$(dirname "$CONFIG_DIR")" "$(basename "$CONFIG_DIR")" || {
            error "Failed to create configuration backup" "no-exit"
            return 1
        }
    fi
    
    # Backup database
    if command -v pg_dump &> /dev/null; then
        source "$CONFIG_DIR/config.yaml"
        PGPASSWORD="$db_password" pg_dump -U "$db_user" "$db_name" > "$BACKUP_DIR/$backup_name-db.sql" || {
            error "Failed to create database backup" "no-exit"
            return 1
        }
    fi
    
    info "Backup created successfully: $backup_path"
    return 0
}

# Restore function
restore_data() {
    local backup_file=$1
    
    if [ ! -f "$backup_file" ]; then
        error "Backup file not found: $backup_file"
    fi
    
    info "Restoring from backup: $backup_file"
    
    # Stop services before restore
    systemctl stop nginx irssh-panel irssh-backend
    
    # Restore configuration
    tar -xzf "$backup_file" -C / || {
        error "Failed to restore configuration"
    }
    
    # Restore database if backup exists
    local db_backup="${backup_file%.*}-db.sql"
    if [ -f "$db_backup" ]; then
        source "$CONFIG_DIR/config.yaml"
        PGPASSWORD="$db_password" psql -U "$db_user" "$db_name" < "$db_backup" || {
            error "Failed to restore database"
        }
    fi
    
    # Restart services
    systemctl start nginx irssh-panel irssh-backend
    
    info "Restore completed successfully"
}

# Cleanup function
cleanup() {
    info "Performing cleanup..."
    rm -rf "$TEMP_DIR"
    # Additional cleanup tasks can be added here
}

# Check system requirements
check_requirements() {
    info "Checking system requirements..."
    
    # Check root privileges
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root"
    fi
    
    # Check OS compatibility
    if [ ! -f /etc/os-release ]; then
        error "Unsupported operating system"
    fi
    source /etc/os-release
    if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
        error "This script requires Ubuntu or Debian"
    fi
    
    # Check system resources
    local MEM_TOTAL=$(free -m | awk '/^Mem:/{print $2}')
    local CPU_CORES=$(nproc)
    local DISK_SPACE=$(df -m / | awk 'NR==2 {print $4}')
    
    if [ "$MEM_TOTAL" -lt "$REQUIRED_MEMORY" ]; then
        warn "System has less than ${REQUIRED_MEMORY}MB RAM. Performance may be affected."
    fi
    
    if [ "$CPU_CORES" -lt 2 ]; then
        warn "System has less than 2 CPU cores. Performance may be affected."
    fi
    
    if [ "$DISK_SPACE" -lt "$REQUIRED_DISK" ]; then
        error "Insufficient disk space. At least ${REQUIRED_DISK}MB required."
    fi
    
    # Check software versions
    if ! command -v node &> /dev/null; then
        info "Installing Node.js..."
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        apt-get install -y nodejs || error "Failed to install Node.js"
    fi
    
    NODE_VERSION=$(node -v | sed 's/v\([0-9]*\).*/\1/')
    if [ "$NODE_VERSION" -lt "$MIN_NODE_VERSION" ]; then
        error "Node.js version must be $MIN_NODE_VERSION or higher"
    fi
    
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    if [ "$(echo "$PYTHON_VERSION < $MIN_PYTHON_VERSION" | bc)" -eq 1 ]; then
        error "Python version must be $MIN_PYTHON_VERSION or higher"
    fi
    
    info "System requirements check completed"
}

# Enhanced Installation Functions
###########################################

# Create and configure directories
setup_directories() {
    info "Creating directory structure..."
    
    # Create main directories with proper permissions
    local directories=(
        "$PANEL_DIR"
        "$CONFIG_DIR"
        "$LOG_DIR"
        "$BACKUP_DIR"
        "$TEMP_DIR"
        "$SSL_DIR"
        "$PANEL_DIR/frontend"
        "$PANEL_DIR/backend"
        "$PANEL_DIR/modules/protocols"
        "$PANEL_DIR/venv"
        "$PANEL_DIR/frontend/public"
        "$PANEL_DIR/frontend/src/components"
        "$PANEL_DIR/frontend/src/stores"
        "$PANEL_DIR/frontend/src/context"
        "$PANEL_DIR/frontend/src/utils"
        "$PANEL_DIR/frontend/src/hooks"
        "$PANEL_DIR/frontend/src/types"
        "$PANEL_DIR/backend/src/routes"
        "$PANEL_DIR/backend/src/middleware"
        "$PANEL_DIR/backend/src/models"
        "$PANEL_DIR/backend/src/utils"
        "$PANEL_DIR/backend/config"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        debug "Created directory: $dir"
    done
    
    # Set proper permissions
    chown -R root:root "$PANEL_DIR"
    chmod 750 "$PANEL_DIR"
    chmod 700 "$CONFIG_DIR"
    chmod 750 "$LOG_DIR"
    chmod 750 "$BACKUP_DIR"
    
    info "Directory structure created successfully"
}

# Generate and configure SSL certificates
setup_ssl() {
    info "Setting up SSL certificates..."
    
    mkdir -p "$SSL_DIR"
    
    # Generate self-signed certificate
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$SSL_DIR/irssh-panel.key" \
        -out "$SSL_DIR/irssh-panel.crt" \
        -subj "/CN=irssh-panel" || error "Failed to generate SSL certificate"
    
    chmod 600 "$SSL_DIR/irssh-panel.key"
    chmod 644 "$SSL_DIR/irssh-panel.crt"
    
    # Configure stunnel
    if [ -f "/etc/stunnel/stunnel.conf" ]; then
        cp "/etc/stunnel/stunnel.conf" "/etc/stunnel/stunnel.conf.backup"
        cat > "/etc/stunnel/stunnel.conf" << EOL
pid = /var/run/stunnel4/stunnel.pid
setuid = stunnel4
setgid = stunnel4
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh]
accept = ${PORTS[SSH_TLS]}
connect = 127.0.0.1:${PORTS[SSH]}
cert = $SSL_DIR/irssh-panel.crt
key = $SSL_DIR/irssh-panel.key
EOL
        systemctl restart stunnel4
    fi
    
    info "SSL setup completed"
}

# Install and configure PostgreSQL
setup_database() {
    info "Setting up PostgreSQL database..."
    
    # Install PostgreSQL
    apt-get install -y postgresql postgresql-contrib || error "Failed to install PostgreSQL"
    
    # Start and enable PostgreSQL
    systemctl start postgresql
    systemctl enable postgresql
    
    # Wait for PostgreSQL to be ready
    local max_attempts=30
    local attempt=1
    while ! pg_isready; do
        if [ $attempt -ge $max_attempts ]; then
            error "PostgreSQL failed to start after $max_attempts attempts"
        fi
        info "Waiting for PostgreSQL... (attempt $attempt/$max_attempts)"
        sleep 1
        ((attempt++))
    done
    
    # Configure pg_hba.conf for both IPv4 and IPv6
    local PG_HBA="/etc/postgresql/14/main/pg_hba.conf"
    cp "$PG_HBA" "${PG_HBA}.backup"
    
    sed -i \
        -e 's/local\s\+all\s\+all\s\+peer/local   all             all                                     md5/' \
        -e 's/host\s\+all\s\+all\s\+127.0.0.1\/32\s\+scram-sha-256/host    all             all             127.0.0.1\/32            md5/' \
        -e 's/host\s\+all\s\+all\s\+::1\/128\s\+scram-sha-256/host    all             all             ::1\/128                 md5/' \
        "$PG_HBA"
    
    # Reload PostgreSQL configuration
    systemctl reload postgresql
    
    # Setup database and user
    source "$CONFIG_DIR/config.yaml"
    su - postgres << EOF
psql -c "CREATE USER $db_user WITH PASSWORD '$db_password';"
psql -c "CREATE DATABASE $db_name OWNER $db_user;"
psql -c "GRANT ALL PRIVILEGES ON DATABASE $db_name TO $db_user;"
psql -c "ALTER SYSTEM SET password_encryption = 'md5';"
EOF
    
    # Verify database connection
    if ! PGPASSWORD="$db_password" psql -h localhost -U "$db_user" -d "$db_name" -c '\q'; then
        error "Database connection verification failed"
    fi
    
    info "Database setup completed successfully"
}

# Install and configure Python environment
setup_python() {
    info "Setting up Python environment..."
    
    # Install Python and development packages
    apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        libpq-dev \
        gcc || error "Failed to install Python packages"
    
    # Create and activate virtual environment
    python3 -m venv "$PANEL_DIR/venv"
    source "$PANEL_DIR/venv/bin/activate"
    
    # Upgrade pip and install base packages
    pip install --upgrade pip setuptools wheel
    
    # Install urllib3 with specific version first
    pip install urllib3==2.0.7
    
    # Install required Python packages
    pip install \
        requests==2.31.0 \
        prometheus_client \
        psutil \
        python-dotenv \
        PyYAML \
        cryptography \
        PyJWT \
        websockets \
        aiofiles \
        fastapi \
        uvicorn \
        sqlalchemy \
        alembic \
        passlib \
        pydantic \
        psycopg2-binary \
        paramiko || error "Failed to install Python packages"
    
    # Create helper script for loading configuration
    cat > "$PANEL_DIR/venv/bin/load_config.py" << 'EOL'
#!/usr/bin/env python3
import os
import yaml

def load_config():
    config_file = "/etc/enhanced_ssh/config.yaml"
    if not os.path.exists(config_file):
        print("Configuration file not found!")
        exit(1)
        
    with open(config_file, "r") as f:
        config = yaml.safe_load(f)
        
    # Set environment variables with IRSSH prefix
    for key, value in config.items():
        os.environ[f"IRSSH_{key.upper()}"] = str(value)

if __name__ == "__main__":
    load_config()
EOL

    chmod +x "$PANEL_DIR/venv/bin/load_config.py"
    
    info "Python environment setup completed"
    deactivate
}

# Install and configure Node.js environment
setup_nodejs() {
    info "Setting up Node.js environment..."
    
    # Install Node.js and npm
    if ! command -v node &> /dev/null; then
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        apt-get install -y nodejs || error "Failed to install Node.js"
    fi
    
    # Install global packages
    npm install -g pm2 typescript @types/node || error "Failed to install global npm packages"
    
    # Setup frontend
    cd "$PANEL_DIR/frontend" || error "Failed to access frontend directory"
    
    # Initialize package.json
    cat > package.json << 'EOL'
{
  "name": "irssh-panel-frontend",
  "version": "3.5.2",
  "private": true,
  "dependencies": {
    "@headlessui/react": "^1.7.17",
    "@heroicons/react": "^2.0.18",
    "axios": "^1.6.2",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.21.0",
    "react-query": "^3.39.3",
    "zustand": "^4.4.7"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.2.1",
    "@types/node": "^20.10.4",
    "@types/react": "^18.2.45",
    "@types/react-dom": "^18.2.17",
    "typescript": "^5.3.3",
    "autoprefixer": "^10.4.16",
    "tailwindcss": "^3.3.6",
    "vite": "^5.0.7"
  },
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview"
  }
}
EOL

    # Install dependencies
    npm install || error "Failed to install frontend dependencies"
    
    # Setup backend
    cd "$PANEL_DIR/backend" || error "Failed to access backend directory"
    
    # Initialize package.json for backend
    cat > package.json << 'EOL'
{
  "name": "irssh-panel-backend",
  "version": "3.5.2",
  "private": true,
  "dependencies": {
    "express": "^4.18.2",
    "mongoose": "^8.0.3",
    "jsonwebtoken": "^9.0.2",
    "bcryptjs": "^2.4.3",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "helmet": "^7.1.0",
    "winston": "^3.11.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.2",
    "jest": "^29.7.0",
    "eslint": "^8.55.0"
  },
  "scripts": {
    "start": "node src/index.js",
    "dev": "nodemon src/index.js",
    "test": "jest"
  }
}
EOL

    # Install backend dependencies
    npm install || error "Failed to install backend dependencies"
    
    info "Node.js environment setup completed"
}

# Protocol Installation Functions
###########################################

# Install and configure SSH
install_ssh() {
    info "Installing SSH server..."
    
    # Install required packages
    apt-get install -y openssh-server stunnel4 || error "Failed to install SSH packages"
    
    # Backup and configure SSH
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    cat > /etc/ssh/sshd_config << EOL
Port ${PORTS[SSH]}
PermitRootLogin yes
PasswordAuthentication yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
EOL

    # Configure stunnel
    mkdir -p /etc/stunnel
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/stunnel/stunnel.pem \
        -out /etc/stunnel/stunnel.pem \
        -subj "/CN=localhost" || error "Failed to generate SSL certificate"
        
    chmod 600 /etc/stunnel/stunnel.pem
    
    # Create stunnel configuration
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

    # Setup WebSocket service
    cat > /etc/systemd/system/websocket.service << EOL
[Unit]
Description=WebSocket for SSH
After=network.target

[Service]
ExecStart=/usr/local/bin/websocat -t --binary-protocol ws-l:0.0.0.0:${PORTS[WEBSOCKET]} tcp:127.0.0.1:${PORTS[SSH]}
Restart=always

[Install]
WantedBy=multi-user.target
EOL

    # Reload and restart services
    systemctl daemon-reload
    systemctl restart ssh
    systemctl enable stunnel4
    systemctl restart stunnel4
    systemctl enable websocket
    systemctl start websocket
    
    info "SSH server installation completed"
}

# Install and configure L2TP
install_l2tp() {
    info "Installing L2TP/IPsec..."
    
    # Install required packages
    apt-get install -y \
        strongswan \
        strongswan-pki \
        libstrongswan-extra-plugins \
        libcharon-extra-plugins \
        xl2tpd \
        ppp || error "Failed to install L2TP packages"
    
    # Configure strongSwan
    cat > /etc/ipsec.conf << 'EOL'
config setup
    charondebug="ike 2, knl 2, cfg 2, net 2, esp 2, dmn 2,  mgr 2"

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

    # Generate and set PSK
    local PSK=$(openssl rand -base64 32)
    echo ": PSK \"$PSK\"" > /etc/ipsec.secrets
    
    # Configure xl2tpd
    cat > /etc/xl2tpd/xl2tpd.conf << EOL
[global]
ipsec saref = yes
saref refinfo = 30

[lns default]
ip range = 10.10.10.100-10.10.10.200
local ip = 10.10.10.1
refuse chap = yes
refuse pap = yes
require authentication = yes
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOL

    # Configure PPP
    cat > /etc/ppp/options.xl2tpd << EOL
ipcp-accept-local
ipcp-accept-remote
ms-dns 8.8.8.8
ms-dns 8.8.4.4
noccp
auth
mtu 1280
mru 1280
proxyarp
lcp-echo-failure 4
lcp-echo-interval 30
connect-delay 5000
EOL

    # Start services
    systemctl restart strongswan
    systemctl restart xl2tpd
    systemctl enable strongswan
    systemctl enable xl2tpd
    
    info "L2TP/IPsec installation completed"
}

# Install and configure IKEv2
install_ikev2() {
    info "Installing IKEv2..."
    
    # Install required packages
    apt-get install -y strongswan strongswan-pki || error "Failed to install IKEv2 packages"
    
    # Generate certificates
    mkdir -p /etc/ipsec.d/private /etc/ipsec.d/cacerts /etc/ipsec.d/certs
    
    # Generate CA key and certificate
    ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/ca-key.pem
    chmod 600 /etc/ipsec.d/private/ca-key.pem
    
    ipsec pki --self --ca --lifetime 3650 \
        --in /etc/ipsec.d/private/ca-key.pem \
        --type rsa --dn "CN=VPN CA" \
        --outform pem > /etc/ipsec.d/cacerts/ca-cert.pem
    
    # Generate server key and certificate
    ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/server-key.pem
    chmod 600 /etc/ipsec.d/private/server-key.pem
    
    ipsec pki --pub --in /etc/ipsec.d/private/server-key.pem --type rsa \
        | ipsec pki --issue --lifetime 1825 \
            --cacert /etc/ipsec.d/cacerts/ca-cert.pem \
            --cakey /etc/ipsec.d/private/ca-key.pem \
            --dn "CN=vpn.server.com" \
            --san "@vpn.server.com" \
            --flag serverAuth --flag ikeIntermediate \
            --outform pem > /etc/ipsec.d/certs/server-cert.pem
    
    # Configure strongSwan for IKEv2
    cat > /etc/ipsec.conf << 'EOL'
config setup
    charondebug="ike 2, knl 2, cfg 2, net 2, esp 2, dmn 2,  mgr 2"

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
    rightid=%any
    rightauth=eap-mschapv2
    rightsourceip=10.10.10.0/24
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=never
    eap_identity=%identity
EOL

    # Configure strongSwan secrets
    cat > /etc/ipsec.secrets << EOL
: RSA "server-key.pem"
EOL

    # Start service
    systemctl restart strongswan
    systemctl enable strongswan
    
    info "IKEv2 installation completed"
}

# Install and configure OpenConnect (Cisco AnyConnect)
install_cisco() {
    info "Installing OpenConnect (Cisco AnyConnect)..."
    
    # Install required packages
    apt-get install -y ocserv gnutls-bin || error "Failed to install OpenConnect packages"
    
    # Generate certificates
    mkdir -p /etc/ocserv/ssl
    cd /etc/ocserv/ssl || error "Failed to access OpenConnect SSL directory"
    
    # Generate CA key and certificate
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
    
    # Generate server key and certificate
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
    
    # Configure OpenConnect
    cat > /etc/ocserv/ocserv.conf << EOL
auth = "plain[passwd=/etc/ocserv/ocpasswd]"
tcp-port = ${PORTS[CISCO]}
udp-port = ${PORTS[CISCO]}
run-as-user = nobody
run-as-group = daemon
socket-file = /var/run/ocserv-socket
server-cert = /etc/ocserv/ssl/server-cert.pem
server-key = /etc/ocserv/ssl/server-key.pem
ca-cert = /etc/ocserv/ssl/ca-cert.pem
isolate-workers = true
max-clients = 128
max-same-clients = 2
server-stats-reset-time = 604800
keepalive = 32400
mobile-dpd = 1800
try-mtu-discovery = true
cert-user-oid = 0.9.2342.19200300.100.1.1
compression = true
no-compress-limit = 256
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-RSA:-VERS-SSL3.0:-ARCFOUR-128"
auth-timeout = 240
min-reauth-time = 300
max-ban-score = 80
ban-reset-time = 1200
cookie-timeout = 300
deny-roaming = false
rekey-time = 172800
rekey-method = ssl
use-seccomp = true
pid-file = /var/run/ocserv.pid
device = vpns
predictable-ips = true
default-domain = vpn.example.com
ipv4-network = 192.168.1.0
ipv4-netmask = 255.255.255.0
dns = 8.8.8.8
dns = 8.8.4.4
route = default
no-route = 192.168.0.0/255.255.0.0
cisco-client-compat = true
dtls-legacy = true
EOL

    # Create initial user database
    touch /etc/ocserv/ocpasswd
    
    # Enable IP forwarding
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    sysctl -p
    
    # Start service
    systemctl restart ocserv
    systemctl enable ocserv
    
    info "OpenConnect (Cisco AnyConnect) installation completed"
}

# Install and configure WireGuard
install_wireguard() {
    info "Installing WireGuard..."
    
    # Install required packages
    apt-get install -y wireguard || error "Failed to install WireGuard"
    
    # Generate keys
    mkdir -p /etc/wireguard
    cd /etc/wireguard || error "Failed to access WireGuard directory"
    
    # Generate server keys
    wg genkey | tee server_private.key | wg pubkey > server_public.key
    
    # Configure WireGuard
    cat > /etc/wireguard/wg0.conf << EOL
[Interface]
PrivateKey = $(cat server_private.key)
Address = 10.66.66.1/24
ListenPort = ${PORTS[WIREGUARD]}
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
EOL

    # Enable IP forwarding
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    sysctl -p
    
    # Start service
    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
    
    info "WireGuard installation completed"
}

# Install and configure Sing-Box
install_singbox() {
    info "Installing Sing-Box..."
    
    # Download and install Sing-Box
    local SINGBOX_VERSION="1.7.0"
    local ARCH="amd64"
    
    wget "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${ARCH}.tar.gz" \
        -O /tmp/sing-box.tar.gz || error "Failed to download Sing-Box"
    
    tar -xzf /tmp/sing-box.tar.gz -C /tmp
    mv /tmp/sing-box-*/sing-box /usr/local/bin/
    chmod +x /usr/local/bin/sing-box
    
    # Create configuration directory
    mkdir -p /etc/sing-box
    
    # Generate configuration
    cat > /etc/sing-box/config.json << EOL
{
  "log": {
    "level": "info",
    "output": "/var/log/sing-box.log"
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "::",
      "listen_port": ${PORTS[SINGBOX]},
      "sniff": true,
      "sniff_override_destination": false,
      "domain_strategy": "prefer_ipv4"
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ],
  "route": {
    "rules": [
      {
        "geoip": "private",
        "outbound": "block"
      }
    ],
    "auto_detect_interface": true
  }
}
EOL

    # Create systemd service
    cat > /etc/systemd/system/sing-box.service << EOL
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
User=root
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOL

    # Start service
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    
    info "Sing-Box installation completed"
}

# Install and configure Dropbear
install_dropbear() {
    info "Installing Dropbear..."
    
    # Install required packages
    apt-get install -y dropbear || error "Failed to install Dropbear"
    
    # Configure Dropbear
    cat > /etc/default/dropbear << EOL
NO_START=0
DROPBEAR_PORT=${PORTS[DROPBEAR]}
DROPBEAR_EXTRA_ARGS="-p ${PORTS[DROPBEAR]}"
DROPBEAR_BANNER="/etc/issue.net"
DROPBEAR_RECEIVE_WINDOW=65536
EOL

    # Create custom banner
    echo "Welcome to IRSSH Panel - Dropbear SSH Server" > /etc/issue.net
    
    # Generate keys if they don't exist
    mkdir -p /etc/dropbear
    dropbear -R
    
    # Start service
    systemctl restart dropbear
    systemctl enable dropbear
    
    info "Dropbear installation completed"
}

# Configure Nginx web server
setup_nginx() {
    info "Setting up Nginx web server..."
    
    # Install Nginx if not present
    apt-get install -y nginx || error "Failed to install Nginx"
    
    # Create Nginx configuration
    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen ${PORTS[WEB]} ssl http2;
    listen [::]:${PORTS[WEB]} ssl http2;
    server_name _;

    ssl_certificate /etc/nginx/ssl/irssh-panel.crt;
    ssl_certificate_key /etc/nginx/ssl/irssh-panel.key;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;

    root $PANEL_DIR/frontend/dist;
    index index.html;

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript text/javascript application/x-javascript application/xml+rss;

    location / {
        try_files \$uri \$uri/ /index.html;
        add_header Cache-Control "no-store, no-cache, must-revalidate";
    }

    location /api {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        
        # Security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "no-referrer-when-downgrade" always;
        add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    }

    # Deny access to . files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
}
EOL

    # Enable site and remove default
    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    # Test and restart Nginx
    nginx -t || error "Nginx configuration test failed"
    systemctl restart nginx
    
    info "Nginx setup completed"
}

# Main installation function
main() {
    trap cleanup EXIT
    
    log "INFO" "Starting IRSSH Panel installation v${VERSION}"
    
    # Initial setup
    check_requirements
    setup_directories
    
    # Generate configuration
    generate_config
    
    # Core services setup
    setup_database
    setup_python
    setup_nodejs
    setup_ssl
    
    # Install protocols
    [ "${PROTOCOLS[SSH]}" = true ] && install_ssh
    [ "${PROTOCOLS[L2TP]}" = true ] && install_l2tp
    [ "${PROTOCOLS[IKEV2]}" = true ] && install_ikev2
    [ "${PROTOCOLS[CISCO]}" = true ] && install_cisco
    [ "${PROTOCOLS[WIREGUARD]}" = true ] && install_wireguard
    [ "${PROTOCOLS[SINGBOX]}" = true ] && install_singbox
    [ "${PROTOCOLS[DROPBEAR]}" = true ] && install_dropbear
    
    # Final configuration
    setup_nginx
    setup_security
    setup_cron
    verify_installation
    save_installation_info
    
    info "Installation completed successfully!"
    
    # Display installation summary
    cat << EOL

IRSSH Panel Installation Summary
-------------------------------
Version: ${VERSION}
Installation Directory: ${PANEL_DIR}
Web Interface: https://YOUR-SERVER-IP:${PORTS[WEB]}
Configuration Directory: ${CONFIG_DIR}
Log Directory: ${LOG_DIR}

All service configurations and credentials have been saved to:
${CONFIG_DIR}/installation.info

Please make sure to secure this server and change default passwords.
For more information, please refer to the documentation.
EOL
}

# Start installation
main
