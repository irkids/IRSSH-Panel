#!/bin/bash

# IRSSH Panel Complete Installation Script
# Version: 3.5.2
# Aligned with GitHub Repository Structure

###########################################
# Core Configuration and Directory Structure
###########################################

# Base directory structure reflecting GitHub repository
REPO_BASE="/opt/irssh-panel"
declare -A DIRS=(
    ["BACKEND_DIR"]="$REPO_BASE/backend"
    ["FRONTEND_DIR"]="$REPO_BASE/frontend"
    ["CONFIG_DIR"]="$REPO_BASE/config"
    ["MODULES_DIR"]="$REPO_BASE/modules"
    ["DOCS_DIR"]="$REPO_BASE/docs"
    ["TESTS_DIR"]="$REPO_BASE/tests"
    ["ANSIBLE_DIR"]="$REPO_BASE/ansible"
    ["SCRIPTS_DIR"]="$REPO_BASE/scripts"
    ["MONITORING_DIR"]="$REPO_BASE/monitoring"
    ["SECURITY_DIR"]="$REPO_BASE/security"
    ["IAC_DIR"]="$REPO_BASE/iac"
    ["CI_CD_DIR"]="$REPO_BASE/ci_cd"
    ["PROTOCOLS_DIR"]="$REPO_BASE/modules/protocols"
)

# Production specific directories
declare -A PROD_DIRS=(
    ["PROD_CONFIG"]="/etc/enhanced_ssh"
    ["PROD_LOG"]="/var/log/irssh"
    ["PROD_BACKUP"]="/opt/irssh-backups"
    ["PROD_SSL"]="/etc/nginx/ssl"
    ["PROD_PROTOCOLS"]="/etc/enhanced_ssh/protocols"
    ["PROD_METRICS"]="/var/log/irssh/metrics"
)

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
    ["WEB"]=8080
    ["UDPGW"]=7300
)

# System Requirements
declare -A REQUIREMENTS=(
    ["MIN_MEMORY"]=1024
    ["MIN_DISK"]=5120
    ["MIN_CPU_CORES"]=2
    ["MIN_NODE_VERSION"]=16
    ["MIN_PYTHON_VERSION"]="3.8"
)

# Configuration Templates
declare -A CONFIG_TEMPLATES=(
    ["backend"]="$REPO_BASE/config/templates/backend"
    ["frontend"]="$REPO_BASE/config/templates/frontend"
    ["protocols"]="$REPO_BASE/config/templates/protocols"
    ["monitoring"]="$REPO_BASE/config/templates/monitoring"
)

# Colors for output
declare -A COLORS=(
    ["GREEN"]='\033[0;32m'
    ["RED"]='\033[0;31m'
    ["YELLOW"]='\033[1;33m'
    ["BLUE"]='\033[0;34m'
    ["NC"]='\033[0m'
)

###########################################
# Utility Functions
###########################################

# Enhanced logging system
log() {
    local level=$1
    local message=$2
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    local color_code="${COLORS[${level}]:-${COLORS[NC]}}"
    local log_file="${PROD_DIRS[PROD_LOG]}/installation.log"
    
    # Create log directory if it doesn't exist
    mkdir -p "${PROD_DIRS[PROD_LOG]}"
    
    # Console output with color
    echo -e "${color_code}[$timestamp] [$level] $message${COLORS[NC]}"
    
    # File output
    echo "[$timestamp] [$level] $message" >> "$log_file"
    
    # Error logging to separate file
    if [[ "$level" == "ERROR" ]]; then
        echo "[$timestamp] [$level] $message" >> "${PROD_DIRS[PROD_LOG]}/error.log"
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

###########################################
# Core Installation Functions
###########################################

# Initialize directory structure
init_directory_structure() {
    info "Initializing directory structure..."

    # Create base directories
    for dir in "${DIRS[@]}"; do
        mkdir -p "$dir"
        info "Created repository directory: $dir"
    done

    # Create production directories
    for dir in "${PROD_DIRS[@]}"; do
        mkdir -p "$dir"
        info "Created production directory: $dir"
    done

    # Set proper permissions
    chmod 755 "$REPO_BASE"
    chmod 700 "${PROD_DIRS[PROD_CONFIG]}"
    chmod 755 "${PROD_DIRS[PROD_LOG]}"

    # Create necessary subdirectories
    mkdir -p "${DIRS[BACKEND_DIR]}/src/{controllers,routes,middleware,models,utils}"
    mkdir -p "${DIRS[FRONTEND_DIR]}/src/{components,pages,services,styles}"
    mkdir -p "${DIRS[CONFIG_DIR]}/environment/{development,staging,production}"
    mkdir -p "${DIRS[MONITORING_DIR]}/{prometheus,grafana}/config"
    mkdir -p "${DIRS[SECURITY_DIR]}/{certificates,firewall,audit}"
}

# Initialize configuration templates
init_config_templates() {
    info "Setting up configuration templates..."

    for template_dir in "${CONFIG_TEMPLATES[@]}"; do
        mkdir -p "$template_dir"
    done

    # Generate environment-specific configurations
    generate_environment_configs
}

# Generate environment-specific configurations
generate_environment_configs() {
    info "Generating environment-specific configurations..."
    
    local environments=("development" "staging" "production")
    
    for env in "${environments[@]}"; do
        local config_dir="$REPO_BASE/config/environment/$env"
        mkdir -p "$config_dir"
        
        # Generate main config
        cat > "$config_dir/app.config.json" << EOL
{
    "environment": "$env",
    "version": "${VERSION}",
    "protocols": {
        "ssh": ${PROTOCOLS[SSH]},
        "l2tp": ${PROTOCOLS[L2TP]},
        "ikev2": ${PROTOCOLS[IKEV2]},
        "cisco": ${PROTOCOLS[CISCO]},
        "wireguard": ${PROTOCOLS[WIREGUARD]},
        "singbox": ${PROTOCOLS[SINGBOX]}
    },
    "ports": {
        "web": ${PORTS[WEB]},
        "ssh": ${PORTS[SSH]},
        "l2tp": ${PORTS[L2TP]},
        "ikev2": ${PORTS[IKEV2]},
        "cisco": ${PORTS[CISCO]},
        "wireguard": ${PORTS[WIREGUARD]},
        "singbox": ${PORTS[SINGBOX]}
    }
}
EOL

        # Generate database config
        cat > "$config_dir/database.config.json" << EOL
{
    "host": "localhost",
    "port": 5432,
    "database": "irssh_${env}",
    "username": "irssh_user",
    "password": "auto_generated_in_production"
}
EOL

        # Generate monitoring config
        cat > "$config_dir/monitoring.config.json" << EOL
{
    "enabled": ${ENABLE_MONITORING},
    "prometheus_port": 9090,
    "grafana_port": 3000,
    "metrics_retention_days": 30,
    "alert_endpoints": []
}
EOL
    done
}

###########################################
# Database Installation and Configuration
###########################################

setup_database() {
    info "Setting up PostgreSQL database..."
    
    # Install PostgreSQL
    apt-get install -y postgresql-$DB_VERSION postgresql-contrib-$DB_VERSION || error "Failed to install PostgreSQL"

    # Initialize database cluster if not exists
    if ! pg_lsclusters | grep -q "^$DB_VERSION main"; then
        pg_createcluster $DB_VERSION main --start
    fi
    
    # Ensure PostgreSQL is running
    systemctl start postgresql
    systemctl enable postgresql
    
    # Wait for PostgreSQL to be ready
    local max_attempts=5
    local attempt=1
    until pg_isready -h localhost -p 5432; do
        if [ $attempt -ge $max_attempts ]; then
            error "PostgreSQL failed to start after $max_attempts attempts"
        fi
        info "Waiting for PostgreSQL... (attempt $attempt/$max_attempts)"
        sleep 1
        ((attempt++))
    done

    # Create database user and databases for each environment
    local environments=("development" "staging" "production")
    for env in "${environments[@]}"; do
        local db_name="irssh_${env}"
        local db_user="irssh_${env}"
        local db_pass=$(openssl rand -base64 32)
        
        # Create user and database
        su - postgres -c "psql -c \"CREATE USER \\\"$db_user\\\" WITH PASSWORD '$db_pass';\""
        su - postgres -c "psql -c \"CREATE DATABASE \\\"$db_name\\\" OWNER \\\"$db_user\\\";\""
        
        # Save credentials to configuration
        cat > "${DIRS[CONFIG_DIR]}/environment/$env/database.secret.json" << EOL
{
    "DB_USER": "$db_user",
    "DB_PASS": "$db_pass",
    "DB_NAME": "$db_name"
}
EOL
        chmod 600 "${DIRS[CONFIG_DIR]}/environment/$env/database.secret.json"
    done

    # Configure PostgreSQL
    cat > "/etc/postgresql/$DB_VERSION/main/pg_hba.conf" << EOL
# Database administrative login by Unix domain socket
local   all             postgres                                peer

# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     md5
host    all             all             127.0.0.1/32            md5
host    all             all             ::1/128                 md5
EOL

    # Optimize PostgreSQL configuration
    cat > "/etc/postgresql/$DB_VERSION/main/conf.d/optimizations.conf" << EOL
# Memory Configuration
shared_buffers = '256MB'
effective_cache_size = '768MB'
work_mem = '8MB'
maintenance_work_mem = '64MB'

# Checkpoint Configuration
checkpoint_completion_target = 0.9
checkpoint_timeout = '15min'
max_wal_size = '1GB'
min_wal_size = '80MB'

# Query Planner Configuration
random_page_cost = 1.1
effective_io_concurrency = 200

# Logging Configuration
log_min_duration_statement = 1000
log_checkpoints = on
log_connections = on
log_disconnections = on
log_lock_waits = on
log_temp_files = 0
log_autovacuum_min_duration = 0
EOL

    # Restart PostgreSQL
    systemctl restart postgresql
    
    info "Database setup completed successfully"
}

###########################################
# Node.js Setup and Configuration
###########################################

setup_nodejs() {
    info "Setting up Node.js environment..."
    
    # Install Node.js
    if ! command -v node &> /dev/null; then
        curl -fsSL "https://deb.nodesource.com/setup_${NODE_VERSION}.x" | bash -
        apt-get install -y nodejs || error "Failed to install Node.js"
    fi
    
    # Verify npm installation
    if ! command -v npm &> /dev/null; then
        error "npm installation failed"
    fi
    
    # Install global packages
    npm install -g pm2 typescript @types/node nx || error "Failed to install global npm packages"
    
    # Initialize project workspace
    cd "$REPO_BASE" || error "Failed to access repository directory"
    
    # Create workspace configuration
    cat > nx.json << EOL
{
  "npmScope": "irssh",
  "affected": {
    "defaultBase": "main"
  },
  "implicitDependencies": {
    "package.json": {
      "dependencies": "*",
      "devDependencies": "*"
    }
  },
  "tasksRunnerOptions": {
    "default": {
      "runner": "nx/tasks-runners/default",
      "options": {
        "cacheableOperations": ["build", "lint", "test", "e2e"]
      }
    }
  },
  "targetDefaults": {
    "build": {
      "dependsOn": ["^build"]
    }
  }
}
EOL

    # Initialize backend project
    cd "${DIRS[BACKEND_DIR]}" || error "Failed to access backend directory"
    
    cat > package.json << EOL
{
  "name": "@irssh/backend",
  "version": "3.5.2",
  "private": true,
  "scripts": {
    "start": "node dist/main.js",
    "build": "tsc -p tsconfig.build.json",
    "dev": "ts-node-dev --respawn src/main.ts",
    "test": "jest",
    "lint": "eslint \"{src,apps,libs,test}/**/*.ts\"",
    "format": "prettier --write \"src/**/*.ts\""
  },
  "dependencies": {
    "@nestjs/common": "^8.0.0",
    "@nestjs/core": "^8.0.0",
    "@nestjs/platform-express": "^8.0.0",
    "@nestjs/swagger": "^5.0.0",
    "@nestjs/typeorm": "^8.0.0",
    "class-transformer": "^0.4.0",
    "class-validator": "^0.13.0",
    "pg": "^8.7.0",
    "reflect-metadata": "^0.1.13",
    "rxjs": "^7.0.0",
    "typeorm": "^0.2.0"
  },
  "devDependencies": {
    "@types/express": "^4.17.0",
    "@types/jest": "^27.0.0",
    "@types/node": "^16.0.0",
    "@typescript-eslint/eslint-plugin": "^4.0.0",
    "@typescript-eslint/parser": "^4.0.0",
    "eslint": "^7.0.0",
    "eslint-config-prettier": "^8.0.0",
    "eslint-plugin-prettier": "^3.0.0",
    "jest": "^27.0.0",
    "prettier": "^2.0.0",
    "ts-jest": "^27.0.0",
    "ts-node": "^10.0.0",
    "ts-node-dev": "^1.0.0",
    "typescript": "^4.0.0"
  }
}
EOL

    # Initialize frontend project
    cd "${DIRS[FRONTEND_DIR]}" || error "Failed to access frontend directory"
    
    cat > package.json << EOL
{
  "name": "@irssh/frontend",
  "version": "3.5.2",
  "private": true,
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "lint": "eslint src --ext .ts,.tsx",
    "format": "prettier --write \"src/**/*.{ts,tsx}\""
  },
  "dependencies": {
    "@headlessui/react": "^1.7.0",
    "@heroicons/react": "^2.0.0",
    "@tanstack/react-query": "^4.0.0",
    "axios": "^1.0.0",
    "react": "^18.0.0",
    "react-dom": "^18.0.0",
    "react-router-dom": "^6.0.0",
    "recharts": "^2.0.0",
    "tailwindcss": "^3.0.0",
    "zustand": "^4.0.0"
  },
  "devDependencies": {
    "@types/react": "^18.0.0",
    "@types/react-dom": "^18.0.0",
    "@typescript-eslint/eslint-plugin": "^5.0.0",
    "@typescript-eslint/parser": "^5.0.0",
    "@vitejs/plugin-react": "^3.0.0",
    "autoprefixer": "^10.0.0",
    "eslint": "^8.0.0",
    "eslint-plugin-react": "^7.0.0",
    "postcss": "^8.0.0",
    "prettier": "^2.0.0",
    "typescript": "^4.0.0",
    "vite": "^4.0.0"
  }
}
EOL

    # Install dependencies
    cd "$REPO_BASE" || error "Failed to access repository directory"
    npm install || error "Failed to install dependencies"
    
    info "Node.js environment setup completed"
}

###########################################
# VPN Protocol Installation
###########################################

install_protocols() {
    info "Installing VPN protocols..."
    
    # Create protocols directory
    mkdir -p "${DIRS[PROTOCOLS_DIR]}"
    
    # Install each enabled protocol
    for protocol in "${!PROTOCOLS[@]}"; do
        if [ "${PROTOCOLS[$protocol]}" = true ]; then
            info "Installing $protocol protocol..."
            install_protocol_"${protocol,,}"  # Convert to lowercase
        fi
    done
    
    info "VPN protocols installation completed"
}

# SSH Protocol Installation
install_protocol_ssh() {
    info "Installing SSH protocol..."
    
    local protocol_dir="${DIRS[PROTOCOLS_DIR]}/ssh"
    mkdir -p "$protocol_dir"
    
    # Install required packages
    apt-get install -y openssh-server stunnel4 || error "Failed to install SSH packages"
    
    # Create protocol configuration
    cat > "$protocol_dir/config.yaml" << EOL
protocol: ssh
version: ${VERSION}
ports:
  main: ${PORTS[SSH]}
  tls: ${PORTS[SSH_TLS]}
  websocket: ${PORTS[WEBSOCKET]}
features:
  tls_tunnel: true
  websocket: true
  compression: true
security:
  allow_password_auth: true
  max_auth_tries: 6
  allow_root_login: false
logging:
  level: info
  facility: AUTH
monitoring:
  enabled: true
  metrics_path: /metrics/ssh
EOL

    # Generate SSL certificate for stunnel
    if [ ! -f "${PROD_DIRS[PROD_SSL]}/stunnel.pem" ]; then
        mkdir -p "${PROD_DIRS[PROD_SSL]}"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "${PROD_DIRS[PROD_SSL]}/stunnel.pem" \
            -out "${PROD_DIRS[PROD_SSL]}/stunnel.pem" \
            -subj "/CN=localhost" || error "Failed to generate SSL certificate"
        chmod 600 "${PROD_DIRS[PROD_SSL]}/stunnel.pem"
    fi

    # Configure SSH server
    cat > /etc/ssh/sshd_config << EOL
Port ${PORTS[SSH]}
PermitRootLogin no
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server

# Security Settings
MaxAuthTries 6
LoginGraceTime 30
PermitEmptyPasswords no
ClientAliveInterval 300
ClientAliveCountMax 3
MaxStartups 10:30:60
TCPKeepAlive yes

# Logging
SyslogFacility AUTH
LogLevel INFO
EOL

    # Configure stunnel for TLS
    cat > /etc/stunnel/stunnel.conf << EOL
pid = /var/run/stunnel4/stunnel.pid
setuid = stunnel4
setgid = stunnel4
cert = ${PROD_DIRS[PROD_SSL]}/stunnel.pem
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh-tls]
client = no
accept = ${PORTS[SSH_TLS]}
connect = 127.0.0.1:${PORTS[SSH]}
EOL

    # Install and configure websocket service
    install_websocket_service
    
    # Create monitoring script
    cat > "$protocol_dir/monitor.sh" << EOL
#!/bin/bash

# Get active connections
ACTIVE_CONN=\$(netstat -ant | grep :${PORTS[SSH]} | grep ESTABLISHED | wc -l)
echo "ssh_active_connections \$ACTIVE_CONN" > "${PROD_DIRS[PROD_METRICS]}/ssh_connections.prom"

# Get failed login attempts
FAILED_AUTH=\$(grep "Failed password" /var/log/auth.log | wc -l)
echo "ssh_failed_logins \$FAILED_AUTH" > "${PROD_DIRS[PROD_METRICS]}/ssh_failed_logins.prom"

# Get successful logins
SUCCESS_AUTH=\$(grep "Accepted password" /var/log/auth.log | wc -l)
echo "ssh_successful_logins \$SUCCESS_AUTH" > "${PROD_DIRS[PROD_METRICS]}/ssh_successful_logins.prom"
EOL

    chmod +x "$protocol_dir/monitor.sh"
    
    # Add monitoring to cron
    (crontab -l 2>/dev/null || true; echo "*/5 * * * * $protocol_dir/monitor.sh") | crontab -
    
    # Start services
    systemctl restart ssh
    systemctl enable ssh
    systemctl restart stunnel4
    systemctl enable stunnel4
    
    info "SSH protocol installation completed"
}

###########################################
# VPN Protocol Installation (Continued)
###########################################

# WireGuard Installation
install_protocol_wireguard() {
    info "Installing WireGuard protocol..."
    
    local protocol_dir="${DIRS[PROTOCOLS_DIR]}/wireguard"
    mkdir -p "$protocol_dir"
    
    # Install WireGuard
    apt-get install -y wireguard || error "Failed to install WireGuard"
    
    # Generate server keys
    umask 077
    wg genkey | tee "${PROD_DIRS[PROD_PROTOCOLS]}/wg_private.key" | wg pubkey > "${PROD_DIRS[PROD_PROTOCOLS]}/wg_public.key"
    
    # Create protocol configuration
    cat > "$protocol_dir/config.yaml" << EOL
protocol: wireguard
version: ${VERSION}
port: ${PORTS[WIREGUARD]}
server_address: 10.66.66.1/24
dns:
  - 8.8.8.8
  - 8.8.4.4
mtu: 1420
persistent_keepalive: 25
public_key: $(cat "${PROD_DIRS[PROD_PROTOCOLS]}/wg_public.key")
allowed_ips: 10.66.66.0/24
EOL

    # Configure WireGuard interface
    cat > /etc/wireguard/wg0.conf << EOL
[Interface]
PrivateKey = $(cat "${PROD_DIRS[PROD_PROTOCOLS]}/wg_private.key")
Address = 10.66.66.1/24
ListenPort = ${PORTS[WIREGUARD]}
SaveConfig = false

# NAT Configuration
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Performance Settings
MTU = 1420
Table = off
PreUp = sysctl -w net.ipv4.ip_forward=1
EOL

    # Create client management scripts
    cat > "$protocol_dir/add_client.sh" << 'EOL'
#!/bin/bash
if [ $# -ne 1 ]; then
    echo "Usage: $0 <client_name>"
    exit 1
fi

CLIENT_NAME=$1
WG_CONFIG_DIR="/etc/wireguard/clients"
mkdir -p "$WG_CONFIG_DIR"

# Generate client keys
CLIENT_PRIVATE_KEY=$(wg genkey)
CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)
CLIENT_IP="10.66.66.$(( 2 + $(ls -1 "$WG_CONFIG_DIR" | wc -l) ))"

# Create client config
cat > "$WG_CONFIG_DIR/${CLIENT_NAME}.conf" << CONF
[Interface]
PrivateKey = ${CLIENT_PRIVATE_KEY}
Address = ${CLIENT_IP}/24
DNS = 8.8.8.8, 8.8.4.4
MTU = 1420

[Peer]
PublicKey = $(cat "${PROD_DIRS[PROD_PROTOCOLS]}/wg_public.key")
AllowedIPs = 0.0.0.0/0
Endpoint = $(curl -s ifconfig.me):${PORTS[WIREGUARD]}
PersistentKeepalive = 25
CONF

# Add client to server config
cat >> /etc/wireguard/wg0.conf << CONF

[Peer]
PublicKey = ${CLIENT_PUBLIC_KEY}
AllowedIPs = ${CLIENT_IP}/32
CONF

# Restart WireGuard
wg-quick down wg0 && wg-quick up wg0

echo "Client configuration generated: $WG_CONFIG_DIR/${CLIENT_NAME}.conf"
EOL

    chmod +x "$protocol_dir/add_client.sh"

    # Create monitoring script
    cat > "$protocol_dir/monitor.sh" << 'EOL'
#!/bin/bash
# Get WireGuard statistics
STATS=$(wg show wg0)
CONNECTIONS=$(echo "$STATS" | grep -c "latest handshake")
TRANSFER_RX=$(echo "$STATS" | awk '/transfer:/ {sum+=$2} END {print sum}')
TRANSFER_TX=$(echo "$STATS" | awk '/transfer:/ {sum+=$4} END {print sum}')

# Write metrics
echo "wireguard_active_connections $CONNECTIONS" > "${PROD_DIRS[PROD_METRICS]}/wireguard_connections.prom"
echo "wireguard_transfer_bytes{direction=\"rx\"} $TRANSFER_RX" > "${PROD_DIRS[PROD_METRICS]}/wireguard_transfer_rx.prom"
echo "wireguard_transfer_bytes{direction=\"tx\"} $TRANSFER_TX" > "${PROD_DIRS[PROD_METRICS]}/wireguard_transfer_tx.prom"
EOL

    chmod +x "$protocol_dir/monitor.sh"
    
    # Add monitoring to cron
    (crontab -l 2>/dev/null || true; echo "*/5 * * * * $protocol_dir/monitor.sh") | crontab -

    # Enable and start WireGuard
    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
    
    info "WireGuard installation completed"
}

# SingBox Installation
install_protocol_singbox() {
    info "Installing Sing-Box protocol..."
    
    local protocol_dir="${DIRS[PROTOCOLS_DIR]}/singbox"
    mkdir -p "$protocol_dir"
    
    # Download and install Sing-Box
    local ARCH="amd64"
    local DOWNLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${ARCH}.tar.gz"
    
    wget "$DOWNLOAD_URL" -O /tmp/sing-box.tar.gz || error "Failed to download Sing-Box"
    tar -xzf /tmp/sing-box.tar.gz -C /tmp
    mv "/tmp/sing-box-${SINGBOX_VERSION}-linux-${ARCH}/sing-box" /usr/local/bin/
    chmod +x /usr/local/bin/sing-box
    
    # Generate SSL certificates
    mkdir -p "${PROD_DIRS[PROD_SSL]}/singbox"
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "${PROD_DIRS[PROD_SSL]}/singbox/server.key" \
        -out "${PROD_DIRS[PROD_SSL]}/singbox/server.crt" \
        -subj "/CN=singbox.server"
    
    # Create protocol configuration
    cat > "$protocol_dir/config.json" << EOL
{
  "log": {
    "level": "info",
    "output": "${PROD_DIRS[PROD_LOG]}/singbox.log",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "google",
        "address": "8.8.8.8",
        "detour": "direct"
      }
    ]
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
    },
    {
      "type": "shadowsocks",
      "tag": "ss-in",
      "listen": "::",
      "listen_port": ${PORTS[SINGBOX]}-1,
      "method": "aes-256-gcm",
      "password": "$(openssl rand -base64 32)",
      "network": "tcp,udp"
    },
    {
      "type": "vmess",
      "tag": "vmess-in",
      "listen": "::",
      "listen_port": ${PORTS[SINGBOX]}-2,
      "users": [
        {
          "uuid": "$(uuidgen)",
          "alterId": 0
        }
      ],
      "transport": {
        "type": "ws",
        "path": "/vmess"
      },
      "tls": {
        "enabled": true,
        "server_name": "singbox.server",
        "certificate_path": "${PROD_DIRS[PROD_SSL]}/singbox/server.crt",
        "key_path": "${PROD_DIRS[PROD_SSL]}/singbox/server.key"
      }
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
Description=Sing-Box Service
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/usr/local/bin/sing-box run -c ${protocol_dir}/config.json
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOL

    # Create monitoring script
    cat > "$protocol_dir/monitor.sh" << EOL
#!/bin/bash
# Monitor Sing-Box connections
STATS=\$(netstat -ant)
SS_CONN=\$(echo "\$STATS" | grep -c ":$((${PORTS[SINGBOX]}-1))")
VMESS_CONN=\$(echo "\$STATS" | grep -c ":$((${PORTS[SINGBOX]}-2))")
TOTAL_CONN=\$(( SS_CONN + VMESS_CONN ))

# Write metrics
echo "singbox_total_connections \$TOTAL_CONN" > "${PROD_DIRS[PROD_METRICS]}/singbox_total.prom"
echo "singbox_connections{protocol=\"shadowsocks\"} \$SS_CONN" > "${PROD_DIRS[PROD_METRICS]}/singbox_ss.prom"
echo "singbox_connections{protocol=\"vmess\"} \$VMESS_CONN" > "${PROD_DIRS[PROD_METRICS]}/singbox_vmess.prom"
EOL

    chmod +x "$protocol_dir/monitor.sh"
    
    # Add monitoring to cron
    (crontab -l 2>/dev/null || true; echo "*/5 * * * * $protocol_dir/monitor.sh") | crontab -

    # Start service
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    
    info "Sing-Box installation completed"
}

###########################################
# Security Configuration
###########################################

setup_security() {
    info "Setting up security measures..."
    
    # Install security packages
    apt-get install -y \
        fail2ban \
        ufw \
        rkhunter \
        clamav \
        auditd \
        openssl \
        apparmor \
        apparmor-utils \
        || error "Failed to install security packages"

    # Configure AppArmor
    cat > "${DIRS[SECURITY_DIR]}/apparmor/irssh-panel.profile" << 'EOL'
#include <tunables/global>

profile irssh-panel flags=(attach_disconnected,mediate_deleted) {
    #include <abstractions/base>
    #include <abstractions/nameservice>
    #include <abstractions/openssl>
    #include <abstractions/ssl_certs>

    capability net_admin,
    capability net_bind_service,
    capability net_raw,

    # Panel directories
    /opt/irssh-panel/** rw,
    /etc/enhanced_ssh/** rw,
    /var/log/irssh/** rw,
    /var/run/irssh/** rw,

    # Protocol specific
    /etc/wireguard/** rw,
    /etc/sing-box/** rw,
    /etc/ssh/** r,

    # System access
    /proc/sys/net/ipv4/ip_forward rw,
    /sys/class/net/** r,
    /dev/net/tun rw,
}
EOL

    # Configure fail2ban
    cat > /etc/fail2ban/jail.local << EOL
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ${PORTS[SSH]},${PORTS[DROPBEAR]}
logpath = %(sshd_log)s
maxretry = 3

[nginx-http-auth]
enabled = true
port = ${PORTS[WEB]}
logpath = /var/log/nginx/error.log
maxretry = 5

[nginx-limit-req]
enabled = true
port = ${PORTS[WEB]}
logpath = /var/log/nginx/error.log
maxretry = 10

[vpn-auth]
enabled = true
logpath = ${PROD_DIRS[PROD_LOG]}/auth.log
maxretry = 5
findtime = 300
bantime = 3600
EOL

    # Configure UFW firewall
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow configured ports
    for port in "${PORTS[@]}"; do
        ufw allow "$port"
    done
    
    # Enable UFW
    echo "y" | ufw enable

    # Configure audit rules
    cat > /etc/audit/rules.d/irssh-panel.rules << EOL
# Monitor configuration changes
-w ${PROD_DIRS[PROD_CONFIG]} -p wa -k irssh_config
-w /etc/wireguard -p wa -k vpn_config
-w /etc/sing-box -p wa -k vpn_config

# Monitor authentication events
-w /var/log/auth.log -p wa -k auth_log
-w ${PROD_DIRS[PROD_LOG]}/auth.log -p wa -k vpn_auth

# Monitor binary modifications
-w /usr/local/bin/sing-box -p wa -k vpn_binary
-w /usr/bin/wg -p wa -k vpn_binary

# Monitor network configuration
-a exit,always -F arch=b64 -S sethostname -S setdomainname -k system_hostname
-w /etc/hosts -p wa -k system_hosts
-w /etc/network -p wa -k system_network
EOL

    # Restart audit service
    service auditd restart

    # Setup automated security scanning
    cat > "${DIRS[SECURITY_DIR]}/scripts/security_scan.sh" << 'EOL'
#!/bin/bash

LOG_DIR="${PROD_DIRS[PROD_LOG]}/security"
REPORT_FILE="$LOG_DIR/security_report_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$LOG_DIR"

{
    echo "Security Scan Report - $(date)"
    echo "================================="

    # System file integrity check
    echo -e "\nFile Integrity Check:"
    rkhunter --check --skip-keypress --report-warnings-only

    # Malware scan
    echo -e "\nMalware Scan:"
    clamscan --recursive --infected /opt/irssh-panel /etc/enhanced_ssh

    # Network security check
    echo -e "\nOpen Ports:"
    netstat -tuln

    # Authentication attempts
    echo -e "\nFailed Authentication Attempts:"
    grep "Failed password" /var/log/auth.log | tail -n 10

    # Disk usage check
    echo -e "\nDisk Usage:"
    df -h

    # Check running services
    echo -e "\nRunning Services:"
    systemctl list-units --type=service --state=running

    # Check system logs for suspicious activity
    echo -e "\nSuspicious Activity Log:"
    grep -i "error\|warning\|fail" /var/log/syslog | tail -n 20

} > "$REPORT_FILE"

# Generate metrics for monitoring
FAILED_AUTH_COUNT=$(grep -c "Failed password" /var/log/auth.log)
SUSPICIOUS_ACTIVITY=$(grep -ci "error\|warning\|fail" /var/log/syslog)

echo "security_failed_auth_total $FAILED_AUTH_COUNT" > "${PROD_DIRS[PROD_METRICS]}/security_auth.prom"
echo "security_suspicious_activity_total $SUSPICIOUS_ACTIVITY" > "${PROD_DIRS[PROD_METRICS]}/security_activity.prom"
EOL

    chmod +x "${DIRS[SECURITY_DIR]}/scripts/security_scan.sh"
    
    # Add to cron
    (crontab -l 2>/dev/null || true; echo "0 */6 * * * ${DIRS[SECURITY_DIR]}/scripts/security_scan.sh") | crontab -

    info "Security measures setup completed"
}

###########################################
# Monitoring System Setup
###########################################

setup_monitoring() {
    if [ "$ENABLE_MONITORING" != "y" ]; then
        info "Monitoring system disabled, skipping..."
        return 0
    fi
    
    info "Setting up monitoring system..."
    
    # Install monitoring tools
    apt-get install -y \
        prometheus \
        prometheus-node-exporter \
        grafana \
        collectd \
        || error "Failed to install monitoring tools"

    # Configure Prometheus
    cat > "${DIRS[MONITORING_DIR]}/prometheus/prometheus.yml" << EOL
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']

  - job_name: 'irssh-panel'
    static_configs:
      - targets: ['localhost:8000']

  - job_name: 'vpn-metrics'
    file_sd_configs:
      - files:
        - '${PROD_DIRS[PROD_METRICS]}/*.prom'
    
rule_files:
  - 'rules/*.yml'
EOL

    # Configure Prometheus alert rules
    mkdir -p "${DIRS[MONITORING_DIR]}/prometheus/rules"
    cat > "${DIRS[MONITORING_DIR]}/prometheus/rules/alerts.yml" << EOL
groups:
- name: IRSSH-Panel
  rules:
  - alert: HighCPUUsage
    expr: node_cpu_seconds_total{mode="idle"} < 0.1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: High CPU usage detected
      description: CPU usage is above 90% for more than 5 minutes

  - alert: HighMemoryUsage
    expr: node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes * 100 < 10
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: High memory usage detected
      description: Available memory is below 10% for more than 5 minutes

  - alert: VPNConnectionSpike
    expr: rate(vpn_connections_total[5m]) > 100
    for: 1m
    labels:
      severity: warning
    annotations:
      summary: Unusual VPN connection rate
      description: VPN connection rate is unusually high

  - alert: SecurityIncident
    expr: security_suspicious_activity_total > 100
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: Security incident detected
      description: High number of suspicious activities detected
EOL

    # Configure Grafana
    cat > "${DIRS[MONITORING_DIR]}/grafana/provisioning/datasources/prometheus.yml" << EOL
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://localhost:9090
    isDefault: true
EOL

    # Create monitoring dashboard
    cat > "${DIRS[MONITORING_DIR]}/grafana/provisioning/dashboards/irssh-panel.json" << 'EOL'
{
  "annotations": {
    "list": []
  },
  "editable": true,
  "fiscalYearStartMonth": 0,
  "graphTooltip": 0,
  "links": [],
  "liveNow": false,
  "panels": [
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "palette-classic"
          },
          "custom": {
            "axisCenteredZero": false,
            "axisColorMode": "text",
            "axisLabel": "",
            "axisPlacement": "auto",
            "barAlignment": 0,
            "drawStyle": "line",
            "fillOpacity": 0,
            "gradientMode": "none",
            "hideFrom": {
              "legend": false,
              "tooltip": false,
              "viz": false
            },
            "lineInterpolation": "linear",
            "lineWidth": 1,
            "pointSize": 5,
            "scaleDistribution": {
              "type": "linear"
            },
            "showPoints": "auto",
            "spanNulls": false,
            "stacking": {
              "group": "A",
              "mode": "none"
            },
            "thresholdsStyle": {
              "mode": "off"
            }
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "red",
                "value": 80
              }
            ]
          }
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 0
      },
      "options": {
        "legend": {
          "calcs": [],
          "displayMode": "list",
          "placement": "bottom",
          "showLegend": true
        },
        "tooltip": {
          "mode": "single",
          "sort": "none"
        }
      },
      "title": "VPN Connections",
      "type": "timeseries"
    }
  ],
  "refresh": "5s",
  "schemaVersion": 38,
  "style": "dark",
  "tags": [],
  "templating": {
    "list": []
  },
  "time": {
    "from": "now-6h",
    "to": "now"
  },
  "timepicker": {},
  "timezone": "",
  "title": "IRSSH Panel Dashboard",
  "version": 0,
  "weekStart": ""
}
EOL

    # Create metrics collection script
    cat > "${DIRS[MONITORING_DIR]}/scripts/collect_metrics.sh" << 'EOL'
#!/bin/bash

METRICS_DIR="${PROD_DIRS[PROD_METRICS]}"
mkdir -p "$METRICS_DIR"

# System metrics
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}')
MEM_USAGE=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
DISK_USAGE=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')

echo "system_cpu_usage $CPU_USAGE" > "$METRICS_DIR/system.prom"
echo "system_memory_usage $MEM_USAGE" > "$METRICS_DIR/memory.prom"
echo "system_disk_usage $DISK_USAGE" > "$METRICS_DIR/disk.prom"

# Collect VPN metrics from individual protocol monitors
for protocol in ssh wireguard singbox; do
    if [ -x "${DIRS[PROTOCOLS_DIR]}/$protocol/monitor.sh" ]; then
        "${DIRS[PROTOCOLS_DIR]}/$protocol/monitor.sh"
    fi
done
EOL

    chmod +x "${DIRS[MONITORING_DIR]}/scripts/collect_metrics.sh"
    
    # Add to cron
    (crontab -l 2>/dev/null || true; echo "* * * * * ${DIRS[MONITORING_DIR]}/scripts/collect_metrics.sh") | crontab -

    # Start monitoring services
    systemctl restart prometheus
    systemctl enable prometheus
    systemctl restart grafana-server
    systemctl enable grafana-server
    
    info "Monitoring system setup completed"
}

###########################################
# Web Server Configuration
###########################################

setup_nginx() {
    info "Setting up Nginx web server..."
    
    # Install Nginx
    apt-get install -y nginx || error "Failed to install Nginx"

    # Generate SSL certificate if HTTPS is enabled
    if [ "$ENABLE_HTTPS" = "y" ]; then
        mkdir -p "${PROD_DIRS[PROD_SSL]}/nginx"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "${PROD_DIRS[PROD_SSL]}/nginx/server.key" \
            -out "${PROD_DIRS[PROD_SSL]}/nginx/server.crt" \
            -subj "/CN=irssh-panel"
    fi

    # Configure Nginx with optimizations
    cat > /etc/nginx/nginx.conf << 'EOL'
user www-data;
worker_processes auto;
worker_rlimit_nofile 65535;
pid /run/nginx.pid;

events {
    worker_connections 65535;
    multi_accept on;
    use epoll;
}

http {
    charset utf-8;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    server_tokens off;
    log_not_found off;
    types_hash_max_size 2048;
    types_hash_bucket_size 64;
    client_max_body_size 16M;

    # MIME
    include mime.types;
    default_type application/octet-stream;

    # Logging
    access_log /var/log/nginx/access.log combined buffer=512k flush=1m;
    error_log /var/log/nginx/error.log warn;

    # SSL
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

    # Gzip
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript application/rss+xml application/atom+xml image/svg+xml;

    # Virtual Host Configs
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOL

    # Configure panel site
    local nginx_conf="/etc/nginx/sites-available/irssh-panel"
    if [ "$ENABLE_HTTPS" = "y" ]; then
        cat > "$nginx_conf" << EOL
server {
    listen 80;
    server_name _;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name _;
    
    ssl_certificate ${PROD_DIRS[PROD_SSL]}/nginx/server.crt;
    ssl_certificate_key ${PROD_DIRS[PROD_SSL]}/nginx/server.key;
    
    root ${DIRS[FRONTEND_DIR]}/dist;
    index index.html;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location /api {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /metrics {
        auth_basic "Metrics Authentication";
        auth_basic_user_file /etc/nginx/.metrics_htpasswd;
        proxy_pass http://localhost:9090;
    }
}
EOL
    else
        cat > "$nginx_conf" << EOL
server {
    listen ${PORTS[WEB]};
    server_name _;
    
    root ${DIRS[FRONTEND_DIR]}/dist;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location /api {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOL
    fi

    # Enable site
    ln -sf "$nginx_conf" /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default

    # Create metrics authentication
    if [ "$ENABLE_MONITORING" = "y" ]; then
        local metrics_pass=$(openssl rand -base64 12)
        echo "metrics:\$apr1\$$(openssl rand -hex 8)\$$(openssl passwd -apr1 $metrics_pass)" > /etc/nginx/.metrics_htpasswd
        chmod 600 /etc/nginx/.metrics_htpasswd
    fi

    # Test and restart Nginx
    nginx -t || error "Nginx configuration test failed"
    systemctl restart nginx
    systemctl enable nginx
    
    info "Nginx setup completed"
}

###########################################
# Backup Management
###########################################

setup_backup() {
    info "Setting up backup system..."
    
    mkdir -p "${PROD_DIRS[PROD_BACKUP]}/{daily,weekly,monthly}"
    
    # Create backup script
    cat > "${DIRS[SCRIPTS_DIR]}/backup.sh" << 'EOL'
#!/bin/bash

BACKUP_ROOT="${PROD_DIRS[PROD_BACKUP]}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=7
RETENTION_WEEKS=4
RETENTION_MONTHS=3

# Create backup archives
create_backup() {
    local type=$1
    local backup_dir="$BACKUP_ROOT/$type"
    local backup_file="$backup_dir/backup_${TIMESTAMP}.tar.gz"
    
    # Backup configuration files
    tar -czf "$backup_file" \
        "${PROD_DIRS[PROD_CONFIG]}" \
        "${DIRS[CONFIG_DIR]}" \
        /etc/nginx/sites-available/irssh-panel \
        /etc/wireguard \
        /etc/sing-box \
        || return 1

    # Backup database
    local db_backup="$backup_dir/db_${TIMESTAMP}.sql"
    source "${PROD_DIRS[PROD_CONFIG]}/config.yaml"
    PGPASSWORD="$db_password" pg_dump -U "$db_user" "$db_name" > "$db_backup" || return 1

    # Create backup manifest
    local manifest_file="$backup_dir/backup_${TIMESTAMP}.manifest"
    {
        echo "Backup created at: $(date)"
        echo "Version: ${VERSION}"
        echo "Configuration files: $backup_file"
        echo "Database dump: $db_backup"
        echo
        echo "Included files:"
        tar -tvf "$backup_file"
    } > "$manifest_file"

    # Create checksum
    sha256sum "$backup_file" "$db_backup" > "$backup_dir/backup_${TIMESTAMP}.sha256"
}

# Cleanup old backups
cleanup_backups() {
    local type=$1
    local days=$2
    local backup_dir="$BACKUP_ROOT/$type"
    
    find "$backup_dir" -type f -mtime "+$days" -delete
}

# Perform daily backup
create_backup "daily"
cleanup_backups "daily" "$RETENTION_DAYS"

# Perform weekly backup on Sunday
if [ "$(date +%u)" = "7" ]; then
    create_backup "weekly"
    cleanup_backups "weekly" "$((RETENTION_WEEKS * 7))"
fi

# Perform monthly backup on first day of month
if [ "$(date +%d)" = "01" ]; then
    create_backup "monthly"
    cleanup_backups "monthly" "$((RETENTION_MONTHS * 30))"
fi

# Verify latest backup
verify_backup() {
    local type=$1
    local backup_dir="$BACKUP_ROOT/$type"
    local latest_backup=$(ls -t "$backup_dir"/backup_*.tar.gz | head -1)
    local latest_checksum="$backup_dir/$(basename "${latest_backup%.*}").sha256"
    
    if [ -f "$latest_backup" ] && [ -f "$latest_checksum" ]; then
        if ! sha256sum -c "$latest_checksum"; then
            echo "WARNING: Backup verification failed for $type backup!"
            return 1
        fi
    else
        echo "WARNING: Latest backup or checksum file not found for $type backup!"
        return 1
    fi
}

verify_backup "daily"
EOL



    chmod +x "${DIRS[SCRIPTS_DIR]}/backup.sh"
    
    # Add to cron
    (crontab -l 2>/dev/null || true; echo "0 2 * * * ${DIRS[SCRIPTS_DIR]}/backup.sh") | crontab -
    
    info "Backup system setup completed"
}

# System Requirements Check
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
    
    # Install basic requirements
    apt-get update
    apt-get install -y \
        curl \
        wget \
        git \
        postgresql \
        postgresql-contrib \
        build-essential \
        || error "Failed to install basic requirements"

    # Check system resources
    local MEM_TOTAL=$(free -m | awk '/^Mem:/{print $2}')
    local CPU_CORES=$(nproc)
    local DISK_SPACE=$(df -m / | awk 'NR==2 {print $4}')
    
    if [ "$MEM_TOTAL" -lt "${REQUIREMENTS[MIN_MEMORY]}" ]; then
        warn "System has less than ${REQUIREMENTS[MIN_MEMORY]}MB RAM"
    fi
    
    if [ "$CPU_CORES" -lt "${REQUIREMENTS[MIN_CPU_CORES]}" ]; then
        warn "System has less than ${REQUIREMENTS[MIN_CPU_CORES]} CPU cores"
    fi
    
    if [ "$DISK_SPACE" -lt "${REQUIREMENTS[MIN_DISK]}" ]; then
        error "Insufficient disk space. At least ${REQUIREMENTS[MIN_DISK]}MB required"
    fi
}

# Get initial configuration from user
get_initial_config() {
    info "Initial Configuration Setup"
    
    # Get admin credentials
    while [ -z "$ADMIN_USER" ]; do
        read -p "Enter admin username: " ADMIN_USER
    done
    
    while [ -z "$ADMIN_PASS" ]; do
        read -s -p "Enter admin password: " ADMIN_PASS
        echo
        read -s -p "Confirm admin password: " ADMIN_PASS_CONFIRM
        echo
        
        if [ "$ADMIN_PASS" != "$ADMIN_PASS_CONFIRM" ]; then
            error "Passwords do not match" "no-exit"
            ADMIN_PASS=""
        fi
    done
    
    # Get web port
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
    
    # Ask for HTTPS
    read -p "Enable HTTPS? (y/N): " ENABLE_HTTPS
    ENABLE_HTTPS=${ENABLE_HTTPS,,}
    
    # Ask for monitoring
    read -p "Enable system monitoring? (y/N): " ENABLE_MONITORING
    ENABLE_MONITORING=${ENABLE_MONITORING,,}
}

# Cleanup function
cleanup() {
    info "Performing cleanup..."
    
    # Stop services
    for service in nginx postgresql irssh-panel irssh-backend; do
        if systemctl is-active --quiet "$service"; then
            systemctl stop "$service"
        fi
    done
    
    # Remove temporary files
    if [ -d "/tmp/irssh-install" ]; then
        rm -rf "/tmp/irssh-install"
    fi
    
    # Additional cleanup tasks
    apt-get clean
    
    info "Cleanup completed"
}

# Installation verification
verify_installation() {
    info "Verifying installation..."
    
    # Check core services
    local services=("nginx" "postgresql" "irssh-panel" "irssh-backend")
    for service in "${services[@]}"; do
        if ! systemctl is-active --quiet "$service"; then
            error "Service $service is not running" "no-exit"
        fi
    done
    
    # Check web server
    if ! curl -s "http://localhost:${PORTS[WEB]}" >/dev/null; then
        error "Web panel is not accessible" "no-exit"
    fi
    
    # Check database
    if ! psql -U "$db_user" -d "$db_name" -c '\q' >/dev/null 2>&1; then
        error "Database connection failed" "no-exit"
    fi
    
    info "Installation verification completed"
}

###########################################
# Main Installation
###########################################

main() {
    trap cleanup EXIT
    
    log "INFO" "Starting IRSSH Panel installation v${VERSION}"
    
    # Initial setup
    check_requirements
    get_initial_config
    init_directory_structure
    init_config_templates
    
    # Core installation
    install_nodejs
    setup_database
    setup_python
    setup_frontend
    setup_backend
    
    # Protocol installation
    install_protocols
    
    # System configuration
    setup_nginx
    setup_security
    setup_backup
    
    if [ "$ENABLE_MONITORING" = "y" ]; then
        setup_monitoring
    fi
    
    # Verify installation
    verify_installation
    
    # Final steps
    generate_documentation
    
    info "Installation completed successfully!"
    display_completion_summary
}

# Start installation
main

# End of script
