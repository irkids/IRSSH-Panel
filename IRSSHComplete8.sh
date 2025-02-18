#!/bin/bash

# IRSSH Panel Complete Installation Script
# Version: 3.5.2

declare -A CONFIG_FILES
CONFIG_FILES=(
    ["/etc/nginx/sites-available/irssh-panel"]="server {
        listen \${WEB_PORT};
        server_name _;
        # Other configurations
    }"
)

# Global Variables and Constants
###########################################
SCRIPT_PATH=$(readlink -f "${BASH_SOURCE[0]}")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")

# Global Configuration
postgresql_version=12
declare -A CONFIG_FILES

CONFIG_FILES["/etc/nginx/sites-available/irssh-panel"]="server {
    listen \${WEB_PORT};
    server_name _;
    # Rest of nginx config
}"

CONFIG_FILES["/etc/postgresql/$postgresql_version/main/pg_hba.conf"]="local all postgres peer
local all all md5
host all all 127.0.0.1/32 md5
host all all ::1/128 md5"

# Base directories
PANEL_DIR="/opt/irssh-panel"
CONFIG_DIR="/etc/enhanced_ssh"
LOG_DIR="/var/log/irssh"
BACKUP_DIR="/opt/irssh-backups"
TEMP_DIR="/tmp/irssh-install"
SSL_DIR="/etc/nginx/ssl"
MODULES_DIR="$PANEL_DIR/modules"
PROTOCOLS_DIR="$MODULES_DIR/protocols"

# Protocol Installation Modes (default values)
declare -A PROTOCOLS=(
    ["SSH"]=true
    ["DROPBEAR"]=true
    ["L2TP"]=true
    ["IKEV2"]=true
    ["CISCO"]=true
    ["WIREGUARD"]=true
    ["SINGBOX"]=true
)

# Protocol Ports (default values)
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

# User Configuration Variables
ADMIN_USER=""
ADMIN_PASS=""
WEB_PORT=""
UDPGW_PORT=""
ENABLE_HTTPS="n"
ENABLE_MONITORING="n"

# Colors for output
declare -A COLORS=(
    ["GREEN"]='\033[0;32m'
    ["RED"]='\033[0;31m'
    ["YELLOW"]='\033[1;33m'
    ["BLUE"]='\033[0;34m'
    ["NC"]='\033[0m'
)

# Advanced Configuration Options
DB_VERSION="12"
NODE_VERSION="20"
WEBSOCAT_VERSION="1.11.0"
SINGBOX_VERSION="1.7.0"

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
    
    # File output
    echo "[$timestamp] [$level] $message" >> "$LOG_DIR/installation.log"
    
    # Error logging to separate file
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

# Enhanced cleanup function
cleanup() {
    info "Performing cleanup..."
    
    # Remove temporary files
    if [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
    
    # Stop any failed services
    for service in nginx postgresql irssh-panel irssh-backend; do
        if systemctl is-failed --quiet "$service"; then
            systemctl stop "$service"
        fi
    done
    
    # Clean package manager cache
    apt-get clean
    
    info "Cleanup completed"
}

# Advanced backup function
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

# Advanced restore function
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
    
    # Get UDPGW port
    while true; do
        read -p "Enter UDPGW port (4-5 digits) or press Enter for random port: " UDPGW_PORT
        if [ -z "$UDPGW_PORT" ]; then
            UDPGW_PORT=$(shuf -i 1234-65432 -n 1)
            info "Generated random UDPGW port: $UDPGW_PORT"
            break
        elif [[ "$UDPGW_PORT" =~ ^[0-9]{4,5}$ ]] && [ "$UDPGW_PORT" -ge 1234 ] && [ "$UDPGW_PORT" -le 65432 ]; then
            break
        else
            error "Invalid port number. Must be between 1234 and 65432" "no-exit"
        fi
    done
    PORTS["UDPGW"]=$UDPGW_PORT
    
    # Ask for HTTPS
    read -p "Enable HTTPS? (y/N): " ENABLE_HTTPS
    ENABLE_HTTPS=${ENABLE_HTTPS,,}
    
    # Ask for monitoring
    read -p "Enable system monitoring? (y/N): " ENABLE_MONITORING
    ENABLE_MONITORING=${ENABLE_MONITORING,,}
    
    # Display configuration summary
    echo
    info "Configuration Summary:"
    echo "Admin Username: $ADMIN_USER"
    echo "Web Panel Port: ${PORTS[WEB]}"
    echo "UDPGW Port: ${PORTS[UDPGW]}"
    echo "HTTPS Enabled: ${ENABLE_HTTPS}"
    echo "Monitoring Enabled: ${ENABLE_MONITORING}"
    
    read -p "Continue with these settings? (Y/n): " confirm
    if [[ "$confirm" =~ ^[Nn] ]]; then
        error "Installation cancelled by user"
    fi
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
    
    # Install Python 3.8 if not present
    if ! command -v python3.8 &> /dev/null; then
        info "Installing Python 3.8..."
        apt-get update
        apt-get install -y software-properties-common
        if [[ "$ID" == "ubuntu" ]]; then
            add-apt-repository -y ppa:deadsnakes/ppa
        fi
        apt-get update
        apt-get install -y python3.8 python3.8-venv python3.8-dev
        update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1
    fi
    
    # Install Node.js
    if ! command -v node &> /dev/null; then
        info "Installing Node.js..."
        curl -fsSL "https://deb.nodesource.com/setup_${NODE_VERSION}.x" | bash -
        apt-get install -y nodejs
    fi
    
    NODE_VERSION=$(node -v | sed 's/v\([0-9]*\).*/\1/')
    if [ "$NODE_VERSION" -lt "${REQUIREMENTS[MIN_NODE_VERSION]}" ]; then
        error "Node.js version must be ${REQUIREMENTS[MIN_NODE_VERSION]} or higher"
    fi
    
    info "System requirements check completed"
}

# Directory Setup
setup_directories() {
    info "Creating required directories and files..."

        # Create base directories
    mkdir -p /etc/nginx/{sites-available,sites-enabled}
    mkdir -p /opt/irssh-panel/frontend/dist
    mkdir -p "/etc/postgresql/$postgresql_version/main"
    mkdir -p "/var/lib/postgresql/$postgresql_version/main"

    # Set permissions
    chown www-data:www-data /opt/irssh-panel/frontend/dist
    chmod 755 /opt/irssh-panel/frontend/dist
    chown -R postgres:postgres "/etc/postgresql/$postgresql_version"
    chown -R postgres:postgres "/var/lib/postgresql/$postgresql_version"

    # Core directories
    declare -A DIRS=(
        ["/etc/postgresql"]=""
        ["/etc/postgresql/12/main"]=""
        ["/etc/postgresql/12/main"]=""
        ["/var/lib/postgresql/12/main"]=""
        ["/var/lib/postgresql/12/main"]=""
        ["/var/log/postgresql"]=""
        ["/etc/enhanced_ssh"]=""
        ["/opt/irssh-panel"]=""
        ["/opt/irssh-panel/backend"]=""
        ["/opt/irssh-panel/frontend"]=""
        ["/opt/irssh-panel/modules"]=""
        ["/opt/irssh-panel/modules/protocols"]=""
        ["/opt/irssh-panel/scripts"]=""
        ["/opt/irssh-panel/config"]=""
        ["/opt/irssh-panel/logs"]=""
        ["/var/log/irssh"]=""
        ["/var/log/irssh/metrics"]=""
        ["/opt/irssh-backups"]=""
        ["/etc/stunnel"]=""
        ["/etc/wireguard"]=""
        ["/etc/sing-box"]=""
        ["/etc/sing-box/ssl"]=""
        ["/etc/ocserv"]=""
        ["/etc/ocserv/ssl"]=""
        ["/etc/nginx/ssl"]=""
    )

    # Create directories
    for dir in "${!DIRS[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            chmod 755 "$dir"
            info "Created directory: $dir"
        fi
    done

    # Essential configuration files
    declare -A CONFIG_FILES=(
        ["/etc/postgresql/12/main/pg_hba.conf"]="# Database administrative login by Unix domain socket
local   all             postgres                                peer

# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     peer
host    all             all             127.0.0.1/32            md5
host    all             all             ::1/128                 md5"

        ["/etc/postgresql/12/main/postgresql.conf"]="# DB Version: 12
listen_addresses = 'localhost'
port = 5432
max_connections = 100
shared_buffers = 128MB
dynamic_shared_memory_type = posix
ssl = off"

        ["/etc/postgresql/12/main/pg_hba.conf"]="# Database administrative login by Unix domain socket
local   all             postgres                                peer

# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     peer
host    all             all             127.0.0.1/32            md5
host    all             all             ::1/128                 md5"

        ["/etc/postgresql/12/main/postgresql.conf"]="# DB Version: 12
listen_addresses = 'localhost'
port = 5432
max_connections = 100
shared_buffers = 128MB
dynamic_shared_memory_type = posix
ssl = off"

        ["/etc/enhanced_ssh/config.yaml"]="# IRSSH Panel Configuration
db_host: localhost
db_port: 5432
db_name: ${DB_NAME}
db_user: ${DB_USER}
db_password: ${DB_PASS}"

     mkdir -p /opt/irssh-panel/frontend/dist

        ["/etc/nginx/sites-available/irssh-panel"]="server {
    listen 80;
    server_name _;
    root /opt/irssh-panel/frontend/dist;
    index index.html;
}"
    )

    # Create configuration files
    for file in "${!CONFIG_FILES[@]}"; do
        if [ ! -f "$file" ]; then
            echo "${CONFIG_FILES[$file]}" > "$file"
            chmod 644 "$file"
            info "Created configuration file: $file"
        fi
    done

    # Create empty log files
    declare -a LOG_FILES=(
        "/var/log/irssh/installation.log"
        "/var/log/irssh/error.log"
        "/var/log/postgresql/postgresql-12-main.log"
        "/var/log/postgresql/postgresql-12-main.log"
    )

    for file in "${LOG_FILES[@]}"; do
        if [ ! -f "$file" ]; then
            touch "$file"
            chmod 644 "$file"
            info "Created log file: $file"
        fi
    done

    # Create symbolic links
    if [ ! -L "/etc/nginx/sites-enabled/irssh-panel" ]; then
        ln -sf "/etc/nginx/sites-available/irssh-panel" "/etc/nginx/sites-enabled/irssh-panel"
        info "Created symbolic link for Nginx configuration"
    fi

    # Set correct permissions
    chown -R postgres:postgres /etc/postgresql
    chown -R postgres:postgres /var/lib/postgresql
    chown -R www-data:www-data /opt/irssh-panel/frontend/dist

    info "Directory and file setup completed"
}

# Generate Configuration
generate_config() {
    info "Generating configuration..."
    
    # Generate secure credentials
    local DB_NAME="ssh_manager"
    local DB_USER="irssh_admin"
    local DB_PASS=$(openssl rand -base64 32)
    local JWT_SECRET=$(openssl rand -base64 32)
    local ADMIN_PASS_HASH=$(echo -n "$ADMIN_PASS" | sha256sum | cut -d' ' -f1)
    
    # Create main config file
    cat > "$CONFIG_DIR/config.yaml" << EOL
# IRSSH Panel Configuration
# Generated: $(date +'%Y-%m-%d %H:%M:%S')

# System Configuration
version: ${VERSION}
install_date: $(date +'%Y-%m-%d %H:%M:%S')

# Database Configuration
db_host: localhost
db_port: 5432
db_name: $DB_NAME
db_user: $DB_USER
db_password: $DB_PASS

# Web Panel Configuration
web_port: ${PORTS[WEB]}
jwt_secret: $JWT_SECRET
enable_https: ${ENABLE_HTTPS}
enable_monitoring: ${ENABLE_MONITORING}

# Admin Credentials
admin_user: $ADMIN_USER
admin_password_hash: $ADMIN_PASS_HASH

# Protocol Ports
ssh_port: ${PORTS[SSH]}
dropbear_port: ${PORTS[DROPBEAR]}
websocket_port: ${PORTS[WEBSOCKET]}
l2tp_port: ${PORTS[L2TP]}
ikev2_port: ${PORTS[IKEV2]}
cisco_port: ${PORTS[CISCO]}
wireguard_port: ${PORTS[WIREGUARD]}
singbox_port: ${PORTS[SINGBOX]}
udpgw_port: ${PORTS[UDPGW]}

# Protocol Settings
enable_ssh: ${PROTOCOLS[SSH]}
enable_dropbear: ${PROTOCOLS[DROPBEAR]}
enable_l2tp: ${PROTOCOLS[L2TP]}
enable_ikev2: ${PROTOCOLS[IKEV2]}
enable_cisco: ${PROTOCOLS[CISCO]}
enable_wireguard: ${PROTOCOLS[WIREGUARD]}
enable_singbox: ${PROTOCOLS[SINGBOX]}

# Performance Settings
max_clients: 1000
max_connections_per_client: 10
connection_timeout: 300
keepalive_interval: 60

# Security Settings
fail2ban_enabled: true
fail2ban_bantime: 3600
fail2ban_findtime: 600
fail2ban_maxretry: 5

# Monitoring Settings
enable_prometheus: ${ENABLE_MONITORING}
enable_node_exporter: ${ENABLE_MONITORING}
monitoring_retention_days: 30
EOL

    chmod 600 "$CONFIG_DIR/config.yaml"
    
    # Create backend environment file
    cat > "$PANEL_DIR/backend/.env" << EOL
NODE_ENV=production
PORT=8000
JWT_SECRET=$JWT_SECRET
FRONTEND_URL=http${ENABLE_HTTPS:+"s"}://localhost:${PORTS[WEB]}
DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASS=$DB_PASS
ENABLE_MONITORING=${ENABLE_MONITORING}
EOL

    chmod 600 "$PANEL_DIR/backend/.env"
    
    # Export variables for other functions
    export DB_NAME DB_USER DB_PASS JWT_SECRET
    
    info "Configuration generated successfully"
}

generate_db_credentials() {
    info "Generating database credentials..."
    DB_USER="db_${ADMIN_USER}"
    DB_PASS="${ADMIN_PASS}"
    DB_NAME="irssh_db"
    export DB_USER DB_PASS DB_NAME
}

# Database Setup
setup_database() {
    info "Setting up PostgreSQL database..."
    
    # Detect PostgreSQL version
    PG_VERSION=$(apt-cache policy postgresql | grep -A1 "^  Installed:" | grep -oP '\d+' | head -1)
    if [ -z "$PG_VERSION" ]; then
        PG_VERSION=12
    fi
    
    # Use detected version
    apt-get install -y postgresql-$PG_VERSION postgresql-contrib-$PG_VERSION
    systemctl enable postgresql
    systemctl start postgresql

    # Install PostgreSQL if not present
    apt-get install -y postgresql-$postgresql_version postgresql-client-$postgresql_version

    # Create cluster if not exists
    su - postgres -c "pg_createcluster $postgresql_version main --start"

    # Generate database credentials
    generate_db_credentials
    
    # Get PostgreSQL version
    PG_VERSION=$(apt-cache policy postgresql | grep -A1 "^  Installed:" | grep -oP '\d+' | head -1)
    if [ -z "$PG_VERSION" ]; then
        PG_VERSION="12"  # Default to version 12 if not found
    fi
    
    # First detect PostgreSQL version
PG_VERSION=$(pg_config --version | awk '{print $2}' | cut -d. -f1)

# Create required directories for detected version
mkdir -p "/etc/postgresql/$PG_VERSION/main"
mkdir -p "/var/lib/postgresql/$PG_VERSION/main"
chown -R postgres:postgres "/etc/postgresql/$PG_VERSION"
chown -R postgres:postgres "/var/lib/postgresql/$PG_VERSION"

# Initialize database cluster
su - postgres -c "initdb -D /var/lib/postgresql/$PG_VERSION/main"

    # Install PostgreSQL
    apt-get install -y postgresql-$PG_VERSION postgresql-contrib-$PG_VERSION || error "Failed to install PostgreSQL"
    
    # Ensure PostgreSQL directories exist
    mkdir -p "/etc/postgresql/$PG_VERSION/main"
    
    # Create initial pg_hba.conf if it doesn't exist
    if [ ! -f "/etc/postgresql/$PG_VERSION/main/pg_hba.conf" ]; then
        cat > "/etc/postgresql/$PG_VERSION/main/pg_hba.conf" << EOL
# Database administrative login by Unix domain socket
local   all             postgres                                peer

# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     peer
host    all             all             127.0.0.1/32            md5
host    all             all             ::1/128                 md5
EOL
    fi
    
    # Start and wait for PostgreSQL
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
    
    # Configure authentication silently
    sed -i 's/peer/trust/g' "/etc/postgresql/$PG_VERSION/main/pg_hba.conf"
    systemctl restart postgresql
    
    # Create database and user silently
    su - postgres -c "psql -c \"CREATE USER \\\"$DB_USER\\\" WITH PASSWORD '$DB_PASS' CREATEDB;\"" > /dev/null 2>&1
    su - postgres -c "psql -c \"CREATE DATABASE \\\"$DB_NAME\\\" OWNER \\\"$DB_USER\\\";\"" > /dev/null 2>&1
    su - postgres -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE \\\"$DB_NAME\\\" TO \\\"$DB_USER\\\";\"" > /dev/null 2>&1
    
    # Restore secure authentication
    sed -i 's/trust/md5/g' "/etc/postgresql/$PG_VERSION/main/pg_hba.conf"
    systemctl restart postgresql
    
    # Verify connection silently
    if ! PGPASSWORD="$DB_PASS" psql -h localhost -U "$DB_USER" -d "$DB_NAME" -c '\q' > /dev/null 2>&1; then
        error "Database connection verification failed"
    fi
    
    info "Database setup completed successfully"
}

# Python Environment Setup
setup_python() {
    info "Setting up Python environment..."
    
    # Install Python and development packages
    apt-get install -y \
        python3.8 \
        python3.8-dev \
        python3.8-venv \
        python3-pip \
        libpq-dev \
        gcc \
        || error "Failed to install Python packages"
    
    # Create and activate virtual environment
    python3.8 -m venv "$PANEL_DIR/venv"
    source "$PANEL_DIR/venv/bin/activate"
    
    # Upgrade pip and install base packages
    pip install --upgrade pip setuptools wheel

    # Install urllib3 first to avoid dependency issues
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
        boto3 \
        croniter \
        pyAesCrypt \
        aiomysql \
        aioprometheus \
        etcd3 \
        haproxyadmin \
        paramiko \
        fastapi \
        uvicorn \
        sqlalchemy \
        alembic \
        passlib \
        pydantic \
        psycopg2-binary \
        redis \
        pymongo \
        elasticsearch || error "Failed to install Python packages"
    
    # Create helper script for loading configuration
    cat > "$PANEL_DIR/venv/bin/load_config.py" << 'EOL'
#!/usr/bin/env python3
import os
import yaml
import sys

def load_config():
    config_file = "/etc/enhanced_ssh/config.yaml"
    if not os.path.exists(config_file):
        print("Configuration file not found!")
        sys.exit(1)
        
    with open(config_file, "r") as f:
        try:
            config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f"Error parsing configuration: {e}")
            sys.exit(1)
            
    # Set environment variables with IRSSH prefix
    for key, value in config.items():
        os.environ[f"IRSSH_{key.upper()}"] = str(value)
        
    return config

if __name__ == "__main__":
    load_config()
EOL

    chmod +x "$PANEL_DIR/venv/bin/load_config.py"
    
    # Create Python service wrapper
    cat > "$PANEL_DIR/venv/bin/run_service.py" << 'EOL'
#!/usr/bin/env python3
import os
import sys
import signal
import logging
from subprocess import Popen

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('/var/log/irssh/service.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger('IRSSH-Service')

def run_service(cmd, logger):
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}")
        if process:
            process.terminate()
        sys.exit(0)
    
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    while True:
        logger.info(f"Starting service: {cmd}")
        process = Popen(cmd.split())
        process.wait()
        if process.returncode != 0:
            logger.error(f"Service exited with code {process.returncode}")
        logger.info("Restarting service...")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: run_service.py <command>")
        sys.exit(1)
    
    logger = setup_logging()
    run_service(sys.argv[1], logger)
EOL

    chmod +x "$PANEL_DIR/venv/bin/run_service.py"
    
    deactivate
    
    info "Python environment setup completed"
}

# Node.js Environment Setup
setup_nodejs() {
    info "Setting up Node.js environment..."
    
    # Install Node.js if not present
    if ! command -v node &> /dev/null; then
        curl -fsSL "https://deb.nodesource.com/setup_${NODE_VERSION}.x" | bash -
        apt-get install -y nodejs || error "Failed to install Node.js"
    fi
    
    # Verify npm installation
    if ! command -v npm &> /dev/null; then
        error "npm installation failed"
    fi
    
    # Install global packages
    npm install -g pm2 typescript @types/node || error "Failed to install global npm packages"
    
    info "Node.js environment setup completed"
}

# Frontend Setup
setup_frontend() {
    info "Setting up frontend application..."
    
    cd "$PANEL_DIR/frontend" || error "Failed to access frontend directory"
    
    # Create package.json
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
    "zustand": "^4.4.7",
    "tailwindcss": "^3.3.6",
    "chart.js": "^4.0.0",
    "react-chartjs-2": "^5.0.0",
    "date-fns": "^2.30.0",
    "formik": "^2.4.5",
    "yup": "^1.3.2"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.2.1",
    "@types/node": "^20.10.4",
    "@types/react": "^18.2.45",
    "@types/react-dom": "^18.2.17",
    "typescript": "^5.3.3",
    "autoprefixer": "^10.4.16",
    "postcss": "^8.4.32",
    "vite": "^5.0.7",
    "@typescript-eslint/eslint-plugin": "^6.13.1",
    "@typescript-eslint/parser": "^6.13.1",
    "eslint": "^8.55.0",
    "eslint-plugin-react": "^7.33.2",
    "eslint-plugin-react-hooks": "^4.6.0"
  },
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "lint": "eslint src --ext .ts,.tsx",
    "lint:fix": "eslint src --ext .ts,.tsx --fix"
  }
}
EOL

    # Create vite.config.ts
    cat > vite.config.ts << 'EOL'
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: {
          'react-vendor': ['react', 'react-dom', 'react-router-dom'],
          'chart-vendor': ['chart.js', 'react-chartjs-2'],
          'form-vendor': ['formik', 'yup'],
        },
      },
    },
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        secure: false,
      },
    },
  },
  optimizeDeps: {
    include: ['react', 'react-dom', 'react-router-dom', 'zustand'],
  },
});
EOL

    # Create TypeScript configuration
    cat > tsconfig.json << 'EOL'
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"]
    }
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
}
EOL

    # Create ESLint configuration
    cat > .eslintrc.json << 'EOL'
{
  "env": {
    "browser": true,
    "es2021": true
  },
  "extends": [
    "eslint:recommended",
    "plugin:react/recommended",
    "plugin:@typescript-eslint/recommended",
    "plugin:react-hooks/recommended"
  ],
  "parser": "@typescript-eslint/parser",
  "parserOptions": {
    "ecmaFeatures": {
      "jsx": true
    },
    "ecmaVersion": 12,
    "sourceType": "module"
  },
  "plugins": [
    "react",
    "@typescript-eslint",
    "react-hooks"
  ],
  "rules": {
    "react/react-in-jsx-scope": "off",
    "@typescript-eslint/explicit-module-boundary-types": "off",
    "@typescript-eslint/no-explicit-any": "warn",
    "react-hooks/rules-of-hooks": "error",
    "react-hooks/exhaustive-deps": "warn"
  },
  "settings": {
    "react": {
      "version": "detect"
    }
  }
}
EOL

    # Create frontend source directory structure
    mkdir -p src/{components,pages,services,stores,styles,utils,hooks,types}
    mkdir -p src/components/{common,layout,ui}

    # Create base styles
    cat > src/styles/index.css << 'EOL'
@tailwind base;
@tailwind components;
@tailwind utilities;

@layer base {
  :root {
    --background: 0 0% 100%;
    --foreground: 222.2 84% 4.9%;
    --card: 0 0% 100%;
    --card-foreground: 222.2 84% 4.9%;
    --popover: 0 0% 100%;
    --popover-foreground: 222.2 84% 4.9%;
    --primary: 221.2 83.2% 53.3%;
    --primary-foreground: 210 40% 98%;
    --secondary: 210 40% 96.1%;
    --secondary-foreground: 222.2 47.4% 11.2%;
    --muted: 210 40% 96.1%;
    --muted-foreground: 215.4 16.3% 46.9%;
    --accent: 210 40% 96.1%;
    --accent-foreground: 222.2 47.4% 11.2%;
    --destructive: 0 84.2% 60.2%;
    --destructive-foreground: 210 40% 98%;
    --border: 214.3 31.8% 91.4%;
    --input: 214.3 31.8% 91.4%;
    --ring: 221.2 83.2% 53.3%;
    --radius: 0.5rem;
  }

  .dark {
    --background: 222.2 84% 4.9%;
    --foreground: 210 40% 98%;
    --card: 222.2 84% 4.9%;
    --card-foreground: 210 40% 98%;
    --popover: 222.2 84% 4.9%;
    --popover-foreground: 210 40% 98%;
    --primary: 217.2 91.2% 59.8%;
    --primary-foreground: 222.2 47.4% 11.2%;
    --secondary: 217.2 32.6% 17.5%;
    --secondary-foreground: 210 40% 98%;
    --muted: 217.2 32.6% 17.5%;
    --muted-foreground: 215 20.2% 65.1%;
    --accent: 217.2 32.6% 17.5%;
    --accent-foreground: 210 40% 98%;
    --destructive: 0 62.8% 30.6%;
    --destructive-foreground: 210 40% 98%;
    --border: 217.2 32.6% 17.5%;
    --input: 217.2 32.6% 17.5%;
    --ring: 224.3 76.3% 48%;
  }
}

@layer base {
  * {
    @apply border-border;
  }
  body {
    @apply bg-background text-foreground;
  }
}
EOL

    # Create main React components
    cat > src/App.tsx << 'EOL'
import { BrowserRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from 'react-query';
import { Toaster } from 'react-hot-toast';
import AppRoutes from './routes';
import { ThemeProvider } from './components/providers/theme-provider';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: false,
    },
  },
});

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <BrowserRouter>
          <AppRoutes />
          <Toaster position="top-right" />
        </BrowserRouter>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
EOL

# Create Route configuration
    cat > src/routes.tsx << 'EOL'
import { Routes, Route, Navigate } from 'react-router-dom';
import MainLayout from './components/layout/MainLayout';
import Dashboard from './pages/Dashboard';
import Users from './pages/Users';
import Settings from './pages/Settings';
import Login from './pages/Login';
import useAuthStore from './stores/authStore';

const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const { isAuthenticated } = useAuthStore();
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return <>{children}</>;
};

const AppRoutes = () => {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <MainLayout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="users" element={<Users />} />
        <Route path="settings" element={<Settings />} />
      </Route>
    </Routes>
  );
};

export default AppRoutes;
EOL

    # Install dependencies
    npm install || error "Failed to install frontend dependencies"
    
    # Build frontend
    npm run build || error "Failed to build frontend"
    
    info "Frontend setup completed"
}

# Backend Setup
setup_backend() {
    info "Setting up backend application..."
    
    cd "$PANEL_DIR/backend" || error "Failed to access backend directory"
    
    # Create backend package.json
    cat > package.json << 'EOL'
{
  "name": "irssh-panel-backend",
  "version": "3.5.2",
  "private": true,
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "helmet": "^7.1.0",
    "compression": "^1.7.4",
    "jsonwebtoken": "^9.0.2",
    "bcryptjs": "^2.4.3",
    "pg": "^8.11.3",
    "sequelize": "^6.35.1",
    "winston": "^3.11.0",
    "dotenv": "^16.3.1",
    "node-ssh": "^13.1.0",
    "prometheus-client": "^0.5.0",
    "ioredis": "^5.3.2"
  },
  "devDependencies": {
    "nodemon": "^3.0.1",
    "jest": "^29.7.0",
    "supertest": "^6.3.3",
    "eslint": "^8.55.0"
  },
  "scripts": {
    "start": "node src/index.js",
    "dev": "nodemon src/index.js",
    "test": "jest",
    "lint": "eslint src"
  }
}
EOL

    # Create main server file
    mkdir -p src/{routes,middleware,models,utils,services,config}
    
    # Create database models
    cat > src/models/index.js << 'EOL'
const { Sequelize } = require('sequelize');
const config = require('../config/database');

const sequelize = new Sequelize(
  config.database,
  config.username,
  config.password,
  {
    host: config.host,
    dialect: config.dialect,
    logging: false,
    pool: {
      max: 5,
      min: 0,
      acquire: 30000,
      idle: 10000
    }
  }
);

const User = require('./user')(sequelize);
const VPNAccount = require('./vpn-account')(sequelize);
const Session = require('./session')(sequelize);

// Define relationships
User.hasMany(VPNAccount);
VPNAccount.belongsTo(User);

User.hasMany(Session);
Session.belongsTo(User);

module.exports = {
  sequelize,
  User,
  VPNAccount,
  Session
};
EOL

    # Create main application file
    cat > src/index.js << 'EOL'
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const cors = require('cors');
const { createLogger } = require('./utils/logger');
const { sequelize } = require('./models');
const routes = require('./routes');
const errorHandler = require('./middleware/error-handler');
const rateLimiter = require('./middleware/rate-limiter');

const logger = createLogger('app');
const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true
}));
app.use(compression());
app.use(express.json());
app.use(rateLimiter);

// Routes
app.use('/api', routes);

// Error handling
app.use(errorHandler);

// Database connection and server startup
const PORT = process.env.PORT || 8000;

async function startServer() {
  try {
    await sequelize.authenticate();
    logger.info('Database connection established');
    
    await sequelize.sync();
    logger.info('Database tables synchronized');
    
    app.listen(PORT, () => {
      logger.info(`Server running on port ${PORT}`);
    });
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received. Shutting down gracefully...');
  app.close(() => {
    sequelize.close();
    process.exit(0);
  });
});
EOL

    # Install dependencies
    npm install || error "Failed to install backend dependencies"
    
    info "Backend setup completed"
}

# Protocol Installation Functions
install_protocols() {
    info "Installing VPN protocols..."
    
    [ "${PROTOCOLS[SSH]}" = true ] && install_ssh
    [ "${PROTOCOLS[DROPBEAR]}" = true ] && install_dropbear
    [ "${PROTOCOLS[L2TP]}" = true ] && install_l2tp
    [ "${PROTOCOLS[IKEV2]}" = true ] && install_ikev2
    [ "${PROTOCOLS[CISCO]}" = true ] && install_cisco
    [ "${PROTOCOLS[WIREGUARD]}" = true ] && install_wireguard
    [ "${PROTOCOLS[SINGBOX]}" = true ] && install_singbox
    
    info "Protocol installation completed"
}

# SSH Installation and Configuration
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

# Security enhancements
MaxAuthTries 6
LoginGraceTime 30
PermitEmptyPasswords no
ClientAliveInterval 300
ClientAliveCountMax 3
MaxStartups 10:30:60
TCPKeepAlive yes
MaxSessions 10

# Logging
SyslogFacility AUTH
LogLevel INFO
EOL

    # Configure stunnel for SSL/TLS
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

debug = 7
output = /var/log/stunnel4/stunnel.log

[ssh-tls]
client = no
accept = ${PORTS[SSH_TLS]}
connect = 127.0.0.1:${PORTS[SSH]}
EOL

    # Setup WebSocket service
    install_websocat

    cat > /etc/systemd/system/websocket.service << EOL
[Unit]
Description=WebSocket for SSH
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/websocat -t --binary-protocol ws-l:0.0.0.0:${PORTS[WEBSOCKET]} tcp:127.0.0.1:${PORTS[SSH]}
Restart=always
RestartSec=3
StandardOutput=append:/var/log/irssh/websocket.log
StandardError=append:/var/log/irssh/websocket-error.log

[Install]
WantedBy=multi-user.target
EOL

    # Install monitoring scripts
    cat > "$PANEL_DIR/scripts/monitor_ssh.sh" << 'EOL'
#!/bin/bash

# Monitor SSH connections
CONNECTIONS=$(netstat -tn | grep :${SSH_PORT} | grep ESTABLISHED | wc -l)
echo "active_ssh_connections $CONNECTIONS" > /var/log/irssh/metrics/ssh_connections.prom

# Monitor failed login attempts
FAILED_LOGINS=$(grep "Failed password" /var/log/auth.log | wc -l)
echo "ssh_failed_logins $FAILED_LOGINS" > /var/log/irssh/metrics/ssh_failed_logins.prom
EOL

    chmod +x "$PANEL_DIR/scripts/monitor_ssh.sh"

    # Add monitoring to cron
    (crontab -l 2>/dev/null || true; echo "*/5 * * * * $PANEL_DIR/scripts/monitor_ssh.sh") | crontab -

    # Reload and restart services
    systemctl daemon-reload
    systemctl restart ssh
    systemctl enable stunnel4
    systemctl restart stunnel4
    systemctl enable websocket
    systemctl start websocket
    
    info "SSH server installation completed"
}

# Install websocat for WebSocket support
install_websocat() {
    info "Installing websocat..."
    
    local WEBSOCAT_URL="https://github.com/vi/websocat/releases/download/v${WEBSOCAT_VERSION}/websocat.x86_64-unknown-linux-musl"
    
    wget -O /usr/local/bin/websocat "$WEBSOCAT_URL" || error "Failed to download websocat"
    chmod +x /usr/local/bin/websocat || error "Failed to set websocat permissions"
    
    info "Websocat installation completed"
}

# L2TP Installation and Configuration
install_l2tp() {
    info "Installing L2TP/IPsec..."
    
    # Install required packages
    apt-get install -y \
        strongswan \
        strongswan-pki \
        libstrongswan-extra-plugins \
        libcharon-extra-plugins \
        xl2tpd \
        ppp \
        || error "Failed to install L2TP packages"
    
    # Generate IPsec PSK
    local PSK=$(openssl rand -base64 32)
    
    # Configure strongSwan
    cat > /etc/ipsec.conf << EOL
config setup
    charondebug="ike 2, knl 2, cfg 2, net 2, esp 2, dmn 2, mgr 2"
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
    compress=no
    esp=aes256-sha256!
    ike=aes256-sha256-modp2048!
EOL

    # Set IPsec secrets
    echo ": PSK \"$PSK\"" > /etc/ipsec.secrets
    chmod 600 /etc/ipsec.secrets
    
    # Configure xl2tpd
    cat > /etc/xl2tpd/xl2tpd.conf << EOL
[global]
ipsec saref = yes
saref refinfo = 30
port = ${PORTS[L2TP]}
access control = no

[lns default]
ip range = 10.10.10.100-10.10.10.200
local ip = 10.10.10.1
require chap = yes
refuse pap = yes
require authentication = yes
name = L2TP-VPN
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
idle 1800
mtu 1460
mru 1460
nodefaultroute
debug
lock
proxyarp
connect-delay 5000
EOL

    # Enable IP forwarding
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/60-l2tp-vpn.conf
    sysctl -p /etc/sysctl.d/60-l2tp-vpn.conf
    
    # Setup iptables rules
    iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE
    
    # Save iptables rules
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    
    # Create monitoring script
    cat > "$PANEL_DIR/scripts/monitor_l2tp.sh" << 'EOL'
#!/bin/bash
# Monitor L2TP connections
CONNECTIONS=$(netstat -anp | grep xl2tpd | grep ESTABLISHED | wc -l)
echo "active_l2tp_connections $CONNECTIONS" > /var/log/irssh/metrics/l2tp_connections.prom
EOL

    chmod +x "$PANEL_DIR/scripts/monitor_l2tp.sh"
    
    # Add to cron
    (crontab -l 2>/dev/null || true; echo "*/5 * * * * $PANEL_DIR/scripts/monitor_l2tp.sh") | crontab -
    
    # Start services
    systemctl restart strongswan
    systemctl enable strongswan
    systemctl restart xl2tpd
    systemctl enable xl2tpd
    
    # Save configuration
    cat > "$CONFIG_DIR/l2tp.conf" << EOL
PSK=$PSK
LOCAL_IP=10.10.10.1
IP_RANGE=10.10.10.100-10.10.10.200
DNS1=8.8.8.8
DNS2=8.8.4.4
EOL
    
    chmod 600 "$CONFIG_DIR/l2tp.conf"
    
    info "L2TP/IPsec installation completed"
}

# IKEv2 Installation and Configuration
install_ikev2() {
    info "Installing IKEv2..."
    
    # Install required packages
    apt-get install -y strongswan strongswan-pki || error "Failed to install IKEv2 packages"
    
    # Generate certificates
    mkdir -p /etc/ipsec.d/{private,cacerts,certs}
    
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
            --san "vpn.server.com" \
            --flag serverAuth --flag ikeIntermediate \
            --outform pem > /etc/ipsec.d/certs/server-cert.pem
    
    # Configure strongSwan for IKEv2
    cat > /etc/ipsec.conf << EOL
config setup
    charondebug="ike 2, knl 2, cfg 2, net 2, esp 2, dmn 2, mgr 2"

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
    rightsourceip=10.20.20.0/24
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=never
    eap_identity=%identity
    ike=aes256-sha256-modp2048,aes128-sha256-modp2048!
    esp=aes256-sha256,aes128-sha256!
EOL

    # Configure strongSwan secrets
    cat > /etc/ipsec.secrets << EOL
: RSA "server-key.pem"
EOL

    # Enable IP forwarding
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/60-ikev2-vpn.conf
    sysctl -p /etc/sysctl.d/60-ikev2-vpn.conf
    
    # Setup iptables rules
    iptables -t nat -A POSTROUTING -s 10.20.20.0/24 -o eth0 -j MASQUERADE
    
    # Save iptables rules
    iptables-save > /etc/iptables/rules.v4
    
    # Create monitoring script
    cat > "$PANEL_DIR/scripts/monitor_ikev2.sh" << 'EOL'
#!/bin/bash
# Monitor IKEv2 connections
CONNECTIONS=$(ipsec status | grep ESTABLISHED | wc -l)
echo "active_ikev2_connections $CONNECTIONS" > /var/log/irssh/metrics/ikev2_connections.prom
EOL

    chmod +x "$PANEL_DIR/scripts/monitor_ikev2.sh"
    
    # Add to cron
    (crontab -l 2>/dev/null || true; echo "*/5 * * * * $PANEL_DIR/scripts/monitor_ikev2.sh") | crontab -
    
    # Start and enable service
    systemctl restart strongswan
    systemctl enable strongswan
    
    info "IKEv2 installation completed"
}

# Cisco AnyConnect Installation and Configuration
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
keepalive = 32400
mobile-dpd = 1800
try-mtu-discovery = true
compression = true
no-compress-limit = 256
auth-timeout = 240
min-reauth-time = 300
max-ban-score = 80
ban-reset-time = 1200
cookie-timeout = 300
deny-roaming = false
rekey-time = 172800
rekey-method = ssl
use-occtl = true
pid-file = /var/run/ocserv.pid
device = vpns
predictable-ips = true
default-domain = vpn.server.com
ipv4-network = 192.168.1.0/24
dns = 8.8.8.8
dns = 8.8.4.4
route = default
no-route = 192.168.0.0/255.255.0.0
cisco-client-compat = true
dtls-legacy = true
user-profile = profile.xml
EOL

    # Create user profile template
    cat > /etc/ocserv/profile.xml << EOL
<?xml version="1.0" encoding="UTF-8"?>
<AnyConnectProfile xmlns="http://schemas.xmlsoap.org/encoding/">
    <ServerList>
        <HostEntry>
            <HostName>IRSSH VPN</HostName>
            <HostAddress>vpn.server.com</HostAddress>
        </HostEntry>
    </ServerList>
</AnyConnectProfile>
EOL

    # Create initial user database
    touch /etc/ocserv/ocpasswd
    
    # Enable IP forwarding
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    sysctl -p
    
    # Setup iptables rules
    iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -o eth0 -j MASQUERADE
    
    # Create monitoring script
    cat > "$PANEL_DIR/scripts/monitor_cisco.sh" << 'EOL'
#!/bin/bash
# Monitor Cisco AnyConnect connections
CONNECTIONS=$(occtl show users | grep -c "^Username:")
echo "active_cisco_connections $CONNECTIONS" > /var/log/irssh/metrics/cisco_connections.prom
EOL

    chmod +x "$PANEL_DIR/scripts/monitor_cisco.sh"
    
    # Add to cron
    (crontab -l 2>/dev/null || true; echo "*/5 * * * * $PANEL_DIR/scripts/monitor_cisco.sh") | crontab -
    
    # Start and enable service
    systemctl restart ocserv
    systemctl enable ocserv
    
    info "OpenConnect (Cisco AnyConnect) installation completed"
}

# WireGuard Installation and Configuration
install_wireguard() {
    info "Installing WireGuard..."
    
    # Install required packages
    apt-get install -y wireguard || error "Failed to install WireGuard"
    
    # Generate server keys
    mkdir -p /etc/wireguard
    cd /etc/wireguard || error "Failed to access WireGuard directory"
    
    # Generate server keys
    wg genkey | tee server_private.key | wg pubkey > server_public.key
    chmod 600 server_private.key
    
    # Configure WireGuard
    cat > /etc/wireguard/wg0.conf << EOL
[Interface]
PrivateKey = $(cat server_private.key)
Address = 10.66.66.1/24
ListenPort = ${PORTS[WIREGUARD]}
SaveConfig = false
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Advanced settings
MTU = 1420
Table = off
PreUp = sysctl -w net.ipv4.ip_forward=1
PreUp = echo 1 > /proc/sys/net.ipv4.ip_forward

# Performance optimizations
FwMark = 0x1234
RouteTable = 123
DNS = 8.8.8.8, 8.8.4.4
EOL

    # Create WireGuard helper scripts
    mkdir -p "$PANEL_DIR/scripts/wireguard"
    
    # Create client configuration generator
    cat > "$PANEL_DIR/scripts/wireguard/gen_client.sh" << 'EOL'
#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 <client_name>"
    exit 1
fi

CLIENT_NAME=$1
WG_DIR="/etc/wireguard"
CLIENTS_DIR="$WG_DIR/clients"

mkdir -p "$CLIENTS_DIR"

# Generate client keys
CLIENT_PRIVATE_KEY=$(wg genkey)
CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)
CLIENT_IP="10.66.66.$(( 2 + $(ls -1 "$CLIENTS_DIR" | wc -l) ))"

# Create client configuration
cat > "$CLIENTS_DIR/${CLIENT_NAME}.conf" << CONF
[Interface]
PrivateKey = ${CLIENT_PRIVATE_KEY}
Address = ${CLIENT_IP}/24
DNS = 8.8.8.8, 8.8.4.4
MTU = 1420

[Peer]
PublicKey = $(cat "$WG_DIR/server_public.key")
AllowedIPs = 0.0.0.0/0
Endpoint = $(curl -s ifconfig.me):${PORTS[WIREGUARD]}
PersistentKeepalive = 25
CONF

# Add client to server configuration
cat >> "$WG_DIR/wg0.conf" << CONF

[Peer]
PublicKey = ${CLIENT_PUBLIC_KEY}
AllowedIPs = ${CLIENT_IP}/32
CONF

# Restart WireGuard interface
wg-quick down wg0
wg-quick up wg0

echo "Client configuration generated: $CLIENTS_DIR/${CLIENT_NAME}.conf"
EOL

    chmod +x "$PANEL_DIR/scripts/wireguard/gen_client.sh"
    
    # Create monitoring script
    cat > "$PANEL_DIR/scripts/monitor_wireguard.sh" << 'EOL'
#!/bin/bash

# Monitor WireGuard connections
CONNECTIONS=$(wg show wg0 | grep -c "latest handshake")
TRANSFER=$(wg show wg0 | awk '/transfer:/ {print $2}')
echo "active_wireguard_connections $CONNECTIONS" > /var/log/irssh/metrics/wireguard_connections.prom
echo "wireguard_transfer_bytes $TRANSFER" > /var/log/irssh/metrics/wireguard_transfer.prom
EOL

    chmod +x "$PANEL_DIR/scripts/monitor_wireguard.sh"
    
    # Add to cron
    (crontab -l 2>/dev/null || true; echo "*/5 * * * * $PANEL_DIR/scripts/monitor_wireguard.sh") | crontab -
    
    # Enable and start WireGuard
    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
    
    info "WireGuard installation completed"
}

# SingBox Installation and Configuration
install_singbox() {
    info "Installing Sing-Box..."
    
    # Download and install Sing-Box
    cd "$TEMP_DIR" || error "Failed to access temp directory"
    
    local ARCH="amd64"
    local DOWNLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${ARCH}.tar.gz"
    
    wget "$DOWNLOAD_URL" -O sing-box.tar.gz || error "Failed to download Sing-Box"
    tar -xzf sing-box.tar.gz
    mv "sing-box-${SINGBOX_VERSION}-linux-${ARCH}/sing-box" /usr/local/bin/
    chmod +x /usr/local/bin/sing-box
    
    # Create configuration directory
    mkdir -p /etc/sing-box
    
    # Generate certificates for TLS
    mkdir -p /etc/sing-box/ssl
    cd /etc/sing-box/ssl || error "Failed to access Sing-Box SSL directory"
    
    openssl genrsa -out server.key 2048
    openssl req -new -x509 -days 365 -key server.key -out server.crt -subj "/CN=sing-box.server"
    
    # Generate configuration
    cat > /etc/sing-box/config.json << EOL
{
  "log": {
    "level": "info",
    "output": "/var/log/sing-box.log",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "google",
        "address": "8.8.8.8",
        "detour": "direct"
      }
    ],
    "rules": []
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
        "server_name": "sing-box.server",
        "certificate_path": "/etc/sing-box/ssl/server.crt",
        "key_path": "/etc/sing-box/ssl/server.key"
      }
    },
    {
      "type": "trojan",
      "tag": "trojan-in",
      "listen": "::",
      "listen_port": ${PORTS[SINGBOX]}-3,
      "users": [
        {
          "password": "$(openssl rand -base64 24)"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "sing-box.server",
        "certificate_path": "/etc/sing-box/ssl/server.crt",
        "key_path": "/etc/sing-box/ssl/server.key"
      }
    },
    {
      "type": "hysteria2",
      "tag": "hysteria2-in",
      "listen": "::",
      "listen_port": ${PORTS[SINGBOX]}-4,
      "up_mbps": 100,
      "down_mbps": 100,
      "users": [
        {
          "password": "$(openssl rand -base64 32)"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "sing-box.server",
        "certificate_path": "/etc/sing-box/ssl/server.crt",
        "key_path": "/etc/sing-box/ssl/server.key"
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
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOL

    # Create monitoring script
    cat > "$PANEL_DIR/scripts/monitor_singbox.sh" << 'EOL'
#!/bin/bash

# Monitor Sing-Box connections
CONNECTIONS=$(netstat -an | grep -c "${PORTS[SINGBOX]}")
echo "active_singbox_connections $CONNECTIONS" > /var/log/irssh/metrics/singbox_connections.prom

# Monitor specific protocols
SS_CONN=$(netstat -an | grep -c "$((${PORTS[SINGBOX]}-1))")
VMESS_CONN=$(netstat -an | grep -c "$((${PORTS[SINGBOX]}-2))")
TROJAN_CONN=$(netstat -an | grep -c "$((${PORTS[SINGBOX]}-3))")
HY2_CONN=$(netstat -an | grep -c "$((${PORTS[SINGBOX]}-4))")

echo "singbox_shadowsocks_connections $SS_CONN" > /var/log/irssh/metrics/singbox_ss.prom
echo "singbox_vmess_connections $VMESS_CONN" > /var/log/irssh/metrics/singbox_vmess.prom
echo "singbox_trojan_connections $TROJAN_CONN" > /var/log/irssh/metrics/singbox_trojan.prom
echo "singbox_hysteria2_connections $HY2_CONN" > /var/log/irssh/metrics/singbox_hy2.prom
EOL

    chmod +x "$PANEL_DIR/scripts/monitor_singbox.sh"
    
    # Add to cron
    (crontab -l 2>/dev/null || true; echo "*/5 * * * * $PANEL_DIR/scripts/monitor_singbox.sh") | crontab -
    
    # Enable and start service
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    
    info "Sing-Box installation completed"
}

# Setup monitoring system
setup_monitoring() {
    info "Setting up monitoring system..."
    
    if [ "$ENABLE_MONITORING" != "y" ]; then
        info "Monitoring system disabled, skipping..."
        return 0
fi
    
    # Install monitoring tools
    apt-get install -y \
        prometheus-node-exporter \
        collectd \
        vnstat \
        || error "Failed to install monitoring tools"
    
    # Setup Prometheus Node Exporter
    cat > /etc/systemd/system/node-exporter.service << EOL
[Unit]
Description=Prometheus Node Exporter
After=network.target

[Service]
Type=simple
User=node_exporter
ExecStart=/usr/bin/node_exporter \
    --collector.cpu \
    --collector.meminfo \
    --collector.loadavg \
    --collector.filesystem \
    --collector.netstat
Restart=always

[Install]
WantedBy=multi-user.target
EOL

    # Setup monitoring directories
    mkdir -p /var/log/irssh/metrics
    
    # Configure collectd
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

    # Start monitoring services
    systemctl daemon-reload
    systemctl enable node-exporter
    systemctl start node-exporter
    systemctl enable collectd
    systemctl start collectd
    
    info "Monitoring setup completed"
}

# Setup security measures
setup_security() {
    info "Setting up security measures..."
    
    # Install security packages
    apt-get install -y \
        fail2ban \
        ufw \
        rkhunter \
        || error "Failed to install security packages"
    
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
filter = nginx-http-auth
port = ${PORTS[WEB]}
logpath = /var/log/nginx/error.log

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
port = ${PORTS[WEB]}
logpath = /var/log/nginx/error.log
maxretry = 10

[nginx-botsearch]
enabled = true
filter = nginx-botsearch
port = ${PORTS[WEB]}
logpath = /var/log/nginx/access.log
maxretry = 2
EOL

    # Configure UFW
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow configured ports
    ufw allow ${PORTS[WEB]}/tcp
    ufw allow ${PORTS[SSH]}/tcp
    ufw allow ${PORTS[DROPBEAR]}/tcp
    ufw allow ${PORTS[WEBSOCKET]}/tcp
    ufw allow ${PORTS[L2TP]}/udp
    ufw allow ${PORTS[IKEV2]}/udp
    ufw allow ${PORTS[CISCO]}/tcp
    ufw allow ${PORTS[CISCO]}/udp
    ufw allow ${PORTS[WIREGUARD]}/udp
    ufw allow ${PORTS[SINGBOX]}/tcp
    ufw allow ${PORTS[SINGBOX]}/udp
    
    # Enable UFW
    echo "y" | ufw enable
    
    # Configure rkhunter
    rkhunter --update
    rkhunter --propupd
    
    # Setup security checks
    cat > "$PANEL_DIR/scripts/security_check.sh" << 'EOL'
#!/bin/bash

LOG_FILE="/var/log/irssh/security_check.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

echo "Security Check Report - $DATE" > "$LOG_FILE"
echo "=================================" >> "$LOG_FILE"

# Check failed SSH attempts
echo "Failed SSH attempts:" >> "$LOG_FILE"
grep "Failed password" /var/log/auth.log | tail -n 5 >> "$LOG_FILE"

# Check current connections
echo -e "\nCurrent Connections:" >> "$LOG_FILE"
netstat -tun | grep ESTABLISHED >> "$LOG_FILE"

# Check disk usage
echo -e "\nDisk Usage:" >> "$LOG_FILE"
df -h >> "$LOG_FILE"

# Check system load
echo -e "\nSystem Load:" >> "$LOG_FILE"
uptime >> "$LOG_FILE"

# Check for suspicious processes
echo -e "\nSuspicious Processes:" >> "$LOG_FILE"
ps aux | grep -i "suspicious" >> "$LOG_FILE"

# Run rkhunter check
echo -e "\nRKHunter Check:" >> "$LOG_FILE"
rkhunter --check --skip-keypress >> "$LOG_FILE" 2>&1
EOL

    chmod +x "$PANEL_DIR/scripts/security_check.sh"
    
    # Add to cron
    (crontab -l 2>/dev/null || true; echo "0 * * * * $PANEL_DIR/scripts/security_check.sh") | crontab -
    
    info "Security measures setup completed"
}

# Setup backup system
setup_backup() {
    info "Setting up backup system..."
    
    mkdir -p "$BACKUP_DIR"
    
    # Create backup script
    cat > "$PANEL_DIR/scripts/backup.sh" << 'EOL'
#!/bin/bash

BACKUP_DIR="/opt/irssh-backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/backup_$DATE.tar.gz"
DB_BACKUP="$BACKUP_DIR/db_backup_$DATE.sql"

# Backup configuration files
tar -czf "$BACKUP_FILE" \
    /etc/enhanced_ssh \
    /opt/irssh-panel/config \
    /etc/nginx/sites-available/irssh-panel \
    /etc/ssh/sshd_config \
    /etc/wireguard \
    /etc/ipsec.conf \
    /etc/ipsec.secrets \
    /etc/sing-box

# Backup database
source /etc/enhanced_ssh/config.yaml
PGPASSWORD="$db_password" pg_dump -U "$db_user" "$db_name" > "$DB_BACKUP"

# Remove old backups (keep last 7 days)
find "$BACKUP_DIR" -type f -mtime +7 -delete

# Verify backup integrity
if [ -f "$BACKUP_FILE" ] && [ -f "$DB_BACKUP" ]; then
    echo "Backup completed successfully at $DATE"
    echo "Backup files:"
    echo "- $BACKUP_FILE"
    echo "- $DB_BACKUP"
else
    echo "Backup failed!"
    exit 1
fi
EOL

    chmod +x "$PANEL_DIR/scripts/backup.sh"
    
    # Add to cron
    (crontab -l 2>/dev/null || true; echo "0 0 * * * $PANEL_DIR/scripts/backup.sh") | crontab -
    
    info "Backup system setup completed"
}

# Main installation function
main() {
    trap cleanup EXIT
    
    log "INFO" "Starting IRSSH Panel installation v${VERSION}"
    
    # Get initial configuration
    get_initial_config
    
    # Core setup
    check_requirements
    setup_directories
    generate_config
    setup_database
    
    # Install and configure components
    setup_database
    setup_python
    setup_nodejs
    setup_frontend
    setup_backend
    
    # Install protocols
    info "Installing VPN protocols..."
    install_protocols
    
    # Setup additional systems
    if [ "$ENABLE_HTTPS" = "y" ]; then
        setup_ssl
    fi
    
    setup_nginx
    setup_security
    setup_backup
    
    if [ "$ENABLE_MONITORING" = "y" ]; then
        setup_monitoring
    fi
    
    # Verify installation
    verify_installation
    
    # Final configuration
    save_installation_info
    
    info "Installation completed successfully!"
    
    # Display installation summary
    cat << EOL

IRSSH Panel Installation Summary
-------------------------------
Version: ${VERSION}
Installation Directory: ${PANEL_DIR}
Web Interface: http${ENABLE_HTTPS:+"s"}://YOUR-SERVER-IP:${PORTS[WEB]}
Configuration Directory: ${CONFIG_DIR}
Log Directory: ${LOG_DIR}

Admin Credentials:
Username: ${ADMIN_USER}
Password: (As specified during installation)

Enabled Protocols:
$(for protocol in "${!PROTOCOLS[@]}"; do
    if [ "${PROTOCOLS[$protocol]}" = true ]; then
        echo "- $protocol enabled on port ${PORTS[$protocol]}"
    fi
done)

Additional Features:
- HTTPS: ${ENABLE_HTTPS}
- Monitoring: ${ENABLE_MONITORING}
- Daily Backups: Enabled (${BACKUP_DIR})
- Security Measures: Enabled
- Automatic Updates: Configured

Next Steps:
1. Access the web panel at http${ENABLE_HTTPS:+"s"}://YOUR-SERVER-IP:${PORTS[WEB]}
2. Log in with the admin credentials
3. Configure additional users and VPN settings
4. Review the logs at ${LOG_DIR}
5. Check security status with ${PANEL_DIR}/scripts/security_check.sh

Documentation and Support:
- Configuration files: ${CONFIG_DIR}
- Log files: ${LOG_DIR}
- Backup location: ${BACKUP_DIR}

EOL
}

# Start installation
main

# End of script
