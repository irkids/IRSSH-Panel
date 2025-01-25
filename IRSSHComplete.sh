#!/bin/bash

# IRSSH Panel Installation Script v3.2
# Comprehensive installation with user input for credentials and optimized performance

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration directories
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
LOG_DIR="/var/log/irssh"
VENV_DIR="$PANEL_DIR/venv"
BACKUP_DIR="/opt/irssh-backups"

# Default configuration
DEFAULT_HTTP_PORT=80
DEFAULT_HTTPS_PORT=443
DEFAULT_API_PORT=8000

# Prompt for admin credentials
read -p "Enter admin username (default: admin): " ADMIN_USERNAME
ADMIN_USERNAME=${ADMIN_USERNAME:-admin}
read -sp "Enter admin password: " ADMIN_PASSWORD
echo
read -sp "Confirm admin password: " ADMIN_PASSWORD_CONFIRM

if [[ "$ADMIN_PASSWORD" != "$ADMIN_PASSWORD_CONFIRM" ]]; then
    echo -e "${RED}Passwords do not match. Exiting installation.${NC}"
    exit 1
fi

# Generate random strings for security
generate_secure_key() {
    openssl rand -hex 32 2>/dev/null || {
        echo -e "${RED}Error: OpenSSL is not installed or failed to generate a key.${NC}" >&2
        exit 1
    }
}

# Secure keys
JWT_SECRET=$(generate_secure_key)
ADMIN_TOKEN=$(generate_secure_key)

# Logging functions
setup_logging() {
    mkdir -p "$LOG_DIR" || {
        echo -e "${RED}Error: Failed to create log directory.${NC}" >&2
        exit 1
    }
    LOG_FILE="$LOG_DIR/install.log"
    exec > >(tee -a "$LOG_FILE")
    exec 2> >(tee -a "$LOG_FILE" >&2)
    chmod 640 "$LOG_FILE"
}

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" >&2
    cleanup
    exit 1
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Cleanup function
cleanup() {
    if [[ $? -ne 0 ]]; then
        error "Installation failed. Check $LOG_FILE for details."
    fi
}

# Backup function
create_backup() {
    log "Creating backup..."
    mkdir -p "$BACKUP_DIR"
    if [[ -d "$PANEL_DIR" ]]; then
        tar -czf "$BACKUP_DIR/panel-$(date +%Y%m%d-%H%M%S).tar.gz" -C "$(dirname "$PANEL_DIR")" "$(basename "$PANEL_DIR")" || warn "Failed to create a backup."
    fi
}

# Check system requirements
check_requirements() {
    log "Checking system requirements..."

    # Check OS
    [[ -f /etc/os-release ]] || error "Unsupported operating system."

    # Check minimum system resources
    local mem_total=$(free -m | awk '/^Mem:/{print $2}')
    local disk_free=$(df -m / | awk 'NR==2 {print $4}')

    [[ $mem_total -lt 1024 ]] && error "Minimum 1GB RAM required."
    [[ $disk_free -lt 2048 ]] && error "Minimum 2GB free disk space required."

    # Check required commands
    local requirements=(curl wget git python3 pip3 npm node nginx openssl)
    for cmd in "${requirements[@]}"; do
        command -v "$cmd" &>/dev/null || error "$cmd is required but not installed."
    done
}

# Install system packages
install_system_packages() {
    log "Installing system packages..."
    apt-get update -y || error "Failed to update package lists."

    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3 python3-pip python3-venv \
        postgresql postgresql-contrib \
        nginx supervisor curl git npm nodejs \
        certbot python3-certbot-nginx ufw fail2ban || error "Failed to install system packages."
}

# Setup Python environment
setup_python_env() {
    log "Setting up Python environment..."
    python3 -m venv "$VENV_DIR" || error "Failed to create virtual environment."
    source "$VENV_DIR/bin/activate"

    pip install --upgrade pip || error "Failed to upgrade pip."
    pip install fastapi uvicorn[standard] pydantic[dotenv] sqlalchemy psycopg2-binary || error "Failed to install Python packages."
}

# Configure PostgreSQL
define_postgresql() {
    log "Configuring PostgreSQL..."
    systemctl start postgresql || error "Failed to start PostgreSQL."
    systemctl enable postgresql || error "Failed to enable PostgreSQL."

    local DB_NAME="irssh"
    local DB_USER="irssh_admin"
    local DB_PASS=$(generate_secure_key)

    # Check if user exists
    sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER';" | grep -q 1 || \
        sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';" || \
        error "Failed to create database user."

    # Check if database exists
    sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME';" | grep -q 1 || \
        sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;" || \
        error "Failed to create database."

    cat > "$CONFIG_DIR/database.env" << EOL
DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASS=$DB_PASS
EOL
    chmod 600 "$CONFIG_DIR/database.env"

    # Add admin user to database
    sudo -u postgres psql -d "$DB_NAME" -c "CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT);" || error "Failed to initialize user table."
    sudo -u postgres psql -d "$DB_NAME" -c "INSERT INTO users (username, password) VALUES ('$ADMIN_USERNAME', crypt('$ADMIN_PASSWORD', gen_salt('bf'))) ON CONFLICT (username) DO NOTHING;" || error "Failed to add admin user."
}

# Configure Nginx
setup_nginx() {
    log "Configuring Nginx..."

    # Use pre-generated DH parameters to save time
    if [[ ! -f /etc/ssl/certs/dhparam.pem ]]; then
        cp /usr/share/doc/nginx/examples/ssl/dhparam.pem /etc/ssl/certs/dhparam.pem || \
        openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048 || error "Failed to generate DH parameters."
    fi

    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen $DEFAULT_HTTP_PORT;
    server_name _;
    root $FRONTEND_DIR/build;
    index index.html;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    access_log $LOG_DIR/nginx-access.log;
    error_log $LOG_DIR/nginx-error.log;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location /api {
        proxy_pass http://127.0.0.1:$DEFAULT_API_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOL

    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
    nginx -t || error "Nginx configuration test failed."
    systemctl restart nginx || error "Failed to restart Nginx."
}

# Main installation function
main() {
    trap cleanup EXIT

    setup_logging
    log "Starting IRSSH Panel installation..."

    check_requirements
    create_backup
    install_system_packages
    setup_python_env
    define_postgresql
    setup_nginx

    log "Installation completed successfully."
    echo -e "${GREEN}IRSSH Panel is ready!${NC}"
    echo -e "${YELLOW}Admin Credentials:${NC}"
    echo -e "${BLUE}Username:${NC} $ADMIN_USERNAME"
    echo -e "${BLUE}Password:${NC} $ADMIN_PASSWORD"
}

main "$@"
