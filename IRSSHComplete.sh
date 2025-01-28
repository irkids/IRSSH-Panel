#!/bin/bash

# IRSSH Panel Installation Script
# Version: 1.0.0

#====================#
# Global Variables
#====================#
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
LOG_DIR="/var/log/irssh"
BACKUP_DIR="/opt/irssh-backups"
TEMP_DIR="/tmp/irssh-install"

DB_NAME="irssh_panel"
DB_USER="irssh_admin"
DB_PASS=$(openssl rand -base64 32)
ADMIN_PASS=$(openssl rand -base64 16)

# Installation state tracking
STATE_FILE="$TEMP_DIR/install_state.txt"
ROLLBACK_REQUIRED=false

#====================#
# Utility Functions
#====================#
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
    ROLLBACK_REQUIRED=true
    initiate_rollback
    exit 1
}

# State management
save_state() {
    echo "$1" >> "$STATE_FILE"
}

#====================#
# Rollback Functions
#====================#
initiate_rollback() {
    if [ "$ROLLBACK_REQUIRED" = true ]; then
        log "Initiating rollback process..."
        while IFS= read -r state; do
            case "$state" in
                "DIRS_CREATED")
                    rollback_directories
                    ;;
                "DEPS_INSTALLED")
                    rollback_dependencies
                    ;;
                "DB_CREATED")
                    rollback_database
                    ;;
                "PYTHON_ENV_SETUP")
                    rollback_python_env
                    ;;
                "FRONTEND_SETUP")
                    rollback_frontend
                    ;;
                "SERVICES_CONFIGURED")
                    rollback_services
                    ;;
            esac
        done < "$STATE_FILE"
        log "Rollback completed"
    fi
}

rollback_directories() {
    rm -rf "$PANEL_DIR" "$LOG_DIR" "$TEMP_DIR"
}

rollback_database() {
    if sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
        sudo -u postgres psql -c "DROP DATABASE $DB_NAME;"
        sudo -u postgres psql -c "DROP USER $DB_USER;"
    fi
}

#====================#
# Installation Steps
#====================#
check_requirements() {
    log "Checking installation requirements..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi

    # Check minimum system requirements
    local min_ram=2048  # 2GB in MB
    local min_disk=10240  # 10GB in MB
    
    local total_ram=$(free -m | awk '/^Mem:/{print $2}')
    local free_disk=$(df -m / | awk 'NR==2 {print $4}')
    
    if (( total_ram < min_ram )); then
        error "Insufficient RAM. Minimum 2GB required."
    fi
    
    if (( free_disk < min_disk )); then
        error "Insufficient disk space. Minimum 10GB free space required."
    fi

    mkdir -p "$TEMP_DIR"
}

setup_directories() {
    log "Creating directories..."
    mkdir -p "$PANEL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$BACKUP_DIR"
    chown -R root:root "$PANEL_DIR"
    chmod -R 755 "$PANEL_DIR"
    save_state "DIRS_CREATED"
}

install_dependencies() {
    log "Installing system dependencies..."
    apt-get update
    apt-get install -y \
        python3 python3-pip python3-venv \
        postgresql postgresql-contrib \
        nginx certbot python3-certbot-nginx \
        git curl supervisor ufw fail2ban \
        build-essential libpq-dev
    
    # Install Node.js
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    apt-get install -y nodejs
    
    save_state "DEPS_INSTALLED"
}

setup_database() {
    log "Setting up PostgreSQL..."
    if ! systemctl is-active --quiet postgresql; then
        systemctl start postgresql
        systemctl enable postgresql
    fi

    # Create database and user
    if ! sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
        sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
        sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"
    fi

    # Save database configuration
    cat > "$CONFIG_DIR/database.env" << EOL
DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASS=$DB_PASS
EOL
    chmod 600 "$CONFIG_DIR/database.env"
    
    save_state "DB_CREATED"
}

setup_python_environment() {
    log "Setting up Python environment..."
    python3 -m venv "$PANEL_DIR/venv"
    source "$PANEL_DIR/venv/bin/activate"
    
    pip install --upgrade pip
    pip install \
        fastapi[all] uvicorn[standard] \
        sqlalchemy[asyncio] psycopg2-binary \
        python-jose[cryptography] passlib[bcrypt] \
        python-multipart aiofiles python-telegram-bot \
        psutil geoip2 asyncpg aiohttp
    
    save_state "PYTHON_ENV_SETUP"
}

setup_frontend() {
    log "Setting up frontend..."
    cd "$FRONTEND_DIR"
    
    # Initialize React project
    npx create-react-app . --template typescript
    
    # Install dependencies
    npm install \
        @headlessui/react @heroicons/react \
        axios react-router-dom recharts \
        tailwindcss @tailwindcss/forms

    # Build frontend
    npm run build
    
    save_state "FRONTEND_SETUP"
}

configure_services() {
    log "Configuring services..."

    # Configure Nginx
    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen 80;
    server_name _;

    root $FRONTEND_DIR/build;
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
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        
        # CORS headers
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' '*' always;
    }
}
EOL

    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    # Configure Supervisor
    cat > /etc/supervisor/conf.d/irssh-panel.conf << EOL
[program:irssh-panel]
directory=$PANEL_DIR
command=$PANEL_DIR/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
user=root
autostart=true
autorestart=true
stderr_logfile=$LOG_DIR/uvicorn.err.log
stdout_logfile=$LOG_DIR/uvicorn.out.log
environment=PYTHONPATH="$PANEL_DIR"
EOL

    # Configure UFW
    ufw allow 'Nginx Full'
    ufw allow OpenSSH
    
    save_state "SERVICES_CONFIGURED"
}

start_services() {
    log "Starting services..."
    
    systemctl restart nginx
    systemctl enable nginx
    
    supervisorctl reread
    supervisorctl update
    supervisorctl restart irssh-panel
}

perform_security_checks() {
    log "Performing security checks..."
    
    # Check firewall
    if ! ufw status | grep -q "Status: active"; then
        warn "Firewall is not active"
        ufw --force enable
    fi

    # Check fail2ban
    if ! systemctl is-active --quiet fail2ban; then
        warn "Fail2ban is not active"
        systemctl start fail2ban
        systemctl enable fail2ban
    fi

    # Check SSL status
    if [ -n "$DOMAIN" ] && [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
        log "Setting up SSL certificate..."
        certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --email "admin@$DOMAIN"
    fi
}

#====================#
# Main Installation
#====================#
main() {
    log "Starting IRSSH Panel installation..."
    
    check_requirements
    setup_directories
    install_dependencies
    setup_database
    setup_python_environment
    setup_frontend
    configure_services
    start_services
    perform_security_checks
    
    log "Installation completed successfully!"
    echo
    echo "IRSSH Panel has been installed with the following credentials:"
    echo "Admin Username: admin"
    echo "Admin Password: $ADMIN_PASS"
    echo "Database Password: $DB_PASS"
    echo
    echo "Please change these passwords immediately after first login."
    echo "Installation logs are available at: $LOG_DIR"
}

# Start installation
main
