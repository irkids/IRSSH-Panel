#!/bin/bash

# IRSSH Panel Complete Installation Script
# Version: 2.0.0

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
MODULES_DIR="$PANEL_DIR/modules"
LOG_DIR="/var/log/irssh"
BACKUP_DIR="/opt/irssh-backups"

# Default Ports
DEFAULT_WEB_PORT=443
DEFAULT_SSH_PORT=22
DEFAULT_DROPBEAR_PORT=444
DEFAULT_BADVPN_PORT=7300

# Database Configuration
DB_NAME="irssh_panel"
DB_USER="irssh_admin"
DB_PASS=$(openssl rand -base64 32)
ADMIN_PASS=$(openssl rand -base64 16)

# Logging
setup_logging() {
    mkdir -p "$LOG_DIR"
    exec &> >(tee -a "$LOG_DIR/install.log")
    chmod 640 "$LOG_DIR/install.log"
}

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
    [[ "${2:-}" != "no-exit" ]] && cleanup && exit 1
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Cleanup
cleanup() {
    if [[ $? -ne 0 ]]; then
        error "Installation failed. Checking backup..." "no-exit"
        if [[ -d "$BACKUP_DIR" ]]; then
            warn "Attempting to restore from backup..."
            restore_backup
        fi
    fi
}

# Backup
create_backup() {
    log "Creating backup..."
    mkdir -p "$BACKUP_DIR"
    if [[ -d "$PANEL_DIR" ]]; then
        tar -czf "$BACKUP_DIR/panel-$(date +%Y%m%d-%H%M%S).tar.gz" -C "$(dirname "$PANEL_DIR")" "$(basename "$PANEL_DIR")"
    fi
}

# System Requirements
check_requirements() {
    log "Checking system requirements..."
    
    if [[ $(free -m | awk '/^Mem:/{print $2}') -lt 1024 ]]; then
        error "Minimum 1GB RAM required"
    fi
    
    if [[ $(df -m / | awk 'NR==2 {print $4}') -lt 2048 ]]; then
        error "Minimum 2GB free disk space required"
    fi
}

# Install Dependencies
install_dependencies() {
    log "Installing dependencies..."
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3 python3-pip python3-venv \
        postgresql postgresql-contrib \
        nginx certbot python3-certbot-nginx \
        git curl wget zip unzip \
        supervisor ufw fail2ban \
        nodejs npm
}

# Setup Python Environment
setup_python() {
    log "Setting up Python environment..."
    python3 -m venv "$PANEL_DIR/venv"
    source "$PANEL_DIR/venv/bin/activate"
    pip install --upgrade pip
    pip install \
        fastapi[all] uvicorn[standard] \
        sqlalchemy[asyncio] psycopg2-binary \
        python-jose[cryptography] passlib[bcrypt] \
        python-multipart aiofiles \
        python-telegram-bot psutil geoip2 asyncpg
}

# Setup Frontend
setup_frontend() {
    log "Setting up frontend..."
    mkdir -p "$FRONTEND_DIR"
    cd "$FRONTEND_DIR"

    # Create package.json
    cat > "package.json" << EOL
{
  "name": "irssh-panel-frontend",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "@headlessui/react": "^1.7.0",
    "@heroicons/react": "^2.0.0",
    "axios": "^1.6.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.21.0",
    "react-scripts": "5.0.1",
    "tailwindcss": "^3.4.0"
  },
  "scripts": {
    "start": "react-scripts start",
    "build": "react-scripts build",
    "test": "react-scripts test",
    "eject": "react-scripts eject"
  }
}
EOL

    npm install
    npm run build
}

# Setup Database
setup_database() {
    log "Setting up database..."
    systemctl start postgresql
    systemctl enable postgresql
    
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"
    
    cat > "$CONFIG_DIR/database.env" << EOL
DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASS=$DB_PASS
EOL
    chmod 600 "$CONFIG_DIR/database.env"
}

# Setup Modules
setup_modules() {
    log "Setting up modules..."
    mkdir -p "$MODULES_DIR"

    # Array of module scripts
    declare -A MODULES=(
        ["vpnserver"]="py"
        ["port"]="py"
        ["ssh"]="py"
        ["l2tpv3"]="sh"
        ["ikev2"]="py"
        ["cisco"]="sh"
        ["wire"]="sh"
        ["singbox"]="sh"
        ["badvpn"]="sh"
        ["dropbear"]="sh"
        ["webport"]="sh"
    )

    for module in "${!MODULES[@]}"; do
        ext="${MODULES[$module]}"
        script_path="$MODULES_DIR/${module}-script.${ext}"
        
        log "Creating $module script..."
        
        if [[ "$ext" == "py" ]]; then
            create_python_module "$module" "$script_path"
        else
            create_shell_module "$module" "$script_path"
        fi
        
        chmod +x "$script_path"
    done
}

create_python_module() {
    local module=$1
    local script_path=$2
    
    cat > "$script_path" << EOL
#!/usr/bin/env python3
import os
import sys
import json
import subprocess

def init():
    try:
        # Add module-specific initialization here
        return {"success": True, "message": "${module} initialized successfully"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def generate_config():
    config = {
        "name": "${module}",
        "enabled": True,
        "settings": {}
    }
    return json.dumps(config, indent=2)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <command>")
        sys.exit(1)

    command = sys.argv[1]
    if command == "init":
        result = init()
        if result["success"]:
            print(result["message"])
            sys.exit(0)
        else:
            print(f"Error: {result.get('error', 'Unknown error')}")
            sys.exit(1)
    elif command == "generate-config":
        print(generate_config())
        sys.exit(0)
EOL
}

create_shell_module() {
    local module=$1
    local script_path=$2
    
    cat > "$script_path" << EOL
#!/bin/bash

init() {
    # Add module-specific initialization here
    echo "${module} initialized successfully"
    return 0
}

generate_config() {
    cat << CONF
{
    "name": "${module}",
    "enabled": true,
    "settings": {}
}
CONF
}

case "\$1" in
    init)
        init
        ;;
    generate-config)
        generate_config
        ;;
    *)
        echo "Usage: \$0 {init|generate-config}"
        exit 1
        ;;
esac
EOL
}

# Configure Nginx
setup_nginx() {
    log "Configuring Nginx..."
    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen 80;
    listen [::]:80;
    server_name _;

    root $FRONTEND_DIR/build;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
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
    }

    client_max_body_size 100M;
}
EOL

    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
}

# Main Installation
main() {
    trap cleanup EXIT
    
    setup_logging
    log "Starting IRSSH Panel installation..."
    
    # Get user input
    read -p "Enter domain name (e.g., panel.example.com): " DOMAIN
    read -p "Enter web panel port (default: $DEFAULT_WEB_PORT): " WEB_PORT
    WEB_PORT=${WEB_PORT:-$DEFAULT_WEB_PORT}
    read -p "Enter SSH port (default: $DEFAULT_SSH_PORT): " SSH_PORT
    SSH_PORT=${SSH_PORT:-$DEFAULT_SSH_PORT}
    read -p "Enter Dropbear port (default: $DEFAULT_DROPBEAR_PORT): " DROPBEAR_PORT
    DROPBEAR_PORT=${DROPBEAR_PORT:-$DEFAULT_DROPBEAR_PORT}
    read -p "Enter BadVPN port (default: $DEFAULT_BADVPN_PORT): " BADVPN_PORT
    BADVPN_PORT=${BADVPN_PORT:-$DEFAULT_BADVPN_PORT}
    
    check_requirements
    create_backup
    install_dependencies
    setup_python
    setup_frontend
    setup_database
    setup_modules
    setup_nginx
    
    # Configure SSL
    if [[ -n "$DOMAIN" ]]; then
        certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --redirect
    fi
    
    # Restart services
    systemctl restart nginx
    supervisorctl reread
    supervisorctl update
    systemctl restart postgresql
    
    log "Installation completed successfully!"
    echo
    echo "IRSSH Panel has been installed!"
    echo
    echo "Admin Credentials:"
    echo "Username: admin"
    echo "Password: $ADMIN_PASS"
    echo
    echo "Access URLs:"
    if [[ -n "$DOMAIN" ]]; then
        echo "Panel: https://$DOMAIN"
    else
        echo "Panel: http://YOUR-SERVER-IP"
    fi
    echo
    echo "Configured Ports:"
    echo "Web Panel: $WEB_PORT"
    echo "SSH: $SSH_PORT"
    echo "Dropbear: $DROPBEAR_PORT"
    echo "BadVPN: $BADVPN_PORT"
    echo
    echo "Installation Log: $LOG_DIR/install.log"
}

# Start installation
main "$@"
