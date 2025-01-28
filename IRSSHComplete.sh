#!/bin/bash

# IRSSH Panel Complete Installation Script
# Version: 3.1.0

# Directories
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
MODULES_DIR="$PANEL_DIR/modules"
LOG_DIR="/var/log/irssh"
BACKUP_DIR="/opt/irssh-backups"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Database Settings
DB_NAME="irssh_panel"
DB_USER="irssh_admin"
DB_PASS=$(openssl rand -base64 32)
ADMIN_PASS=$(openssl rand -base64 16)

# Logging
setup_logging() {
    mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/install.log"
    exec &> >(tee -a "$LOG_FILE")
    chmod 640 "$LOG_FILE"
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

# Cleanup and Backup
cleanup() {
    if [[ $? -ne 0 ]]; then
        error "Installation failed. Attempting backup restore..." "no-exit"
        if [[ -d "$BACKUP_DIR" ]]; then
            warn "Attempting to restore from backup..."
            restore_backup
        fi
    fi
}

create_backup() {
    mkdir -p "$BACKUP_DIR"
    if [[ -d "$PANEL_DIR" ]]; then
        tar -czf "$BACKUP_DIR/panel-$(date +%Y%m%d-%H%M%S).tar.gz" -C "$(dirname "$PANEL_DIR")" "$(basename "$PANEL_DIR")"
    fi
}

restore_backup() {
    local latest_backup=$(ls -t "$BACKUP_DIR"/*.tar.gz 2>/dev/null | head -1)
    if [[ -n "$latest_backup" ]]; then
        rm -rf "$PANEL_DIR"
        tar -xzf "$latest_backup" -C "$(dirname "$PANEL_DIR")"
        log "Restored from backup: $latest_backup"
    fi
}

# Pre-Installation Checks
check_requirements() {
    # Check root
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi

    # Check system resources
    if [[ $(free -m | awk '/^Mem:/{print $2}') -lt 1024 ]]; then
        error "Minimum 1GB RAM required"
    fi

    if [[ $(df -m / | awk 'NR==2 {print $4}') -lt 2048 ]]; then
        error "Minimum 2GB free disk space required"
    fi

    # Check mandatory commands
    local required_commands=(curl wget git python3 pip3)
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            error "$cmd is required but not installed"
        fi
    done
}

# Clean Previous Node.js Installation
clean_nodejs() {
    log "Cleaning previous Node.js installation..."
    apt-get remove -y nodejs npm || true
    apt-get autoremove -y || true
    rm -f /etc/apt/sources.list.d/nodesource.list*
    apt-get update
}

# Install Dependencies
install_dependencies() {
    log "Installing system dependencies..."
    apt-get update

    # Install basic dependencies
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3 python3-pip python3-venv \
        postgresql postgresql-contrib \
        nginx certbot python3-certbot-nginx \
        git curl wget zip unzip \
        supervisor ufw fail2ban

    # Clean and Install Node.js
    clean_nodejs
    
    log "Installing Node.js and npm..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs

    # Verify Node.js installation
    if ! command -v node &>/dev/null; then
        error "Node.js installation failed"
    fi

    # Update npm
    log "Updating npm..."
    npm install -g npm@latest || error "npm update failed"

    # Verify installations
    log "Node.js version: $(node -v)"
    log "npm version: $(npm -v)"
}

# Setup Python Environment
setup_python() {
    log "Setting up Python environment..."
    python3 -m venv "$PANEL_DIR/venv"
    source "$PANEL_DIR/venv/bin/activate"
    
    pip install --upgrade pip wheel setuptools
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
    rm -rf "$FRONTEND_DIR"
    mkdir -p "$FRONTEND_DIR"
    cd "$FRONTEND_DIR"

    # Verify Node.js and npm
    if ! command -v node &>/dev/null || ! command -v npm &>/dev/null; then
        error "Node.js or npm not found. Please check installation."
    fi

    # Create project structure
    mkdir -p public src/components

    # Create index.html
    cat > public/index.html << 'EOL'
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>IRSSH Panel</title>
  </head>
  <body>
    <div id="root"></div>
  </body>
</html>
EOL

    # Create package.json
    cat > package.json << 'EOL'
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
  },
  "browserslist": {
    "production": [
      ">0.2%",
      "not dead",
      "not op_mini all"
    ]
  }
}
EOL

    # Create App.js
    cat > src/App.js << 'EOL'
import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';

function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-gray-100">
        <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
          <h1 className="text-3xl font-bold text-gray-900">
            IRSSH Panel
          </h1>
        </div>
      </div>
    </BrowserRouter>
  );
}

export default App;
EOL

    # Create index.js
    cat > src/index.js << 'EOL'
import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
EOL

    # Create index.css
    cat > src/index.css << 'EOL'
@tailwind base;
@tailwind components;
@tailwind utilities;
EOL

    # Install dependencies and build
    log "Installing frontend dependencies..."
    npm install
    
    log "Building frontend..."
    npm run build
}

# Setup Database
setup_database() {
    log "Setting up database..."
    systemctl start postgresql
    systemctl enable postgresql

    # Wait for PostgreSQL
    for i in {1..30}; do
        if pg_isready -q; then
            break
        fi
        sleep 1
    done

    # Create database and user
    sudo -u postgres psql -c "DROP DATABASE IF EXISTS $DB_NAME;"
    sudo -u postgres psql -c "DROP USER IF EXISTS $DB_USER;"
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"

    # Save configuration
    cat > "$CONFIG_DIR/database.env" << EOL
DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASS=$DB_PASS
EOL
    chmod 600 "$CONFIG_DIR/database.env"
}

# Configure Nginx
setup_nginx() {
    log "Configuring Nginx..."
    
    # Create nginx configuration
    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;

    location / {
        root $FRONTEND_DIR/build;
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

    location /ws {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
    }

    client_max_body_size 100M;
}
EOL

    # Enable site
    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/

    # Test configuration
    nginx -t || error "Nginx configuration test failed"
}

# Configure SSL
setup_ssl() {
    if [[ -n "$DOMAIN" ]]; then
        log "Setting up SSL..."
        certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --redirect \
            --email "admin@$DOMAIN" || error "SSL setup failed"
    fi
}

# Configure Firewall
setup_firewall() {
    log "Configuring firewall..."
    
    # Reset UFW
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing

    # Allow ports
    ufw allow ssh
    ufw allow http
    ufw allow https
    ufw allow "$WEB_PORT"
    ufw allow "$SSH_PORT"
    ufw allow "$DROPBEAR_PORT"
    ufw allow "$BADVPN_PORT/udp"

    # Enable firewall
    echo "y" | ufw enable
}

# Setup Modules
setup_modules() {
    log "Setting up modules..."
    mkdir -p "$MODULES_DIR"
    
    # Copy module scripts if they exist
    if [[ -d "/root/irssh-panel/modules" ]]; then
        cp -r /root/irssh-panel/modules/* "$MODULES_DIR/"
        chmod +x "$MODULES_DIR"/*.{py,sh}
    fi
}

# Verify Installation
verify_installation() {
    log "Verifying installation..."

    # Check services
    local services=(nginx postgresql supervisor)
    for service in "${services[@]}"; do
        if ! systemctl is-active --quiet $service; then
            error "Service $service is not running"
        fi
    done

    # Check web server
    if ! curl -s "http://localhost" > /dev/null; then
        error "Web server is not responding"
    fi

    # Check database
    if ! pg_isready -h localhost -U "$DB_USER" -d "$DB_NAME" > /dev/null 2>&1; then
        error "Database is not accessible"
    fi
}

# Main Installation
main() {
    trap cleanup EXIT
    
    setup_logging
    log "Starting IRSSH Panel installation..."
    
    # Get user input
    read -p "Enter domain name (e.g., panel.example.com): " DOMAIN
    read -p "Enter web panel port (default: 443): " WEB_PORT
    WEB_PORT=${WEB_PORT:-443}
    read -p "Enter SSH port (default: 22): " SSH_PORT
    SSH_PORT=${SSH_PORT:-22}
    read -p "Enter Dropbear port (default: 444): " DROPBEAR_PORT
    DROPBEAR_PORT=${DROPBEAR_PORT:-444}
    read -p "Enter BadVPN port (default: 7300): " BADVPN_PORT
    BADVPN_PORT=${BADVPN_PORT:-7300}
    
    check_requirements
    create_backup
    install_dependencies
    setup_python
    setup_frontend
    setup_database
    setup_modules
    setup_nginx
    setup_ssl
    setup_firewall
    verify_installation
    
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
    echo
    echo "Important Notes:"
    echo "1. Please save these credentials securely"
    echo "2. Change the admin password after first login"
    echo "3. Configure additional security settings in the panel"
    echo "4. Check the installation log for any warnings"
}

# Start installation
main "$@"
