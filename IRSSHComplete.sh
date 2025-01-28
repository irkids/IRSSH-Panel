#!/bin/bash

# IRSSH Panel Complete Installation Script

# Configuration
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
LOG_DIR="/var/log/irssh"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Logging
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
    cleanup
    exit 1
}

# Cleanup function
cleanup() {
    log "Cleaning up installation..."
    if [ -d "$PANEL_DIR" ]; then
        rm -rf "$PANEL_DIR"
    fi
    if [ -f "/etc/nginx/sites-enabled/irssh-panel" ]; then
        rm -f "/etc/nginx/sites-enabled/irssh-panel"
    fi
    if [ -f "/etc/supervisor/conf.d/irssh-panel.conf" ]; then
        rm -f "/etc/supervisor/conf.d/irssh-panel.conf"
    fi
}

# Trap for cleanup
trap cleanup ERR

# User Input
read -p "Enter domain name (e.g., panel.example.com): " DOMAIN
read -p "Enter web panel port (default: 443): " WEB_PORT
WEB_PORT=${WEB_PORT:-443}
read -p "Enter SSH port (default: 22): " SSH_PORT
SSH_PORT=${SSH_PORT:-22}
read -p "Enter Dropbear port (default: 444): " DROPBEAR_PORT
DROPBEAR_PORT=${DROPBEAR_PORT:-444}
read -p "Enter BadVPN port (default: 7300): " BADVPN_PORT
BADVPN_PORT=${BADVPN_PORT:-7300}

# Generate secure passwords
ADMIN_USER="admin"
ADMIN_PASS=$(openssl rand -base64 12)
DB_USER="irssh_admin"
DB_PASS=$(openssl rand -base64 32)
DB_NAME="irssh_panel"

# Check root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
fi

# Install Dependencies
log "Installing dependencies..."
apt-get update
apt-get install -y \
    curl \
    wget \
    git \
    nginx \
    postgresql \
    python3 \
    python3-pip \
    python3-venv \
    supervisor \
    ufw \
    fail2ban \
    nodejs \
    npm \
    certbot \
    python3-certbot-nginx

# Setup PostgreSQL
log "Setting up database..."
if ! systemctl is-active --quiet postgresql; then
    systemctl start postgresql
    systemctl enable postgresql
fi

sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"

# Setup Directories
log "Setting up directories..."
mkdir -p "$FRONTEND_DIR"
mkdir -p "$BACKEND_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"

# Setup Python Environment
log "Setting up Python environment..."
python3 -m venv "$PANEL_DIR/venv"
source "$PANEL_DIR/venv/bin/activate"

pip install \
    fastapi[all] \
    uvicorn[standard] \
    sqlalchemy[asyncio] \
    psycopg2-binary \
    python-jose[cryptography] \
    passlib[bcrypt] \
    python-multipart \
    aiofiles

# Setup Frontend
log "Setting up frontend..."
cd "$FRONTEND_DIR"
npx create-react-app . --template typescript
npm install \
    @headlessui/react \
    @heroicons/react \
    axios \
    react-router-dom \
    tailwindcss \
    @tailwindcss/forms

# Configure Frontend
cat > "$FRONTEND_DIR/src/App.tsx" << 'EOL'
import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';

function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-gray-100">
        <Routes>
          <Route path="/" element={<div>IRSSH Panel</div>} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default App;
EOL

# Build Frontend
npm run build

# Configure Nginx
log "Configuring Nginx..."
cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen 80;
    server_name $DOMAIN;

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
        proxy_cache_bypass \$http_upgrade;
    }
}
EOL

ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Configure SSL
log "Configuring SSL..."
certbot --nginx -d $DOMAIN --non-interactive --agree-tos --redirect

# Configure Supervisor
log "Configuring Supervisor..."
cat > /etc/supervisor/conf.d/irssh-panel.conf << EOL
[program:irssh-panel]
directory=$BACKEND_DIR
command=$PANEL_DIR/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
user=root
autostart=true
autorestart=true
stderr_logfile=$LOG_DIR/uvicorn.err.log
stdout_logfile=$LOG_DIR/uvicorn.out.log
EOL

# Save Configuration
log "Saving configuration..."
cat > "$CONFIG_DIR/config.env" << EOL
DOMAIN=$DOMAIN
WEB_PORT=$WEB_PORT
SSH_PORT=$SSH_PORT
DROPBEAR_PORT=$DROPBEAR_PORT
BADVPN_PORT=$BADVPN_PORT
ADMIN_USER=$ADMIN_USER
ADMIN_PASS=$ADMIN_PASS
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASS=$DB_PASS
EOL

chmod 600 "$CONFIG_DIR/config.env"

# Configure Firewall
log "Configuring firewall..."
ufw allow $WEB_PORT/tcp
ufw allow $SSH_PORT/tcp
ufw allow $DROPBEAR_PORT/tcp
ufw allow $BADVPN_PORT/udp
ufw --force enable

# Start Services
log "Starting services..."
systemctl restart nginx
supervisorctl reread
supervisorctl update
supervisorctl restart irssh-panel

# Final Check
log "Performing final checks..."
if ! curl -s "http://localhost:8000/api/health" | grep -q "healthy"; then
    error "API health check failed"
fi

# Installation Complete
log "Installation completed successfully!"
echo
echo "IRSSH Panel has been installed with the following credentials:"
echo "Panel URL: https://$DOMAIN"
echo "Admin Username: $ADMIN_USER"
echo "Admin Password: $ADMIN_PASS"
echo
echo "Please save these credentials and change the password after first login."
echo "Installation logs are available at: $LOG_DIR"
