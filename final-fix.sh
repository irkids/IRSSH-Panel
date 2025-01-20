#!/bin/bash

# IRSSH Panel Final Fix Script

# === Configuration ===
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
VENV_DIR="$PANEL_DIR/venv"
LOG_DIR="/var/log/irssh"

# === Colors ===
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
    exit 1
}

# === Check Root ===
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
fi

# === Ask for HTTPS or HTTP ===
log "Do you want to enable HTTPS? (y/n)"
read -r ENABLE_HTTPS
if [[ "$ENABLE_HTTPS" == "y" ]]; then
    USE_HTTPS=true
else
    USE_HTTPS=false
fi

# === Get Domain or Use IP ===
read -p "Enter your domain or subdomain (leave blank to use server IP): " DOMAIN
if [[ -z "$DOMAIN" ]]; then
    DOMAIN=$(curl -s ifconfig.me)
    log "No domain provided. Using server IP: $DOMAIN"
fi

# === Get Port ===
read -p "Enter port for the panel (leave blank for random): " PANEL_PORT
if [[ -z "$PANEL_PORT" ]]; then
    PANEL_PORT=$((RANDOM % 9000 + 10000)) # Random 5-digit port
    log "No port provided. Using random port: $PANEL_PORT"
fi

# === Get Admin Credentials ===
read -p "Enter admin username: " ADMIN_USER
if [[ -z "$ADMIN_USER" ]]; then
    ADMIN_USER="admin"
    log "No username provided. Using default: admin"
fi

read -sp "Enter admin password: " ADMIN_PASS
if [[ -z "$ADMIN_PASS" ]]; then
    ADMIN_PASS="password"
    log "No password provided. Using default: password"
fi
echo

# === Install Dependencies ===
log "Installing system dependencies..."
apt-get update
apt-get install -y jq build-essential python3-dev python3-pip python3-venv \
    libpq-dev nginx supervisor curl || error "Dependency installation failed"

if $USE_HTTPS; then
    apt-get install -y certbot python3-certbot-nginx || error "Certbot installation failed"
fi

# === Setup Backend ===
log "Setting up backend..."
mkdir -p "$BACKEND_DIR/app/"{core,api,models,schemas,utils}
mkdir -p "$BACKEND_DIR/app/api/v1/endpoints"
mkdir -p "$CONFIG_DIR" "$LOG_DIR"

cat > "$BACKEND_DIR/app/core/config.py" << EOL
from pydantic import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "IRSSH Panel"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "VPN Server Management Panel"
    ADMIN_USERNAME: str = "$ADMIN_USER"
    ADMIN_PASSWORD: str = "$ADMIN_PASS"
    DOMAIN: str = "$DOMAIN"
    PANEL_PORT: int = $PANEL_PORT

settings = Settings()
EOL

# === Setup Frontend ===
log "Setting up frontend..."
rm -rf "$FRONTEND_DIR"
mkdir -p "$FRONTEND_DIR"
npx create-react-app "$FRONTEND_DIR" --template typescript --use-npm
cd "$FRONTEND_DIR"
npm install @headlessui/react @heroicons/react axios react-router-dom tailwindcss
npx tailwindcss init -p

cat > "$FRONTEND_DIR/src/App.js" << 'EOL'
import React from 'react';

function Dashboard() {
    return <h1 className="text-3xl font-bold text-center mt-10">Welcome to IRSSH Panel</h1>;
}

function App() {
    return (
        <div className="min-h-screen bg-gray-100">
            <Dashboard />
        </div>
    );
}

export default App;
EOL

npm run build

# === Configure Nginx ===
log "Configuring Nginx..."
if $USE_HTTPS; then
    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen $PANEL_PORT ssl;
    server_name $DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    root $FRONTEND_DIR/build;
    index index.html;

    location / {
        try_files \$uri /index.html;
    }

    location /api {
        proxy_pass http://localhost:8000/api;
    }

    client_max_body_size 100M;
}
EOL
else
    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen $PANEL_PORT;
    server_name $DOMAIN;

    root $FRONTEND_DIR/build;
    index index.html;

    location / {
        try_files \$uri /index.html;
    }

    location /api {
        proxy_pass http://localhost:8000/api;
    }

    client_max_body_size 100M;
}
EOL
fi

ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
systemctl reload nginx || error "Nginx configuration failed"

# === Enable HTTPS with Certbot ===
if $USE_HTTPS; then
    log "Enabling HTTPS with Certbot..."
    certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email your-email@example.com || error "Certbot failed to issue certificate"
fi

# === Final Message ===
log "Installation completed successfully!"
if $USE_HTTPS; then
    echo "Access your panel at: https://$DOMAIN:$PANEL_PORT"
    echo "API Endpoint: https://$DOMAIN:$PANEL_PORT/api"
else
    echo "Access your panel at: http://$DOMAIN:$PANEL_PORT"
    echo "API Endpoint: http://$DOMAIN:$PANEL_PORT/api"
fi
