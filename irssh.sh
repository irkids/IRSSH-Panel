#!/bin/bash

# IRSSH Panel Installation Script

# Configuration
PANEL_DIR="/opt/irssh-panel"
CONFIG_DIR="$PANEL_DIR/config"
MODULES_DIR="$PANEL_DIR/modules"
LOG_DIR="/var/log/irssh"
DB_NAME="irssh_panel"
DB_USER="irssh_admin"
DB_PASS=$(openssl rand -base64 32)

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
    exit 1
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
fi

# Get installation parameters
echo "Welcome to IRSSH Panel Installation"
echo "-----------------------------------"
echo

# Get port number
read -p "Enter panel port (default: 8080): " PANEL_PORT
PANEL_PORT=${PANEL_PORT:-8080}

# Validate port number
if ! [[ "$PANEL_PORT" =~ ^[0-9]+$ ]] || [ "$PANEL_PORT" -lt 1 ] || [ "$PANEL_PORT" -gt 65535 ]; then
    error "Invalid port number. Please use a number between 1 and 65535."
fi

# Check if port is available
if netstat -tuln | grep ":$PANEL_PORT " > /dev/null; then
    error "Port $PANEL_PORT is already in use. Please choose a different port."
fi

# Get admin credentials
read -p "Enter admin username (default: admin): " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}

while true; do
    read -s -p "Enter admin password (leave blank for random): " ADMIN_PASS
    echo
    if [ -z "$ADMIN_PASS" ]; then
        ADMIN_PASS=$(openssl rand -base64 16)
        echo "Using generated password: $ADMIN_PASS"
        break
    else
        read -s -p "Confirm admin password: " ADMIN_PASS_CONFIRM
        echo
        if [ "$ADMIN_PASS" = "$ADMIN_PASS_CONFIRM" ]; then
            break
        else
            echo "Passwords do not match. Please try again."
        fi
    fi
done

# Create required directories
log "Creating directories..."
mkdir -p "$PANEL_DIR"/{app,config,modules,frontend,logs}
mkdir -p "$PANEL_DIR/app"/{api,core,models,schemas,utils}
mkdir -p "$LOG_DIR"

# Install system dependencies
log "Installing system dependencies..."
apt-get update
apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    postgresql \
    postgresql-contrib \
    nginx \
    certbot \
    python3-certbot-nginx \
    git \
    curl \
    tar \
    unzip \
    supervisor \
    ufw \
    net-tools

# Setup PostgreSQL
log "Setting up PostgreSQL..."
if ! systemctl is-active --quiet postgresql; then
    systemctl start postgresql
    systemctl enable postgresql
fi

# Create database and user
sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';" || error "Failed to create database user"
sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;" || error "Failed to create database"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;" || error "Failed to grant privileges"

# Save database configuration
cat > "$CONFIG_DIR/database.env" << EOL
DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASS=$DB_PASS
EOL

chmod 600 "$CONFIG_DIR/database.env"

# Setup Python environment
log "Setting up Python environment..."
python3 -m venv "$PANEL_DIR/venv"
source "$PANEL_DIR/venv/bin/activate"

# Install Python requirements
log "Installing Python dependencies..."
pip install --upgrade pip
pip install \
    fastapi[all] \
    uvicorn[standard] \
    sqlalchemy[asyncio] \
    psycopg2-binary \
    python-jose[cryptography] \
    passlib[bcrypt] \
    python-multipart \
    aiofiles \
    python-telegram-bot \
    psutil \
    geoip2 \
    asyncpg \
    aiohttp

# Create application structure
log "Creating application structure..."

# Create main.py
cat > "$PANEL_DIR/app/main.py" << EOL
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.router import api_router

app = FastAPI(
    title="IRSSH Panel",
    description="Advanced VPN Server Management Panel",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api")
EOL

# Create config.py
cat > "$PANEL_DIR/app/core/config.py" << EOL
from pydantic_settings import BaseSettings
from typing import List
import os

class Settings(BaseSettings):
    PROJECT_NAME: str = "IRSSH Panel"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = "$(openssl rand -hex 32)"
    PANEL_PORT: int = $PANEL_PORT
    
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    DB_USER: str = "$DB_USER"
    DB_PASS: str = "$DB_PASS"
    DB_NAME: str = "$DB_NAME"
    
    MODULES_DIR: str = "$MODULES_DIR"
    LOG_DIR: str = "$LOG_DIR"
    
    class Config:
        case_sensitive = True

settings = Settings()
EOL

# Copy all backend files
log "Setting up backend..."
cp -r backend/* "$PANEL_DIR/app/"

# Download module scripts
log "Setting up modules..."
MODULE_SCRIPTS=(
    "vpnserver-script.py"
    "port-script.py"
    "ssh-script.py"
    "l2tpv3-script.sh"
    "ikev2-script.py"
    "cisco-script.sh"
    "wire-script.sh"
    "singbox-script.sh"
    "badvpn-script.sh"
    "dropbear-script.sh"
    "webport-script.sh"
)

for script in "${MODULE_SCRIPTS[@]}"; do
    log "Downloading $script..."
    curl -o "$MODULES_DIR/$script" "https://raw.githubusercontent.com/irkids/Optimize2Ubuntu/refs/heads/main/$script"
    chmod +x "$MODULES_DIR/$script"
    if [[ "$script" == *.sh ]]; then
        sed -i 's/\r$//' "$MODULES_DIR/$script"
    fi
done

# Create supervisor configuration
log "Configuring supervisor..."
cat > /etc/supervisor/conf.d/irssh-panel.conf << EOL
[program:irssh-panel]
directory=$PANEL_DIR
command=$PANEL_DIR/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port $PANEL_PORT
user=root
autostart=true
autorestart=true
stderr_logfile=$LOG_DIR/uvicorn.err.log
stdout_logfile=$LOG_DIR/uvicorn.out.log
environment=PYTHONPATH="$PANEL_DIR"
EOL

# Configure Nginx
log "Configuring Nginx..."
cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen $PANEL_PORT;
    server_name _;

    location / {
        root $PANEL_DIR/frontend/build;
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
    }

    location /ws {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
    }

    access_log $LOG_DIR/access.log;
    error_log $LOG_DIR/error.log;
}
EOL

ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Configure firewall
log "Configuring firewall..."
ufw allow "$PANEL_PORT"/tcp
ufw allow ssh
ufw --force enable

# Create admin user
log "Creating admin user..."
cat > "$PANEL_DIR/create_admin.py" << EOL
import os
import sys
sys.path.append('$PANEL_DIR')

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models import Base, User
from app.core.security import get_password_hash

DATABASE_URL = "postgresql://$DB_USER:$DB_PASS@localhost:5432/$DB_NAME"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

def create_admin():
    Base.metadata.create_all(engine)
    db = SessionLocal()
    try:
        admin = User(
            username="$ADMIN_USER",
            hashed_password=get_password_hash("$ADMIN_PASS"),
            email="admin@localhost",
            is_admin=True,
            is_active=True
        )
        db.add(admin)
        db.commit()
        print("Admin user created successfully")
    except Exception as e:
        print(f"Error creating admin user: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    create_admin()
EOL

# Set PYTHONPATH and create admin user
export PYTHONPATH="$PANEL_DIR"
source "$PANEL_DIR/venv/bin/activate"
python3 "$PANEL_DIR/create_admin.py"

# Start services
log "Starting services..."
systemctl daemon-reload
systemctl enable --now supervisor
systemctl enable --now nginx
supervisorctl reread
supervisorctl update
supervisorctl restart irssh-panel

# Test API health
log "Testing API health..."
sleep 5
response=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:$PANEL_PORT/api/health")
if [ "$response" != "200" ]; then
    error "API health check failed. Please check the logs at $LOG_DIR"
fi

# Installation cleanup
log "Cleaning up..."
rm -f "$PANEL_DIR/create_admin.py"
apt-get clean
apt-get autoremove -y

# Installation complete
log "Installation completed successfully!"
echo
echo "IRSSH Panel has been installed with the following credentials:"
echo
echo "Admin Username: $ADMIN_USER"
echo "Admin Password: $ADMIN_PASS"
echo
echo "Database Configuration:"
echo "Database Name: $DB_NAME"
echo "Database User: $DB_USER"
echo "Database Password: $DB_PASS"
echo
echo "Panel URL: http://$(hostname -I | cut -d' ' -f1):$PANEL_PORT"
echo "API URL: http://$(hostname -I | cut -d' ' -f1):$PANEL_PORT/api"
echo "Documentation: http://$(hostname -I | cut -d' ' -f1):$PANEL_PORT/api/docs"
echo
echo "For security reasons, please change the admin password after first login."
echo
echo "Logs can be found in: $LOG_DIR"
