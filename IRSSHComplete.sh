#!/bin/bash

# IRSSH Panel Complete Installation Script
# Version: 1.0.0

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
MODULES_DIR="$PANEL_DIR/modules"
LOG_DIR="/var/log/irssh"
VENV_DIR="$PANEL_DIR/venv"

# Database Configuration
DB_NAME="irssh_panel"
DB_USER="irssh_admin"
DB_PASS=$(openssl rand -base64 32)
ADMIN_PASS=$(openssl rand -base64 16)

# Logging
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
    exit 1
}

# Check root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
fi

# User Input
log "Getting user input..."
read -p "Enter domain name (e.g., panel.example.com): " DOMAIN
read -p "Enter panel port (default: 443): " PANEL_PORT
PANEL_PORT=${PANEL_PORT:-443}
read -p "Enter SSH port (default: 22): " SSH_PORT
SSH_PORT=${SSH_PORT:-22}
read -p "Enter Dropbear port (default: 444): " DROPBEAR_PORT
DROPBEAR_PORT=${DROPBEAR_PORT:-444}
read -p "Enter BadVPN port (default: 7300): " BADVPN_PORT
BADVPN_PORT=${BADVPN_PORT:-7300}

# Create directories
log "Creating directories..."
mkdir -p "$FRONTEND_DIR"
mkdir -p "$BACKEND_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$MODULES_DIR"
mkdir -p "$LOG_DIR"

# Install dependencies
log "Installing system dependencies..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
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
    supervisor \
    ufw \
    fail2ban \
    net-tools \
    npm \
    nodejs

# Setup PostgreSQL
log "Setting up PostgreSQL..."
systemctl start postgresql
systemctl enable postgresql

# Create database and user
if ! sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
    log "Creating database..."
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

# Setup Python environment
log "Setting up Python environment..."
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

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
    asyncpg

# Setup Frontend
log "Setting up frontend..."
cd "$FRONTEND_DIR"
npm init -y

# Install React and dependencies
npm install \
    react \
    react-dom \
    @headlessui/react \
    @heroicons/react \
    axios \
    react-router-dom \
    tailwindcss \
    @tailwindcss/forms

# Create React app structure
mkdir -p src/components/{Dashboard,UserManagement,Settings,Monitoring}

# Copy frontend files from repository
if [ -d "/root/irssh-panel/frontend/src" ]; then
    cp -r /root/irssh-panel/frontend/src/* "$FRONTEND_DIR/src/"
fi

# Build frontend
npm run build

# Configure Nginx
log "Configuring Nginx..."
cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    server_name $DOMAIN;

    root $FRONTEND_DIR/build;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
        add_header X-Frame-Options "SAMEORIGIN";
        add_header X-Content-Type-Options "nosniff";
        add_header X-XSS-Protection "1; mode=block";
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

ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Configure SSL
log "Configuring SSL..."
certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email admin@$DOMAIN

# Configure supervisor
log "Configuring supervisor..."
cat > /etc/supervisor/conf.d/irssh-panel.conf << EOL
[program:irssh-panel]
directory=$BACKEND_DIR
command=$VENV_DIR/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
user=root
autostart=true
autorestart=true
stderr_logfile=$LOG_DIR/uvicorn.err.log
stdout_logfile=$LOG_DIR/uvicorn.out.log
environment=PYTHONPATH="$BACKEND_DIR"
EOL

# Setup modules
log "Setting up modules..."
for module in ssh l2tp ikev2 cisco wireguard singbox; do
    log "Initializing $module module..."
    "$MODULES_DIR/$module-script.py" init || error "Failed to initialize $module module"
    
    # Generate default configuration
    "$MODULES_DIR/$module-script.py" generate-config > "$CONFIG_DIR/$module.json"
    chmod 600 "$CONFIG_DIR/$module.json"
done

# Configure firewall
log "Configuring firewall..."
ufw allow $PANEL_PORT/tcp
ufw allow $SSH_PORT/tcp
ufw allow $DROPBEAR_PORT/tcp
ufw allow $BADVPN_PORT/udp
ufw --force enable

# Create initial admin user
log "Creating admin user..."
cat > "$BACKEND_DIR/create_admin.py" << EOL
from app.core.security import get_password_hash
from app.models import User
from app.core.database import SessionLocal
import asyncio

async def create_admin():
    db = SessionLocal()
    admin = User(
        username="admin",
        hashed_password=get_password_hash("$ADMIN_PASS"),
        email="admin@$DOMAIN",
        is_superuser=True
    )
    db.add(admin)
    await db.commit()

asyncio.run(create_admin())
EOL

source "$VENV_DIR/bin/activate"
python "$BACKEND_DIR/create_admin.py"

# Start services
log "Starting services..."
systemctl restart nginx
supervisorctl reread
supervisorctl update
supervisorctl restart irssh-panel

# Final verification
log "Performing final verification..."
sleep 5

# Check if services are running
if ! systemctl is-active --quiet nginx; then
    error "Nginx is not running"
fi

if ! pgrep -f "uvicorn app.main:app" > /dev/null; then
    error "Backend service is not running"
fi

log "Installation completed successfully!"
echo
echo "IRSSH Panel has been installed with the following credentials:"
echo "Panel URL: https://$DOMAIN"
echo "Admin Username: admin"
echo "Admin Password: $ADMIN_PASS"
echo
echo "Please change these passwords immediately after first login."
echo "Installation logs are available at: $LOG_DIR"
echo
echo "Configured ports:"
echo "Panel: $PANEL_PORT"
echo "SSH: $SSH_PORT"
echo "Dropbear: $DROPBEAR_PORT"
echo "BadVPN: $BADVPN_PORT"
