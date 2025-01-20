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
ADMIN_PASS=$(openssl rand -base64 16)

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Logging
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
    exit 1
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
fi

# Create required directories
log "Creating directories..."
mkdir -p "$PANEL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$MODULES_DIR"
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
    ufw

# Setup PostgreSQL
log "Setting up PostgreSQL..."
if ! systemctl is-active --quiet postgresql; then
    systemctl start postgresql
    systemctl enable postgresql
fi

# Create database and user
sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';" || error "Failed to create database user"
sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;" || error "Failed to create database"

# Save database configuration
cat > "$CONFIG_DIR/database.env" << EOL
DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASS=$DB_PASS
EOL

# Clone repository and setup Python environment
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
    asyncpg

# Download and install module scripts
log "Installing modules..."
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
log "Setting up supervisor..."
cat > /etc/supervisor/conf.d/irssh-panel.conf << EOL
[program:irssh-panel]
directory=$PANEL_DIR
command=$PANEL_DIR/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
user=root
autostart=true
autorestart=true
stderr_logfile=$LOG_DIR/uvicorn.err.log
stdout_logfile=$LOG_DIR/uvicorn.out.log
environment=
    PATH="$PANEL_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    PYTHONPATH="$PANEL_DIR"
EOL

# Configure Nginx
log "Configuring Nginx..."
cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen 80;
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
    }

    location /ws {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
    }
}
EOL

ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Configure firewall
log "Configuring firewall..."
ufw allow 'Nginx Full'
ufw allow 8000  # API port
ufw allow 22    # SSH
ufw --force enable

# Create systemd service for background tasks
log "Creating background service..."
cat > /etc/systemd/system/irssh-tasks.service << EOL
[Unit]
Description=IRSSH Panel Background Tasks
After=network.target postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=$PANEL_DIR
Environment=PYTHONPATH=$PANEL_DIR
ExecStart=$PANEL_DIR/venv/bin/python3 -m app.core.tasks
Restart=always

[Install]
WantedBy=multi-user.target
EOL

# Create initial admin user
log "Creating admin user..."
cat > "$PANEL_DIR/create_admin.py" << EOL
from app.models import User
from app.core.database import get_db
from app.core.security import get_password_hash

async def create_admin():
    async with get_db() as db:
        admin = User(
            username="admin",
            hashed_password=get_password_hash("$ADMIN_PASS"),
            email="admin@localhost",
            is_admin=True
        )
        db.add(admin)
        await db.commit()

if __name__ == "__main__":
    import asyncio
    asyncio.run(create_admin())
EOL

# Initialize database
log "Initializing database..."
source "$PANEL_DIR/venv/bin/activate"
python3 "$PANEL_DIR/create_admin.py"

# Start services
log "Starting services..."
systemctl daemon-reload
systemctl enable --now supervisor
systemctl enable --now nginx
systemctl enable --now irssh-tasks
supervisorctl reread
supervisorctl update
supervisorctl restart irssh-panel

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
echo "Admin Username: admin"
echo "Admin Password: $ADMIN_PASS"
echo
echo "Database Configuration:"
echo "Database Name: $DB_NAME"
echo "Database User: $DB_USER"
echo "Database Password: $DB_PASS"
echo
echo "Panel URL: http://your-server-ip"
echo "API URL: http://your-server-ip/api"
echo "Documentation: http://your-server-ip/api/docs"
echo
echo "For security reasons, please change the admin password after first login."
echo
echo "Logs can be found in: $LOG_DIR"
