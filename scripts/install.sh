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
        sed -i 's/\r$//' "$MODULES_DIR/$script"  # Fix line endings
    fi
done

# Setup backend service
log "Setting up backend service..."
cat > /etc/systemd/system/irssh-panel.service << EOL
[Unit]
Description=IRSSH Panel Backend
After=network.target postgresql.service

[Service]
User=root
Group=root
WorkingDirectory=$PANEL_DIR
Environment="PATH=$PANEL_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EnvironmentFile=$CONFIG_DIR/database.env
ExecStart=$PANEL_DIR/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=3
StartLimitBurst=5
StartLimitInterval=60s

[Install]
WantedBy=multi-user.target
EOL

# Setup Nginx configuration
log "Setting up Nginx..."
cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen 80;
    server_name _;

    # Frontend
    location / {
        root $PANEL_DIR/frontend/build;
        try_files \$uri \$uri/ /index.html;
    }

    # Backend API
    location /api {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # WebSocket endpoints
    location /api/monitoring/ws {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 86400;
    }
}
EOL

# Enable Nginx configuration
ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
systemctl restart nginx

# Setup UFW firewall
log "Configuring firewall..."
ufw allow 'Nginx Full'
ufw allow ssh
ufw allow 1194/udp  # OpenVPN
ufw allow 500/udp   # IKEv2
ufw allow 4500/udp  # IKEv2 NAT-T
ufw allow 1701/udp  # L2TP
ufw allow 51820/udp # WireGuard
ufw --force enable

# Create admin user
log "Creating admin user..."
cat > "$PANEL_DIR/create_admin.py" << EOL
from app.models import User
from app.core.database import SessionLocal
from app.utils.auth import get_password_hash
import asyncio

async def create_admin():
    db = SessionLocal()
    admin = User(
        username="admin",
        hashed_password=get_password_hash("$ADMIN_PASS"),
        email="admin@localhost",
        is_superuser=True
    )
    db.add(admin)
    db.commit()

asyncio.run(create_admin())
EOL

python3 "$PANEL_DIR/create_admin.py"
rm "$PANEL_DIR/create_admin.py"

# Start services
log "Starting services..."
systemctl daemon-reload
systemctl enable postgresql
systemctl enable nginx
systemctl enable irssh-panel
systemctl start irssh-panel

# Initialize database
log "Initializing database..."
source "$PANEL_DIR/venv/bin/activate"
python3 -c "from app.core.database import init_db; asyncio.run(init_db())"

# Setup automatic updates
log "Setting up automatic updates..."
cat > /etc/cron.daily/irssh-panel-update << EOL
#!/bin/bash
cd $PANEL_DIR
git pull
source venv/bin/activate
pip install -r requirements.txt
systemctl restart irssh-panel
EOL
chmod +x /etc/cron.daily/irssh-panel-update

# Setup backup cron job
log "Setting up automatic backups..."
cat > /etc/cron.daily/irssh-panel-backup << EOL
#!/bin/bash
curl -X POST http://localhost:8000/api/settings/backup \
     -H "Content-Type: application/json" \
     -d '{"components": ["database", "config", "certificates"], "cleanup": true}'
EOL
chmod +x /etc/cron.daily/irssh-panel-backup

# Success message
log "Installation completed successfully!"
echo
echo "IRSSH Panel has been installed!"
echo "Frontend URL: http://your-server-ip"
echo "API URL: http://your-server-ip/api"
echo
echo "Admin credentials:"
echo "Username: admin"
echo "Password: $ADMIN_PASS"
echo
echo "Database credentials:"
echo "Database: $DB_NAME"
echo "Username: $DB_USER"
echo "Password: $DB_PASS"
echo
echo "Please save these credentials and change the admin password after first login!"
echo
echo "Installation directory: $PANEL_DIR"
echo "Configuration directory: $CONFIG_DIR"
echo "Log directory: $LOG_DIR"

# Clean up
unset DB_PASS ADMIN_PASS

# Final checks
log "Running final checks..."
systemctl is-active --quiet postgresql && echo "PostgreSQL: Running" || echo "PostgreSQL: NOT Running"
systemctl is-active --quiet nginx && echo "Nginx: Running" || echo "Nginx: NOT Running"
systemctl is-active --quiet irssh-panel && echo "IRSSH Panel: Running" || echo "IRSSH Panel: NOT Running"
curl -s http://localhost:8000/api/health | grep -q "healthy" && echo "API Health Check: OK" || echo "API Health Check: Failed"

exit 0
