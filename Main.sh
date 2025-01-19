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
    if [[ $script == *.sh ]]; then
        sed -i 's/\r$//' "$MODULES_DIR/$script"  # Fix line endings for shell scripts
    fi
done

# Configure Nginx
log "Configuring Nginx..."
cat > /etc/nginx/sites-available/irssh-panel << 'EOL'
server {
    listen 80;
    server_name _;

    # Frontend
    location / {
        root /opt/irssh-panel/frontend/build;
        try_files $uri $uri/ /index.html;
        add_header Cache-Control "no-cache";
    }

    # Backend API
    location /api {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket connections
    location /ws {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
    }

    access_log /var/log/nginx/irssh-access.log;
    error_log /var/log/nginx/irssh-error.log;
}
EOL

# Enable Nginx configuration
ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t || error "Nginx configuration test failed"

# Configure systemd service
log "Creating systemd service..."
cat > /etc/systemd/system/irssh-panel.service << EOL
[Unit]
Description=IRSSH Panel Backend
After=network.target postgresql.service

[Service]
User=root
Group=root
WorkingDirectory=/opt/irssh-panel/backend
Environment="PATH=/opt/irssh-panel/venv/bin"
ExecStart=/opt/irssh-panel/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always
StandardOutput=append:/var/log/irssh/backend.log
StandardError=append:/var/log/irssh/backend-error.log

[Install]
WantedBy=multi-user.target
EOL

# Create fix script
log "Creating maintenance script..."
cat > "$PANEL_DIR/scripts/fix.sh" << 'EOL'
#!/bin/bash

# Configuration
PANEL_DIR="/opt/irssh-panel"
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
}

# Check logs
check_logs() {
    log "Checking logs..."
    echo "=== Backend Errors ==="
    tail -n 50 $LOG_DIR/backend-error.log
    echo "=== Nginx Errors ==="
    tail -n 50 /var/log/nginx/irssh-error.log
}

# Fix permissions
fix_permissions() {
    log "Fixing permissions..."
    chown -R root:root $PANEL_DIR
    chmod -R 755 $PANEL_DIR
    chmod -R 777 $LOG_DIR
}

# Check services
check_services() {
    log "Checking services..."
    systemctl status postgresql
    systemctl status nginx
    systemctl status irssh-panel
}

# Restart services
restart_services() {
    log "Restarting services..."
    systemctl restart postgresql
    systemctl restart nginx
    systemctl restart irssh-panel
}

# Apply Nginx config
apply_nginx_config() {
    log "Applying Nginx configuration..."
    nginx -t && systemctl restart nginx
}

# Check database
check_database() {
    log "Checking database connection..."
    source $PANEL_DIR/config/database.env
    PGPASSWORD=$DB_PASS psql -h localhost -U $DB_USER -d $DB_NAME -c '\dt'
}

# Main
log "Starting fix process..."

# Run checks
fix_permissions
check_database
apply_nginx_config
restart_services
check_services
check_logs

log "Fix process completed. Please check the logs above for any errors."
EOL

chmod +x "$PANEL_DIR/scripts/fix.sh"

# Set up firewall
log "Configuring firewall..."
ufw allow ssh
ufw allow http
ufw allow https
ufw allow 8000
ufw --force enable

# Start services
log "Starting services..."
systemctl daemon-reload
systemctl enable postgresql
systemctl enable nginx
systemctl enable irssh-panel
systemctl start postgresql
systemctl start nginx
systemctl start irssh-panel

# Create admin user
log "Creating admin user..."
source "$PANEL_DIR/venv/bin/activate"
python3 << EOL
from app.models import User
from app.core.database import SessionLocal
from app.core.security import get_password_hash

db = SessionLocal()
admin = User(
    username="admin",
    email="admin@localhost",
    hashed_password=get_password_hash("$ADMIN_PASS"),
    is_admin=True
)
db.add(admin)
db.commit()
EOL

# Final steps
log "Installation completed successfully!"
echo
echo "Panel URL: http://YOUR_SERVER_IP"
echo "Admin username: admin"
echo "Admin password: $ADMIN_PASS"
echo
echo "Database credentials are stored in: $CONFIG_DIR/database.env"
echo "Maintenance script: $PANEL_DIR/scripts/fix.sh"
echo
echo "If you encounter any issues, run the maintenance script:"
echo "bash $PANEL_DIR/scripts/fix.sh"
