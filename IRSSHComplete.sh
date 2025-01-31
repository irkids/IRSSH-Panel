#!/bin/bash

# IRSSH Panel Complete Installation Script
# Version: 3.4.4 (Updated)

# Directories
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
MODULES_DIR="$PANEL_DIR/modules"
LOG_DIR="/var/log/irssh"
BACKUP_DIR="/opt/irssh-backups"

# Colors for logging
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Secure credentials
DB_NAME="irssh_panel"
DB_USER="irssh_admin"
DB_PASS=$(openssl rand -base64 32)
ADMIN_PASS=$(openssl rand -base64 16)
JWT_SECRET=$(openssl rand -base64 32)

# Protocol installation flags
INSTALL_SSH=true
INSTALL_L2TP=true
INSTALL_IKEV2=true
INSTALL_CISCO=true
INSTALL_WIREGUARD=true
INSTALL_SINGBOX=true

# Ports
SSH_PORT=22
L2TP_PORT=1701
IKEV2_PORT=500
CISCO_PORT=443
WIREGUARD_PORT=51820
SINGBOX_PORT=1080
BADVPN_PORT=7300
DROPBEAR_PORT=444

# Logging function
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
    [[ "${2:-}" != "no-exit" ]] && exit 1
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Setup directories
setup_directories() {
    log "Setting up directories..."
    mkdir -p "$PANEL_DIR"/{frontend,backend,config,modules,modules/protocols}
    chmod -R 755 "$PANEL_DIR"
}
# Install system dependencies
install_dependencies() {
    log "Installing system dependencies..."
    apt-get update

    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3 python3-pip python3-venv \
        postgresql postgresql-contrib \
        nginx certbot python3-certbot-nginx \
        git curl wget zip unzip \
        supervisor ufw fail2ban \
        sysstat iftop vnstat \
        strongswan xl2tpd ppp \
        ocserv wireguard-tools \
        golang iptables-persistent

    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    apt-get install -y nodejs
    npm install -g npm@8.19.4 || error "npm installation failed"
}

# Setup Python environment
setup_python() {
    log "Creating Python virtual environment..."
    python3 -m venv "$PANEL_DIR/venv"
    source "$PANEL_DIR/venv/bin/activate"
    pip install -U pip wheel
    pip install fastapi uvicorn sqlalchemy psycopg2-binary passlib cryptography
}

# Setup Python Backend
setup_python_backend() {
    log "Initializing database schema..."
    cat > "$BACKEND_DIR/app/main.py" << 'EOL'
from fastapi import FastAPI
from app.api import monitoring, auth, users
from app.core.database import engine, Base
Base.metadata.create_all(bind=engine)

app = FastAPI()
app.include_router(monitoring.router)
app.include_router(auth.router)
app.include_router(users.router)

@app.get("/")
def read_root():
    return {"status": "IRSSH Panel Ready"}
EOL

    cat > "$BACKEND_DIR/migrations/init_db.py" << 'EOL'
from app.core.database import Base
from app.models.user import User
def run_migrations():
    Base.metadata.create_all()
EOL
}
setup_nginx() {
    log "Configuring Nginx..."
    
    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen 80;
    server_name ${DOMAIN};

    root ${FRONTEND_DIR}/build;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location /api {
        proxy_pass http://localhost:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOL

    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
    nginx -t || error "Nginx configuration test failed"
}

setup_firewall() {
    log "Configuring firewall..."
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow http
    ufw allow https
    ufw allow "$SSH_PORT"
    ufw allow "$L2TP_PORT"
    ufw allow "$IKEV2_PORT"
    ufw allow "$CISCO_PORT"
    ufw allow "$WIREGUARD_PORT"
    ufw allow "$SINGBOX_PORT"
    echo "y" | ufw enable
}
cat > "$BACKEND_DIR/app/utils/monitoring.py" << 'EOL'
import psutil

class SystemMonitor:
    def get_cpu_usage(self):
        return psutil.cpu_percent(interval=1)

    def get_memory_usage(self):
        return psutil.virtual_memory().percent

    def get_disk_usage(self):
        return psutil.disk_usage('/').percent

system_monitor = SystemMonitor()
EOL

cat > "$BACKEND_DIR/app/api/monitoring.py" << 'EOL'
from fastapi import APIRouter
from ..utils.monitoring import system_monitor

router = APIRouter()

@router.get("/system")
async def get_system_info():
    return {
        "cpu": system_monitor.get_cpu_usage(),
        "memory": system_monitor.get_memory_usage(),
        "disk": system_monitor.get_disk_usage()
    }
EOL
setup_database() {
    log "Setting up database..."
    systemctl start postgresql
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"
}

cat > "$BACKEND_DIR/app/api/users.py" << 'EOL'
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.user import User
router = APIRouter()

@router.get("/users")
def get_all_users(db: Session = Depends(get_db)):
    return db.query(User).all()
EOL
main() {
    setup_logging
    setup_directories
    install_dependencies
    setup_python
    setup_python_backend
    setup_nginx
    setup_firewall
    setup_database
    log "Installation completed successfully!"
}

main "$@"
