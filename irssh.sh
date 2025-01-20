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
GITHUB_RAW="https://raw.githubusercontent.com/irkids/Optimize2Ubuntu/refs/heads/main"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Logging
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
    exit 1
}

# Pre-installation checks
preinstall_checks() {
    log "Running pre-installation checks..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi

    # Check system memory
    total_mem=$(free -m | awk '/^Mem:/{print $2}')
    if [ $total_mem -lt 1024 ]; then
        error "Minimum 1GB of RAM required. Current: ${total_mem}MB"
    fi

    # Check disk space
    free_space=$(df -m / | awk 'NR==2{print $4}')
    if [ $free_space -lt 5120 ]; then
        error "Minimum 5GB of free disk space required. Current: ${free_space}MB"
    fi

    # Disable needrestart interactive prompts
    if [ -f "/etc/needrestart/needrestart.conf" ]; then
        sed -i "s/#\$nrconf{restart} = 'i';/\$nrconf{restart} = 'a';/" /etc/needrestart/needrestart.conf
    fi
}

# System preparation
prepare_system() {
    log "Preparing system..."

    # Update package list
    apt-get update || error "Failed to update package list"

    # Install essential packages
    log "Installing essential packages..."
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
        tar \
        unzip \
        supervisor \
        ufw \
        jq \
        net-tools \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        gnupg \
        lsb-release \
        build-essential \
        libssl-dev \
        libffi-dev \
        python3-dev || error "Failed to install essential packages"

    # Create required directories
    log "Creating directories..."
    mkdir -p "$PANEL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$MODULES_DIR"
    mkdir -p "$LOG_DIR"
    
    # Set correct permissions
    chown -R www-data:www-data "$PANEL_DIR"
    chown -R www-data:www-data "$LOG_DIR"
    chmod -R 755 "$PANEL_DIR"
    chmod -R 755 "$LOG_DIR"
}

# Database setup
setup_database() {
    log "Setting up PostgreSQL..."
    
    if ! systemctl is-active --quiet postgresql; then
        systemctl start postgresql
        systemctl enable postgresql
    fi

    # Create database user and database
    log "Creating database and user..."
    sudo -u postgres psql -c "DROP DATABASE IF EXISTS $DB_NAME;"
    sudo -u postgres psql -c "DROP USER IF EXISTS $DB_USER;"
    
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';" || error "Failed to create database user"
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME;" || error "Failed to create database"
    sudo -u postgres psql -c "ALTER DATABASE $DB_NAME OWNER TO $DB_USER;" || error "Failed to set database owner"
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
}

# Python environment setup
setup_python_env() {
    log "Setting up Python environment..."
    
    # Create virtual environment
    python3 -m venv "$PANEL_DIR/venv" || error "Failed to create virtual environment"
    source "$PANEL_DIR/venv/bin/activate"

    # Upgrade pip
    pip install --upgrade pip

    # Install Python dependencies
    log "Installing Python dependencies..."
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
        python-dotenv \
        pydantic \
        pydantic-settings \
        jinja2 \
        pytest \
        pytest-asyncio \
        requests \
        websockets \
        cryptography || error "Failed to install Python dependencies"
}

# Setup modules
setup_modules() {
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
        curl -o "$MODULES_DIR/$script" "$GITHUB_RAW/$script" || warn "Failed to download $script"
        chmod +x "$MODULES_DIR/$script"
        if [[ "$script" == *.sh ]]; then
            sed -i 's/\r$//' "$MODULES_DIR/$script"
        fi
    done
}

# Configure services
configure_services() {
    log "Configuring services..."

    # Supervisor configuration
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

    # Nginx configuration
    log "Configuring Nginx..."
    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen 80;
    server_name _;
    
    access_log /var/log/nginx/irssh-access.log;
    error_log /var/log/nginx/irssh-error.log;

    client_max_body_size 100M;

    location / {
        root $PANEL_DIR/frontend/build;
        try_files \$uri \$uri/ /index.html;
        add_header Cache-Control "no-store, no-cache, must-revalidate";
    }

    location /api {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # Add timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    location /ws {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        
        # Timeouts
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
    }
}
EOL

    # Enable site and remove default
    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default

    # Test nginx configuration
    nginx -t || error "Nginx configuration test failed"
}

# Configure firewall
configure_firewall() {
    log "Configuring firewall..."
    
    ufw allow 'Nginx Full'
    ufw allow 8000  # API port
    ufw allow 22    # SSH
    ufw allow PostgreSQL
    
    # Enable firewall
    ufw --force enable
}

# Create admin user
create_admin_user() {
    log "Creating admin user..."
    
    # Create initial admin user
    cat > "$PANEL_DIR/create_admin.py" << EOL
from app.models import User
from app.core.database import get_db
from app.core.security import get_password_hash
import asyncio

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
    asyncio.run(create_admin())
EOL

    source "$PANEL_DIR/venv/bin/activate"
    python3 "$PANEL_DIR/create_admin.py" || warn "Failed to create admin user"
    rm -f "$PANEL_DIR/create_admin.py"
}

# Start services
start_services() {
    log "Starting services..."
    
    systemctl daemon-reload
    systemctl enable --now supervisor
    systemctl enable --now nginx
    
    supervisorctl reread
    supervisorctl update
    supervisorctl restart irssh-panel
    
    systemctl restart nginx
}

# Main installation
main() {
    log "Starting IRSSH Panel installation..."
    
    setup_backend() {
    log "Setting up backend..."
    
    # Create app directory structure
    mkdir -p "$PANEL_DIR/app"
    mkdir -p "$PANEL_DIR/app/api/v1/endpoints"
    mkdir -p "$PANEL_DIR/app/core"
    mkdir -p "$PANEL_DIR/app/models"
    mkdir -p "$PANEL_DIR/app/schemas"
    mkdir -p "$PANEL_DIR/app/utils"

    # Create __init__.py files
    touch "$PANEL_DIR/app/__init__.py"
    touch "$PANEL_DIR/app/api/__init__.py"
    touch "$PANEL_DIR/app/api/v1/__init__.py"
    touch "$PANEL_DIR/app/api/v1/endpoints/__init__.py"
    touch "$PANEL_DIR/app/core/__init__.py"
    touch "$PANEL_DIR/app/models/__init__.py"
    touch "$PANEL_DIR/app/schemas/__init__.py"
    touch "$PANEL_DIR/app/utils/__init__.py"

    # Download core backend files from repository
    BACKEND_FILES=(
        "app/main.py"
        "app/core/config.py"
        "app/core/database.py"
        "app/core/security.py"
        "app/core/logger.py"
        "app/models/models.py"
        "app/api/deps.py"
        "app/api/router.py"
        "app/api/v1/endpoints/auth.py"
        "app/api/v1/endpoints/users.py"
        "app/api/v1/endpoints/protocols.py"
        "app/api/v1/endpoints/settings.py"
        "app/api/v1/endpoints/monitoring.py"
    )

    for file in "${BACKEND_FILES[@]}"; do
        log "Downloading $file..."
        dir=$(dirname "$PANEL_DIR/$file")
        mkdir -p "$dir"
        curl -o "$PANEL_DIR/$file" "$GITHUB_RAW/backend/$file" || warn "Failed to download $file"
    done

    # Set correct permissions
    chown -R www-data:www-data "$PANEL_DIR/app"
    chmod -R 755 "$PANEL_DIR/app"

    # Create main.py if download failed
    if [ ! -f "$PANEL_DIR/app/main.py" ]; then
        log "Creating fallback main.py..."
        cat > "$PANEL_DIR/app/main.py" << 'EOL'
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.database import init_db
from app.api.router import api_router

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=settings.DESCRIPTION
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    await init_db()

app.include_router(api_router, prefix="/api")

@app.get("/")
async def root():
    return {"message": "IRSSH Panel API"}
EOL
    fi

    # Create minimal models.py if download failed
    if [ ! -f "$PANEL_DIR/app/models/models.py" ]; then
        log "Creating fallback models.py..."
        cat > "$PANEL_DIR/app/models/models.py" << 'EOL'
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from app.core.database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    email = Column(String, unique=True, index=True, nullable=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
EOL
    fi

    # Create config.py if download failed
    if [ ! -f "$PANEL_DIR/app/core/config.py" ]; then
        log "Creating fallback config.py..."
        cat > "$PANEL_DIR/app/core/config.py" << 'EOL'
import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "IRSSH Panel"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "VPN Server Management Panel"

    MODULES_DIR: str = "/opt/irssh-panel/modules"
    LOG_DIR: str = "/var/log/irssh"

    # Load database config from env file
    with open('/opt/irssh-panel/config/database.env', 'r') as f:
        for line in f:
            if '=' in line:
                key, value = line.strip().split('=', 1)
                os.environ[key] = value

    DB_HOST: str = os.getenv("DB_HOST", "localhost")
    DB_PORT: int = int(os.getenv("DB_PORT", "5432"))
    DB_USER: str = os.getenv("DB_USER", "irssh_admin")
    DB_PASS: str = os.getenv("DB_PASS", "")
    DB_NAME: str = os.getenv("DB_NAME", "irssh_panel")

    @property
    def DATABASE_URI(self) -> str:
        return f"postgresql://{self.DB_USER}:{self.DB_PASS}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

settings = Settings()
EOL
    fi

    log "Backend setup completed"
}
    preinstall_checks
    prepare_system
    setup_database
    setup_python_env
    setup_modules
    configure_services
    configure_firewall
    create_admin_user
    start_services

    # Installation cleanup
    log "Cleaning up..."
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
}

# Run installation
main
