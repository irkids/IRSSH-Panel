#!/bin/bash

# Configuration
PANEL_DIR="/opt/irssh-panel"
CONFIG_DIR="$PANEL_DIR/config"
MODULES_DIR="$PANEL_DIR/modules"
LOG_DIR="/var/log/irssh"
APP_DIR="$PANEL_DIR/app"
DB_NAME="irssh_panel"
DB_USER="irssh_admin"
DB_PASS=$(openssl rand -base64 32)
ADMIN_PASS=$(openssl rand -base64 16)

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
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

# Service check function
check_service() {
    local service=$1
    if ! systemctl is-active --quiet $service; then
        warn "$service is not running. Attempting to start..."
        systemctl start $service
        if ! systemctl is-active --quiet $service; then
            error "Failed to start $service"
        fi
    fi
}

# Check root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
fi

# Clean up any existing installation
log "Cleaning up any existing installation..."
systemctl stop irssh-panel >/dev/null 2>&1
supervisorctl stop irssh-panel >/dev/null 2>&1
rm -rf "$PANEL_DIR"
rm -rf "$LOG_DIR"
rm -f /etc/supervisor/conf.d/irssh-panel.conf
rm -f /etc/nginx/sites-enabled/irssh-panel
rm -f /etc/nginx/sites-available/irssh-panel

# Create directories with proper permissions
log "Creating directories..."
mkdir -p "$PANEL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$MODULES_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$APP_DIR/api/v1/endpoints"
mkdir -p "$APP_DIR/core"
mkdir -p "$APP_DIR/models"
mkdir -p "$APP_DIR/schemas"
mkdir -p "$APP_DIR/utils"
chown -R root:root "$PANEL_DIR"
chmod -R 755 "$PANEL_DIR"

# Create __init__.py files
touch "$APP_DIR/__init__.py"
touch "$APP_DIR/api/__init__.py"
touch "$APP_DIR/api/v1/__init__.py"
touch "$APP_DIR/api/v1/endpoints/__init__.py"
touch "$APP_DIR/core/__init__.py"
touch "$APP_DIR/models/__init__.py"
touch "$APP_DIR/schemas/__init__.py"
touch "$APP_DIR/utils/__init__.py"

# Create config.py with updated settings
cat > "$APP_DIR/core/config.py" << EOL
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List

class Settings(BaseSettings):
    PROJECT_NAME: str = "IRSSH Panel"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "Advanced VPN Server Management Panel"
    
    DATABASE_URL: str = "postgresql+asyncpg://$DB_USER:$DB_PASS@localhost:5432/$DB_NAME"
    
    SECRET_KEY: str = "$(openssl rand -hex 32)"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    
    MODULES_DIR: str = "$MODULES_DIR"
    LOG_DIR: str = "$LOG_DIR"

    model_config = SettingsConfigDict(case_sensitive=True)

settings = Settings()
EOL

# Create database.py
cat > "$APP_DIR/core/database.py" << 'EOL'
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.core.config import settings

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=True,
    pool_size=5,
    max_overflow=10,
    pool_timeout=30
)

async_session = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

Base = declarative_base()

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_db():
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
EOL

# Create models/user.py
cat > "$APP_DIR/models/user.py" << 'EOL'
from sqlalchemy import Boolean, Column, Integer, String, DateTime
from datetime import datetime
from app.core.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
EOL

# Create main.py
cat > "$APP_DIR/main.py" << 'EOL'
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.core.config import settings
from app.core.database import init_db

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_db()
    yield
    # Shutdown

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=settings.DESCRIPTION,
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    return {"status": "healthy"}
EOL

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
    supervisor \
    curl \
    git \
    tar \
    unzip

# Check PostgreSQL
log "Setting up PostgreSQL..."
check_service postgresql

# Create database and user
log "Creating database..."
sudo -u postgres psql -c "DROP DATABASE IF EXISTS $DB_NAME;"
sudo -u postgres psql -c "DROP USER IF EXISTS $DB_USER;"
sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"

# Setup Python environment
log "Setting up Python environment..."
python3 -m venv "$PANEL_DIR/venv"
source "$PANEL_DIR/venv/bin/activate"

# Install Python dependencies
log "Installing Python dependencies..."
pip install --upgrade pip wheel setuptools
pip install \
    fastapi[all] \
    uvicorn[standard] \
    sqlalchemy[asyncio] \
    asyncpg \
    psycopg2-binary \
    python-jose[cryptography] \
    passlib[bcrypt] \
    python-multipart \
    aiofiles \
    pydantic-settings \
    python-dotenv \
    tenacity \
    rich

# Create admin user script
log "Creating admin user script..."
cat > "$PANEL_DIR/create_admin.py" << EOL
from app.models.user import User
from app.core.database import async_session
from passlib.context import CryptContext
import asyncio

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def create_admin():
    async with async_session() as db:
        admin = User(
            username="admin",
            email="admin@localhost",
            hashed_password=pwd_context.hash("$ADMIN_PASS"),
            is_admin=True
        )
        db.add(admin)
        await db.commit()

if __name__ == "__main__":
    asyncio.run(create_admin())
EOL

# Configure supervisor
log "Configuring supervisor..."
cat > /etc/supervisor/conf.d/irssh-panel.conf << EOL
[program:irssh-panel]
directory=$PANEL_DIR
command=$PANEL_DIR/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2
user=root
autostart=true
autorestart=true
stderr_logfile=$LOG_DIR/uvicorn.err.log
stdout_logfile=$LOG_DIR/uvicorn.out.log
environment=PYTHONPATH="$PANEL_DIR"

[supervisord]
nodaemon=false
EOL

# Configure Nginx
log "Configuring Nginx..."
cat > /etc/nginx/sites-available/irssh-panel << 'EOL'
server {
    listen 80;
    server_name _;

    access_log /var/log/nginx/irssh-access.log;
    error_log /var/log/nginx/irssh-error.log;

    location / {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /static {
        alias /opt/irssh-panel/static;
        expires 30d;
        add_header Cache-Control "public, no-transform";
    }
}
EOL

ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Create admin user
log "Creating admin user..."
source "$PANEL_DIR/venv/bin/activate"
python3 "$PANEL_DIR/create_admin.py"

# Start and check services
log "Starting services..."
systemctl daemon-reload
supervisorctl reread
supervisorctl update
systemctl restart nginx

# Check services
check_service nginx
if ! supervisorctl status irssh-panel | grep -q "RUNNING"; then
    error "Failed to start irssh-panel service"
fi

# Test API
log "Testing API health..."
for i in {1..5}; do
    if curl -s http://localhost:8000/health | grep -q "healthy"; then
        break
    fi
    if [ $i -eq 5 ]; then
        error "API health check failed"
    fi
    sleep 1
done

# Installation cleanup
log "Cleaning up..."
rm -f "$PANEL_DIR/create_admin.py"

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
echo "Panel URL: http://$(curl -s ifconfig.me)"
echo "API URL: http://$(curl -s ifconfig.me)/api"
echo
echo "Please change the admin password after first login."
echo
echo "Logs can be found in:"
echo "- Application: $LOG_DIR"
echo "- Nginx: /var/log/nginx/irssh-*.log"
echo "- Supervisor: /var/log/supervisor/irssh-panel*.log"
