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
RED='\033[0;31m'
NC='\033[0m'

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

# Remove existing installation
log "Cleaning up previous installation..."
systemctl stop irssh-panel >/dev/null 2>&1
supervisorctl stop irssh-panel >/dev/null 2>&1
rm -rf "$PANEL_DIR"
rm -rf "$LOG_DIR"

# Create directories
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

# Setup PostgreSQL
log "Setting up PostgreSQL..."
systemctl start postgresql
systemctl enable postgresql

# Drop and recreate database and user
sudo -u postgres psql <<EOF
DROP DATABASE IF EXISTS $DB_NAME;
DROP USER IF EXISTS $DB_USER;
CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';
CREATE DATABASE $DB_NAME OWNER $DB_USER;
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
EOF

# Setup Python environment
log "Setting up Python environment..."
python3 -m venv "$PANEL_DIR/venv"
source "$PANEL_DIR/venv/bin/activate"

# Install Python dependencies
log "Installing Python dependencies..."
pip install --upgrade pip
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
    python-dateutil \
    pydantic[email]

# Copy application files
log "Setting up application files..."

# Create core files
cat > "$APP_DIR/core/config.py" << EOL
from pydantic import BaseSettings, PostgresDsn
from typing import Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "IRSSH Panel"
    VERSION: str = "1.0.0"
    
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_USER: str = "$DB_USER"
    POSTGRES_PASSWORD: str = "$DB_PASS"
    POSTGRES_DB: str = "$DB_NAME"
    
    SQLALCHEMY_DATABASE_URI: Optional[PostgresDsn] = f"postgresql+asyncpg://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_SERVER}/{POSTGRES_DB}"
    
    SECRET_KEY: str = "$(openssl rand -hex 32)"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7

    class Config:
        case_sensitive = True

settings = Settings()
EOL

# Create database.py
cat > "$APP_DIR/core/database.py" << 'EOL'
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker
from app.core.config import settings

engine = create_async_engine(
    str(settings.SQLALCHEMY_DATABASE_URI),
    echo=True,
    future=True
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
EOL

# Copy models
cp user-model.py "$APP_DIR/models/user.py"

# Create admin script
cat > "$PANEL_DIR/create_admin.py" << 'EOL'
#!/usr/bin/env python3

import asyncio
import logging
from app.core.database import init_db, engine, async_session
from app.models.user import Base, User
from passlib.context import CryptContext

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def create_admin_user():
    try:
        # Initialize database and create tables
        logger.info("Creating database tables...")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        # Create admin user
        logger.info("Creating admin user...")
        async with async_session() as session:
            admin = User(
                username="admin",
                email="admin@localhost",
                hashed_password=pwd_context.hash("ADMIN_PASS"),
                is_active=True,
                is_admin=True
            )
            session.add(admin)
            await session.commit()
            logger.info("Admin user created successfully!")

    except Exception as e:
        logger.error(f"Error creating admin user: {str(e)}")
        raise

if __name__ == "__main__":
    asyncio.run(create_admin_user())
EOL

# Replace placeholder password in admin script
sed -i "s/ADMIN_PASS/$ADMIN_PASS/g" "$PANEL_DIR/create_admin.py"
chmod +x "$PANEL_DIR/create_admin.py"

# Create admin user
log "Creating admin user..."
source "$PANEL_DIR/venv/bin/activate"
python3 "$PANEL_DIR/create_admin.py"

# Configure supervisor
log "Setting up supervisor..."
cat > /etc/supervisor/conf.d/irssh-panel.conf << EOL
[program:irssh-panel]
directory=$PANEL_DIR
command=$PANEL_DIR/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
user=root
autostart=true
autorestart=true
stderr_logfile=$LOG_DIR/uvicorn.err.log
stdout_logfile=$LOG_DIR/uvicorn.out.log
environment=PYTHONPATH="$PANEL_DIR"
EOL

supervisorctl reread
supervisorctl update

# Configure Nginx
log "Setting up Nginx..."
cat > /etc/nginx/sites-available/irssh-panel << 'EOL'
server {
    listen 80;
    server_name _;
    
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOL

ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx

# Set permissions
log "Setting permissions..."
chown -R root:root "$PANEL_DIR"
chmod -R 755 "$PANEL_DIR"

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
echo "Web Interface: http://your-server-ip"
echo "API Documentation: http://your-server-ip/docs"
echo
echo "Installation logs: $LOG_DIR"
