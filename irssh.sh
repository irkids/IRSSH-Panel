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

# Create FastAPI app structure
log "Creating application structure..."

# Create __init__.py files
touch "$APP_DIR/__init__.py"
touch "$APP_DIR/api/__init__.py"
touch "$APP_DIR/api/v1/__init__.py"
touch "$APP_DIR/api/v1/endpoints/__init__.py"
touch "$APP_DIR/core/__init__.py"
touch "$APP_DIR/models/__init__.py"
touch "$APP_DIR/schemas/__init__.py"
touch "$APP_DIR/utils/__init__.py"

# Create main.py
cat > "$APP_DIR/main.py" << 'EOL'
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.v1.api import api_router
from app.core.database import init_db

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

app.include_router(api_router, prefix="/api/v1")

@app.on_event("startup")
async def startup_event():
    await init_db()
EOL

# Create database.py
cat > "$APP_DIR/core/database.py" << 'EOL'
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from app.core.config import settings

engine = create_async_engine(settings.DATABASE_URL, echo=True)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

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

# Create config.py
cat > "$APP_DIR/core/config.py" << EOL
from pydantic import BaseSettings
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

    class Config:
        case_sensitive = True

settings = Settings()
EOL

# Create models/user.py
cat > "$APP_DIR/models/user.py" << 'EOL'
from sqlalchemy import Boolean, Column, Integer, String
from app.core.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
EOL

# Create schemas/user.py
cat > "$APP_DIR/schemas/user.py" << 'EOL'
from pydantic import BaseModel

class UserBase(BaseModel):
    username: str
    email: str | None = None
    is_active: bool = True
    is_admin: bool = False

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int

    class Config:
        orm_mode = True
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
    supervisor

# Setup PostgreSQL
log "Setting up PostgreSQL..."
systemctl start postgresql
systemctl enable postgresql

# Create database and user
sudo -u postgres psql <<EOF
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
    aiofiles

# Create admin user script
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
command=$PANEL_DIR/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
user=root
autostart=true
autorestart=true
stderr_logfile=$LOG_DIR/uvicorn.err.log
stdout_logfile=$LOG_DIR/uvicorn.out.log
environment=PYTHONPATH="$PANEL_DIR"
EOL

# Configure Nginx
log "Configuring Nginx..."
cat > /etc/nginx/sites-available/irssh-panel << 'EOL'
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
EOL

ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Create admin user
log "Creating admin user..."
source "$PANEL_DIR/venv/bin/activate"
python3 "$PANEL_DIR/create_admin.py"

# Start services
log "Starting services..."
systemctl daemon-reload
systemctl enable --now nginx
supervisorctl reread
supervisorctl update
supervisorctl restart irssh-panel

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
echo "Panel URL: http://your-server-ip"
echo "API URL: http://your-server-ip/api/v1"
echo
echo "Please change the admin password after first login."
EOL
