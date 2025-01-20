#!/bin/bash

# IRSSH Panel Installation Fix Script 2

# Configuration
PANEL_DIR="/opt/irssh-panel"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
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
    exit 1
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
fi

# Fix directory structure
log "Fixing directory structure..."
mkdir -p "$BACKEND_DIR/app/"{core,api,models,schemas,utils}
mkdir -p "$BACKEND_DIR/app/api/v1/endpoints"

# Create necessary __init__.py files
log "Creating Python package files..."
for dir in $(find "$BACKEND_DIR/app" -type d); do
    touch "$dir/__init__.py"
done

# Create main FastAPI application file
log "Creating main application file..."
cat > "$BACKEND_DIR/app/main.py" << 'EOL'
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os

from app.core.config import settings
from app.api.router import api_router

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=settings.DESCRIPTION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(api_router, prefix="/api")

@app.get("/api/health")
async def health_check():
    return {"status": "healthy"}
EOL

# Fix supervisor configuration
log "Fixing supervisor configuration..."
cat > /etc/supervisor/conf.d/irssh-panel.conf << EOL
[program:irssh-panel]
directory=$BACKEND_DIR
command=$PANEL_DIR/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
user=root
autostart=true
autorestart=true
stderr_logfile=$LOG_DIR/uvicorn.err.log
stdout_logfile=$LOG_DIR/uvicorn.out.log
environment=
    PATH="$PANEL_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    PYTHONPATH="$BACKEND_DIR"
EOL

# Fix environment settings
log "Fixing environment settings..."
cat > "$CONFIG_DIR/settings.env" << EOL
PROJECT_NAME=IRSSH Panel
VERSION=1.0.0
DESCRIPTION=Advanced VPN Server Management Panel
API_V1_STR=/api/v1
ALLOWED_ORIGINS=["http://localhost:3000", "http://localhost:8000"]
DB_HOST=localhost
DB_PORT=5432
DB_NAME=irssh_panel
DB_USER=irssh_admin
EOL

# Read database password from existing config
DB_PASS=$(grep DB_PASS "$CONFIG_DIR/database.env" | cut -d'=' -f2)
echo "DB_PASS=$DB_PASS" >> "$CONFIG_DIR/settings.env"

# Install/Update Python dependencies
log "Installing/Updating Python dependencies..."
source "$PANEL_DIR/venv/bin/activate"
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
    python-dotenv \
    pydantic-settings \
    asyncpg \
    psutil \
    aiohttp

# Create models
log "Creating database models..."
cat > "$BACKEND_DIR/app/models/models.py" << 'EOL'
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, JSON, Enum, BigInteger
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

from app.core.database import Base

class UserStatus(str, enum.Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    EXPIRED = "expired"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    email = Column(String, unique=True, index=True, nullable=True)
    status = Column(Enum(UserStatus), default=UserStatus.ACTIVE)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
EOL

# Create database initialization script
log "Creating database initialization script..."
cat > "$BACKEND_DIR/app/core/database.py" << 'EOL'
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
import os
from app.core.config import settings

SQLALCHEMY_DATABASE_URL = f"postgresql+asyncpg://{settings.DB_USER}:{settings.DB_PASS}@{settings.DB_HOST}:{settings.DB_PORT}/{settings.DB_NAME}"

engine = create_async_engine(SQLALCHEMY_DATABASE_URL, echo=True)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

Base = declarative_base()

async def get_db():
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
EOL

# Fix file permissions
log "Fixing file permissions..."
chown -R root:root "$PANEL_DIR"
chmod -R 755 "$PANEL_DIR"
chmod -R 600 "$CONFIG_DIR"/*

# Restart services
log "Restarting services..."
supervisorctl update
supervisorctl restart irssh-panel

# Verify installation
log "Verifying installation..."
sleep 5  # Wait for service to start

response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/api/health || echo "000")

if [ "$response" = "200" ]; then
    log "Installation fixed successfully!"
    echo
    echo "API is now running and responding correctly"
    echo "You can access the API documentation at: http://localhost:8000/api/docs"
else
    error "API is not responding correctly (HTTP $response)"
fi
