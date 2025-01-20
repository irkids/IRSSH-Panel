#!/bin/bash

# IRSSH Panel Final Fix Script

# === Configuration ===
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
VENV_DIR="$PANEL_DIR/venv"
LOG_DIR="/var/log/irssh"

# === Colors ===
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
    exit 1
}

# === Check Root ===
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
fi

# === Get Domain and Port ===
read -p "Enter your domain (e.g., panel.example.com): " DOMAIN
if [[ -z "$DOMAIN" ]]; then
    error "Domain cannot be empty"
fi

read -p "Enter port for the panel (leave blank for random): " PANEL_PORT
if [[ -z "$PANEL_PORT" ]]; then
    PANEL_PORT=$((RANDOM % 9000 + 10000)) # Random 5-digit port
    log "No port provided. Using random port: $PANEL_PORT"
fi

# === Get Admin Credentials ===
read -p "Enter admin username: " ADMIN_USER
if [[ -z "$ADMIN_USER" ]]; then
    ADMIN_USER="admin"
    log "No username provided. Using default: admin"
fi

read -sp "Enter admin password: " ADMIN_PASS
if [[ -z "$ADMIN_PASS" ]]; then
    ADMIN_PASS="password"
    log "No password provided. Using default: password"
fi
echo

# === Install Dependencies ===
log "Installing system dependencies..."
apt-get update
apt-get install -y jq build-essential python3-dev python3-pip python3-venv \
    libpq-dev nginx supervisor curl certbot python3-certbot-nginx || error "Dependency installation failed"

# === Setup Backend ===
log "Setting up backend directories and files..."
mkdir -p "$BACKEND_DIR/app/"{core,api,models,schemas,utils}
mkdir -p "$BACKEND_DIR/app/api/v1/endpoints"
mkdir -p "$CONFIG_DIR" "$LOG_DIR"

cat > "$BACKEND_DIR/app/core/config.py" << EOL
from pydantic import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "IRSSH Panel"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "VPN Server Management Panel"
    ADMIN_USERNAME: str = "$ADMIN_USER"
    ADMIN_PASSWORD: str = "$ADMIN_PASS"
    DOMAIN: str = "$DOMAIN"
    PANEL_PORT: int = $PANEL_PORT

settings = Settings()
EOL

cat > "$BACKEND_DIR/app/api/router.py" << 'EOL'
from fastapi import APIRouter
from app.api.v1.endpoints import auth

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])

@api_router.get("/health")
async def health_check():
    return {"status": "healthy"}
EOL

cat > "$BACKEND_DIR/app/api/v1/endpoints/auth.py" << 'EOL'
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta
import jwt
from app.core.config import settings

router = APIRouter()

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username != settings.ADMIN_USERNAME or form_data.password != settings.ADMIN_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    access_token = create_access_token({"sub": form_data.username})
    return {"access_token": access_token, "token_type": "bearer"}
EOL

# === Setup Frontend ===
log "Setting up frontend..."
rm -rf "$FRONTEND_DIR"
mkdir -p "$FRONTEND_DIR"
npx create-react-app "$FRONTEND_DIR" --template typescript --use-npm
cd "$FRONTEND_DIR"
npm install @headlessui/react @heroicons/react axios react-router-dom tailwindcss
npx tailwindcss init -p

cat > "$FRONTEND_DIR/src/App.js" << 'EOL'
import React from 'react';

function Dashboard() {
    return <h1 className="text-3xl font-bold text-center mt-10">Welcome to IRSSH Panel</h1>;
}

function App() {
    return (
        <div className="min-h-screen bg-gray-100">
            <Dashboard />
        </div>
    );
}

export default App;
EOL

npm run build

# === Configure Nginx ===
log "Configuring Nginx..."
cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen $PANEL_PORT ssl;
    server_name $DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    root $FRONTEND_DIR/build;
    index index.html;

    location / {
        try_files \$uri /index.html;
    }

    location /api {
        proxy_pass http://localhost:8000/api;
    }

    client_max_body_size 100M;
}
EOL

ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
systemctl reload nginx

# === Configure Supervisor ===
log "Configuring Supervisor..."
cat > /etc/supervisor/conf.d/irssh-panel.conf << EOL
[program:irssh-panel]
directory=$BACKEND_DIR
command=$VENV_DIR/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
user=root
autostart=true
autorestart=true
stderr_logfile=$LOG_DIR/uvicorn.err.log
stdout_logfile=$LOG_DIR/uvicorn.out.log
environment=PYTHONPATH="$BACKEND_DIR"
EOL

supervisorctl reread
supervisorctl update
supervisorctl restart irssh-panel

# === Enable HTTPS with Certbot ===
log "Enabling HTTPS with Certbot..."
certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email your-email@example.com || error "Certbot failed to issue certificate"

# === Final Message ===
log "Installation completed successfully!"
echo "Access your panel at: https://$DOMAIN:$PANEL_PORT"
echo "API Endpoint: https://$DOMAIN:$PANEL_PORT/api"
