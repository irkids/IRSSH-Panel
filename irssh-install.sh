#!/bin/bash

# IRSSH Panel Complete Fix Script

# === Configuration ===
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
LOG_DIR="/var/log/irssh"
VENV_DIR="$PANEL_DIR/venv"
DOMAIN="panel.example.com"  # Update with a valid domain for production

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

# === Check Root Permissions ===
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
fi

# === Install Dependencies ===
log "Installing system dependencies..."
apt-get update
apt-get install -y jq build-essential python3-dev python3-pip python3-venv \
    libpq-dev nginx supervisor curl certbot python3-certbot-nginx

# === Fix Node.js and NPM ===
log "Installing Node.js and cleaning NPM conflicts..."
apt-get remove --purge -y nodejs npm || true
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt-get install -y nodejs

# === Setup Project Directories ===
log "Setting up project directories..."
mkdir -p "$BACKEND_DIR/app/"{core,api,models,schemas,utils}
mkdir -p "$BACKEND_DIR/app/api/v1/endpoints"
mkdir -p "$CONFIG_DIR" "$LOG_DIR"
mkdir -p "$FRONTEND_DIR/src"

# Create necessary __init__.py files
for dir in $(find "$BACKEND_DIR/app" -type d); do
    touch "$dir/__init__.py"
done

# === Virtual Environment Setup ===
log "Setting up Python virtual environment..."
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install fastapi[all] uvicorn[standard] sqlalchemy[asyncio] psycopg2-binary \
    python-jose[cryptography] passlib[bcrypt] python-multipart aiofiles aiohttp

# === Create Backend Files ===
log "Creating backend files..."
cat > "$BACKEND_DIR/app/main.py" << 'EOL'
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.router import api_router

app = FastAPI(title="IRSSH Panel", version="1.0.0", description="VPN Server Management Panel")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

app.include_router(api_router, prefix="/api")

@app.get("/api/health")
async def health_check():
    return {"status": "healthy"}
EOL

cat > "$BACKEND_DIR/app/api/router.py" << 'EOL'
from fastapi import APIRouter

api_router = APIRouter()

@api_router.get("/health")
async def health_check():
    return {"status": "healthy"}
EOL

cat > "$BACKEND_DIR/app/core/config.py" << 'EOL'
from pydantic import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "IRSSH Panel"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "VPN Server Management Panel"
    DB_USER: str = "irssh_admin"
    DB_PASS: str = "YourSecurePassword"
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    DB_NAME: str = "irssh_panel"

settings = Settings()
EOL

# === Configure Nginx ===
log "Configuring Nginx..."
cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    server_name $DOMAIN;

    root $FRONTEND_DIR/build;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location /api {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
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

# === Build Frontend ===
log "Setting up and building the frontend..."
rm -rf "$FRONTEND_DIR/*"
npx create-react-app "$FRONTEND_DIR" --template typescript
cd "$FRONTEND_DIR"
npm install @headlessui/react @heroicons/react axios react-router-dom tailwindcss
npx tailwindcss init -p
npm run build

# === Final Verification ===
log "Verifying installation..."
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/api/health || echo "000")
if [[ "$response" == "200" ]]; then
    log "IRSSH Panel is running successfully!"
    echo "Visit: http://$DOMAIN"
else
    error "API is not responding correctly. Check logs at $LOG_DIR"
fi
