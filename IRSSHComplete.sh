#!/bin/bash

# تنظیمات اصلی
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
LOG_DIR="/var/log/irssh"
VENV_DIR="$PANEL_DIR/venv"
DEFAULT_HTTP_PORT=80
DEFAULT_HTTPS_PORT=443
DEFAULT_API_PORT=8000

# رنگها
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# توابع پایه
log() { echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"; }
error() { echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" >&2; exit 1; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
generate_secure_key() { openssl rand -hex 32; }

# پیش‌نیازها
check_requirements() {
    log "Checking requirements..."
    local requirements=(curl wget git python3 pip3)
    for cmd in "${requirements[@]}"; do
        command -v "$cmd" >/dev/null 2>&1 || error "$cmd is required"
    done
}

# نصب پکیج‌ها
install_system_packages() {
    log "Installing system packages..."
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3 python3-pip python3-venv postgresql postgresql-contrib nginx \
        supervisor curl git certbot python3-certbot-nginx net-tools || error "Package installation failed"
}

# تنظیم Node.js
setup_node() {
    log "Setting up Node.js..."
    export NVM_DIR="$HOME/.nvm"
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
    nvm install 18 && nvm use 18
    command -v node >/dev/null 2>&1 || error "Node.js installation failed"
}

# تنظیم محیط Python
setup_python_env() {
    log "Setting up Python environment..."
    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"
    pip install --upgrade pip
    pip install fastapi[all] uvicorn[standard] sqlalchemy[asyncio] \
        psycopg2-binary python-jose[cryptography] passlib[bcrypt] \
        python-multipart aiofiles python-dotenv pydantic-settings \
        asyncpg bcrypt pydantic requests aiohttp psutil
}

# تنظیم دیتابیس
setup_database() {
    log "Setting up database..."
    DB_NAME="irssh"
    DB_USER="irssh_admin"
    DB_PASS=$(generate_secure_key)
    
    systemctl start postgresql
    systemctl enable postgresql
    sleep 3
    
    su - postgres -c "psql -c \"DROP DATABASE IF EXISTS $DB_NAME WITH (FORCE);\""
    su - postgres -c "psql -c \"DROP USER IF EXISTS $DB_USER;\""
    su - postgres -c "psql -c \"CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';\""
    su - postgres -c "psql -c \"CREATE DATABASE $DB_NAME OWNER $DB_USER;\""
    su - postgres -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;\""
    
    mkdir -p "$CONFIG_DIR"
    echo "DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASS=$DB_PASS" > "$CONFIG_DIR/database.env"
    chmod 600 "$CONFIG_DIR/database.env"
}

# تنظیم frontend
setup_frontend() {
    log "Setting up frontend..."
    rm -rf "$FRONTEND_DIR"
    mkdir -p "$FRONTEND_DIR"
    cd "$FRONTEND_DIR"

    # تنظیم package.json
    echo '{
        "name": "irssh-frontend",
        "version": "0.1.0",
        "private": true,
        "dependencies": {
            "react": "^18.2.0",
            "react-dom": "^18.2.0",
            "react-router-dom": "^6.20.0",
            "axios": "^1.6.0"
        }
    }' > package.json

    # ساخت فایل‌های اصلی
    mkdir -p src public
    echo '<!DOCTYPE html>
<html>
<head>
    <title>IRSSH Panel</title>
</head>
<body>
    <div id="root"></div>
</body>
</html>' > public/index.html

    echo 'import React from "react";
import ReactDOM from "react-dom";
ReactDOM.render(<div>IRSSH Panel</div>, document.getElementById("root"));' > src/index.js

    npm install
}

# تنظیم Nginx
setup_nginx() {
    log "Setting up Nginx..."
    
    echo "server {
    listen 80 default_server;
    server_name _;
    
    root $FRONTEND_DIR;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ /index.html;
        autoindex on;
    }
    
    location /api {
        proxy_pass http://localhost:$DEFAULT_API_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}" > /etc/nginx/sites-available/irssh-panel

    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
    nginx -t || error "Nginx config test failed"
}

# تنظیم Supervisor
setup_supervisor() {
    log "Setting up Supervisor..."
    mkdir -p /var/log/irssh
    chmod 755 /var/log/irssh
    
    echo "[program:irssh-panel]
directory=$BACKEND_DIR
command=$VENV_DIR/bin/uvicorn app.main:app --host 0.0.0.0 --port $DEFAULT_API_PORT
user=root
autostart=true
autorestart=true
stdout_logfile=/var/log/irssh/uvicorn.out.log
stderr_logfile=/var/log/irssh/uvicorn.err.log
environment=PYTHONPATH=\"$BACKEND_DIR\",DB_HOST=\"localhost\",DB_PORT=\"5432\",DB_NAME=\"irssh\",DB_USER=\"irssh_admin\",DB_PASS=\"$(grep DB_PASS $CONFIG_DIR/database.env | cut -d= -f2)\"" > /etc/supervisor/conf.d/irssh-panel.conf

    supervisorctl reread
    supervisorctl update
}

# تابع اصلی
main() {
    [[ $EUID -ne 0 ]] && error "This script must be run as root"
    
    log "Starting IRSSH Panel installation..."
    
    check_requirements
    install_system_packages
    setup_node
    setup_python_env
    setup_database
    setup_frontend
    setup_nginx
    setup_supervisor
    
    systemctl restart nginx
    supervisorctl restart irssh-panel
    
    log "Installation completed successfully!"
    echo "Panel URL: http://YOUR-IP"
    echo "API URL: http://YOUR-IP/api"
}

main "$@"
