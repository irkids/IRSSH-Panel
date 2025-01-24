#!/bin/bash

# تنظیمات رنگ‌ها برای خروجی
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# تنظیمات مسیرها
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
LOG_DIR="/var/log/irssh"
VENV_DIR="$PANEL_DIR/venv"

# تنظیمات پیش‌فرض پورت‌ها
DEFAULT_HTTP_PORT=80
DEFAULT_HTTPS_PORT=443
DEFAULT_API_PORT=8000

# تابع تولید کلید تصادفی
generate_secure_key() {
    openssl rand -hex 32
}

JWT_SECRET=$(generate_secure_key)

# تنظیم لاگ‌ها
setup_logging() {
    mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/install.log"
    exec 1> >(tee -a "$LOG_FILE")
    exec 2> >(tee -a "$LOG_FILE" >&2)
    chmod 644 "$LOG_FILE"
}

# توابع لاگ
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" >&2
    [[ "${2:-}" != "no-exit" ]] && cleanup && exit 1
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# تابع پاکسازی
cleanup() {
    log "Cleaning up failed installation..."
    systemctl stop nginx 2>/dev/null || true
    systemctl stop postgresql 2>/dev/null || true
    supervisorctl stop irssh-panel 2>/dev/null || true
    
    if [[ -d "$PANEL_DIR" ]]; then
        rm -rf "$PANEL_DIR"
    fi
    
    if [[ -f "/etc/nginx/sites-enabled/irssh-panel" ]]; then
        rm -f "/etc/nginx/sites-enabled/irssh-panel"
    fi
    
    if [[ -f "/etc/supervisor/conf.d/irssh-panel.conf" ]]; then
        rm -f "/etc/supervisor/conf.d/irssh-panel.conf"
    fi
}

# بررسی نیازمندی‌ها
check_requirements() {
    log "Checking system requirements..."
    local mem_total=$(free -m | awk '/^Mem:/{print $2}')
    local disk_free=$(df -m / | awk 'NR==2 {print $4}')
    
    [[ $mem_total -lt 1024 ]] && error "Minimum 1GB RAM required"
    [[ $disk_free -lt 2048 ]] && error "Minimum 2GB free disk space required"
    
    local requirements=(curl wget git python3 pip3)
    for cmd in "${requirements[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            error "$cmd is required but not installed"
        fi
    done
}

# نصب پکیج‌های سیستمی
install_system_packages() {
    log "Installing system packages..."
    apt-get update || error "Failed to update package lists"
    
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        postgresql \
        postgresql-contrib \
        nginx \
        supervisor \
        curl \
        git \
        certbot \
        python3-certbot-nginx \
        net-tools || error "Failed to install system packages"
}

# تنظیم Node.js
setup_node() {
    log "Setting up Node.js..."
    
    export NVM_DIR="$HOME/.nvm"
    if [[ ! -d "$NVM_DIR" ]]; then
        curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
        [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
    fi
    
    nvm install 18
    nvm use 18
    
    if ! command -v node &> /dev/null; then
        error "Node.js installation failed"
    fi
}

# تنظیم محیط Python
setup_python_env() {
    log "Setting up Python environment..."
    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"
    
    pip install --upgrade pip wheel setuptools

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
        bcrypt \
        pydantic \
        requests \
        aiohttp \
        psutil || error "Failed to install Python packages"
}

# تنظیم PostgreSQL
setup_database() {
    log "Setting up PostgreSQL..."
    
    systemctl start postgresql
    systemctl enable postgresql
    sleep 5
    
    local DB_NAME="irssh"
    local DB_USER="irssh_admin"
    local DB_PASS=$(generate_secure_key)
    
    # تغییر authentication در pg_hba.conf
    cp /etc/postgresql/*/main/pg_hba.conf /etc/postgresql/*/main/pg_hba.conf.bak
    cat > /etc/postgresql/*/main/pg_hba.conf << EOL
local   all             postgres                                trust
local   all             all                                     md5
host    all             all             127.0.0.1/32            md5
host    all             all             ::1/128                 md5
EOL
    
    systemctl restart postgresql
    sleep 3

    # ایجاد کاربر و دیتابیس
    su - postgres -c "psql -c \"DROP DATABASE IF EXISTS $DB_NAME;\"" || true
    su - postgres -c "psql -c \"DROP USER IF EXISTS $DB_USER;\"" || true
    su - postgres -c "psql -c \"CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';\"" || true
    su - postgres -c "psql -c \"CREATE DATABASE $DB_NAME OWNER $DB_USER;\"" || true
    su - postgres -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;\"" || true

    # ذخیره تنظیمات
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_DIR/database.env" << EOL
DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASS=$DB_PASS
EOL
    chmod 600 "$CONFIG_DIR/database.env"
}

# تنظیم بخش فرانت‌اند
setup_frontend() {
    log "Setting up frontend..."
    
    rm -rf "$FRONTEND_DIR"
    mkdir -p "$FRONTEND_DIR"
    cd "$FRONTEND_DIR"

    # Create basic React app structure
    mkdir -p src public
    
    # Create package.json
    cat > package.json << 'EOL'
{
  "name": "irssh-frontend",
  "version": "0.1.0",
  "private": true,
  "dependencies": {
    "@mantine/core": "^7.0.0",
    "@mantine/hooks": "^7.0.0",
    "axios": "^1.6.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.20.0",
    "react-scripts": "5.0.1"
  },
  "scripts": {
    "start": "react-scripts start",
    "build": "react-scripts build"
  },
  "browserslist": {
    "production": [">0.2%", "not dead", "not op_mini all"],
    "development": ["last 1 chrome version", "last 1 firefox version", "last 1 safari version"]
  }
}
EOL

    # Create index.html
    cat > public/index.html << 'EOL'
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>IRSSH Panel</title>
  </head>
  <body>
    <div id="root"></div>
  </body>
</html>
EOL

    # Create index.js
    cat > src/index.js << 'EOL'
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
EOL

    # Create App.js
    cat > src/App.js << 'EOL'
import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';

const App = () => {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<div>Login Page</div>} />
        <Route path="/" element={<Navigate to="/login" />} />
      </Routes>
    </Router>
  );
};

export default App;
EOL

    # Install dependencies and build
    export NVM_DIR="$HOME/.nvm"
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
    nvm use 18
    
    npm install
    npm run build
}

# تنظیم Nginx
setup_nginx() {
    log "Configuring Nginx..."
    
    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen 80;
    server_name _;
    
    root $FRONTEND_DIR/build;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
        autoindex off;
    }
    
    location /api {
        proxy_pass http://localhost:$DEFAULT_API_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_cache_bypass \$http_upgrade;
        
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' '*' always;
        
        if (\$request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' '*';
            add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS';
            add_header 'Access-Control-Allow-Headers' '*';
            add_header 'Access-Control-Max-Age' 1728000;
            add_header 'Content-Type' 'text/plain charset=UTF-8';
            add_header 'Content-Length' 0;
            return 204;
        }
    }
}
EOL

    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
    
    nginx -t || error "Nginx configuration test failed"
}

# تنظیم Supervisor
setup_supervisor() {
    log "Configuring Supervisor..."
    
    mkdir -p /var/log/irssh
    
    cat > /etc/supervisor/conf.d/irssh-panel.conf << EOL
[program:irssh-panel]
directory=$BACKEND_DIR
command=$VENV_DIR/bin/uvicorn app.main:app --host 0.0.0.0 --port $DEFAULT_API_PORT --reload
user=root
autostart=true
autorestart=true
stderr_logfile=/var/log/irssh/uvicorn.err.log
stdout_logfile=/var/log/irssh/uvicorn.out.log
environment=
    PYTHONPATH="$BACKEND_DIR",
    DB_HOST="localhost",
    DB_PORT="5432",
    DB_NAME="irssh",
    DB_USER="irssh_admin",
    DB_PASS="$(grep DB_PASS $CONFIG_DIR/database.env | cut -d= -f2)"
EOL

    supervisorctl reread
    supervisorctl update
}

# تنظیم فایروال
setup_firewall() {
    log "Setting up firewall rules..."
    
    apt-get install -y ufw || error "Failed to install UFW"
    
    ufw allow ssh
    ufw allow http
    ufw allow https
    ufw allow $DEFAULT_API_PORT/tcp
    
    ufw --force enable
}

# تابع اصلی نصب
main() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi

    setup_logging
    log "Starting IRSSH Panel installation..."
    
    check_requirements
    install_system_packages
    setup_node
    setup_python_env
    setup_database
    setup_frontend
    setup_nginx
    setup_supervisor
    setup_firewall
    
    systemctl restart nginx
    supervisorctl restart irssh-panel
    
    log "Installation completed successfully!"
    echo "Panel URL: http://YOUR-IP"
    echo "API URL: http://YOUR-IP/api"
    echo "Installation log: $LOG_FILE"
}

# شروع نصب
main "$@"
