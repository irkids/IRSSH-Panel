#!/bin/bash

# IRSSH Panel Installation Script v2.2
# Updated with all required fixes

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration directories
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
LOG_DIR="/var/log/irssh"
VENV_DIR="$PANEL_DIR/venv"
BACKUP_DIR="/opt/irssh-backups"

# Default configuration
DEFAULT_HTTP_PORT=80
DEFAULT_HTTPS_PORT=443
DEFAULT_API_PORT=8000

# Generate random strings for security
generate_secure_key() {
    openssl rand -hex 32
}

JWT_SECRET=$(generate_secure_key)
ADMIN_TOKEN=$(generate_secure_key)

# Logging functions
setup_logging() {
    mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/install.log"
    exec 1> >(tee -a "$LOG_FILE")
    exec 2> >(tee -a "$LOG_FILE" >&2)
    chmod 644 "$LOG_FILE"
}

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

# Cleanup function
cleanup() {
    if [[ $? -ne 0 ]]; then
        error "Installation failed. Check $LOG_DIR/install.log for details" "no-exit"
        if [[ -d "$BACKUP_DIR" ]]; then
            warn "Attempting to restore from backup..."
            restore_backup
        fi
    fi
}

# Backup function
create_backup() {
    log "Creating backup..."
    mkdir -p "$BACKUP_DIR"
    if [[ -d "$PANEL_DIR" ]]; then
        tar -czf "$BACKUP_DIR/panel-$(date +%Y%m%d-%H%M%S).tar.gz" -C "$(dirname "$PANEL_DIR")" "$(basename "$PANEL_DIR")"
    fi
}

# Restore function
restore_backup() {
    local latest_backup=$(ls -t "$BACKUP_DIR"/*.tar.gz 2>/dev/null | head -1)
    if [[ -f "$latest_backup" ]]; then
        rm -rf "$PANEL_DIR"
        tar -xzf "$latest_backup" -C "$(dirname "$PANEL_DIR")"
        log "Backup restored from $latest_backup"
    else
        error "No backup found to restore" "no-exit"
    fi
}

# Check system requirements
check_requirements() {
    log "Checking system requirements..."
    
    # Check minimum system resources
    local mem_total=$(free -m | awk '/^Mem:/{print $2}')
    local disk_free=$(df -m / | awk 'NR==2 {print $4}')
    
    [[ $mem_total -lt 1024 ]] && error "Minimum 1GB RAM required"
    [[ $disk_free -lt 2048 ]] && error "Minimum 2GB free disk space required"
    
    # Check required commands
    local requirements=(curl wget git python3 pip3 nginx)
    for cmd in "${requirements[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            error "$cmd is required but not installed"
        fi
    done
}

# Install system packages
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
        ufw \
        fail2ban || error "Failed to install system packages"
}

# Setup Node.js using nvm
setup_node() {
    log "Setting up Node.js with nvm..."
    
    # Install nvm
    export NVM_DIR="$HOME/.nvm"
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
    
    # Load nvm
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
    
    # Install Node.js
    nvm install 18
    nvm use 18
    
    # Verify installation
    if ! command -v node &> /dev/null; then
        error "Node.js installation failed"
    fi
}

# Setup Python environment
setup_python_env() {
    log "Setting up Python environment..."
    
    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"
    
    pip install --upgrade pip

    # Install Python packages
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

# Configure PostgreSQL
setup_database() {
    log "Setting up PostgreSQL..."
    
    systemctl start postgresql
    systemctl enable postgresql
    
    local DB_NAME="irssh"
    local DB_USER="irssh_admin"
    local DB_PASS=$(generate_secure_key)
    
    # Create database user
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';" || \
    sudo -u postgres psql -c "ALTER USER $DB_USER WITH PASSWORD '$DB_PASS';"
    
    # Create database
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;" || \
    sudo -u postgres psql -c "ALTER DATABASE $DB_NAME OWNER TO $DB_USER;"
    
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

# Setup backend structure
setup_backend() {
    log "Setting up backend structure..."
    
    # Create clean backend directory
    rm -rf "$BACKEND_DIR"
    mkdir -p "$BACKEND_DIR"
    
    # Set up Python package structure
    cd "$BACKEND_DIR"
    mkdir -p app/{core,api,models,schemas,utils}
    mkdir -p app/api/v1/endpoints
    
    # Create __init__.py files
    touch app/__init__.py
    touch app/core/__init__.py
    touch app/api/__init__.py
    touch app/models/__init__.py
    
    # Create main.py
    cat > app/main.py << 'EOL'
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "IRSSH Panel API"}

@app.get("/api/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/api/test")
async def test():
    return {"message": "API is working correctly"}
EOL

    # Set permissions
    chown -R root:root "$BACKEND_DIR"
    chmod -R 755 "$BACKEND_DIR"
}

# Setup frontend
setup_frontend() {
    log "Setting up frontend..."
    
    # Clean frontend directory
    rm -rf "$FRONTEND_DIR"
    
    # Create React app
    cd "$PANEL_DIR"
    npx create-react-app frontend --template typescript
    cd "$FRONTEND_DIR"
    
    # Install dependencies
    npm install \
        @headlessui/react \
        @heroicons/react \
        axios \
        react-router-dom
    
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

    # Create App.js
    cat > src/App.js << 'EOL'
import React from 'react';

function App() {
  return (
    <div>
      <h1>IRSSH Panel</h1>
    </div>
  );
}

export default App;
EOL

    # Create index.js
    cat > src/index.js << 'EOL'
import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';

const container = document.getElementById('root');
const root = createRoot(container);
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
EOL

    # Build frontend
    npm run build
    
    # Set permissions
    chown -R root:root "$FRONTEND_DIR"
    chmod -R 755 "$FRONTEND_DIR/build"
}

# Configure Nginx
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
        add_header Cache-Control "no-cache";
    }
    
    location /api {
        proxy_pass http://localhost:$DEFAULT_API_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # CORS headers
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' '*' always;
    }
}
EOL

    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
    
    nginx -t || error "Nginx configuration test failed"
}

# Configure Supervisor
setup_supervisor() {
    log "Configuring Supervisor..."
    
    cat > /etc/supervisor/conf.d/irssh-panel.conf << EOL
[program:irssh-panel]
directory=$BACKEND_DIR
command=$VENV_DIR/bin/uvicorn app.main:app --host 0.0.0.0 --port $DEFAULT_API_PORT --reload
user=root
autostart=true
autorestart=true
stdout_logfile=$LOG_DIR/uvicorn.out.log
stderr_logfile=$LOG_DIR/uvicorn.err.log
environment=
    PYTHONPATH="$BACKEND_DIR",
    DB_NAME="irssh",
    DB_USER="irssh_admin",
    DB_PASS="$(grep DB_PASS $CONFIG_DIR/database.env | cut -d= -f2)",
    DB_HOST="localhost"
EOL

    supervisorctl reread
    supervisorctl update
}

# Configure firewall rules (without enabling)
setup_firewall() {
    log "Setting up firewall rules..."
    
    ufw allow ssh
    ufw allow http
    ufw allow https
    ufw allow $DEFAULT_API_PORT
}

# Main installation function
main() {
    trap cleanup EXIT
    
    setup_logging
    log "Starting IRSSH Panel installation..."
    
    check_requirements
    create_backup
    install_system_packages
    setup_node
    setup_python_env
    setup_database
    setup_backend
    setup_frontend
    setup_nginx
    setup_supervisor
    setup_firewall
    
    # Restart services
    systemctl restart nginx
    supervisorctl restart irssh-panel
    
    # Test installation
    log "Testing installation..."
    sleep 5
    
    response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:$DEFAULT_API_PORT/api/health)
    if [ "$response" = "200" ]; then
        log "API is responding correctly"
    else
        warn "API is not responding correctly (HTTP $response)"
    fi
    
    log "Installation completed successfully!"
    echo
    echo "IRSSH Panel has been installed!"
    echo
    echo "Panel URL: http://YOUR-IP"
    echo "API URL: http://YOUR-IP/api"
}

# Start installation
main "$@"
