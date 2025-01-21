#!/bin/bash

# IRSSH Panel Installation Script v2.0
# Comprehensive installation with error handling and security features

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
 log_partition=$(df -P "$LOG_DIR" | awk 'NR==2 {print $4}')
    if [ "$log_partition" -lt 1048576 ]; then  # 1GB in KB
        warn "Less than 1GB free space available for logs"
    fi
    LOG_FILE="$LOG_DIR/install.log"
    exec 1> >(tee -a "$LOG_FILE")
    exec 2> >(tee -a "$LOG_FILE" >&2)
    chmod 640 "$LOG_FILE"
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
    
    # Check if pip3 is installed, if not install it
    if ! command -v pip3 &>/dev/null; then
        log "Installing pip3..."
        apt-get update
        apt-get install -y python3-pip
    fi
    
    # Check OS
    if [[ ! -f /etc/os-release ]]; then
        error "Unsupported operating system"
    fi
    
    # Check minimum system resources
    local mem_total=$(free -m | awk '/^Mem:/{print $2}')
    local disk_free=$(df -m / | awk 'NR==2 {print $4}')
    
    [[ $mem_total -lt 1024 ]] && error "Minimum 1GB RAM required"
    [[ $disk_free -lt 2048 ]] && error "Minimum 2GB free disk space required"
    
    # Check required commands
    local requirements=(curl wget git python3 pip3 node nginx)
    for cmd in "${requirements[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            error "$cmd is required but not installed"
            
    done
}

# Install system packages
install_system_packages() {
    # Add these lines at beginning
    apt-get update
    apt-get install -y software-properties-common
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -

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

# Setup Python environment
setup_python_env() {
    log "Setting up Python environment..."
    
    python3 -m venv "$VENV_DIR" || error "Failed to create virtual environment"
    source "$VENV_DIR/bin/activate"
    
    pip install --upgrade pip || error "Failed to upgrade pip"
    
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
        python-jose[cryptography] \
        bcrypt \
        pydantic \      # Added
        requests \     # Added
        aiohttp \        # Added
        psutil \          # Added
        python-multipart || error "Failed to install Python packages"
}

# Configure PostgreSQL
setup_database() {
    log "Setting up PostgreSQL..."
    
    systemctl start postgresql
    systemctl enable postgresql
    
    local DB_NAME="irssh"
    local DB_USER="irssh_admin"
    local DB_PASS=$(generate_secure_key)
    
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';" || error "Failed to create database user"
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;" || error "Failed to create database"
    
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

# Configure Nginx
setup_nginx() {
    log "Configuring Nginx..."
    
    # Generate strong DH parameters
    openssl dhparam -out /etc/nginx/dhparam.pem 2048
    
    # Create Nginx configuration
    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen 80;
    listen [::]:80;
    server_name _;

    root $FRONTEND_DIR/build;
    index index.html;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Logging
    access_log $LOG_DIR/nginx-access.log combined buffer=512k flush=1m;
    error_log $LOG_DIR/nginx-error.log warn;

    # Frontend
    location / {
        try_files \$uri \$uri/ /index.html;
        expires 1h;
        add_header Cache-Control "public, no-transform";
    }

    # API endpoints
    location /api {
        proxy_pass http://127.0.0.1:$DEFAULT_API_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # CORS
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;
        add_header 'Access-Control-Expose-Headers' 'Content-Length,Content-Range' always;

        # Preflighted requests
        if (\$request_method = 'OPTIONS') {
            add_header 'Access-Control-Max-Age' 1728000;
            add_header 'Content-Type' 'text/plain; charset=utf-8';
            add_header 'Content-Length' 0;
            return 204;
        }
    }

    # WebSocket support
    location /ws {
        proxy_pass http://127.0.0.1:$DEFAULT_API_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }

    # Deny access to sensitive files
    location ~ /\. {
        deny all;
    }
    
    location ~ /(config|log)/ {
        deny all;
    }

    # Optimize file serving
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|svg|woff|woff2|ttf|eot)$ {
        expires 7d;
        add_header Cache-Control "public, no-transform";
    }

    # Large file uploads
    client_max_body_size 100M;
    client_body_timeout 300s;
    
    # Timeouts
    keepalive_timeout 65;
    send_timeout 30;
}
EOL

    # Enable site and remove default
    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/

    # Test configuration
    nginx -t || error "Nginx configuration test failed"
}

# Configure Supervisor
setup_supervisor() {
    log "Configuring Supervisor..."
    
    cat > /etc/supervisor/conf.d/irssh-panel.conf << EOL
[program:irssh-panel]
directory=$BACKEND_DIR
command=$VENV_DIR/bin/uvicorn app.main:app --host 0.0.0.0 --port $DEFAULT_API_PORT --workers 4
user=root
autostart=true
autorestart=true
startsecs=10
startretries=3
stopwaitsecs=10
stopasgroup=true
killasgroup=true
stdout_logfile=$LOG_DIR/uvicorn.out.log
stderr_logfile=$LOG_DIR/uvicorn.err.log
stdout_logfile_maxbytes=10MB
stderr_logfile_maxbytes=10MB
stdout_logfile_backups=5
stderr_logfile_backups=5
environment=PYTHONPATH="$BACKEND_DIR",JWT_SECRET="$JWT_SECRET"
EOL

    supervisorctl reread
    supervisorctl update
}

# Configure Firewall
setup_firewall() {
    log "Configuring firewall..."
    
    ufw default deny incoming
    ufw default allow outgoing
    
    ufw allow ssh
    ufw allow http
    ufw allow https
    ufw allow $DEFAULT_API_PORT
    
    # Enable firewall
    echo "y" | ufw enable
}

# Setup log rotation
setup_logrotate() {
    log "Configuring log rotation..."
    
    cat > /etc/logrotate.d/irssh-panel << EOL
$LOG_DIR/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        supervisorctl restart irssh-panel >/dev/null 2>&1 || true
        nginx -s reopen >/dev/null 2>&1 || true
    endscript
}
EOL
}

# Create admin user
create_admin_user() {
    log "Creating admin user..."
    
    read -p "Enter admin username (default: admin): " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-admin}
    
    read -s -p "Enter admin password (default: random): " ADMIN_PASS
    echo
    if [[ -z "$ADMIN_PASS" ]]; then
        ADMIN_PASS=$(openssl rand -base64 12)
        echo "Generated admin password: $ADMIN_PASS"
    fi
    
    source "$VENV_DIR/bin/activate"
    python3 -c "
from app.core.security import get_password_hash
from app.models.user import User
from app.core.database import SessionLocal, Base, engine
import logging

logging.basicConfig(filename='$LOG_DIR/admin_creation.log', level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    admin = User(
        username='$ADMIN_USER',
        hashed_password=get_password_hash('$ADMIN_PASS'),
        is_admin=True,
        is_active=True
    )
    db.add(admin)
    db.commit()
    logger.info('Admin user created successfully')
except Exception as e:
    logger.error(f'Error creating admin user: {str(e)}')
    raise
finally:
    db.close()
"
}

# Main installation function
main() {
    trap cleanup EXIT
    
    setup_logging
    
    log "Starting IRSSH Panel installation..."
    
    check_requirements
    create_backup
    install_system_packages
    setup_python_env
    setup_database
    setup_nginx
    setup_supervisor
    setup_firewall
    setup_logrotate
    create_admin_user
    
    # Restart services
    systemctl restart nginx
    supervisorctl restart irssh-panel
    
 # Add before final echo statements
    test_service() {
    log "Testing service..."
    sleep 5  # Wait for services to start
    
    # Test API
    response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:$DEFAULT_API_PORT/api/health)
    if [ "$response" = "200" ]; then
        log "API is responding correctly"
    else
        warn "API is not responding correctly (HTTP $response)"
    fi
    
    # Test Nginx
    response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost)
    if [ "$response" = "200" ]; then
        log "Web server is responding correctly"
    else
        warn "Web server is not responding correctly (HTTP $response)"
    fi
}

    test_service

    # Installation complete
    log "Installation completed successfully!"
    echo
    echo "IRSSH Panel has been installed!"
    echo
    echo "Admin Credentials:"
    echo "Username: $ADMIN_USER"
    echo "Password: $ADMIN_PASS"
    echo
    echo "Important URLs:"
    echo "Panel: http://YOUR-IP"
    echo "API: http://YOUR-IP/api"
    echo
    echo "Log Files:"
    echo "- Main Application: $LOG_DIR/app.log"
    echo "- Authentication: $LOG_DIR/auth.log"
    echo "- Database: $LOG_DIR/database.log"
    echo "- Nginx Access: $LOG_DIR/nginx-access.log"
    echo "- Nginx Error: $LOG_DIR/nginx-error.log"
    echo "- API Server: $LOG_DIR/uvicorn.{out,err}.log"
    echo
    echo "Useful Commands:"
    echo "- View logs: tail -f $LOG_DIR/app.log"
    echo "- Restart panel: supervisorctl restart irssh-panel"
    echo "- Check status: supervisorctl status"
    echo "- Test API: curl http://localhost:$DEFAULT_API_PORT/api/health"
    echo
    echo "Security Notes:"
    echo "1. Change the admin password after first login"
    echo "2. Setup SSL/TLS using certbot"
    echo "3. Review firewall rules: ufw status"
    echo "4. Monitor auth logs regularly"
    echo
    echo "For support, check the documentation or contact support."
}

# Start installation
main "$@"    
