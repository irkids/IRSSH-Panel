#!/bin/bash

# IRSSH Panel - Unified Setup Script
# Version: 1.0.0
# This script handles complete setup of IRSSH Panel including server initialization,
# panel installation, and module configuration.

# Configuration
PANEL_DIR="/opt/irssh-panel"
CONFIG_DIR="$PANEL_DIR/config"
MODULES_DIR="$PANEL_DIR/modules"
LOG_DIR="/var/log/irssh"
BACKUP_DIR="$PANEL_DIR/backups"
REPO_URL="https://raw.githubusercontent.com/irkids/Optimize2Ubuntu/refs/heads/main"

# Colors and Styling
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
BOLD='\033[1m'

# Logging
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a $LOG_DIR/install.log
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" | tee -a $LOG_DIR/install.log
    exit 1
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1" | tee -a $LOG_DIR/install.log
}

# Check system requirements
check_requirements() {
    log "Checking system requirements..."
    
    # Check OS
    if [ ! -f /etc/lsb-release ]; then
        error "This script requires Ubuntu 20.04 or higher"
    fi

    # Check memory
    total_mem=$(free -m | awk '/^Mem:/{print $2}')
    if [ $total_mem -lt 1024 ]; then
        error "Minimum 1GB RAM required"
    fi

    # Check disk space
    free_space=$(df -m / | awk 'NR==2{print $4}')
    if [ $free_space -lt 5120 ]; then
        error "Minimum 5GB free space required"
    fi

    # Check if root
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi
}

# Initialize server
init_server() {
    log "Initializing server..."

    # Update system
    apt-get update
    apt-get upgrade -y

    # Install essential packages
    log "Installing essential packages..."
    apt-get install -y \
        curl wget git vim htop tmux zip unzip \
        net-tools iptables ufw fail2ban ntp \
        ca-certificates gnupg lsb-release \
        python3 python3-pip python3-venv \
        postgresql postgresql-contrib nginx \
        certbot python3-certbot-nginx supervisor

    # Configure timezone
    log "Configuring timezone..."
    timedatectl set-timezone UTC
    systemctl restart ntp

    # Configure system limits
    log "Optimizing system settings..."
    cat > /etc/sysctl.d/99-irssh.conf << EOL
# Network optimizations
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 262144
net.ipv4.tcp_max_syn_backlog = 262144
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 87380 16777216
net.ipv4.tcp_mem = 786432 1048576 26777216
net.ipv4.tcp_max_tw_buckets = 6000000
net.ipv4.tcp_fin_timeout = 15
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_fastopen = 3
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216

# Enable BBR
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOL
    sysctl --system

    # Configure firewall
    log "Configuring firewall..."
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow http
    ufw allow https
    ufw --force enable
}

# Setup Database
setup_database() {
    log "Setting up PostgreSQL database..."
    
    # Generate secure passwords
    DB_PASS=$(openssl rand -base64 32)
    ADMIN_PASS=$(openssl rand -base64 16)
    
    # Start PostgreSQL
    systemctl start postgresql
    systemctl enable postgresql
    
    # Create database and user
    sudo -u postgres psql -c "CREATE USER irssh_admin WITH PASSWORD '$DB_PASS';"
    sudo -u postgres psql -c "CREATE DATABASE irssh_panel OWNER irssh_admin;"
    
    # Save credentials
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_DIR/database.env" << EOL
DB_HOST=localhost
DB_PORT=5432
DB_NAME=irssh_panel
DB_USER=irssh_admin
DB_PASS=$DB_PASS
EOL

    # Save admin credentials
    cat > "$CONFIG_DIR/admin.env" << EOL
ADMIN_USER=admin
ADMIN_PASS=$ADMIN_PASS
EOL
}

# Install and configure modules
setup_modules() {
    log "Setting up modules..."
    
    # Create modules directory
    mkdir -p "$MODULES_DIR"
    
    # Define module list
    MODULES=(
        "vpnserver-script.py"
        "port-script.py"
        "ssh-script.py"
        "l2tpv3-script.sh"
        "ikev2-script.py"
        "cisco-script.sh"
        "wire-script.sh"
        "singbox-script.sh"
        "badvpn-script.sh"
        "dropbear-script.sh"
        "webport-script.sh"
    )
    
    # Download and configure each module
    for module in "${MODULES[@]}"; do
        log "Installing module: $module"
        curl -o "$MODULES_DIR/$module" "$REPO_URL/$module"
        chmod +x "$MODULES_DIR/$module"
        
        if [[ "$module" == *.sh ]]; then
            sed -i 's/\r$//' "$MODULES_DIR/$module"
        fi
        
        # Execute module setup if available
        if [[ -x "$MODULES_DIR/$module" ]]; then
            "$MODULES_DIR/$module" setup || warn "Module setup failed: $module"
        fi
    done
}

# Setup Panel Backend
setup_backend() {
    log "Setting up panel backend..."
    
    # Create Python virtual environment
    python3 -m venv "$PANEL_DIR/venv"
    source "$PANEL_DIR/venv/bin/activate"
    
    # Install Python dependencies
    pip install --upgrade pip
    pip install \
        fastapi[all] uvicorn[standard] \
        sqlalchemy[asyncio] psycopg2-binary \
        python-jose[cryptography] passlib[bcrypt] \
        python-multipart aiofiles python-telegram-bot \
        psutil geoip2 asyncpg
    
    # Setup supervisor
    cat > /etc/supervisor/conf.d/irssh-panel.conf << EOL
[program:irssh-panel]
directory=$PANEL_DIR
command=$PANEL_DIR/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
user=root
autostart=true
autorestart=true
stderr_logfile=$LOG_DIR/uvicorn.err.log
stdout_logfile=$LOG_DIR/uvicorn.out.log
EOL

    supervisorctl reread
    supervisorctl update
}

# Setup Panel Frontend
setup_frontend() {
    log "Setting up panel frontend..."
    
    # Configure Nginx
    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen 80;
    server_name _;

    location / {
        root $PANEL_DIR/frontend/build;
        try_files \$uri \$uri/ /index.html;
    }

    location /api {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }

    location /ws {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
    }
}
EOL

    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    systemctl restart nginx
}

# Setup monitoring and maintenance
setup_monitoring() {
    log "Setting up monitoring..."
    
    # Create monitoring scripts directory
    mkdir -p "$PANEL_DIR/scripts"
    
    # Create monitoring script
    cat > "$PANEL_DIR/scripts/monitor.sh" << 'EOL'
#!/bin/bash
LOG_FILE="/var/log/irssh/monitor.log"

echo "[$(date)] Starting system check..." >> $LOG_FILE

# Check system resources
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
MEM_USAGE=$(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2 }')
DISK_USAGE=$(df -h / | awk 'NR==2{print $5}')

echo "CPU Usage: $CPU_USAGE%" >> $LOG_FILE
echo "Memory Usage: $MEM_USAGE" >> $LOG_FILE
echo "Disk Usage: $DISK_USAGE" >> $LOG_FILE

# Check services
services=("postgresql" "nginx" "supervisor")
for service in "${services[@]}"; do
    if systemctl is-active --quiet $service; then
        echo "$service: Running" >> $LOG_FILE
    else
        echo "$service: Stopped" >> $LOG_FILE
        systemctl restart $service
        echo "Attempted to restart $service" >> $LOG_FILE
    fi
done

# Check connections
echo "Active Connections: $(netstat -an | grep ESTABLISHED | wc -l)" >> $LOG_FILE

# Cleanup old logs
find /var/log/irssh -type f -name "*.log" -mtime +30 -delete
EOL

    chmod +x "$PANEL_DIR/scripts/monitor.sh"
    
    # Setup cron job
    cat > /etc/cron.d/irssh << EOL
*/5 * * * * root $PANEL_DIR/scripts/monitor.sh
0 3 * * * root apt-get update && apt-get upgrade -y
EOL
}

# Main installation function
main() {
    # Create log directory
    mkdir -p "$LOG_DIR"
    
    # Start installation log
    log "Starting IRSSH Panel installation..."
    
    # Run installation steps
    check_requirements
    init_server
    setup_database
    setup_modules
    setup_backend
    setup_frontend
    setup_monitoring
    
    # Final steps
    log "Installation completed successfully!"
    
    # Show installation info
    echo
    echo -e "${BOLD}IRSSH Panel Installation Complete${NC}"
    echo -e "${BLUE}----------------------------------------${NC}"
    echo "Panel URL: http://$(curl -s ipv4.icanhazip.com)"
    echo "API URL: http://$(curl -s ipv4.icanhazip.com)/api"
    echo
    echo -e "${YELLOW}Admin Credentials:${NC}"
    echo "Username: admin"
    echo "Password: $(cat $CONFIG_DIR/admin.env | grep ADMIN_PASS | cut -d= -f2)"
    echo
    echo -e "${GREEN}Installation logs are available at: $LOG_DIR/install.log${NC}"
    echo
    echo -e "${RED}IMPORTANT: Please change the admin password after first login!${NC}"
}

# Run main installation
main "$@"
