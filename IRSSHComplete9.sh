#!/bin/bash

# IRSSH Panel Complete Installation Script
# Version: 3.5.2

# Base paths and repositories
GITHUB_REPO="https://raw.githubusercontent.com/irkids/IRSSH-Panel/main"
MODULES_SOURCE="$GITHUB_REPO/modules"
SCRIPTS_SOURCE="$GITHUB_REPO/scripts/modules"

# Base directory structure
REPO_BASE="/opt/irssh-panel"
declare -A DIRS=(
    ["BACKEND_DIR"]="$REPO_BASE/backend"
    ["FRONTEND_DIR"]="$REPO_BASE/frontend"
    ["CONFIG_DIR"]="$REPO_BASE/config"
    ["MODULES_DIR"]="$REPO_BASE/modules"
    ["DOCS_DIR"]="$REPO_BASE/docs"
    ["TESTS_DIR"]="$REPO_BASE/tests"
    ["ANSIBLE_DIR"]="$REPO_BASE/ansible"
    ["SCRIPTS_DIR"]="$REPO_BASE/scripts"
    ["MONITORING_DIR"]="$REPO_BASE/monitoring"
    ["SECURITY_DIR"]="$REPO_BASE/security"
    ["IAC_DIR"]="$REPO_BASE/iac"
    ["CI_CD_DIR"]="$REPO_BASE/ci_cd"
    ["PROTOCOLS_DIR"]="$REPO_BASE/modules/protocols"
)

# Production directories
declare -A PROD_DIRS=(
    ["PROD_CONFIG"]="/etc/enhanced_ssh"
    ["PROD_LOG"]="/var/log/irssh"
    ["PROD_BACKUP"]="/opt/irssh-backups"
    ["PROD_SSL"]="/etc/nginx/ssl"
    ["PROD_METRICS"]="/var/log/irssh/metrics"
)

# Protocol modes
declare -A PROTOCOLS=(
    ["SSH"]=true
    ["L2TP"]=true
    ["IKEV2"]=true
    ["CISCO"]=true
    ["WIREGUARD"]=true
    ["SINGBOX"]=true
)

# Default ports
declare -A PORTS=(
    ["SSH"]=22
    ["WEBSOCKET"]=2082
    ["L2TP"]=1701
    ["IKEV2"]=500
    ["CISCO"]=443
    ["WIREGUARD"]=51820
    ["SINGBOX"]=1080
    ["WEB"]=8080
)

# System requirements
declare -A REQUIREMENTS=(
    ["MIN_MEMORY"]=1024
    ["MIN_DISK"]=5120
    ["MIN_CPU_CORES"]=2
    ["MIN_NODE_VERSION"]=16
    ["MIN_PYTHON_VERSION"]="3.8"
)

# Colors for output
declare -A COLORS=(
    ["GREEN"]='\033[0;32m'
    ["RED"]='\033[0;31m'
    ["YELLOW"]='\033[1;33m'
    ["BLUE"]='\033[0;34m'
    ["NC"]='\033[0m'
)

# Logging functions
log() {
    local level=$1
    local message=$2
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    local color_code="${COLORS[${level}]:-${COLORS[NC]}}"
    
    mkdir -p "${PROD_DIRS[PROD_LOG]}"
    echo -e "${color_code}[$timestamp] [$level] $message${COLORS[NC]}"
    echo "[$timestamp] [$level] $message" >> "${PROD_DIRS[PROD_LOG]}/install.log"
}

error() {
    log "ERROR" "$1"
    [ "${2:-}" != "no-exit" ] && cleanup && exit 1
}

info() { log "INFO" "$1"; }
warn() { log "WARN" "$1"; }
debug() { [ "${DEBUG:-false}" = "true" ] && log "DEBUG" "$1"; }

# Cleanup function
cleanup() {
    info "Performing cleanup..."
    for service in nginx postgresql irssh-panel; do
        systemctl is-active --quiet "$service" && systemctl stop "$service"
    done
    [ -d "/tmp/irssh-install" ] && rm -rf "/tmp/irssh-install"
    apt-get clean
}

# System checks
check_requirements() {
    info "Checking system requirements..."
    [ "$EUID" -ne 0 ] && error "Please run as root"
    [ ! -f /etc/os-release ] && error "Unsupported operating system"
    
    source /etc/os-release
    [[ "$ID" != "ubuntu" && "$ID" != "debian" ]] && error "Requires Ubuntu or Debian"

    local MEM_TOTAL=$(free -m | awk '/^Mem:/{print $2}')
    local CPU_CORES=$(nproc)
    local DISK_SPACE=$(df -m / | awk 'NR==2 {print $4}')
    
    [ "$MEM_TOTAL" -lt "${REQUIREMENTS[MIN_MEMORY]}" ] && warn "Low memory"
    [ "$CPU_CORES" -lt "${REQUIREMENTS[MIN_CPU_CORES]}" ] && warn "Low CPU cores"
    [ "$DISK_SPACE" -lt "${REQUIREMENTS[MIN_DISK]}" ] && error "Insufficient disk space"

    apt-get update
    apt-get install -y curl wget git build-essential
}

# Initial configuration
get_initial_config() {
    info "Getting initial configuration..."

    while [ -z "$ADMIN_USER" ]; do
        read -p "Enter admin username: " ADMIN_USER
    done
    
    while [ -z "$ADMIN_PASS" ]; do
        read -s -p "Enter admin password: " ADMIN_PASS
        echo
        read -s -p "Confirm password: " ADMIN_PASS_CONFIRM
        echo
        [ "$ADMIN_PASS" = "$ADMIN_PASS_CONFIRM" ] || { error "Passwords don't match" "no-exit"; ADMIN_PASS=""; }
    done

    while true; do
        read -p "Enter web panel port (4-5 digits, Enter for random): " WEB_PORT
        if [ -z "$WEB_PORT" ]; then
            WEB_PORT=$(shuf -i 1234-65432 -n 1)
            info "Generated port: $WEB_PORT"
            break
        elif [[ "$WEB_PORT" =~ ^[0-9]{4,5}$ ]] && [ "$WEB_PORT" -ge 1234 ] && [ "$WEB_PORT" -le 65432 ]; then
            break
        fi
        error "Invalid port number" "no-exit"
    done
    PORTS["WEB"]=$WEB_PORT

    read -p "Enable HTTPS? (y/N): " ENABLE_HTTPS
    ENABLE_HTTPS=${ENABLE_HTTPS,,}
    
    read -p "Enable monitoring? (y/N): " ENABLE_MONITORING
    ENABLE_MONITORING=${ENABLE_MONITORING,,}
}

# Directory setup
init_directories() {
    info "Initializing directories..."
    for dir in "${DIRS[@]}"; do
        mkdir -p "$dir"
        info "Created directory: $dir"
    done
    for dir in "${PROD_DIRS[@]}"; do
        mkdir -p "$dir"
        info "Created production directory: $dir"
    done
}

# Module installation
install_module() {
    local module_name=$1
    local target_dir="${DIRS[MODULES_DIR]}/$module_name"
    
    info "Installing module: $module_name"
    mkdir -p "$target_dir"
    cd "$target_dir" || error "Failed to access module directory"
    
    wget -q "$MODULES_SOURCE/$module_name/install.sh" -O install.sh || error "Failed to download installer"
    [ -f "install.sh" ] && chmod +x install.sh && ./install.sh
}

# Protocol installation
install_protocols() {
    info "Installing protocols..."
    for protocol in "${!PROTOCOLS[@]}"; do
        if [ "${PROTOCOLS[$protocol]}" = true ]; then
            install_module "${protocol,,}"
        fi
    done
}

# Database setup
setup_database() {
    info "Setting up database..."
    
    apt-get install -y postgresql postgresql-contrib || error "Failed to install PostgreSQL"
    systemctl start postgresql
    systemctl enable postgresql

    local db_name="irssh_db"
    local db_user="irssh_user"
    local db_pass=$(openssl rand -base64 32)

    su - postgres -c "psql -c \"CREATE USER $db_user WITH PASSWORD '$db_pass';\""
    su - postgres -c "psql -c \"CREATE DATABASE $db_name OWNER $db_user;\""
}

# Web server setup
setup_nginx() {
    info "Setting up web server..."
    
    apt-get install -y nginx || error "Failed to install Nginx"
    
    if [ "$ENABLE_HTTPS" = "y" ]; then
        mkdir -p "${PROD_DIRS[PROD_SSL]}/nginx"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "${PROD_DIRS[PROD_SSL]}/nginx/server.key" \
            -out "${PROD_DIRS[PROD_SSL]}/nginx/server.crt" \
            -subj "/CN=irssh-panel"
    fi

    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen ${PORTS[WEB]};
    server_name _;
    root ${DIRS[FRONTEND_DIR]}/dist;
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
    }
}
EOL

    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    systemctl restart nginx
    systemctl enable nginx
}

# Security setup
setup_security() {
    info "Setting up security measures..."
    
    apt-get install -y fail2ban ufw || error "Failed to install security packages"
    
    ufw default deny incoming
    ufw default allow outgoing
    
    for port in "${PORTS[@]}"; do
        ufw allow "$port"
    done
    
    echo "y" | ufw enable
}

# Main installation
main() {
    trap cleanup EXIT
    
    info "Starting IRSSH Panel installation v3.5.2"
    
    check_requirements
    get_initial_config
    init_directories
    
    install_protocols
    setup_database
    setup_nginx
    setup_security
    
    [ "$ENABLE_MONITORING" = "y" ] && setup_monitoring
    
    info "Installation completed successfully!"
}

main
