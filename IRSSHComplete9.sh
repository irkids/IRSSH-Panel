#!/bin/bash

# IRSSH Panel Complete Installation Script
# Version: 3.5.2

# Base paths and version
VERSION="3.5.2"
REPO_BASE="/opt/irssh-panel"

# Base and production directories
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

declare -A PROD_DIRS=(
    ["PROD_CONFIG"]="/etc/enhanced_ssh"
    ["PROD_LOG"]="/var/log/irssh"
    ["PROD_BACKUP"]="/opt/irssh-backups"
    ["PROD_SSL"]="/etc/nginx/ssl"
    ["PROD_METRICS"]="/var/log/irssh/metrics"
)

# Base module URLs
declare -A BASE_MODULES=(
    ["vpnserver"]="https://raw.githubusercontent.com/irkids/IRSSH-Panel/refs/heads/main/modules/vpnserver-script.py"
    ["webport"]="https://raw.githubusercontent.com/irkids/IRSSH-Panel/refs/heads/main/modules/webport-script.sh"
    ["port"]="https://raw.githubusercontent.com/irkids/IRSSH-Panel/refs/heads/main/modules/port-script.py"
    ["dropbear"]="https://raw.githubusercontent.com/irkids/IRSSH-Panel/refs/heads/main/modules/dropbear-script.sh"
)

# Protocol module URLs
declare -A PROTOCOL_MODULES=(
    ["ssh"]="https://raw.githubusercontent.com/irkids/IRSSH-Panel/refs/heads/main/modules/ssh-script.py"
    ["l2tp"]="https://raw.githubusercontent.com/irkids/IRSSH-Panel/refs/heads/main/modules/l2tpv3-script.sh"
    ["ikev2"]="https://raw.githubusercontent.com/irkids/IRSSH-Panel/refs/heads/main/modules/ikev2-script.py"
    ["cisco"]="https://raw.githubusercontent.com/irkids/IRSSH-Panel/refs/heads/main/modules/cisco-script.sh"
    ["wireguard"]="https://raw.githubusercontent.com/irkids/IRSSH-Panel/refs/heads/main/modules/wire-script.sh"
    ["singbox"]="https://raw.githubusercontent.com/irkids/IRSSH-Panel/refs/heads/main/modules/singbox-script.sh"
)

# Protocol configurations
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

error() { log "ERROR" "$1"; [ "${2:-}" != "no-exit" ] && cleanup && exit 1; }
info() { log "INFO" "$1"; }
warn() { log "WARN" "$1"; }
debug() { [ "${DEBUG:-false}" = "true" ] && log "DEBUG" "$1"; }

# System cleanup
cleanup() {
    info "Performing cleanup..."
    for service in nginx postgresql irssh-panel; do
        systemctl is-active --quiet "$service" && systemctl stop "$service"
    done
    [ -d "/tmp/irssh-install" ] && rm -rf "/tmp/irssh-install"
    apt-get clean
}

# System requirements check
check_requirements() {
    info "Checking system requirements..."
    [ "$EUID" -ne 0 ] && error "Please run as root"
    [ ! -f /etc/os-release ] && error "Unsupported operating system"
    
    source /etc/os-release
    [[ "$ID" != "ubuntu" && "$ID" != "debian" ]] && error "Requires Ubuntu or Debian"

    apt-get update
    apt-get install -y curl wget git build-essential python3 python3-pip || error "Failed to install basic requirements"

    local MEM_TOTAL=$(free -m | awk '/^Mem:/{print $2}')
    local CPU_CORES=$(nproc)
    local DISK_SPACE=$(df -m / | awk 'NR==2 {print $4}')
    
    [ "$MEM_TOTAL" -lt "${REQUIREMENTS[MIN_MEMORY]}" ] && warn "Low memory"
    [ "$CPU_CORES" -lt "${REQUIREMENTS[MIN_CPU_CORES]}" ] && warn "Low CPU cores"
    [ "$DISK_SPACE" -lt "${REQUIREMENTS[MIN_DISK]}" ] && error "Insufficient disk space"
}

# Get initial configuration
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

# Initialize directories
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

# Module installation function
install_module() {
    local module_name=$1
    local script_url=$2
    local target_dir="${DIRS[MODULES_DIR]}/$module_name"
    local script_ext="${script_url##*.}"
    
    info "Installing module: $module_name"
    mkdir -p "$target_dir"
    cd "$target_dir" || error "Failed to access module directory"
    
    local script_name="install.$script_ext"
    wget -q "$script_url" -O "$script_name" || error "Failed to download $module_name script"
    chmod +x "$script_name"
    
    case "$script_ext" in
        "py")
            python3 "$script_name"
            ;;
        "sh")
            bash "$script_name"
            ;;
        *)
            error "Unsupported script type: $script_ext"
            ;;
    esac
}

# Install base modules
install_base_modules() {
    info "Installing base modules..."
    for module in "${!BASE_MODULES[@]}"; do
        install_module "$module" "${BASE_MODULES[$module]}"
    done
}

# Install protocol modules
install_protocols() {
    info "Installing VPN protocols..."
    for protocol in "${!PROTOCOLS[@]}"; do
        if [ "${PROTOCOLS[$protocol]}" = true ]; then
            local protocol_lower="${protocol,,}"
            if [ -n "${PROTOCOL_MODULES[$protocol_lower]}" ]; then
                install_module "$protocol_lower" "${PROTOCOL_MODULES[$protocol_lower]}"
            fi
        fi
    done
}

# Setup web server
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

# Setup security
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

# Main installation function
main() {
    trap cleanup EXIT
    
    info "Starting IRSSH Panel installation v$VERSION"
    
    check_requirements
    get_initial_config
    init_directories
    
    # Install modules in correct order
    install_base_modules
    install_protocols
    
    # Complete setup
    setup_nginx
    setup_security
    
    [ "$ENABLE_MONITORING" = "y" ] && setup_monitoring
    
    info "Installation completed successfully!"

    # Display installation summary
    cat << EOL

IRSSH Panel Installation Summary
------------------------------
Version: $VERSION
Web Panel URL: http${ENABLE_HTTPS:+s}://YOUR-SERVER-IP:${PORTS[WEB]}
Admin Username: $ADMIN_USER

Installation Locations:
- Configuration: ${PROD_DIRS[PROD_CONFIG]}
- Logs: ${PROD_DIRS[PROD_LOG]}
- Backups: ${PROD_DIRS[PROD_BACKUP]}

Enabled Features:
- HTTPS: ${ENABLE_HTTPS:-n}
- Monitoring: ${ENABLE_MONITORING:-n}

Active Ports:
$(for name in "${!PORTS[@]}"; do echo "- $name: ${PORTS[$name]}"; done)

Next Steps:
1. Access the web panel using the URL above
2. Log in with your admin credentials
3. Configure additional users and settings
4. Check the logs at ${PROD_DIRS[PROD_LOG]}

EOL
}

# Start installation
main
