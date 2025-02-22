#!/bin/bash

# IRSSH Panel Installation Script - Version 3.5.2
VERSION="3.5.2"
REPO_BASE="/opt/irssh-panel"

# Directory structure
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

# Module URLs
declare -A MODULE_URLS=(
    ["vpnserver"]="https://raw.githubusercontent.com/irkids/IRSSH-Panel/refs/heads/main/modules/vpnserver-script.py"
    ["webport"]="https://raw.githubusercontent.com/irkids/IRSSH-Panel/refs/heads/main/modules/webport-script.sh"
    ["dropbear"]="https://raw.githubusercontent.com/irkids/IRSSH-Panel/refs/heads/main/modules/dropbear-script.sh"
    ["port"]="https://raw.githubusercontent.com/irkids/IRSSH-Panel/refs/heads/main/modules/port-script.py"
    ["ssh"]="https://raw.githubusercontent.com/irkids/IRSSH-Panel/refs/heads/main/modules/ssh-script.py"
    ["l2tp"]="https://raw.githubusercontent.com/irkids/IRSSH-Panel/refs/heads/main/modules/l2tpv3-script.sh"
    ["ikev2"]="https://raw.githubusercontent.com/irkids/IRSSH-Panel/refs/heads/main/modules/ikev2-script.py"
    ["cisco"]="https://raw.githubusercontent.com/irkids/IRSSH-Panel/refs/heads/main/modules/cisco-script.sh"
    ["wireguard"]="https://raw.githubusercontent.com/irkids/IRSSH-Panel/refs/heads/main/modules/wire-script.sh"
    ["singbox"]="https://raw.githubusercontent.com/irkids/IRSSH-Panel/refs/heads/main/modules/singbox-script.sh"
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

# System cleanup
cleanup() {
    info "Performing cleanup..."
    rm -rf /tmp/irssh-install
    apt-get clean
}

# Pre-installation checks and setup
prepare_system() {
    info "Preparing system for installation..."
    
    # Fix apt_pkg error first
    rm -f /usr/lib/python3/dist-packages/apt_pkg.cpython*
    rm -f /usr/lib/python3/dist-packages/command_not_found
    apt-get remove -y python3-apt
    apt-get install -y python3-apt --reinstall
    
    export DEBIAN_FRONTEND=noninteractive
    
    # Fix apt_pkg error
    apt-get install -y -qq \
        python3-apt \
        python3-distutils \
        python3-pkg-resources \
        || error "Failed to install Python apt packages"

    # Remove problematic Python packages
    rm -rf /usr/lib/python3/dist-packages/command_not_found
    
    # Update package lists
    apt-get update -qq
    
    # Install essential packages
    apt-get install -y -qq \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        curl \
        wget \
        git \
        build-essential \
        python3.8 \
        python3.8-dev \
        python3.8-venv \
        python3.8-distutils \
        || error "Failed to install essential packages"

    # Create symbolic links
    update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1

    # Fix pip issues
    curl -sS https://bootstrap.pypa.io/get-pip.py | python3.8
    
    info "System preparation completed"
}

# Python environment setup
setup_python_env() {
    info "Setting up Python environment..."
    
    cd "${DIRS[MODULES_DIR]}" || error "Failed to access modules directory"
    
    # Create and activate virtual environment
    python3.8 -m venv .venv
    source .venv/bin/activate
    
    # Upgrade pip and install setuptools first
    pip install --no-cache-dir --upgrade pip setuptools wheel

    # First uninstall tensorflow and typing-extensions if they exist
    pip uninstall -y tensorflow typing-extensions

    # Install dependencies in the correct order
    pip install --no-cache-dir \
        typing-extensions==4.5.0 \
        python-dotenv==1.0.0 \
        requests==2.31.0 \
        psutil==5.9.0 \
        pymongo==4.3.3 \
        redis==4.5.1 \
        aiohttp==3.8.4 \
        pyyaml==6.0.1 \
        pandas==2.0.3 \
        networkx==3.1 \
        || error "Failed to install Python packages"
        
    # tensorflow is optional, only install if needed
    # pip install tensorflow==2.13.1
    
    deactivate
    
    info "Python environment setup completed"
}

# Install module function
install_module() {
    local module_name=$1
    local script_url="${MODULE_URLS[$module_name]}"
    local target_dir="${DIRS[MODULES_DIR]}/$module_name"
    
    if [ -z "$script_url" ]; then
        error "Module URL not found: $module_name" "no-exit"
        return 1
    fi
    
    info "Installing module: $module_name"
    mkdir -p "$target_dir"
    cd "$target_dir" || error "Failed to access module directory"
    
    local script_ext="${script_url##*.}"
    local script_name="install.$script_ext"
    wget -q "$script_url" -O "$script_name" || error "Failed to download $module_name script"
    chmod +x "$script_name"
    
    case "$script_ext" in
        "py")
            source "${DIRS[MODULES_DIR]}/.venv/bin/activate"
            python3 "$script_name"
            local result=$?
            deactivate
            [ $result -ne 0 ] && error "Failed to execute Python script: $module_name"
            ;;
        "sh")
            bash "$script_name" || error "Failed to execute shell script: $module_name"
            ;;
        *)
            error "Unsupported script type: $script_ext"
            ;;
    esac
}

# Get user configuration
get_config() {
    info "Getting configuration details..."
    
    while [ -z "$ADMIN_USER" ]; do
        read -p "Enter admin username: " ADMIN_USER
    done
    
    while [ -z "$ADMIN_PASS" ]; do
        read -s -p "Enter admin password: " ADMIN_PASS
        echo
        read -s -p "Confirm password: " ADMIN_PASS_CONFIRM
        echo
        [ "$ADMIN_PASS" = "$ADMIN_PASS_CONFIRM" ] || { 
            error "Passwords don't match" "no-exit"
            ADMIN_PASS=""
        }
    done
    
    while true; do
        read -p "Enter web panel port (4-5 digits, Enter for random): " WEB_PORT
        if [ -z "$WEB_PORT" ]; then
            WEB_PORT=$(shuf -i 1234-65432 -n 1)
            info "Generated random port: $WEB_PORT"
            break
        elif [[ "$WEB_PORT" =~ ^[0-9]{4,5}$ ]] && [ "$WEB_PORT" -ge 1234 ] && [ "$WEB_PORT" -le 65432 ]; then
            break
        fi
        error "Invalid port number" "no-exit"
    done
    
    read -p "Enable HTTPS? (y/N): " ENABLE_HTTPS
    ENABLE_HTTPS=${ENABLE_HTTPS,,}
    
    read -p "Enable monitoring? (y/N): " ENABLE_MONITORING
    ENABLE_MONITORING=${ENABLE_MONITORING,,}
}

# Initialize directories
init_directories() {
    info "Creating directories..."
    
    for dir in "${DIRS[@]}"; do
        mkdir -p "$dir"
        chmod 755 "$dir"
    done
    
    for dir in "${PROD_DIRS[@]}"; do
        mkdir -p "$dir"
        chmod 700 "$dir"
    done
}

# Save installation info
save_install_info() {
    local info_file="${PROD_DIRS[PROD_CONFIG]}/install_info.yml"
    
    cat > "$info_file" << EOL
version: $VERSION
install_date: $(date +'%Y-%m-%d %H:%M:%S')
admin_user: $ADMIN_USER
web_port: $WEB_PORT
https_enabled: ${ENABLE_HTTPS:-n}
monitoring_enabled: ${ENABLE_MONITORING:-n}
EOL

    chmod 600 "$info_file"
}

# Main installation
main() {
    trap cleanup EXIT
    
    info "Starting IRSSH Panel installation v$VERSION"
    
    # Initial setup
    prepare_system
    get_config
    init_directories
    setup_python_env
    
    # Install base modules
    for module in "vpnserver" "webport" "port" "dropbear"; do
        install_module "$module"
    done
    
    # Install VPN protocols
    for module in "ssh" "l2tp" "ikev2" "cisco" "wireguard" "singbox"; do
        install_module "$module"
    done
    
    # Save installation info
    save_install_info
    
    info "Installation completed successfully!"
    
    # Display installation summary
    cat << EOL

IRSSH Panel Installation Summary
------------------------------
Version: $VERSION
Web Panel URL: http${ENABLE_HTTPS:+s}://YOUR-SERVER-IP:$WEB_PORT
Admin Username: $ADMIN_USER

Installation Locations:
- Configuration: ${PROD_DIRS[PROD_CONFIG]}
- Logs: ${PROD_DIRS[PROD_LOG]}
- Backups: ${PROD_DIRS[PROD_BACKUP]}

Enabled Features:
- HTTPS: ${ENABLE_HTTPS:-n}
- Monitoring: ${ENABLE_MONITORING:-n}

Next Steps:
1. Access the web panel using the URL above
2. Log in with your admin credentials
3. Configure additional users and settings
4. Check the logs at ${PROD_DIRS[PROD_LOG]}

EOL
}

# Start installation
main
