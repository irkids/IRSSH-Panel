#!/bin/bash

# IRSSH Panel Complete Installation Script
# Version: 3.5.0

WEB_PORT=""

# Ask for web port
read -p "Enter custom port for web panel (4-5 digits) or press Enter for random port: " WEB_PORT
if [ -z "$WEB_PORT" ]; then
    # Generate random port between 1234 and 65432
    WEB_PORT=$(shuf -i 1234-65432 -n 1)
    log "Generated random port: $WEB_PORT"
else
    # Validate custom port
    if ! [[ "$WEB_PORT" =~ ^[0-9]{4,5}$ ]]; then
        error "Invalid port number. Must be 4-5 digits."
    fi
    if [ "$WEB_PORT" -lt 1234 ] || [ "$WEB_PORT" -gt 65432 ]; then
        error "Port must be between 1234 and 65432"
    fi
fi

# Exit on error
set -e

# Directories
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
MODULES_DIR="$PANEL_DIR/modules"
PROTOCOLS_DIR="$MODULES_DIR/protocols"
LOG_DIR="/var/log/irssh"
BACKUP_DIR="/opt/irssh-backups"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Utility functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    [[ "${2:-}" != "no-exit" ]] && cleanup && exit 1
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

cleanup() {
    log "Performing cleanup..."
    # Remove temporary files
    rm -rf /tmp/irssh-temp 2>/dev/null || true
}

# Generate secure keys and passwords
generate_secrets() {
    log "Generating secure credentials..."
    DB_NAME="irssh_panel"
    DB_USER="irssh_admin"
    DB_PASS=$(openssl rand -base64 32)
    ADMIN_PASS=$(openssl rand -base64 16)
    JWT_SECRET=$(openssl rand -base64 32)

    # Save credentials
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_DIR/credentials.env" << EOL
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASS=$DB_PASS
ADMIN_PASS=$ADMIN_PASS
JWT_SECRET=$JWT_SECRET
EOL
    chmod 600 "$CONFIG_DIR/credentials.env"
}

setup_database() {
    log "Setting up PostgreSQL database..."

    # Make sure PostgreSQL is running
    systemctl start postgresql
    systemctl enable postgresql

    # Wait for PostgreSQL to be ready
    until pg_isready; do
        log "Waiting for PostgreSQL to be ready..."
        sleep 1
    done

    # Check if user exists
    if ! su - postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'\"" | grep -q 1; then
        # Create user if not exists
        su - postgres -c "psql -c \"CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';\"" || error "Failed to create database user"
    else
        # Update password if user exists
        su - postgres -c "psql -c \"ALTER USER $DB_USER WITH PASSWORD '$DB_PASS';\"" || error "Failed to update database user password"
    fi

    # Check if database exists
    if ! su - postgres -c "psql -lqt | cut -d \| -f 1 | grep -qw $DB_NAME"; then
        # Create database if not exists
        su - postgres -c "psql -c \"CREATE DATABASE $DB_NAME OWNER $DB_USER;\"" || error "Failed to create database"
    fi

    # Grant privileges (will update if already exists)
    su - postgres -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;\"" || error "Failed to grant privileges"

    log "Database setup completed successfully"
}

check_requirements() {
    log "Checking and installing basic requirements..."
    
    # Check root privileges
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root"
    fi

    # Check OS compatibility
    if [ ! -f /etc/os-release ]; then
        error "Unsupported operating system"
    fi
    source /etc/os-release
    if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
        error "This script requires Ubuntu or Debian"
    fi

    # First, update package lists
    log "Updating package lists..."
    apt-get update || error "Failed to update package lists"

    # Install essential packages first
    log "Installing essential packages..."
    apt-get install -y curl wget git unzip build-essential python3 || error "Failed to install essential packages"

    # Check system resources
    log "Checking system resources..."
    MEM_TOTAL=$(free -m | awk '/^Mem:/{print $2}')
    CPU_CORES=$(nproc)
    DISK_SPACE=$(df -m / | awk 'NR==2 {print $4}')

    if [ "$MEM_TOTAL" -lt 1024 ]; then
        warn "System has less than 1GB RAM. Performance may be affected."
    fi

    if [ "$CPU_CORES" -lt 2 ]; then
        warn "System has less than 2 CPU cores. Performance may be affected."
    fi

    if [ "$DISK_SPACE" -lt 5120 ]; then
        error "Insufficient disk space. At least 5GB free space required."
    fi

    log "Basic requirements check completed successfully"
}

create_backup() {
    log "Creating backup of existing installation..."
    if [ -d "$PANEL_DIR" ]; then
        local backup_file="$BACKUP_DIR/irssh-panel-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
        mkdir -p "$BACKUP_DIR"
        tar -czf "$backup_file" -C "$(dirname "$PANEL_DIR")" "$(basename "$PANEL_DIR")" || warn "Backup failed"
    fi
}

setup_directories() {
    log "Creating directory structure..."
    
    # Create main directories
    mkdir -p "$PANEL_DIR"/{frontend,backend,config,modules/protocols}
    mkdir -p "$FRONTEND_DIR"/{public,src/{components,stores,context,utils,hooks,types}}
    mkdir -p "$BACKEND_DIR"/{src/{routes,middleware,models,utils},config}
    mkdir -p "$LOG_DIR"
    
    # Set permissions
    chown -R root:root "$PANEL_DIR"
    chmod -R 755 "$PANEL_DIR"
    chmod 700 "$CONFIG_DIR"
}

install_dependencies() {
    log "Installing system dependencies..."
    
    # Prevent interactive prompts
    export DEBIAN_FRONTEND=noninteractive
    
    # Update package lists
    apt-get update || error "Failed to update package lists"
    
    # Automatic restart configuration for daemons
    echo '#!/bin/sh
exit 0' > /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d
    
    # Python packages first (needed for protocol scripts)
    log "Installing Python packages..."
    apt-get install -y \
        python3 \
        python3-pip \
        python3-setuptools \
        python3-venv \
        || error "Failed to install Python"

python3 -m venv /opt/irssh-panel/venv
source /opt/irssh-panel/venv/bin/activate
/opt/irssh-panel/venv/bin/pip install --upgrade pip
/opt/irssh-panel/venv/bin/pip install requests psutil python-dotenv prometheus_client colorama
if [ $? -ne 0 ]; then error "Failed to install Python packages"; fi
deactivate

    # Essential system packages
    log "Installing essential packages..."
    apt-get install -y \
        curl \
        wget \
        git \
        unzip \
        build-essential \
        pkg-config \
        autoconf \
        automake \
        nginx \
        postgresql \
        postgresql-contrib \
        fail2ban \
        net-tools \
        iptables \
        netfilter-persistent \
        || error "Failed to install essential packages"

    # Protocol-specific packages
    log "Installing protocol-specific packages..."
    apt-get install -y \
        openssh-server \
        stunnel4 \
        dropbear \
        strongswan \
        strongswan-pki \
        libstrongswan-extra-plugins \
        libcharon-extra-plugins \
        xl2tpd \
        ppp \
        ocserv \
        gnutls-bin \
        wireguard \
        wireguard-tools \
        || error "Failed to install protocol packages"

    # NodeJS installation
    log "Installing Node.js..."
    if ! command -v node &> /dev/null; then
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        apt-get install -y nodejs
    fi

    # Install global npm packages
    log "Installing global npm packages..."
    npm install -g pm2 typescript @types/node || error "Failed to install global npm packages"

    # Additional tools
    log "Installing additional tools..."
    apt-get install -y \
        htop \
        iftop \
        vnstat \
        screen \
        supervisor \
        || error "Failed to install additional tools"

    # Install websocat
    log "Installing websocat..."
    WEBSOCAT_VERSION="1.11.0"
    wget -O /usr/local/bin/websocat \
        "https://github.com/vi/websocat/releases/download/v${WEBSOCAT_VERSION}/websocat.x86_64-unknown-linux-musl" \
        || error "Failed to download websocat"
    chmod +x /usr/local/bin/websocat

    # Remove automatic restart configuration
    rm -f /usr/sbin/policy-rc.d

    log "All dependencies installed successfully"
}

setup_python_environment() {
    log "Setting up Python environment..."
    
    # Install Python and development packages
    apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        libpq-dev \
        gcc \
        || error "Failed to install Python and development packages"
    
    # Create and activate virtual environment
    mkdir -p "$PANEL_DIR/venv"
    python3 -m venv "$PANEL_DIR/venv"
    
    # Update pip and install base packages
    "$PANEL_DIR/venv/bin/pip" install --upgrade pip setuptools wheel

    # Install urllib3 first to avoid dependency issues
    "$PANEL_DIR/venv/bin/pip" install urllib3==2.0.7

    # Now install other packages
    "$PANEL_DIR/venv/bin/pip" install \
        requests \
        prometheus_client \
        psutil \
        python-dotenv \
        PyYAML \
        cryptography \
        PyJWT \
        websockets \
        aiofiles \
        boto3 \
        croniter \
        pyAesCrypt \
        aiomysql \
        aioprometheus \
        etcd3 \
        haproxyadmin \
        paramiko \
        fastapi \
        uvicorn \
        sqlalchemy \
        alembic \
        passlib \
        pydantic \
        psycopg2-binary \
        redis \
        pymongo \
        elasticsearch || error "Failed to install primary Python packages"
    
    # Verify the installation using the virtual environment's Python
    "$PANEL_DIR/venv/bin/python3" -c "import urllib3, requests, prometheus_client, psutil" || error "Failed to verify Python packages"
    
    # Create symlinks if needed
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    SITE_PACKAGES="$PANEL_DIR/venv/lib/python${PYTHON_VERSION}/site-packages"
    
    # Create symbolic links for all major packages
    for package in urllib3 prometheus_client psycopg2 requests psutil; do
        if [ -d "$SITE_PACKAGES/$package" ]; then
            ln -sf "$SITE_PACKAGES/$package" /usr/lib/python3/dist-packages/ || warn "Failed to create symlink for $package"
        fi
    done
    
    log "Python environment setup completed"
}

# Protocol Installation Modes and Ports
INSTALL_SSH=true
INSTALL_DROPBEAR=true
INSTALL_L2TP=true
INSTALL_IKEV2=true
INSTALL_CISCO=true
INSTALL_WIREGUARD=true
INSTALL_SINGBOX=true

# Protocol Ports
SSH_PORT=22
DROPBEAR_PORT=22722
WEBSOCKET_PORT=2082
SSH_TLS_PORT=443
L2TP_PORT=1701
IKEV2_PORT=500
CISCO_PORT=443
WIREGUARD_PORT=51820
SINGBOX_PORT=1080
BADVPN_PORT=7300
WEB_PORT=443

# Protocol Installation Function
install_protocols() {
    log "Installing VPN protocols using project modules..."
            log "Creating temporary haproxy_api module..."
    # Get Python version
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    SITE_PACKAGES="/opt/irssh-panel/venv/lib/python${PYTHON_VERSION}/site-packages"
    
    # Create directory if not exists
    mkdir -p "$SITE_PACKAGES"
    
    # Create temporary haproxy_api module
    cat > "$SITE_PACKAGES/haproxy_api.py" << 'EOL'
# Temporary module for compatibility
class HAProxy:
    def __init__(self):
        pass
EOL

    # Create modules directory
    mkdir -p "$MODULES_DIR/protocols"
    cd "$MODULES_DIR/protocols" || error "Failed to access modules directory"

    # Activate virtual environment
    source /opt/irssh-panel/venv/bin/activate || error "Failed to activate virtual environment"
    
    # First remove requests and its dependencies completely
    log "Removing existing requests installation..."
    pip uninstall -y requests chardet urllib3 charset-normalizer certifi idna

    # Clean pip cache
    pip cache purge
    
    # Install chardet first
    log "Installing chardet..."
    pip install --no-cache-dir chardet==4.0.0

    # Then install requests with all dependencies
    log "Installing requests and dependencies..."
    pip install --no-cache-dir \
        urllib3==2.0.7 \
        charset-normalizer==3.3.2 \
        certifi==2024.2.2 \
        idna==3.6 \
        requests==2.31.0 \
        || error "Failed to install requests and dependencies"

    # Install Consul if needed
    log "Installing Consul..."
    apt-get install -y consul || error "Failed to install Consul"

# First remove asyncio if installed in venv
    log "Cleaning up existing packages..."
    pip uninstall -y asyncio

    # Then remove the entire asyncio directory from venv if exists
    rm -rf /opt/irssh-panel/venv/lib/python3.8/site-packages/asyncio

    # Install required packages
    log "Installing Python packages..."
    pip install --no-cache-dir \
        prometheus_client \
        psycopg2-binary \
        pyyaml \
        structlog \
        websockets \
        psutil \
        chardet==4.0.0 \
        requests==2.31.0 \
        protobuf==3.20.0 \
        grpcio==1.44.0 \
        etcd3==0.12.0 \
        python-consul==1.1.0 \
        boto3==1.34.34 \
        python-dotenv==1.0.0 || error "Failed to install Python packages"

    # Verify installations
    log "Verifying package installations..."
    python3 -c "import chardet; import requests; print('Chardet version:', chardet.__version__); print('Requests version:', requests.__version__)" || error "Failed to verify package installations"

    # Download protocol modules
    log "Downloading protocol modules..."
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

    REPO_URL="https://raw.githubusercontent.com/irkids/IRSSH-Panel/master/scripts/modules"

    for module in "${MODULES[@]}"; do
        wget "$REPO_URL/$module" -O "$module" || error "Failed to download $module"
        chmod +x "$module"
    done

    # Execute protocol installations with PYTHONPATH set
    if [ "$INSTALL_SSH" = true ]; then
        log "Installing SSH and related protocols..."
        PYTHONPATH="/opt/irssh-panel/venv/lib/python3.8/site-packages" ./ssh-script.py --port "$SSH_PORT" || error "SSH installation failed"
        ./dropbear-script.sh --port "$DROPBEAR_PORT" || error "Dropbear installation failed"
        ./webport-script.sh --port "$WEBSOCKET_PORT" || error "WebSocket installation failed"
    fi

    if [ "$INSTALL_L2TP" = true ]; then
        log "Installing L2TP/IPsec..."
        PYTHONPATH="/opt/irssh-panel/venv/lib/python3.8/site-packages" ./l2tpv3-script.sh --port "$L2TP_PORT" || error "L2TP installation failed"
    fi

    if [ "$INSTALL_IKEV2" = true ]; then
        log "Installing IKEv2..."
        PYTHONPATH="/opt/irssh-panel/venv/lib/python3.8/site-packages" ./ikev2-script.py --port "$IKEV2_PORT" || error "IKEv2 installation failed"
    fi

    if [ "$INSTALL_CISCO" = true ]; then
        log "Installing Cisco AnyConnect..."
        ./cisco-script.sh --port "$CISCO_PORT" || error "Cisco installation failed"
    fi

    if [ "$INSTALL_WIREGUARD" = true ]; then
        log "Installing WireGuard..."
        ./wire-script.sh --port "$WIREGUARD_PORT" || error "WireGuard installation failed"
    fi

    if [ "$INSTALL_SINGBOX" = true ]; then
        log "Installing SingBox..."
        ./singbox-script.sh --port "$SINGBOX_PORT" || error "SingBox installation failed"
    fi

    # Install BadVPN if required
    ./badvpn-script.sh --port "$BADVPN_PORT" || error "BadVPN installation failed"

    # Configure VPN server settings
    PYTHONPATH="/opt/irssh-panel/venv/lib/python3.8/site-packages" ./vpnserver-script.py --configure || error "VPN server configuration failed"
    PYTHONPATH="/opt/irssh-panel/venv/lib/python3.8/site-packages" ./port-script.py --update-all || error "Port configuration failed"

    # Deactivate virtual environment
    deactivate
    
    log "All protocols installed successfully"
}

install_ssh() {
    log "Configuring SSH server..."
    
    # Install openssh-server and stunnel4
    apt-get install -y openssh-server stunnel4 || error "Failed to install SSH server packages"
    
    # Install websocat manually
    log "Installing websocat..."
    WEBSOCAT_VERSION="1.11.0"
    WEBSOCAT_URL="https://github.com/vi/websocat/releases/download/v${WEBSOCAT_VERSION}/websocat.x86_64-unknown-linux-musl"
    
    wget -O /usr/local/bin/websocat "$WEBSOCAT_URL" || error "Failed to download websocat"
    chmod +x /usr/local/bin/websocat || error "Failed to set websocat permissions"

    # Backup and configure SSH
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    cat > /etc/ssh/sshd_config << EOL
Port $SSH_PORT
PermitRootLogin yes
PasswordAuthentication yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem       sftp    /usr/lib/openssh/sftp-server
EOL

    # Configure stunnel
    mkdir -p /etc/stunnel
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/stunnel/stunnel.pem \
        -out /etc/stunnel/stunnel.pem \
        -subj "/CN=localhost" || error "Failed to generate SSL certificate"

    chmod 600 /etc/stunnel/stunnel.pem

    # Create stunnel configuration
cat > /etc/stunnel/stunnel.conf << "EOL"
pid = /var/run/stunnel4/stunnel.pid
setuid = stunnel4
setgid = stunnel4
cert = /etc/stunnel/stunnel.pem
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

# Debugging
debug = 7
output = /var/log/stunnel4/stunnel.log

[ssh-tls]
client = no
accept = 4433
connect = 127.0.0.1:22
EOL

    # Set correct permissions
    chown stunnel4:stunnel4 /etc/stunnel/stunnel.conf
    chmod 644 /etc/stunnel/stunnel.conf
    chown stunnel4:stunnel4 /etc/stunnel/stunnel.pem
    chmod 600 /etc/stunnel/stunnel.pem

    # Create required directories
    mkdir -p /var/run/stunnel4
    chown stunnel4:stunnel4 /var/run/stunnel4

    # Configure WebSocket service
    cat > /etc/systemd/system/websocket.service << EOL
[Unit]
Description=WebSocket for SSH
After=network.target

[Service]
ExecStart=/usr/local/bin/websocat -t --binary-protocol ws-l:0.0.0.0:${WEBSOCKET_PORT} tcp:127.0.0.1:${SSH_PORT}
Restart=always

[Install]
WantedBy=multi-user.target
EOL

    # Reload systemd and enable services
    systemctl daemon-reload
    systemctl restart ssh
    systemctl enable stunnel4
    systemctl restart stunnel4
    systemctl enable websocket
    systemctl start websocket

    log "SSH server configuration completed successfully"
}

# [Other protocol installation functions go here - L2TP, IKEv2, Cisco, WireGuard, SingBox]
# These functions would be directly copied from your original IRSSHComplete6.sh

setup_typescript() {
    log "Setting up TypeScript configuration..."
    cd "$FRONTEND_DIR" || error "Failed to access frontend directory"
    
    # Create tsconfig.json
    cat > tsconfig.json << 'EOL'
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"]
    },
    "noUnusedLocals": false,
    "noUnusedParameters": false
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
}
EOL

    cat > tsconfig.node.json << 'EOL'
{
  "compilerOptions": {
    "composite": true,
    "skipLibCheck": true,
    "module": "ESNext",
    "moduleResolution": "bundler",
    "allowSyntheticDefaultImports": true
  },
  "include": ["vite.config.ts"]
}
EOL
}

setup_stores() {
    log "Setting up Zustand stores..."
    mkdir -p "$FRONTEND_DIR/src/stores"
    
    # Create roleStore.ts
    cat > "$FRONTEND_DIR/src/stores/roleStore.ts" << 'EOL'
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export interface User {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  createdAt: Date;
  lastLogin?: Date;
  status: UserStatus;
  protocol: Protocol;
}

export enum UserRole {
  ADMIN = 'admin',
  USER = 'user',
  RESELLER = 'reseller'
}

export enum UserStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  EXPIRED = 'expired',
  SUSPENDED = 'suspended'
}

export enum Protocol {
  SSH = 'ssh',
  L2TP = 'l2tp',
  IKEV2 = 'ikev2',
  CISCO = 'cisco',
  WIREGUARD = 'wireguard',
  SINGBOX = 'singbox'
}

interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  setUser: (user: User | null) => void;
  setToken: (token: string | null) => void;
  logout: () => void;
}

const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      token: null,
      isAuthenticated: false,
      setUser: (user) => set({ user, isAuthenticated: !!user }),
      setToken: (token) => set({ token }),
      logout: () => set({ user: null, token: null, isAuthenticated: false }),
    }),
    {
      name: 'auth-storage',
    }
  )
);

export default useAuthStore;
EOL

    # Create themeStore.ts
    cat > "$FRONTEND_DIR/src/stores/themeStore.ts" << 'EOL'
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface ThemeState {
  isDark: boolean;
  toggleTheme: () => void;
}

const useThemeStore = create<ThemeState>()(
  persist(
    (set) => ({
      isDark: false,
      toggleTheme: () => set((state) => ({ isDark: !state.isDark })),
    }),
    {
      name: 'theme-storage',
    }
  )
);

export default useThemeStore;
EOL
}

setup_frontend() {
    log "Setting up frontend application..."
    cd "$FRONTEND_DIR" || error "Failed to access frontend directory"

    # Create package.json
    cat > package.json << 'EOL'
{
  "name": "irssh-panel-frontend",
  "version": "3.5.0",
  "type": "module",
  "private": true,
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "@headlessui/react": "^1.7.17",
    "@heroicons/react": "^2.0.18",
    "axios": "^1.6.2",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.21.0",
    "react-query": "^3.39.3",
    "react-hot-toast": "^2.4.1",
    "zustand": "^4.4.7"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.2.1",
    "@vitejs/plugin-react-swc": "^3.5.0",
    "@types/node": "^20.10.4",
    "@types/react": "^18.2.45",
    "@types/react-dom": "^18.2.17",
    "typescript": "^5.3.3",
    "autoprefixer": "^10.4.16",
    "postcss": "^8.4.32",
    "tailwindcss": "^3.3.6",
    "vite": "^5.0.7"
  }
}
EOL

    # Clean install
    rm -rf node_modules package-lock.json
    npm install || error "Frontend dependency installation failed"

    # Create postcss.config.cjs
    cat > postcss.config.cjs << 'EOL'
module.exports = {
  plugins: {
    tailwindcss: {},
    autoprefixer: {}
  }
}
EOL

   # Create vite.config.ts with plugin-react-swc
    cat > vite.config.ts << 'EOL'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  }
})
EOL

    # Create tailwind.config.cjs
    cat > tailwind.config.cjs << 'EOL'
module.exports = {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {},
  },
  plugins: []
}
EOL

    # Create index.html
    cat > index.html << 'EOL'
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>IRSSH Panel</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
EOL

    # Create src directory structure
    mkdir -p src/{components/layout,pages,context,lib}

    # Create main.tsx
    cat > src/main.tsx << 'EOL'
import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>,
)
EOL

    # Create index.css
    cat > src/index.css << 'EOL'
@tailwind base;
@tailwind components;
@tailwind utilities;
EOL

    # Create App.tsx
    cat > src/App.tsx << 'EOL'
import { Routes, Route } from 'react-router-dom'
import MainLayout from './components/layout/MainLayout'
import Dashboard from './pages/Dashboard'
import Users from './pages/Users'
import OnlineUsers from './pages/OnlineUsers'
import Settings from './pages/Settings'
import Login from './pages/Login'

const App = () => {
  return (
    <Routes>
      <Route path="/" element={<MainLayout />}>
        <Route index element={<Dashboard />} />
        <Route path="users" element={<Users />} />
        <Route path="online-users" element={<OnlineUsers />} />
        <Route path="settings" element={<Settings />} />
      </Route>
      <Route path="/login" element={<Login />} />
    </Routes>
  )
}

export default App
EOL

    # Create pages and components
    for page in Dashboard Users OnlineUsers Settings Login; do
        cat > "src/pages/${page}.tsx" << EOL
const ${page} = () => {
  return (
    <div>
      <h1 className="text-2xl font-bold">${page}</h1>
    </div>
  );
};

export default ${page};
EOL
    done

    # Create MainLayout
    cat > src/components/layout/MainLayout.tsx << 'EOL'
import { Outlet } from 'react-router-dom'

const MainLayout = () => {
  return (
    <div className="min-h-screen bg-white dark:bg-gray-900">
      <div className="container mx-auto px-4">
        <Outlet />
      </div>
    </div>
  );
};

export default MainLayout;
EOL

    # Setup TypeScript
    setup_typescript

    # Setup stores
    setup_stores

    # Build frontend
    npm run build || error "Frontend build failed"
}

setup_backend() {
    log "Setting up backend server..."
    cd "$BACKEND_DIR" || error "Failed to access backend directory"

    # Create package.json for backend
    cat > package.json << 'EOL'
{
  "name": "irssh-panel-backend",
  "version": "3.5.0",
  "private": true,
  "scripts": {
    "start": "node src/index.js",
    "start:dev": "nodemon src/index.js",
    "test": "jest",
    "lint": "eslint ."
  },
  "dependencies": {
    "express": "^4.18.2",
    "mongoose": "^8.0.3",
    "jsonwebtoken": "^9.0.2",
    "bcryptjs": "^2.4.3",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "helmet": "^7.1.0",
    "winston": "^3.11.0",
    "express-validator": "^7.0.1",
    "express-rate-limit": "^7.1.5",
    "compression": "^1.7.4"
  },
  "devDependencies": {
    "nodemon": "^3.0.2",
    "jest": "^29.7.0",
    "supertest": "^6.3.3",
    "eslint": "^8.55.0"
  }
}
EOL

    # Install dependencies
    npm install || error "Backend dependency installation failed"

    # Create systemd service for backend
    cat > /etc/systemd/system/irssh-backend.service << EOL
[Unit]
Description=IRSSH Panel Backend
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${BACKEND_DIR}
ExecStart=/usr/bin/node src/index.js
Restart=always
Environment=NODE_ENV=production
Environment=PORT=8000

[Install]
WantedBy=multi-user.target
EOL

    # Setup CORS configuration
    mkdir -p src/middleware
    cat > src/middleware/cors.js << 'EOL'
const cors = require('cors');

const corsOptions = {
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 86400
};

module.exports = cors(corsOptions);
EOL

    # Create main server file
    cat > src/index.js << 'EOL'
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const cors = require('./middleware/cors');
const path = require('path');

const app = express();

// Security middleware
app.use(helmet());
app.use(cors);
app.use(compression());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// API Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/users', require('./routes/users'));
app.use('/api/protocols', require('./routes/protocols'));
app.use('/api/monitoring', require('./routes/monitoring'));

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.status(200).json({ status: 'ok' });
});

// Serve static frontend
app.use(express.static(path.join(__dirname, '../../frontend/dist')));

// Handle React routing
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../../frontend/dist/index.html'));
});

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

process.on('unhandledRejection', (err) => {
    console.error('Unhandled Promise Rejection:', err);
});
EOL

    # Create basic route files
    mkdir -p src/routes
    for route in auth users protocols monitoring; do
        cat > "src/routes/${route}.js" << EOL
const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
    res.json({ message: '${route} endpoint' });
});

module.exports = router;
EOL
    done

    # Create environment configuration
    cat > .env << EOL
NODE_ENV=production
PORT=8000
JWT_SECRET=${JWT_SECRET}
FRONTEND_URL=http://localhost:${WEB_PORT}
DB_HOST=localhost
DB_PORT=5432
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASS=${DB_PASS}
EOL

    # Set proper permissions
    chmod 600 .env

    # Reload systemd and start backend service
    systemctl daemon-reload
    systemctl enable irssh-backend
    systemctl start irssh-backend

    log "Backend setup completed successfully"
}

setup_nginx() {
    log "Configuring Nginx..."

    # Stop any service using required ports
    fuser -k "${WEB_PORT}/tcp" 2>/dev/null || true
    systemctl stop nginx

    # Check for existing configuration
    if [ -f "/etc/nginx/sites-enabled/default" ]; then
        rm -f /etc/nginx/sites-enabled/default
    fi

    # Create Nginx configuration
    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen ${WEB_PORT};
    listen [::]:${WEB_PORT};
    server_name _;

    root ${FRONTEND_DIR}/dist;
    index index.html;

    # Enable gzip compression
    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    # Serve static files
    location / {
        try_files \$uri \$uri/ /index.html;
        add_header Cache-Control "public, no-cache";
    }

    # Backend API proxy
    location /api {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOL

    # Set correct permissions
    chown -R www-data:www-data ${FRONTEND_DIR}/dist
    chmod -R 755 ${FRONTEND_DIR}/dist

    # Enable site configuration
    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/

    # Test configuration
    nginx -t || error "Nginx configuration test failed"

    # Start Nginx with debug output
    systemctl start nginx || {
        log "Nginx failed to start. Checking logs..."
        journalctl -xe --unit=nginx.service
        error "Failed to start Nginx. See logs above."
    }

    log "Nginx configuration completed successfully"
}

verify_installation() {
    log "Verifying installation..."
    
    # Check critical services
    services=("nginx" "postgresql")
    for service in "${services[@]}"; do
        systemctl is-active --quiet "$service" || error "Service $service is not running"
    done

    # Check frontend build
    [ -d "$FRONTEND_DIR/build" ] || error "Frontend build directory not found"

    # Check backend
    curl -s http://localhost:8000/api/health > /dev/null || error "Backend health check failed"

    # Check database
    su - postgres -c "psql -d $DB_NAME -c '\q'" || error "Database connection failed"

    log "Installation verification completed successfully"
}

save_installation_info() {
    log "Saving installation information..."
    
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_DIR/installation.info" << EOL
Installation Date: $(date +"%Y-%m-%d %H:%M:%S")
Version: 3.5.0
Web Port: ${WEB_PORT}
SSH Port: ${SSH_PORT}
Database Name: ${DB_NAME}
Database User: ${DB_USER}
Installation Directory: ${PANEL_DIR}
Frontend URL: http://localhost:${WEB_PORT}
Backend URL: http://localhost:8000
EOL

    chmod 600 "$CONFIG_DIR/installation.info"
    log "Installation information saved successfully"
}

setup_ssl() {
    log "Setting up SSL certificates..."
    
    # Create SSL directory
    mkdir -p /etc/nginx/ssl
    
    # Generate self-signed certificate
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/irssh-panel.key \
        -out /etc/nginx/ssl/irssh-panel.crt \
        -subj "/CN=irssh-panel" \
        || error "Failed to generate SSL certificate"
    
    # Set correct permissions
    chmod 600 /etc/nginx/ssl/irssh-panel.key
    chmod 644 /etc/nginx/ssl/irssh-panel.crt
    
    log "SSL certificates setup completed"
}

setup_firewall() {
    log "Setting up firewall rules..."

    # Install UFW if not present
    apt-get install -y ufw || error "Failed to install UFW"

    # Reset UFW to default state
    ufw --force reset

    # Default policies
    ufw default deny incoming
    ufw default allow outgoing

    # Allow SSH
    ufw allow ${SSH_PORT}/tcp

    # Allow web ports
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    # Allow other VPN protocols
    [ "$INSTALL_L2TP" = true ] && ufw allow ${L2TP_PORT}/tcp
    [ "$INSTALL_IKEV2" = true ] && ufw allow ${IKEV2_PORT}/udp
    [ "$INSTALL_CISCO" = true ] && ufw allow ${CISCO_PORT}/tcp
    [ "$INSTALL_WIREGUARD" = true ] && ufw allow ${WIREGUARD_PORT}/udp
    [ "$INSTALL_SINGBOX" = true ] && ufw allow ${SINGBOX_PORT}/tcp

    # Allow websocket port if needed
    ufw allow ${WEBSOCKET_PORT}/tcp

    # Enable UFW non-interactively
    echo "y" | ufw enable

    log "Firewall setup completed"
}

setup_security() {
    log "Setting up additional security measures..."

    # Install fail2ban if not present
    apt-get install -y fail2ban || error "Failed to install fail2ban"

    # Configure fail2ban
    cat > /etc/fail2ban/jail.local << 'EOL'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh,22722
logpath = %(sshd_log)s
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
port = http,https
logpath = /var/log/nginx/error.log

[nginx-botsearch]
enabled = true
filter = nginx-botsearch
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 2
EOL

    # Set secure permissions on important directories
    chmod 700 "$CONFIG_DIR"
    chmod 700 "$LOG_DIR"
    
    # Secure shared memory
    echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
    
    # Update SSH configuration for better security
    sed -i 's/#PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    
    # Restart security services
    systemctl restart fail2ban
    systemctl enable fail2ban
    
    log "Security setup completed"
}

setup_cron() {
    log "Setting up cron jobs..."

    # Create cron directory if not exists
    mkdir -p "$PANEL_DIR/cron"

    # Create cleanup script
    cat > "$PANEL_DIR/cron/cleanup.sh" << 'EOL'
#!/bin/bash
# Cleanup old logs
find /var/log/irssh -type f -name "*.log" -mtime +30 -delete
# Cleanup old backups
find /opt/irssh-backups -type f -mtime +7 -delete
EOL
    chmod +x "$PANEL_DIR/cron/cleanup.sh"

    # Add cron jobs
    (crontab -l 2>/dev/null || true; echo "0 0 * * * $PANEL_DIR/cron/cleanup.sh") | crontab -
    (crontab -l 2>/dev/null || true; echo "*/5 * * * * systemctl is-active --quiet nginx || systemctl restart nginx") | crontab -
    (crontab -l 2>/dev/null || true; echo "*/5 * * * * systemctl is-active --quiet stunnel4 || systemctl restart stunnel4") | crontab -

    log "Cron jobs setup completed"
}

verify_installation() {
    log "Verifying installation..."
    
    # Check critical services
    services=("nginx" "postgresql" "stunnel4" "fail2ban" "irssh-backend")
    for service in "${services[@]}"; do
        if ! systemctl is-active --quiet "$service"; then
            error "Service $service is not running"
        fi
    done

    # Check frontend build
    if [ ! -d "$FRONTEND_DIR/dist" ]; then
        error "Frontend build directory not found"
    fi

    # Wait for backend to be ready (max 30 seconds)
    local max_attempts=30
    local attempt=1
    while ! curl -s http://localhost:8000/api/health > /dev/null; do
        if [ $attempt -ge $max_attempts ]; then
            error "Backend health check failed after $max_attempts attempts"
        fi
        log "Waiting for backend to be ready... (attempt $attempt/$max_attempts)"
        sleep 1
        ((attempt++))
    done

    # Check database
    if ! su - postgres -c "psql -d $DB_NAME -c '\q'" 2>/dev/null; then
        error "Database connection failed"
    fi

    # Check SSL certificates
    if [ ! -f "/etc/nginx/ssl/irssh-panel.crt" ] || [ ! -f "/etc/nginx/ssl/irssh-panel.key" ]; then
        error "SSL certificates not found"
    fi

    log "Installation verification completed successfully"
}

save_installation_info() {
    log "Saving installation information..."
    
    # Create config directory if not exists
    mkdir -p "$CONFIG_DIR"
    
    # Save installation details
    cat > "$CONFIG_DIR/installation.info" << EOL
Installation Date: $(date +"%Y-%m-%d %H:%M:%S")
Version: 3.5.0
Web Port: ${WEB_PORT}
SSH Port: ${SSH_PORT}
Database Name: ${DB_NAME}
Database User: ${DB_USER}
Installation Directory: ${PANEL_DIR}
Frontend URL: http://localhost:${WEB_PORT}
Backend URL: http://localhost:8000
EOL

    # Set secure permissions
    chmod 600 "$CONFIG_DIR/installation.info"
    
    log "Installation information saved successfully"
}

# Main installation flow
main() {
    trap cleanup EXIT
    
    log "Starting IRSSH Panel installation v3.5.0"
    
    check_requirements
    create_backup
    setup_directories
    install_dependencies
    setup_python_environment
    generate_secrets
    setup_database
    install_protocols
    setup_typescript
    setup_stores
    setup_frontend
    setup_backend
    setup_nginx
    setup_ssl
    setup_firewall
    setup_security
    setup_cron
    verify_installation
    save_installation_info
        
    log "Installation completed successfully!"
    
    # Display installation summary
    echo
    echo "IRSSH Panel has been installed successfully!"
    echo "Admin Credentials:"
    echo "Username: admin"
    echo "Password: $ADMIN_PASS"
    echo
    echo "Installation information saved to: $CONFIG_DIR/installation.info"
    echo "Access the panel at: http://YOUR-SERVER-IP:$WEB_PORT"
}

# Start installation
main
