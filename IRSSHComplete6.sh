#!/bin/bash

# IRSSH Panel Complete Installation Script
# Version: 3.5.0

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
    source "$PANEL_DIR/venv/bin/activate"

# Check and create virtual environment
if [ ! -d "/opt/irssh-panel/venv" ]; then
    python3 -m venv /opt/irssh-panel/venv
fi

# Activate virtual environment
source /opt/irssh-panel/venv/bin/activate

# Update pip in venv
/opt/irssh-panel/venv/bin/pip install --upgrade pip setuptools wheel

    # Install packages in venv
/opt/irssh-panel/venv/bin/pip install \
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
        elasticsearch \
        numpy \
        pandas \
        scipy \
        matplotlib \
        seaborn \
        scikit-learn \
        tensorflow-cpu \
        jupyter \
        ipython \
        kubernetes \
        grpcio \
        grpcio-tools \
        ansible \
        pyopenssl \
        kafka-python \
        pika \
        apache-beam \
        helm \
        python-consul \
        nomad \
        mlflow \
        bentoml \
        seldon-core \
        prefect \
        dask \
        opentelemetry-sdk \
        opentelemetry-exporter-jaeger \
        datadog \
        sentry-sdk \
        newrelic \
        grafana-api \
        || error "Failed to install Python libraries"

# Deactivate virtual environment after installation
deactivate

# Install Consul
apt-get install -y consul

    # Create symbolic links for required packages
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    SITE_PACKAGES="$PANEL_DIR/venv/lib/python${PYTHON_VERSION}/site-packages"
    
    # Create symbolic links for all major packages
    for package in prometheus_client psycopg2 requests psutil; do
        if [ -d "$SITE_PACKAGES/$package" ]; then
            ln -sf "$SITE_PACKAGES/$package" /usr/lib/python3/dist-packages/ || warn "Failed to create symlink for $package"
        fi
    done
    
    # Add virtual environment to system path
    echo "export PATH=$PANEL_DIR/venv/bin:$PATH" > /etc/profile.d/irssh.sh
    echo "source $PANEL_DIR/venv/bin/activate" >> /etc/profile.d/irssh.sh
    chmod +x /etc/profile.d/irssh.sh
    
    # Verify installations
    log "Verifying Python package installations..."
    python3 -c "import prometheus_client, psycopg2, requests, psutil" || error "Failed to verify Python packages"
    
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

    # Create modules directory
    mkdir -p "$MODULES_DIR/protocols"
    cd "$MODULES_DIR/protocols" || error "Failed to access modules directory"

    # Download protocol modules from GitHub
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

    # Execute protocol installations
    if [ "$INSTALL_SSH" = true ]; then
        log "Installing SSH and related protocols..."
        ./ssh-script.py --port "$SSH_PORT" || error "SSH installation failed"
        ./dropbear-script.sh --port "$DROPBEAR_PORT" || error "Dropbear installation failed"
        ./webport-script.sh --port "$WEBSOCKET_PORT" || error "WebSocket installation failed"
    fi

    if [ "$INSTALL_L2TP" = true ]; then
        log "Installing L2TP/IPsec..."
        ./l2tpv3-script.sh --port "$L2TP_PORT" || error "L2TP installation failed"
    fi

    if [ "$INSTALL_IKEV2" = true ]; then
        log "Installing IKEv2..."
        ./ikev2-script.py --port "$IKEV2_PORT" || error "IKEv2 installation failed"
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
    ./vpnserver-script.py --configure || error "VPN server configuration failed"
    ./port-script.py --update-all || error "Port configuration failed"

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

    # Configure stunnel for SSH-TLS
    mkdir -p /etc/stunnel
    cat > /etc/stunnel/stunnel.conf << EOL
cert = /etc/stunnel/stunnel.pem
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh-tls]
accept = $SSH_TLS_PORT
connect = 127.0.0.1:$SSH_PORT
EOL

    # Generate self-signed certificate for stunnel
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/stunnel/stunnel.pem \
        -out /etc/stunnel/stunnel.pem \
        -subj "/CN=localhost" || error "Failed to generate SSL certificate"

    # Configure WebSocket service
    cat > /etc/systemd/system/websocket.service << EOL
[Unit]
Description=WebSocket for SSH
After=network.target

[Service]
ExecStart=/usr/local/bin/websocat -t --binary-protocol ws-l:0.0.0.0:$WEBSOCKET_PORT tcp:127.0.0.1:$SSH_PORT
Restart=always

[Install]
WantedBy=multi-user.target
EOL

    # Enable and start services
    systemctl daemon-reload
    systemctl enable stunnel4 websocket
    systemctl restart ssh stunnel4
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
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "baseUrl": "./src",
    "paths": {
      "@/*": ["*"],
      "@components/*": ["components/*"],
      "@stores/*": ["stores/*"],
      "@context/*": ["context/*"],
      "@utils/*": ["utils/*"],
      "@hooks/*": ["hooks/*"],
      "@types/*": ["types/*"]
    }
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
  "private": true,
  "dependencies": {
    "@headlessui/react": "^1.7.17",
    "@heroicons/react": "^2.0.18",
    "axios": "^1.6.2",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.21.0",
    "recharts": "^2.10.3",
    "zustand": "^4.4.7",
    "clsx": "^2.0.0",
    "@types/node": "^20.10.4",
    "@types/react": "^18.2.45",
    "@types/react-dom": "^18.2.17",
    "typescript": "^5.3.3"
  },
  "devDependencies": {
    "@typescript-eslint/eslint-plugin": "^6.14.0",
    "@typescript-eslint/parser": "^6.14.0",
    "@vitejs/plugin-react-swc": "^3.5.0",
    "autoprefixer": "^10.4.16",
    "eslint": "^8.55.0",
    "eslint-plugin-react-hooks": "^4.6.0",
    "eslint-plugin-react-refresh": "^0.4.5",
    "postcss": "^8.4.32",
    "tailwindcss": "^3.3.6",
    "vite": "^5.0.7"
  },
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "lint": "eslint src --ext ts,tsx --report-unused-disable-directives --max-warnings 0",
    "preview": "vite preview"
  }
}
EOL

    # Install dependencies
    npm install --legacy-peer-deps || error "Frontend dependency installation failed"

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

    # Install backend dependencies
    npm install || error "Backend dependency installation failed"

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

    # Create backend server configuration
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

// Serve static frontend
app.use(express.static(path.join(__dirname, '../../frontend/build')));

// Handle React routing
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../../frontend/build/index.html'));
});

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

process.on('unhandledRejection', (err) => {
    console.error('Unhandled Promise Rejection:', err);
});
EOL

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
}

setup_nginx() {
    log "Configuring Nginx..."
    
    # Create Nginx configuration
    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen ${WEB_PORT};
    listen [::]:${WEB_PORT};
    server_name _;

    root ${FRONTEND_DIR}/build;
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
        proxy_cache_bypass \$http_upgrade;
    }
}
EOL

    # Enable site configuration
    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default

    # Test and restart Nginx
    nginx -t || error "Nginx configuration test failed"
    systemctl restart nginx
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
    
    cat > "$CONFIG_DIR/installation.info" << EOL
Installation Date: $(date +"%Y-%m-%d %H:%M:%S")
Version: 3.5.0
Web Port: ${WEB_PORT}
SSH Port: ${SSH_PORT}
Database Name: ${DB_NAME}
Database User: ${DB_USER}
EOL
    chmod 600 "$CONFIG_DIR/installation.info"
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
