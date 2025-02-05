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
    log "Checking system requirements..."
    
    # Check root privileges
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root"
    fi

    # Check OS
    if [ ! -f /etc/os-release ]; then
        error "Unsupported operating system"
    fi
    
    # Check minimum system resources
    local mem_total=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$mem_total" -lt 1024 ]; then
        warn "System has less than 1GB RAM. Performance may be affected."
    fi

    # Check required commands
    local required_commands=("curl" "wget" "git" "tar" "unzip")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            error "Required command '$cmd' not found. Please install it first."
        fi
    done
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
    
    # Update package lists
    apt-get update || error "Failed to update package lists"
    
    # Install essential packages
    apt-get install -y \
        curl \
        wget \
        git \
        unzip \
        build-essential \
        python3 \
        python3-pip \
        nginx \
        postgresql \
        postgresql-contrib \
        ufw \
        fail2ban \
        || error "Failed to install essential packages"

    # Install Node.js (LTS version)
    if ! command -v node &> /dev/null; then
        log "Installing Node.js..."
        curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
        apt-get install -y nodejs || error "Failed to install Node.js"
    fi

    # Install global npm packages
    npm install -g pm2 typescript @types/node || error "Failed to install global npm packages"
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
    log "Installing VPN protocols..."

    if [ "$INSTALL_SSH" = true ]; then
        install_ssh
    fi

    if [ "$INSTALL_L2TP" = true ]; then
        install_l2tp
    fi

    if [ "$INSTALL_IKEV2" = true ]; then
        install_ikev2
    fi

    if [ "$INSTALL_CISCO" = true ]; then
        install_cisco
    fi

    if [ "$INSTALL_WIREGUARD" = true ]; then
        install_wireguard
    fi

    if [ "$INSTALL_SINGBOX" = true ]; then
        install_singbox
    fi
}

install_ssh() {
    log "Configuring SSH server..."
    apt-get install -y openssh-server stunnel4 websocat || error "Failed to install SSH dependencies"

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
ExecStart=/usr/bin/websocat -t --binary-protocol ws-l:0.0.0.0:$WEBSOCKET_PORT tcp:127.0.0.1:$SSH_PORT
Restart=always

[Install]
WantedBy=multi-user.target
EOL

    # Enable and start services
    systemctl enable stunnel4 websocket
    systemctl restart ssh stunnel4
    systemctl start websocket
}

# [Other protocol installation functions go here - L2TP, IKEv2, Cisco, WireGuard, SingBox]
# These functions would be directly copied from your original IRSSHComplete4.sh

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
