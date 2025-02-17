#!/bin/bash

# IRSSH Panel Complete Installation Script
# Version: 3.5.2

# Base Configuration
###########################################

# Base directories
PANEL_DIR="/opt/irssh-panel"
CONFIG_DIR="/etc/enhanced_ssh"
LOG_DIR="/var/log/irssh"
BACKUP_DIR="/opt/irssh-backups"
TEMP_DIR="/tmp/irssh-install"
SSL_DIR="/etc/nginx/ssl"

# Protocol Installation Modes
declare -A PROTOCOLS=(
    ["SSH"]=true
    ["DROPBEAR"]=true
    ["L2TP"]=true
    ["IKEV2"]=true
    ["CISCO"]=true
    ["WIREGUARD"]=true
    ["SINGBOX"]=true
)

# Protocol Ports
declare -A PORTS=(
    ["SSH"]=22
    ["DROPBEAR"]=22722
    ["WEBSOCKET"]=2082
    ["SSH_TLS"]=443
    ["L2TP"]=1701
    ["IKEV2"]=500
    ["CISCO"]=443
    ["WIREGUARD"]=51820
    ["SINGBOX"]=1080
    ["BADVPN"]=7300
)

# Colors for output
declare -A COLORS=(
    ["GREEN"]='\033[0;32m'
    ["RED"]='\033[0;31m'
    ["YELLOW"]='\033[1;33m'
    ["BLUE"]='\033[0;34m'
    ["NC"]='\033[0m'
)

# Version Information
VERSION="3.5.2"
MIN_NODE_VERSION=16
MIN_PYTHON_VERSION="3.8"
REQUIRED_MEMORY=1024
REQUIRED_DISK=5120

# User Configuration Variables
ADMIN_USER=""
ADMIN_PASS=""
WEB_PORT=""
UDPGW_PORT=""
ENABLE_HTTPS="n"

# Get initial configuration from user
get_initial_config() {
    log "INFO" "Initial Configuration Setup"
    
    # Get admin credentials
    while [ -z "$ADMIN_USER" ]; do
        read -p "Enter admin username: " ADMIN_USER
    done
    
    while [ -z "$ADMIN_PASS" ]; do
        read -s -p "Enter admin password: " ADMIN_PASS
        echo
        read -s -p "Confirm admin password: " ADMIN_PASS_CONFIRM
        echo
        
        if [ "$ADMIN_PASS" != "$ADMIN_PASS_CONFIRM" ]; then
            log "ERROR" "Passwords do not match"
            ADMIN_PASS=""
        fi
    done
    
    # Get web port
    while true; do
        read -p "Enter web panel port (4-5 digits) or press Enter for random port: " WEB_PORT
        if [ -z "$WEB_PORT" ]; then
            WEB_PORT=$(shuf -i 1234-65432 -n 1)
            log "INFO" "Generated random port: $WEB_PORT"
            break
        elif [[ "$WEB_PORT" =~ ^[0-9]{4,5}$ ]] && [ "$WEB_PORT" -ge 1234 ] && [ "$WEB_PORT" -le 65432 ]; then
            break
        else
            log "ERROR" "Invalid port number. Must be between 1234 and 65432"
        fi
    done
    PORTS["WEB"]=$WEB_PORT
    
    # Get UDPGW port
    while true; do
        read -p "Enter UDPGW port (4-5 digits) or press Enter for random port: " UDPGW_PORT
        if [ -z "$UDPGW_PORT" ]; then
            UDPGW_PORT=$(shuf -i 1234-65432 -n 1)
            log "INFO" "Generated random UDPGW port: $UDPGW_PORT"
            break
        elif [[ "$UDPGW_PORT" =~ ^[0-9]{4,5}$ ]] && [ "$UDPGW_PORT" -ge 1234 ] && [ "$UDPGW_PORT" -le 65432 ]; then
            break
        else
            log "ERROR" "Invalid port number. Must be between 1234 and 65432"
        fi
    done
    PORTS["UDPGW"]=$UDPGW_PORT
    
    # Confirm settings
    echo
    log "INFO" "Configuration Summary:"
    echo "Admin Username: $ADMIN_USER"
    echo "Web Panel Port: ${PORTS[WEB]}"
    echo "UDPGW Port: ${PORTS[UDPGW]}"
    
    read -p "Continue with these settings? (Y/n): " confirm
    if [[ "$confirm" =~ ^[Nn] ]]; then
        log "ERROR" "Installation cancelled by user"
        exit 1
    fi
}

# Logging Functions
###########################################

log() {
    local level=$1
    local message=$2
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    local color_code="${COLORS[${level}]:-${COLORS[NC]}}"
    
    echo -e "${color_code}[$timestamp] [$level] $message${COLORS[NC]}"
    echo "[$timestamp] [$level] $message" >> "$LOG_DIR/installation.log"
}

error() {
    log "ERROR" "$1"
    if [[ "${2:-}" != "no-exit" ]]; then
        cleanup
        exit 1
    fi
}

warn() {
    log "WARN" "$1"
}

info() {
    log "INFO" "$1"
}

# Setup Functions
###########################################

check_requirements() {
    info "Checking system requirements..."
    
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
    
    # Check system resources
    local MEM_TOTAL=$(free -m | awk '/^Mem:/{print $2}')
    local CPU_CORES=$(nproc)
    local DISK_SPACE=$(df -m / | awk 'NR==2 {print $4}')
    
    if [ "$MEM_TOTAL" -lt "$REQUIRED_MEMORY" ]; then
        warn "System has less than ${REQUIRED_MEMORY}MB RAM"
    fi
    
    if [ "$CPU_CORES" -lt 2 ]; then
        warn "System has less than 2 CPU cores"
    fi
    
    if [ "$DISK_SPACE" -lt "$REQUIRED_DISK" ]; then
        error "Insufficient disk space. At least ${REQUIRED_DISK}MB required"
    fi
    
    # Install Python 3.8 if not present
    if ! command -v python3.8 &> /dev/null; then
        info "Installing Python 3.8..."
        apt-get update
        apt-get install -y software-properties-common
        if [[ "$ID" == "ubuntu" ]]; then
            add-apt-repository -y ppa:deadsnakes/ppa
        fi
        apt-get update
        apt-get install -y python3.8 python3.8-venv python3.8-dev
        update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1
    fi
    
    # Install Node.js
    if ! command -v node &> /dev/null; then
        info "Installing Node.js..."
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        apt-get install -y nodejs
    fi
    
    NODE_VERSION=$(node -v | sed 's/v\([0-9]*\).*/\1/')
    if [ "$NODE_VERSION" -lt "$MIN_NODE_VERSION" ]; then
        error "Node.js version must be $MIN_NODE_VERSION or higher"
    fi
    
    info "System requirements check completed"
}

setup_directories() {
    info "Creating directory structure..."
    
    local directories=(
        "$PANEL_DIR"
        "$CONFIG_DIR"
        "$LOG_DIR"
        "$BACKUP_DIR"
        "$TEMP_DIR"
        "$PANEL_DIR/frontend"
        "$PANEL_DIR/backend"
        "$PANEL_DIR/modules/protocols"
        "$PANEL_DIR/venv"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
    done
    
    chmod 750 "$PANEL_DIR"
    chmod 700 "$CONFIG_DIR"
    chmod 750 "$LOG_DIR"
    chmod 750 "$BACKUP_DIR"
    
    info "Directory structure created successfully"
}

# Generate and configure basic settings
generate_config() {
    info "Generating configuration..."
    
    # Generate secure credentials
    local DB_NAME="ssh_manager"
    local DB_USER="irssh_admin"
    local DB_PASS=$(openssl rand -base64 32)
    local JWT_SECRET=$(openssl rand -base64 32)
    
    # Create main config file
    cat > "$CONFIG_DIR/config.yaml" << EOL
# IRSSH Panel Configuration
# Generated: $(date +'%Y-%m-%d %H:%M:%S')

# Database Configuration
db_host: localhost
db_port: 5432
db_name: $DB_NAME
db_user: $DB_USER
db_password: $DB_PASS

# Web Panel Configuration
web_port: ${PORTS[WEB]}
jwt_secret: $JWT_SECRET

# Admin Credentials
admin_user: $ADMIN_USER
admin_password_hash: $(echo -n "$ADMIN_PASS" | sha256sum | cut -d' ' -f1)

# Protocol Ports
ssh_port: ${PORTS[SSH]}
dropbear_port: ${PORTS[DROPBEAR]}
websocket_port: ${PORTS[WEBSOCKET]}
l2tp_port: ${PORTS[L2TP]}
ikev2_port: ${PORTS[IKEV2]}
cisco_port: ${PORTS[CISCO]}
wireguard_port: ${PORTS[WIREGUARD]}
singbox_port: ${PORTS[SINGBOX]}
udpgw_port: ${PORTS[UDPGW]}

# Protocol Settings
enable_ssh: ${PROTOCOLS[SSH]}
enable_dropbear: ${PROTOCOLS[DROPBEAR]}
enable_l2tp: ${PROTOCOLS[L2TP]}
enable_ikev2: ${PROTOCOLS[IKEV2]}
enable_cisco: ${PROTOCOLS[CISCO]}
enable_wireguard: ${PROTOCOLS[WIREGUARD]}
enable_singbox: ${PROTOCOLS[SINGBOX]}
EOL

    chmod 600 "$CONFIG_DIR/config.yaml"
    
    # Export variables for other functions
    export DB_NAME DB_USER DB_PASS JWT_SECRET
    
    info "Configuration generated successfully"
}

# Setup Frontend Dependencies
setup_frontend() {
    info "Setting up frontend application..."
    
    cd "$PANEL_DIR/frontend" || error "Failed to access frontend directory"
    
    # Create package.json
    cat > package.json << 'EOL'
{
  "name": "irssh-panel-frontend",
  "version": "3.5.2",
  "private": true,
  "dependencies": {
    "@headlessui/react": "^1.7.17",
    "@heroicons/react": "^2.0.18",
    "axios": "^1.6.2",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.21.0",
    "react-query": "^3.39.3",
    "zustand": "^4.4.7",
    "tailwindcss": "^3.3.6"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.2.1",
    "@types/node": "^20.10.4",
    "@types/react": "^18.2.45",
    "@types/react-dom": "^18.2.17",
    "typescript": "^5.3.3",
    "autoprefixer": "^10.4.16",
    "vite": "^5.0.7"
  },
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview"
  }
}
EOL

    # Create vite.config.js
    cat > vite.config.js << 'EOL'
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

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
  },
  server: {
    proxy: {
      '/api': 'http://localhost:8000'
    }
  }
});
EOL

    # Create src directory structure
    mkdir -p src/{components,pages,services,stores,styles}
    mkdir -p src/components/{common,layout}
    
    # Create main application files
    cat > src/App.tsx << 'EOL'
import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import MainLayout from './components/layout/MainLayout';
import ErrorBoundary from './components/common/ErrorBoundary';
import Dashboard from './pages/Dashboard';
import Users from './pages/Users';
import Settings from './pages/Settings';
import Login from './pages/Login';

const App = () => {
  return (
    <ErrorBoundary>
      <Router>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<MainLayout />}>
            <Route index element={<Dashboard />} />
            <Route path="users" element={<Users />} />
            <Route path="settings" element={<Settings />} />
          </Route>
        </Routes>
      </Router>
    </ErrorBoundary>
  );
};

export default App;
EOL

    # Create API service
    cat > src/services/api.ts << 'EOL'
import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  timeout: 10000,
});

api.interceptors.request.use(config => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
}, error => Promise.reject(error));

api.interceptors.response.use(
  response => response,
  error => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export default api;
EOL

    # Create store for authentication
    cat > src/stores/authStore.ts << 'EOL'
import create from 'zustand';

interface AuthState {
  user: any | null;
  token: string | null;
  setUser: (user: any) => void;
  setToken: (token: string) => void;
  logout: () => void;
}

const useAuthStore = create<AuthState>((set) => ({
  user: null,
  token: localStorage.getItem('token'),
  setUser: (user) => set({ user }),
  setToken: (token) => {
    localStorage.setItem('token', token);
    set({ token });
  },
  logout: () => {
    localStorage.removeItem('token');
    set({ user: null, token: null });
  },
}));

export default useAuthStore;
EOL

    # Install dependencies
    npm install || error "Failed to install frontend dependencies"
    
    # Build frontend
    npm run build || error "Failed to build frontend"
    
    info "Frontend setup completed"
}

# Setup Backend
setup_backend() {
    info "Setting up backend application..."
    
    cd "$PANEL_DIR/backend" || error "Failed to access backend directory"
    
    # Create package.json
    cat > package.json << 'EOL'
{
  "name": "irssh-panel-backend",
  "version": "3.5.2",
  "private": true,
  "dependencies": {
    "express": "^4.18.2",
    "mongoose": "^8.0.3",
    "jsonwebtoken": "^9.0.2",
    "bcryptjs": "^2.4.3",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "helmet": "^7.1.0",
    "winston": "^3.11.0",
    "pg": "^8.11.3",
    "sequelize": "^6.35.1"
  },
  "devDependencies": {
    "nodemon": "^3.0.2",
    "jest": "^29.7.0",
    "eslint": "^8.55.0"
  },
  "scripts": {
    "start": "node src/index.js",
    "dev": "nodemon src/index.js",
    "test": "jest"
  }
}
EOL

    # Create main application file
    mkdir -p src/{routes,middleware,models,utils}
    
    cat > src/index.js << 'EOL'
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
const { Sequelize } = require('sequelize');
require('dotenv').config();

const app = express();

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Database connection
const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASS,
  {
    host: process.env.DB_HOST,
    dialect: 'postgres',
    logging: false
  }
);

// Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/users', require('./routes/users'));
app.use('/api/vpn', require('./routes/vpn'));

// Serve static frontend
app.use(express.static(path.join(__dirname, '../../frontend/dist')));

// Handle React routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../../frontend/dist/index.html'));
});

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
EOL

    # Create route files
    cat > src/routes/auth.js << 'EOL'
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  // Add your authentication logic here
  
  res.json({ token: 'your-jwt-token' });
});

module.exports = router;
EOL

    # Install dependencies
    npm install || error "Failed to install backend dependencies"
    
    info "Backend setup completed"
}

# Install and configure VPN protocols
install_vpn_protocols() {
    info "Installing VPN protocols..."
    
    [ "${PROTOCOLS[SSH]}" = true ] && install_ssh
    [ "${PROTOCOLS[L2TP]}" = true ] && install_l2tp
    [ "${PROTOCOLS[IKEV2]}" = true ] && install_ikev2
    [ "${PROTOCOLS[CISCO]}" = true ] && install_cisco
    [ "${PROTOCOLS[WIREGUARD]}" = true ] && install_wireguard
    [ "${PROTOCOLS[SINGBOX]}" = true ] && install_singbox
    [ "${PROTOCOLS[DROPBEAR]}" = true ] && install_dropbear
    
    info "VPN protocols installation completed"
}

# Functions for individual protocol installation continue here...
[... Previous protocol installation functions remain the same ...]

# Additional new functions for improved security and monitoring

setup_monitoring() {
    info "Setting up monitoring system..."
    
    # Install monitoring tools
    apt-get install -y \
        prometheus-node-exporter \
        collectd \
        vnstat || error "Failed to install monitoring tools"
    
    # Configure Prometheus Node Exporter
    cat > /etc/systemd/system/node-exporter.service << EOL
[Unit]
Description=Prometheus Node Exporter
After=network.target

[Service]
Type=simple
User=node_exporter
ExecStart=/usr/bin/node_exporter

[Install]
WantedBy=multi-user.target
EOL

    # Start monitoring services
    systemctl daemon-reload
    systemctl enable node-exporter
    systemctl start node-exporter
    
    info "Monitoring setup completed"
}

setup_backup_system() {
    info "Setting up backup system..."
    
    # Create backup script
    cat > "$PANEL_DIR/scripts/backup.sh" << 'EOL'
#!/bin/bash

BACKUP_DIR="/opt/irssh-backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/backup_$TIMESTAMP.tar.gz"

# Backup configuration files
tar -czf "$BACKUP_FILE" \
    /etc/enhanced_ssh \
    /opt/irssh-panel/config \
    /etc/nginx/sites-available/irssh-panel

# Backup database
pg_dump ssh_manager > "$BACKUP_DIR/database_$TIMESTAMP.sql"

# Remove old backups (keep last 7 days)
find "$BACKUP_DIR" -type f -mtime +7 -delete
EOL

    chmod +x "$PANEL_DIR/scripts/backup.sh"
    
    # Add to crontab
    (crontab -l 2>/dev/null || true; echo "0 0 * * * $PANEL_DIR/scripts/backup.sh") | crontab -
    
    info "Backup system setup completed"
}

# Unified installation function
main() {
    trap cleanup EXIT
    
    log "INFO" "Starting IRSSH Panel installation v${VERSION}"
    
    # Get initial configuration
    get_initial_config
    
    # Core setup
    check_requirements
    setup_directories
    generate_config
    setup_database
    
    # Install and configure components
    setup_python
    setup_nodejs
    setup_frontend
    setup_backend
    
    # Install VPN protocols
    install_vpn_protocols
    
    # Security and monitoring
    setup_ssl
    setup_nginx
    setup_firewall
    setup_monitoring
    setup_backup_system
    
    # Final steps
    setup_cron
    verify_installation
    save_installation_info
    
    info "Installation completed successfully!"
    
    # Display installation summary
    cat << EOL

IRSSH Panel Installation Summary
-------------------------------
Version: ${VERSION}
Installation Directory: ${PANEL_DIR}
Web Interface: http://YOUR-SERVER-IP:${PORTS[WEB]}
Configuration Directory: ${CONFIG_DIR}
Log Directory: ${LOG_DIR}

Admin Credentials:
Username: ${ADMIN_USER}
Password: (As specified during installation)

Enabled Protocols:
$(for protocol in "${!PROTOCOLS[@]}"; do
   if [ "${PROTOCOLS[$protocol]}" = true ]; then
        echo "- $protocol enabled on port ${PORTS[$protocol]}"
    fi
done)

Port Configuration:
- Web Panel: ${PORTS[WEB]}
- UDPGW: ${PORTS[UDPGW]}
- SSH: ${PORTS[SSH]}
- Dropbear: ${PORTS[DROPBEAR]}
- WebSocket: ${PORTS[WEBSOCKET]}
- L2TP: ${PORTS[L2TP]}
- IKEv2: ${PORTS[IKEV2]}
- Cisco: ${PORTS[CISCO]}
- WireGuard: ${PORTS[WIREGUARD]}
- SingBox: ${PORTS[SINGBOX]}

All service configurations and credentials have been saved to:
${CONFIG_DIR}/installation.info

Next Steps:
1. Access the web panel at http://YOUR-SERVER-IP:${PORTS[WEB]}
2. Log in with the admin credentials provided during installation
3. Configure additional users and VPN settings through the web interface
4. Review the logs at ${LOG_DIR} for any potential issues

For security purposes:
- Change the admin password after first login
- Configure firewall rules as needed
- Set up SSL certificate if required
- Regular backups are scheduled daily at midnight

Support and Documentation:
- Documentation: ${PANEL_DIR}/docs
- Logs: ${LOG_DIR}
- Backup Location: ${BACKUP_DIR}

EOL
}

# Execute main installation
main

# Additional helper functions

verify_service() {
    local service=$1
    local port=$2
    
    info "Verifying $service on port $port..."
    
    if ! netstat -tuln | grep -q ":$port\\b"; then
        warn "$service is not listening on port $port"
        return 1
    fi
    
    if ! systemctl is-active --quiet "$service"; then
        warn "$service service is not running"
        return 1
    fi
    
    return 0
}

verify_web_access() {
    info "Verifying web panel access..."
    
    local max_attempts=5
    local attempt=1
    local delay=2
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s -o /dev/null "http://localhost:${PORTS[WEB]}"; then
            info "Web panel is accessible"
            return 0
        fi
        
        warn "Web panel not accessible, attempt $attempt of $max_attempts"
        sleep $delay
        ((attempt++))
    done
    
    error "Web panel verification failed after $max_attempts attempts"
    return 1
}

check_port_conflicts() {
    info "Checking for port conflicts..."
    
    local conflicts=0
    
    for protocol in "${!PORTS[@]}"; do
        local port="${PORTS[$protocol]}"
        if netstat -tuln | grep -q ":$port\\b"; then
            warn "Port $port is already in use (needed for $protocol)"
            ((conflicts++))
        fi
    done
    
    if [ $conflicts -gt 0 ]; then
        error "Found $conflicts port conflicts. Please resolve before installation."
        return 1
    fi
    
    info "No port conflicts found"
    return 0
}

setup_kernel_parameters() {
    info "Configuring kernel parameters..."
    
    cat > /etc/sysctl.d/99-irssh-panel.conf << EOL
# IPv4 Forward
net.ipv4.ip_forward=1

# TCP/IP Parameters
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_max_syn_backlog=4096
net.ipv4.tcp_fin_timeout=30
net.ipv4.tcp_keepalive_time=1200
net.ipv4.tcp_keepalive_intvl=15
net.ipv4.tcp_keepalive_probes=5

# UDP Buffer Size
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.udp_mem="8388608 12582912 16777216"

# Connection Tracking
net.netfilter.nf_conntrack_max=1000000
net.netfilter.nf_conntrack_tcp_timeout_established=7200
EOL

    sysctl -p /etc/sysctl.d/99-irssh-panel.conf
    
    info "Kernel parameters configured successfully"
}

optimize_network_stack() {
    info "Optimizing network stack..."
    
    # Install additional network tools
    apt-get install -y \
        ethtool \
        irqbalance \
        ifstat \
        || error "Failed to install network tools"
    
    # Enable and start irqbalance
    systemctl enable irqbalance
    systemctl start irqbalance
    
    # Configure network interface optimizations
    local main_interface=$(ip route | grep default | awk '{print $5}')
    if [ -n "$main_interface" ]; then
        ethtool -K "$main_interface" tso on gso on gro on
        ethtool -G "$main_interface" rx 4096 tx 4096
    fi
    
    info "Network stack optimization completed"
}

setup_fail2ban() {
    info "Configuring Fail2ban..."
    
    apt-get install -y fail2ban || error "Failed to install Fail2ban"
    
    cat > /etc/fail2ban/jail.local << EOL
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ${PORTS[SSH]},${PORTS[DROPBEAR]}
logpath = %(sshd_log)s
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = ${PORTS[WEB]}
logpath = /var/log/nginx/error.log
maxretry = 5

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
port = ${PORTS[WEB]}
logpath = /var/log/nginx/error.log
maxretry = 10
EOL

    systemctl enable fail2ban
    systemctl restart fail2ban
    
    info "Fail2ban configuration completed"
}

install_udpgw() {
    info "Installing badvpn-udpgw..."
    
    # Install build dependencies
    apt-get install -y \
        cmake \
        build-essential \
        || error "Failed to install build dependencies"
    
    # Download and compile badvpn
    cd "$TEMP_DIR" || error "Failed to access temp directory"
    git clone https://github.com/ambrop72/badvpn.git
    cd badvpn || error "Failed to access badvpn directory"
    mkdir build
    cd build
    cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
    make install
    
    # Create service file
    cat > /etc/systemd/system/badvpn-udpgw.service << EOL
[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:${PORTS[UDPGW]} --max-clients 1000 --max-connections-for-client 20
Restart=always

[Install]
WantedBy=multi-user.target
EOL

    # Start and enable service
    systemctl daemon-reload
    systemctl enable badvpn-udpgw
    systemctl start badvpn-udpgw
    
    info "badvpn-udpgw installation completed"
}

# End of script
