#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
    exit 1
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
fi

# Update package lists
log "Updating package lists..."
apt-get update

# Install essential packages
log "Installing essential packages..."
apt-get install -y \
    build-essential \
    python3-dev \
    python3-pip \
    python3-venv \
    libpq-dev \
    nginx \
    supervisor \
    certbot \
    python3-certbot-nginx \
    git \
    curl \
    wget \
    tar \
    unzip \
    ufw \
    fail2ban \
    net-tools \
    postgresql \
    postgresql-contrib \
    software-properties-common

# Install Node.js and npm
log "Installing Node.js and npm..."
if ! command -v node &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    apt-get install -y nodejs
    npm install -g npm@latest
fi

# Set up UFW
log "Configuring firewall..."
ufw allow ssh
ufw allow http
ufw allow https
ufw --force enable

# Create required directories
log "Creating required directories..."
mkdir -p /opt/irssh-panel/{frontend,backend,config,modules}
mkdir -p /var/log/irssh

# Setup log files
touch /var/log/irssh/install.log
chmod 644 /var/log/irssh/install.log

# Verify installations
log "Verifying installations..."

# Check Node.js and npm
node_version=$(node --version)
npm_version=$(npm --version)
info "Node.js version: $node_version"
info "npm version: $npm_version"

# Check nginx
nginx_version=$(nginx -v 2>&1)
info "nginx version: $nginx_version"

# Check PostgreSQL
pg_version=$(psql --version)
info "PostgreSQL version: $pg_version"

# Check Python
python_version=$(python3 --version)
info "Python version: $python_version"

# Set correct permissions
log "Setting permissions..."
chown -R root:root /opt/irssh-panel
chmod -R 755 /opt/irssh-panel
chmod -R 744 /var/log/irssh

echo
echo "All prerequisites have been installed successfully!"
echo "You can now run the main installation script."
echo
echo "Installed components:"
echo "1. Node.js and npm"
echo "2. nginx"
echo "3. PostgreSQL"
echo "4. Python 3 and development tools"
echo "5. UFW (firewall)"
echo "6. Supervisor"
echo "7. Other essential tools"
