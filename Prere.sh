#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Logging
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
    exit 1
}

# Check root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
fi

# Update system
log "Updating system packages..."
apt-get update

# Install essential packages
log "Installing essential packages..."
apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3.10-venv \
    postgresql \
    postgresql-contrib \
    nginx \
    supervisor \
    curl \
    git \
    ufw

# Start and enable PostgreSQL
log "Setting up PostgreSQL..."
systemctl start postgresql
systemctl enable postgresql

# Verify installations
log "Verifying installations..."

if ! command -v python3 &> /dev/null; then
    error "Python3 installation failed"
fi

if ! command -v pip3 &> /dev/null; then
    error "Pip3 installation failed"
fi

if ! command -v nginx &> /dev/null; then
    error "Nginx installation failed"
fi

if ! command -v supervisorctl &> /dev/null; then
    error "Supervisor installation failed"
fi

if ! systemctl is-active --quiet postgresql; then
    error "PostgreSQL is not running"
fi

# Create necessary directories
log "Creating necessary directories..."
mkdir -p /etc/nginx/sites-available
mkdir -p /etc/nginx/sites-enabled
mkdir -p /etc/supervisor/conf.d
mkdir -p /var/log/supervisor

# Configure PostgreSQL for remote connections
log "Configuring PostgreSQL..."
sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '*'/" /etc/postgresql/*/main/postgresql.conf
echo "host    all             all             0.0.0.0/0               md5" >> /etc/postgresql/*/main/pg_hba.conf
systemctl restart postgresql

log "Prerequisites installation completed successfully!"
echo
echo "You can now run the main installation script."
