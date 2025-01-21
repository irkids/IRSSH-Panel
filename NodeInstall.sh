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

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
fi

# Install Node.js and npm
log "Installing Node.js and npm..."

# Remove old versions if exist
apt-get remove -y nodejs npm || true
apt-get autoremove -y

# Add NodeSource repository
log "Adding NodeSource repository..."
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -

# Install Node.js
log "Installing Node.js..."
apt-get install -y nodejs

# Verify installations
log "Verifying installations..."
node_version=$(node --version)
npm_version=$(npm --version)

if [ $? -eq 0 ]; then
    log "Node.js version: $node_version"
    log "npm version: $npm_version"
    log "Installation successful!"
else
    error "Failed to install Node.js and npm"
fi

# Update npm to latest version
log "Updating npm to latest version..."
npm install -g npm@latest

echo
echo "Node.js and npm have been installed successfully!"
echo "You can now run the main installation script again."
