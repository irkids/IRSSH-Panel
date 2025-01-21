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

# Remove conflicting packages
log "Removing conflicting packages..."
apt-get remove -y nodejs npm
apt-get autoremove -y
apt-get clean

# Clear apt cache
log "Clearing apt cache..."
rm -rf /var/lib/apt/lists/*
apt-get clean
apt-get update

# Remove NodeSource repository
log "Removing old NodeSource repository..."
rm -f /etc/apt/sources.list.d/nodesource.list*

# Add NodeSource repository properly
log "Adding NodeSource repository..."
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -

# Install Node.js (this will include npm)
log "Installing Node.js..."
apt-get install -y nodejs

# Verify installation
log "Verifying installation..."
node_version=$(node --version)
npm_version=$(npm --version)

if [ $? -eq 0 ]; then
    log "Node.js version: $node_version"
    log "npm version: $npm_version"
    log "Installation successful!"
else
    error "Failed to install Node.js and npm"
fi

echo
echo "Node.js and npm have been fixed!"
echo "You can now run the main installation script again."
