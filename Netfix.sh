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
}

# Check UFW status
log "Checking UFW status..."
if ! systemctl is-active --quiet ufw; then
    log "Enabling UFW..."
    ufw enable
fi

# Configure UFW
log "Configuring firewall rules..."
ufw allow ssh
ufw allow 8675/tcp
ufw allow 8000/tcp
ufw allow http
ufw allow https

# Update UFW
log "Updating UFW rules..."
ufw --force enable

# Test ports
log "Testing ports..."
echo "Port 8675:"
netstat -tuln | grep 8675
echo "Port 8000:"
netstat -tuln | grep 8000

# Check Nginx configuration
log "Checking Nginx configuration..."
nginx -t

# Check Nginx status
log "Checking Nginx status..."
systemctl status nginx

# Print useful information
log "Current port status:"
ss -tuln | grep -E ':(80|8675|8000)'

echo
echo "Please try accessing:"
echo "1. http://77.239.124.50:8675"
echo "2. http://77.239.124.50:8000"
echo
echo "If still not accessible, please check:"
echo "1. netstat -tuln (to see all listening ports)"
echo "2. ufw status (to see firewall rules)"
