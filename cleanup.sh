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

# Stop services
log "Stopping services..."
systemctl stop irssh-panel irssh-tasks >/dev/null 2>&1
supervisorctl stop irssh-panel >/dev/null 2>&1

# Remove database and user
log "Removing database..."
sudo -u postgres psql -c "DROP DATABASE IF EXISTS irssh_panel;"
sudo -u postgres psql -c "DROP ROLE IF EXISTS irssh_admin;"

# Remove directories
log "Removing directories..."
rm -rf /opt/irssh-panel
rm -rf /var/log/irssh

# Remove configuration files
log "Removing configuration files..."
rm -f /etc/supervisor/conf.d/irssh-panel.conf
rm -f /etc/nginx/sites-enabled/irssh-panel
rm -f /etc/nginx/sites-available/irssh-panel
rm -f /etc/systemd/system/irssh-panel.service
rm -f /etc/systemd/system/irssh-tasks.service

# Reload configurations
log "Reloading system configurations..."
systemctl daemon-reload
supervisorctl reread
supervisorctl update
systemctl restart nginx

log "Cleanup completed successfully. You can now run the installation script again."
