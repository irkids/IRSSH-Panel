#!/bin/bash

# IRSSH Panel Uninstallation Script

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
PANEL_DIR="/opt/irssh-panel"
LOG_DIR="/var/log/irssh"
DB_NAME="irssh_panel"
DB_USER="irssh_admin"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run as root${NC}"
    exit 1
fi

# Confirmation
echo -e "${YELLOW}WARNING: This will completely remove IRSSH Panel and all its data!${NC}"
echo -e "${YELLOW}This action cannot be undone!${NC}"
read -p "Are you sure you want to continue? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Uninstallation cancelled"
    exit 1
fi

# Optional backup before removal
read -p "Would you like to create a backup before uninstalling? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${GREEN}Creating backup...${NC}"
    BACKUP_DIR="/root/irssh-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    # Backup database
    sudo -u postgres pg_dump $DB_NAME > "$BACKUP_DIR/database.sql"
    
    # Backup configuration
    cp -r "$PANEL_DIR/config" "$BACKUP_DIR/"
    
    # Backup certificates
    cp -r "$PANEL_DIR/certs" "$BACKUP_DIR/" 2>/dev/null || true
    
    # Backup logs
    cp -r "$LOG_DIR" "$BACKUP_DIR/" 2>/dev/null || true
    
    # Create archive
    cd /root
    tar czf "$BACKUP_DIR.tar.gz" "$(basename "$BACKUP_DIR")"
    rm -rf "$BACKUP_DIR"
    
    echo -e "${GREEN}Backup created: $BACKUP_DIR.tar.gz${NC}"
fi

echo -e "${GREEN}Starting uninstallation...${NC}"

# Stop services
echo "Stopping services..."
systemctl stop irssh-panel
systemctl stop nginx
systemctl disable irssh-panel
systemctl disable nginx

# Remove systemd service
rm -f /etc/systemd/system/irssh-panel.service
systemctl daemon-reload

# Remove Nginx configuration
rm -f /etc/nginx/sites-enabled/irssh-panel
rm -f /etc/nginx/sites-available/irssh-panel

# Remove cron jobs
rm -f /etc/cron.daily/irssh-panel-update
rm -f /etc/cron.daily/irssh-panel-backup

# Remove database
echo "Removing database..."
sudo -u postgres psql -c "DROP DATABASE IF EXISTS $DB_NAME;"
sudo -u postgres psql -c "DROP USER IF EXISTS $DB_USER;"

# Remove directories
echo "Removing files..."
rm -rf "$PANEL_DIR"
rm -rf "$LOG_DIR"

# Remove Python virtual environment
rm -rf "$PANEL_DIR/venv"

# Reset UFW rules (optional)
echo "Resetting firewall rules..."
ufw reset

# Clean up system dependencies (optional)
read -p "Would you like to remove installed system dependencies? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Removing system dependencies..."
    apt-get remove -y \
        python3-venv \
        postgresql \
        postgresql-contrib \
        nginx \
        certbot \
        python3-certbot-nginx \
        supervisor
    apt-get autoremove -y
fi

# Remove user data
echo "Removing user data..."
for protocol in ssh l2tp ikev2 cisco wireguard singbox; do
    if [ -f "$PANEL_DIR/modules/$protocol-script.py" ]; then
        "$PANEL_DIR/modules/$protocol-script.py" cleanup || true
    elif [ -f "$PANEL_DIR/modules/$protocol-script.sh" ]; then
        "$PANEL_DIR/modules/$protocol-script.sh" cleanup || true
    fi
done

# Final cleanup
echo "Performing final cleanup..."
find /tmp -name 'irssh-*' -exec rm -rf {} + 2>/dev/null || true
find /var/log -name 'irssh-*' -exec rm -f {} + 2>/dev/null || true
find /var/log -name 'uvicorn-irssh*' -exec rm -f {} + 2>/dev/null || true

echo -e "${GREEN}Uninstallation completed successfully!${NC}"
if [ -f "$BACKUP_DIR.tar.gz" ]; then
    echo -e "${YELLOW}Don't forget your backup file: $BACKUP_DIR.tar.gz${NC}"
fi

echo -e "${YELLOW}Note: Some system configurations and dependencies might still remain.${NC}"
echo -e "${YELLOW}You may need to manually remove them if necessary.${NC}"

exit 0
