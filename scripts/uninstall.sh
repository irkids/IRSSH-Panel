#!/bin/bash

# IRSSH Panel Uninstall Script
# Version: 3.4.5

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Directories
PANEL_DIR="/opt/irssh-panel"
LOG_DIR="/var/log/irssh"
BACKUP_DIR="/opt/irssh-backups"

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Confirmation function
confirm() {
    read -p "${1} (y/N) " response
    case "$response" in
        [yY][eE][sS]|[yY]) 
            true
            ;;
        *)
            false
            ;;
    esac
}

# Stop and remove services
remove_services() {
    log "Stopping and removing services..."
    
    # Stop and disable services
    local services=(
        "nginx"
        "postgresql"
        "supervisor"
        "strongswan"
        "xl2tpd"
        "ocserv"
        "wg-quick@wg0"
        "sing-box"
    )

    for service in "${services[@]}"; do
        if systemctl is-active --quiet $service; then
            systemctl stop $service
            systemctl disable $service
        fi
    done

    # Remove service files
    rm -f /etc/systemd/system/sing-box.service
    systemctl daemon-reload
}

# Remove packages
remove_packages() {
    log "Removing installed packages..."
    
    apt-get remove -y \
        python3-pip python3-venv \
        postgresql postgresql-contrib \
        nginx certbot python3-certbot-nginx \
        supervisor ufw fail2ban \
        strongswan xl2tpd ocserv \
        wireguard nodejs

    apt-get autoremove -y
    apt-get clean
}

# Remove files and directories
remove_files() {
    log "Removing files and directories..."
    
    # Remove main directories
    rm -rf "$PANEL_DIR"
    rm -rf "$LOG_DIR"
    
    # Remove configuration files
    rm -f /etc/nginx/sites-available/irssh-panel
    rm -f /etc/nginx/sites-enabled/irssh-panel
    rm -f /etc/supervisor/conf.d/irssh-backend.conf
    rm -f /etc/cron.d/irssh-*
    
    # Remove SSL certificates
    certbot delete --cert-name "$DOMAIN" 2>/dev/null
}

# Remove database
remove_database() {
    log "Removing database..."
    
    if command -v psql &>/dev/null; then
        su - postgres -c "dropdb irssh_panel" 2>/dev/null
        su - postgres -c "dropuser irssh_admin" 2>/dev/null
    fi
}

# Main uninstall function
main() {
    echo "WARNING: This will completely remove IRSSH Panel and all its data."
    echo "Make sure you have backed up any important data before proceeding."
    echo
    
    if ! confirm "Are you sure you want to continue with uninstallation?"; then
        echo "Uninstallation cancelled."
        exit 0
    fi

    if confirm "Would you like to keep the backups in $BACKUP_DIR?"; then
        KEEP_BACKUPS=true
    else
        KEEP_BACKUPS=false
    fi

    log "Starting uninstallation process..."

    remove_services
    remove_packages
    remove_database
    remove_files

    if [ "$KEEP_BACKUPS" = false ] && [ -d "$BACKUP_DIR" ]; then
        rm -rf "$BACKUP_DIR"
    fi

    log "Uninstallation completed successfully!"
    
    if [ "$KEEP_BACKUPS" = true ] && [ -d "$BACKUP_DIR" ]; then
        echo "Backups have been preserved in: $BACKUP_DIR"
    fi
}

# Start uninstallation
main
