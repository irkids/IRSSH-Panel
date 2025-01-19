#!/bin/bash

# Configuration
PANEL_DIR="/opt/irssh-panel"
LOG_DIR="/var/log/irssh"

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

# Check logs
check_logs() {
    log "Checking logs..."
    echo "=== Backend Errors ==="
    tail -n 50 $LOG_DIR/backend-error.log
    echo "=== Nginx Errors ==="
    tail -n 50 /var/log/nginx/irssh-error.log
}

# Fix permissions
fix_permissions() {
    log "Fixing permissions..."
    chown -R root:root $PANEL_DIR
    chmod -R 755 $PANEL_DIR
    chmod -R 777 $LOG_DIR
}

# Check services
check_services() {
    log "Checking services..."
    systemctl status postgresql
    systemctl status nginx
    systemctl status irssh-panel
}

# Restart services
restart_services() {
    log "Restarting services..."
    systemctl restart postgresql
    systemctl restart nginx
    systemctl restart irssh-panel
}

# Apply Nginx config
apply_nginx_config() {
    log "Applying Nginx configuration..."
    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    nginx -t && systemctl restart nginx
}

# Check database
check_database() {
    log "Checking database connection..."
    source $PANEL_DIR/config/database.env
    PGPASSWORD=$DB_PASS psql -h localhost -U $DB_USER -d $DB_NAME -c '\dt'
}

# Main
log "Starting fix process..."

# Run checks
fix_permissions
check_database
apply_nginx_config
restart_services
check_services
check_logs

log "Fix process completed. Please check the logs above for any errors."
