#!/bin/bash

# Utility functions for IRSSH Panel installation

# Logging setup
setup_logging() {
    mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/install.log"
    exec &> >(tee -a "$LOG_FILE")
    chmod 640 "$LOG_FILE"
}

# Logging functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
    [[ "${2:-}" != "no-exit" ]] && cleanup && exit 1
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Cleanup function
cleanup() {
    if [[ $? -ne 0 ]]; then
        log "Installation failed. Checking error logs..."
        if [[ -f "$LOG_DIR/install.log" ]]; then
            tail -n 50 "$LOG_DIR/install.log"
        fi
        if [[ -d "$BACKUP_DIR" ]]; then
            log "Attempting to restore from backup..."
            restore_backup
        fi
    fi
}

# Backup functions
create_backup() {
    mkdir -p "$BACKUP_DIR"
    if [[ -d "$PANEL_DIR" ]]; then
        tar -czf "$BACKUP_DIR/panel-$(date +%Y%m%d-%H%M%S).tar.gz" \
            -C "$(dirname "$PANEL_DIR")" "$(basename "$PANEL_DIR")" || \
            error "Failed to create backup"
    fi
}

restore_backup() {
    local latest_backup=$(ls -t "$BACKUP_DIR"/*.tar.gz 2>/dev/null | head -1)
    if [[ -n "$latest_backup" ]]; then
        rm -rf "$PANEL_DIR"
        tar -xzf "$latest_backup" -C "$(dirname "$PANEL_DIR")"
        log "Restored from backup: $latest_backup"
    fi
}

# Check system requirements
check_requirements() {
    # Check root access
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi

    # Check minimum RAM
    if [[ $(free -m | awk '/^Mem:/{print $2}') -lt 1024 ]]; then
        error "Minimum 1GB RAM required"
    fi

    # Check minimum disk space
    if [[ $(df -m / | awk 'NR==2 {print $4}') -lt 2048 ]]; then
        error "Minimum 2GB free disk space required"
    fi

    # Check required commands
    local required_commands=(curl wget git python3 pip3)
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            error "$cmd is required but not installed"
        fi
    done

    # Check system architecture
    if [[ "$(uname -m)" != "x86_64" ]]; then
        error "Only x86_64 architecture is supported"
    fi

    # Check operating system
    if ! grep -qi "ubuntu\|debian" /etc/os-release; then
        error "Only Ubuntu and Debian are supported"
    fi
}

# Setup directories
setup_directories() {
    log "Setting up directories..."
    
    # Create main directories
    mkdir -p "$PANEL_DIR"/{frontend,backend,config,modules/protocols}
    mkdir -p "$FRONTEND_DIR"/{public,src/{components,styles,config,utils,assets,layouts}}
    mkdir -p "$BACKEND_DIR"/{app/{api,core,models,schemas,utils},migrations}
    
    # Set permissions
    chmod -R 755 "$PANEL_DIR"
    chown -R root:root "$PANEL_DIR"
}

# Save installation information
save_installation_info() {
    log "Saving installation information..."
    
    cat > "$CONFIG_DIR/installation.info" << EOL
Installation Date: $(date +"%Y-%m-%d %H:%M:%S")
Version: 3.4.5
Domain: ${DOMAIN}
Web Port: ${WEB_PORT}
SSH Port: ${SSH_PORT}
L2TP Port: ${L2TP_PORT}
IKEv2 Port: ${IKEV2_PORT}
Cisco Port: ${CISCO_PORT}
WireGuard Port: ${WIREGUARD_PORT}
SingBox Port: ${SINGBOX_PORT}
BadVPN Port: ${BADVPN_PORT}
Dropbear Port: ${DROPBEAR_PORT}
Admin Username: admin
Admin Password: ${ADMIN_PASS}
Database Name: ${DB_NAME}
Database User: ${DB_USER}
Database Password: ${DB_PASS}
JWT Secret: ${JWT_SECRET}
EOL
    chmod 600 "$CONFIG_DIR/installation.info"

    # Create environment file
    cat > "$CONFIG_DIR/env" << EOL
ADMIN_USER=admin
ADMIN_PASS=${ADMIN_PASS}
JWT_SECRET_KEY=${JWT_SECRET}
DB_HOST=localhost
DB_PORT=5432
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASS=${DB_PASS}
EOL
    chmod 600 "$CONFIG_DIR/env"
}

# Show completion message
show_completion_message() {
    echo
    echo "IRSSH Panel has been installed!"
    echo
    echo "Admin Credentials:"
    echo "Username: admin"
    echo "Password: $ADMIN_PASS"
    echo
    echo "Access URLs:"
    if [[ -n "$DOMAIN" ]]; then
        echo "Panel: https://$DOMAIN"
    else
        echo "Panel: http://YOUR-SERVER-IP"
    fi
    echo
    echo "Installed Protocols:"
    [ "$INSTALL_SSH" = true ] && echo "- SSH (Port: $SSH_PORT)"
    [ "$INSTALL_L2TP" = true ] && echo "- L2TP/IPsec (Port: $L2TP_PORT)"
    [ "$INSTALL_IKEV2" = true ] && echo "- IKEv2 (Port: $IKEV2_PORT)"
    [ "$INSTALL_CISCO" = true ] && echo "- Cisco AnyConnect (Port: $CISCO_PORT)"
    [ "$INSTALL_WIREGUARD" = true ] && echo "- WireGuard (Port: $WIREGUARD_PORT)"
    [ "$INSTALL_SINGBOX" = true ] && echo "- SingBox (Port: $SINGBOX_PORT)"
    echo
    echo "Additional Services:"
    echo "- BadVPN: Port $BADVPN_PORT"
    echo "- Dropbear: Port $DROPBEAR_PORT"
    echo
    echo "Installation Log: $LOG_DIR/install.log"
    echo "Installation Info: $CONFIG_DIR/installation.info"
    echo
    echo "Important Notes:"
    echo "1. Please save these credentials securely"
    echo "2. Change the admin password after first login"
    echo "3. Configure additional security settings in the panel"
    echo "4. Check the installation log for any warnings"
    echo "5. A backup of the previous installation (if any) has been saved in: $BACKUP_DIR"
    echo
    echo "For support, please visit the repository issues page."
}

# Setup cron jobs
setup_cron() {
    log "Setting up cron jobs..."

    # Create system monitoring cron job
    cat > /etc/cron.d/irssh-monitor << EOL
* * * * * root $MODULES_DIR/monitor.sh > /tmp/system_stats.json 2>> $LOG_DIR/monitor.err.log
EOL

    # Create bandwidth monitoring cron job
    cat > /etc/cron.d/irssh-bandwidth << EOL
0 * * * * root $MODULES_DIR/bandwidth.sh >> $LOG_DIR/bandwidth.log 2>&1
EOL

    # Create backup cron job
    cat > /etc/cron.d/irssh-backup << EOL
0 0 * * * root $MODULES_DIR/backup.sh >> $LOG_DIR/backup.log 2>&1
EOL

    chmod 644 /etc/cron.d/irssh-*
}

# Create monitoring scripts
setup_monitoring() {
    log "Setting up monitoring scripts..."

    # Create system monitoring script
    cat > "$MODULES_DIR/monitor.sh" << 'EOL'
#!/bin/bash

get_cpu_usage() {
    top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}'
}

get_mem_usage() {
    free | grep Mem | awk '{print ($3/$2) * 100}'
}

get_disk_usage() {
    df -h / | awk 'NR==2 {print $5}' | sed 's/%//'
}

get_network_stats() {
    if command -v vnstat &> /dev/null; then
        vnstat -h 1
    else
        echo "vnstat not installed"
    fi
}

echo "{"
echo "  \"cpu\": $(get_cpu_usage),"
echo "  \"memory\": $(get_mem_usage | xargs printf "%.1f"),"
echo "  \"disk\": $(get_disk_usage),"
echo "  \"network\": \"$(get_network_stats)\""
echo "}"
EOL
    chmod +x "$MODULES_DIR/monitor.sh"

    # Create bandwidth monitoring script
    cat > "$MODULES_DIR/bandwidth.sh" << 'EOL'
#!/bin/bash
vnstat -h >> "$LOG_DIR/bandwidth_hourly.log"
vnstat -d >> "$LOG_DIR/bandwidth_daily.log"
vnstat -m >> "$LOG_DIR/bandwidth_monthly.log"
EOL
    chmod +x "$MODULES_DIR/bandwidth.sh"

    # Create backup script
    cat > "$MODULES_DIR/backup.sh" << 'EOL'
#!/bin/bash
BACKUP_DIR="/opt/irssh-backups"
PANEL_DIR="/opt/irssh-panel"
LOG_DIR="/var/log/irssh"

mkdir -p "$BACKUP_DIR"
BACKUP_FILE="$BACKUP_DIR/panel-$(date +%Y%m%d-%H%M%S).tar.gz"

# Backup panel files
tar -czf "$BACKUP_FILE" -C "$(dirname "$PANEL_DIR")" "$(basename "$PANEL_DIR")"

# Backup database
pg_dump -U irssh_admin irssh_panel > "$BACKUP_DIR/database-$(date +%Y%m%d-%H%M%S).sql"

# Remove old backups (keep last 7 days)
find "$BACKUP_DIR" -type f -mtime +7 -name "panel-*.tar.gz" -delete
find "$BACKUP_DIR" -type f -mtime +7 -name "database-*.sql" -delete
EOL
    chmod +x "$MODULES_DIR/backup.sh"
}
