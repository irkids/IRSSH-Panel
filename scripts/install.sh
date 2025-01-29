#!/bin/bash

# IRSSH Panel Installation Script
# Version: 3.4.5

# Directories
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
MODULES_DIR="$PANEL_DIR/modules"
PROTOCOLS_DIR="$MODULES_DIR/protocols"
LOG_DIR="/var/log/irssh"
BACKUP_DIR="/opt/irssh-backups"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Generate secure passwords
DB_NAME="irssh_panel"
DB_USER="irssh_admin"
DB_PASS=$(openssl rand -base64 32)
ADMIN_PASS=$(openssl rand -base64 16)
JWT_SECRET=$(openssl rand -base64 32)

# Protocol installation flags
INSTALL_SSH=true
INSTALL_L2TP=true
INSTALL_IKEV2=true
INSTALL_CISCO=true
INSTALL_WIREGUARD=true
INSTALL_SINGBOX=true

# Protocol ports
SSH_PORT=22
L2TP_PORT=1701
IKEV2_PORT=500
CISCO_PORT=443
WIREGUARD_PORT=51820
SINGBOX_PORT=1080
BADVPN_PORT=7300
DROPBEAR_PORT=444

# Current directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Source install functions
source "$SCRIPT_DIR/install/utils.sh"
source "$SCRIPT_DIR/install/dependencies.sh"
source "$SCRIPT_DIR/install/protocols.sh"
source "$SCRIPT_DIR/install/frontend.sh"
source "$SCRIPT_DIR/install/backend.sh"
source "$SCRIPT_DIR/install/database.sh"
source "$SCRIPT_DIR/install/security.sh"

# Main installation function
main() {
    trap cleanup EXIT
    
    setup_logging
    log "Starting IRSSH Panel installation v3.4.5"
    
    # Get user input
    read -p "Enter domain name (e.g., panel.example.com): " DOMAIN
    read -p "Enter web panel port (default: 443): " WEB_PORT
    WEB_PORT=${WEB_PORT:-443}
    read -p "Enter SSH port (default: 22): " SSH_PORT
    SSH_PORT=${SSH_PORT:-22}
    
    # Protocol installation options
    read -p "Install L2TP/IPsec? (Y/n): " install_l2tp
    INSTALL_L2TP=${install_l2tp:-Y}
    [ "${INSTALL_L2TP,,}" = "y" ] && INSTALL_L2TP=true || INSTALL_L2TP=false

    read -p "Install IKEv2? (Y/n): " install_ikev2
    INSTALL_IKEV2=${install_ikev2:-Y}
    [ "${INSTALL_IKEV2,,}" = "y" ] && INSTALL_IKEV2=true || INSTALL_IKEV2=false

    read -p "Install Cisco AnyConnect? (Y/n): " install_cisco
    INSTALL_CISCO=${install_cisco:-Y}
    [ "${INSTALL_CISCO,,}" = "y" ] && INSTALL_CISCO=true || INSTALL_CISCO=false

    read -p "Install WireGuard? (Y/n): " install_wireguard
    INSTALL_WIREGUARD=${install_wireguard:-Y}
    [ "${INSTALL_WIREGUARD,,}" = "y" ] && INSTALL_WIREGUARD=true || INSTALL_WIREGUARD=false

    read -p "Install SingBox? (Y/n): " install_singbox
    INSTALL_SINGBOX=${install_singbox:-Y}
    [ "${INSTALL_SINGBOX,,}" = "y" ] && INSTALL_SINGBOX=true || INSTALL_SINGBOX=false
    
    # Run installation steps
    check_requirements
    create_backup
    setup_directories
    install_dependencies
    install_protocols
    setup_database
    setup_backend
    setup_frontend
    setup_nginx
    setup_ssl
    setup_firewall
    setup_security
    setup_cron
    verify_installation
    save_installation_info
    
    log "Installation completed successfully!"
    show_completion_message
}

# Start installation
main "$@"
