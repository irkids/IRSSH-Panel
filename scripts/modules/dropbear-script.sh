#!/bin/bash

# Ultra-High Super Advanced Dropbear Installer and Configurator Script
# Enhanced Version with Dynamic Configuration and PostgreSQL Logging

# Strict error handling
set -euo pipefail

# Configuration Variables
SCRIPT_VERSION="2.1.0"
DEFAULT_PORT=22022
DROPBEAR_PACKAGE="dropbear"
DROPBEAR_CONFIG_FILE="/etc/default/dropbear"
DROPBEAR_LOG="/var/log/dropbear_install.log"
POSTGRES_DB="server_management"
POSTGRES_USER="sysadmin"
POSTGRES_TABLE="ssh_installations"

# Performance and Security Optimization Functions
apply_system_optimizations() {
    # TCP and Network Optimization
    cat >> /etc/sysctl.conf <<EOL
# Advanced Network Tuning
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=65536
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_sack=1
EOL
    
    # Apply sysctl settings
    sysctl -p

    # Fail2Ban Installation and Configuration
    apt-get install -y fail2ban
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    
    # Customize Fail2Ban for Dropbear
    cat >> /etc/fail2ban/jail.local <<EOL
[dropbear]
enabled = true
port = $DROPBEAR_PORT
filter = dropbear
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOL

    systemctl enable fail2ban
    systemctl restart fail2ban

    # Log Rotation Configuration
    cat > /etc/logrotate.d/dropbear <<EOL
$DROPBEAR_LOG {
    rotate 7
    daily
    compress
    missingok
    notifempty
}
EOL
}

# Monitoring Function for SSH Connectivity
monitor_ssh_connectivity() {
    local host="localhost"
    local port="$DROPBEAR_PORT"
    local max_attempts=3
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        if nc -z -w5 "$host" "$port"; then
            advanced_log "SSH Connectivity Test: PASSED" "INFO"
            return 0
        else
            advanced_log "SSH Connectivity Test: ATTEMPT $((attempt+1)) FAILED" "WARNING"
            ((attempt++))
            sleep 2
        fi
    done

    advanced_log "SSH Connectivity Test: CRITICAL FAILURE" "CRITICAL"
    return 1
}

# Dependency and PostgreSQL Setup Function
setup_dependencies() {
    # Install required packages
    apt-get update -y
    apt-get install -y \
        postgresql \
        postgresql-contrib \
        python3-psycopg2 \
        python3-pip \
        dropbear \
        net-tools \
        netcat

    # Install PostgreSQL Python connector
    pip3 install psycopg2-binary
}

# PostgreSQL Database Initialization
initialize_database() {
    sudo -u postgres psql <<EOF
CREATE DATABASE IF NOT EXISTS $POSTGRES_DB;
\c $POSTGRES_DB
CREATE TABLE IF NOT EXISTS $POSTGRES_TABLE (
    id SERIAL PRIMARY KEY,
    installation_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    dropbear_port INTEGER,
    server_hostname VARCHAR(255),
    installation_status VARCHAR(50),
    additional_notes TEXT
);
EOF
}

# Advanced Logging Function with PostgreSQL Integration
advanced_log() {
    local message="$1"
    local status="${2:-INFO}"

    # Log to file
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [$status] $message" | tee -a "$DROPBEAR_LOG"

    # Optional PostgreSQL logging (simplified Python script)
    python3 <<END
import psycopg2

try:
    conn = psycopg2.connect(
        dbname="$POSTGRES_DB",
        user="$POSTGRES_USER"
    )
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO $POSTGRES_TABLE 
        (dropbear_port, server_hostname, installation_status, additional_notes)
        VALUES (%s, %s, %s, %s)
    """, (
        $DROPBEAR_PORT, 
        '$(hostname)', 
        '$status', 
        '$message'
    ))
    conn.commit()
    cur.close()
    conn.close()
except Exception as e:
    print(f"Database logging failed: {e}")
END
}

# Root Permission Check
check_root_permissions() {
    if [[ $EUID -ne 0 ]]; then
        advanced_log "Script must be run as root" ERROR
        exit 1
    fi
}

# Dynamic Port Configuration
configure_dropbear_port() {
    # Interactive or argument-based port selection
    if [[ $# -gt 0 ]]; then
        DROPBEAR_PORT="$1"
    else
        read -r -p "Enter Dropbear SSH port (default $DEFAULT_PORT): " DROPBEAR_PORT
        DROPBEAR_PORT=${DROPBEAR_PORT:-$DEFAULT_PORT}
    fi

    # Port validation
    if [[ ! "$DROPBEAR_PORT" =~ ^[0-9]+$ ]] || 
       [[ "$DROPBEAR_PORT" -le 0 ]] || 
       [[ "$DROPBEAR_PORT" -gt 65535 ]]; then
        advanced_log "Invalid port number" ERROR
        exit 1
    fi

    # Port conflict check
    if netstat -tuln | grep -q ":$DROPBEAR_PORT "; then
        advanced_log "Port $DROPBEAR_PORT is already in use" ERROR
        exit 1
    fi
}

# Dropbear Configuration
configure_dropbear() {
    # Backup existing configuration
    [[ -f "$DROPBEAR_CONFIG_FILE" ]] && 
        cp "$DROPBEAR_CONFIG_FILE" "${DROPBEAR_CONFIG_FILE}.bak_$(date '+%Y%m%d%H%M%S')"

    # Create enhanced configuration
    cat > "$DROPBEAR_CONFIG_FILE" <<EOL
NO_START=0
DROPBEAR_PORT=$DROPBEAR_PORT
DROPBEAR_EXTRA_ARGS="-w -s -g -R"
DROPBEAR_BANNER="/etc/issue.net"
DROPBEAR_RECEIVE_WINDOW=65536
EOL

    # Create security banner
    cat > /etc/issue.net <<EOL
**************************************************************************
*                   Secure Dropbear SSH Server                           *
* Unauthorized access is strictly prohibited                             *
**************************************************************************
EOL
}

# Main Installation Workflow
main() {
    check_root_permissions
    setup_dependencies
    initialize_database
    configure_dropbear_port "$@"
    configure_dropbear
    
    # Apply system optimizations
    apply_system_optimizations

    # Enable and start Dropbear
    systemctl enable dropbear
    systemctl restart dropbear

    # UFW Configuration
    if command -v ufw &> /dev/null; then
        ufw allow "$DROPBEAR_PORT"/tcp
        ufw reload
    fi

    # Run connectivity monitoring
    monitor_ssh_connectivity

    # Final logging
    advanced_log "Dropbear SSH installed successfully on port $DROPBEAR_PORT with advanced optimizations"
}

# Execute main function with arguments
main "$@"
