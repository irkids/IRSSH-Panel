#!/bin/bash

# Install system dependencies
install_dependencies() {
    log "Installing system dependencies..."
    apt-get update || error "Failed to update package lists"

    # Install required packages
    local packages=(
        "python3" "python3-pip" "python3-venv"
        "postgresql" "postgresql-contrib"
        "nginx" "certbot" "python3-certbot-nginx"
        "git" "curl" "wget" "zip" "unzip"
        "supervisor" "ufw" "fail2ban"
        "sysstat" "iftop" "vnstat"
        "strongswan" "xl2tpd" "ppp"
        "wireguard" "golang"
        "iptables-persistent"
    )

    for package in "${packages[@]}"; do
        log "Installing $package..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y $package || error "Failed to install $package"
    done

    # Install Node.js
    log "Installing Node.js..."
    if ! command -v node &> /dev/null; then
        curl -fsSL https://deb.nodesource.com/setup_18.x | bash - || error "Failed to setup Node.js repository"
        DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs || error "Failed to install Node.js"
    fi

    # Install specific npm version
    npm install -g npm@8.19.4 || error "Failed to update npm"

    # Install global npm packages
    npm install -g pm2 || error "Failed to install pm2"

    # Install Python packages
    pip3 install --upgrade pip wheel setuptools || error "Failed to upgrade pip"

    # Install required Python packages
    pip3 install \
        fastapi[all] \
        uvicorn[standard] \
        sqlalchemy[asyncio] \
        psycopg2-binary \
        python-jose[cryptography] \
        passlib[bcrypt] \
        python-multipart \
        aiofiles \
        psutil \
        prometheus_client \
        python-telegram-bot \
        geoip2 \
        asyncpg || error "Failed to install Python packages"

    # Install Certbot plugins
    apt-get install -y \
        python3-certbot-nginx \
        python3-certbot-apache || error "Failed to install Certbot plugins"

    # Install development tools
    apt-get install -y \
        build-essential \
        libssl-dev \
        libffi-dev \
        python3-dev || error "Failed to install development tools"

    # Install monitoring tools
    apt-get install -y \
        htop \
        atop \
        iotop \
        nload \
        nethogs \
        speedtest-cli || error "Failed to install monitoring tools"

    # Install security tools
    apt-get install -y \
        unattended-upgrades \
        apt-listchanges \
        fail2ban \
        rkhunter \
        chkrootkit || error "Failed to install security tools"

    # Configure unattended-upgrades
    echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";' > /etc/apt/apt.conf.d/20auto-upgrades

    # Enable and start services
    systemctl enable --now \
        fail2ban \
        unattended-upgrades || error "Failed to enable services"

    log "Successfully installed all dependencies"
}

# Configure firewall
setup_firewall() {
    log "Configuring firewall..."
    
    # Reset UFW
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing

    # Allow SSH before enabling UFW
    ufw allow ssh

    # Allow required ports
    ufw allow http
    ufw allow https
    ufw allow "$WEB_PORT"
    ufw allow "$SSH_PORT"
    ufw allow "$DROPBEAR_PORT"
    ufw allow "$BADVPN_PORT/udp"

    # Allow protocol ports if enabled
    [ "$INSTALL_L2TP" = true ] && ufw allow "$L2TP_PORT"
    [ "$INSTALL_IKEV2" = true ] && ufw allow "$IKEV2_PORT"
    [ "$INSTALL_CISCO" = true ] && ufw allow "$CISCO_PORT"
    [ "$INSTALL_WIREGUARD" = true ] && ufw allow "$WIREGUARD_PORT"
    [ "$INSTALL_SINGBOX" = true ] && ufw allow "$SINGBOX_PORT"

    # Enable UFW
    echo "y" | ufw enable

    # Save rules
    ufw status verbose > "$CONFIG_DIR/firewall_rules.txt"

    log "Firewall configured successfully"
}

# Setup fail2ban
setup_fail2ban() {
    log "Configuring fail2ban..."

    # Backup original config
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.conf.backup

    # Create custom config
    cat > /etc/fail2ban/jail.local << EOL
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = $SSH_PORT
logpath = /var/log/auth.log

[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
EOL

    # Restart fail2ban
    systemctl restart fail2ban

    log "fail2ban configured successfully"
}

# Setup system optimizations
setup_system_optimizations() {
    log "Configuring system optimizations..."

    # Backup sysctl.conf
    cp /etc/sysctl.conf /etc/sysctl.conf.backup

    # Add system optimizations
    cat >> /etc/sysctl.conf << EOL
# Network optimizations
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.ip_forward = 1

# System optimizations
vm.swappiness = 10
vm.vfs_cache_pressure = 50
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5
EOL

    # Apply changes
    sysctl -p

    log "System optimizations applied successfully"
}
