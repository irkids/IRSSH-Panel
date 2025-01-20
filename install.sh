#!/bin/bash

# IRSSH Server Initialization Script

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

# Update system
log "Updating system packages..."
apt-get update
apt-get upgrade -y

# Install essential packages
log "Installing essential packages..."
apt-get install -y \
    curl \
    wget \
    git \
    vim \
    htop \
    tmux \
    zip \
    unzip \
    net-tools \
    iptables \
    ufw \
    fail2ban \
    ntp \
    ca-certificates \
    gnupg \
    lsb-release

# Configure timezone
log "Configuring timezone..."
timedatectl set-timezone UTC
systemctl restart ntp

# Configure system limits
log "Configuring system limits..."
cat >> /etc/security/limits.conf << EOL
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOL

# Configure sysctl
log "Configuring sysctl..."
cat > /etc/sysctl.d/99-irssh.conf << EOL
# Network optimizations
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 262144
net.ipv4.tcp_max_syn_backlog = 262144
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_retries2 = 8
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 87380 16777216
net.ipv4.tcp_mem = 786432 1048576 26777216
net.ipv4.tcp_max_tw_buckets = 6000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.optmem_max = 40960

# Enable BBR
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Security settings
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# IPv6 settings
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.all.forwarding = 1
EOL

sysctl --system

# Configure fail2ban
log "Configuring fail2ban..."
cat > /etc/fail2ban/jail.local << EOL
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
EOL

systemctl enable fail2ban
systemctl restart fail2ban

# Configure SSH
log "Configuring SSH..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
cat > /etc/ssh/sshd_config << EOL
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
UsePrivilegeSeparation yes
KeyRegenerationInterval 3600
ServerKeyBits 2048
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 120
PermitRootLogin prohibit-password
StrictModes yes
RSAAuthentication yes
PubkeyAuthentication yes
IgnoreRhosts yes
RhostsRSAAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
X11Forwarding yes
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes
MaxStartups 10:30:100
AllowTcpForwarding yes
EOL

systemctl restart ssh

# Configure UFW
log "Configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https
ufw --force enable

# Setup swap if needed
log "Checking swap..."
if [ $(free -m | grep Swap | awk '{print $2}') -eq 0 ]; then
    log "Setting up swap..."
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    
    # Configure swappiness
    echo 'vm.swappiness=10' >> /etc/sysctl.d/99-irssh.conf
    echo 'vm.vfs_cache_pressure=50' >> /etc/sysctl.d/99-irssh.conf
    sysctl -p
fi

# Create monitoring scripts
log "Creating monitoring scripts..."
mkdir -p /opt/irssh/scripts

# System monitor script
cat > /opt/irssh/scripts/monitor.sh << 'EOL'
#!/bin/bash
echo "System Resources:"
echo "----------------"
echo "CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')%"
echo "Memory Usage: $(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2 }')"
echo "Disk Usage: $(df -h / | awk 'NR==2{print $5}')"
echo
echo "Network Connections:"
echo "------------------"
echo "Current Connections: $(netstat -an | grep ESTABLISHED | wc -l)"
echo "TCP Connections: $(netstat -nt | wc -l)"
echo "UDP Connections: $(netstat -nu | wc -l)"
echo
echo "Load Average:"
echo "------------"
uptime
EOL

chmod +x /opt/irssh/scripts/monitor.sh

# Create cron jobs
log "Setting up cron jobs..."
cat > /etc/cron.d/irssh << EOL
# System updates
0 3 * * * root apt-get update && apt-get upgrade -y
# Cleanup
0 4 * * * root /usr/sbin/logrotate /etc/logrotate.conf
# Monitoring
*/5 * * * * root /opt/irssh/scripts/monitor.sh > /var/log/irssh/system_status.log
EOL

# Setup log rotation
log "Configuring log rotation..."
cat > /etc/logrotate.d/irssh << EOL
/var/log/irssh/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 640 root root
    sharedscripts
    postrotate
        systemctl reload rsyslog >/dev/null 2>&1 || true
    endscript
}
EOL

# Installation complete
log "Server initialization completed successfully!"
echo
echo "Please review the following:"
echo "1. SSH configuration at /etc/ssh/sshd_config"
echo "2. Firewall rules using 'ufw status'"
echo "3. System monitoring logs at /var/log/irssh/system_status.log"
echo
echo "System is now ready for IRSSH Panel installation."
