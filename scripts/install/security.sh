#!/bin/bash

# Setup security configurations
setup_security() {
    log "Setting up security configurations..."

    # Configure fail2ban
    setup_fail2ban
    
    # Configure SSH
    secure_ssh
    
    # Configure firewall
    setup_firewall
    
    # Setup SSL/TLS
    setup_ssl_security
    
    # Setup system security
    setup_system_security
}

# Configure fail2ban
setup_fail2ban() {
    log "Configuring fail2ban..."

    # Create jail configuration
    cat > /etc/fail2ban/jail.local << EOL
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
banaction = iptables-multiport

[sshd]
enabled = true
port = $SSH_PORT
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-botsearch]
enabled = true
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 2

[nginx-badbots]
enabled = true
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 2

[nginx-nohome]
enabled = true
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 2
EOL

    # Create custom filter for nginx
    cat > /etc/fail2ban/filter.d/nginx-nohome.conf << 'EOL'
[Definition]
failregex = ^<HOST> -.*GET .*/~.*
ignoreregex =
EOL

    # Restart fail2ban
    systemctl restart fail2ban
}

# Secure SSH configuration
secure_ssh() {
    log "Securing SSH configuration..."

    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

    # Configure SSH
    cat > /etc/ssh/sshd_config << EOL
Port $SSH_PORT
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Authentication
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Security
X11Forwarding no
AllowTcpForwarding yes
AllowAgentForwarding yes
PermitTunnel yes
PrintMotd no
TCPKeepAlive yes
ClientAliveInterval 120
ClientAliveCountMax 3

# Logging
SyslogFacility AUTH
LogLevel INFO

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

# Override default of no subsystems
Subsystem sftp /usr/lib/openssh/sftp-server
EOL

    # Restart SSH
    systemctl restart sshd
}

# Setup SSL/TLS security
setup_ssl_security() {
    log "Configuring SSL/TLS security..."

    # Create strong DH parameters
    if [[ ! -f /etc/nginx/dhparam.pem ]]; then
        openssl dhparam -out /etc/nginx/dhparam.pem 2048
    fi

    # Configure SSL in Nginx
    cat > /etc/nginx/conf.d/ssl.conf << 'EOL'
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;
ssl_dhparam /etc/nginx/dhparam.pem;
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
EOL
}

# Setup system security
setup_system_security() {
    log "Configuring system security..."

    # Configure system limits
    cat > /etc/security/limits.d/irssh.conf << EOL
* soft nofile 65535
* hard nofile 65535
* soft nproc 65535
* hard nproc 65535
EOL

    # Configure sysctl security settings
    cat > /etc/sysctl.d/99-security.conf << EOL
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore Directed pings
net.ipv4.icmp_echo_ignore_all = 1

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.lo.disable_ipv6 = 0

# Enable IP forwarding
net.ipv4.ip_forward = 1
EOL

    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-security.conf

    # Install additional security tools
    apt-get install -y \
        unattended-upgrades \
        apt-listchanges \
        rkhunter \
        chkrootkit \
        lynis \
        aide \
        || error "Failed to install security tools"

    # Configure unattended-upgrades
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOL'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

Unattended-Upgrade::Package-Blacklist {
};

Unattended-Upgrade::DevRelease "auto";
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Mail "";
Unattended-Upgrade::MailOnlyOnError "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOL

    # Enable unattended-upgrades
    echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";' > /etc/apt/apt.conf.d/20auto-upgrades

    # Configure AIDE
    aide --init
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

    # Setup daily security scans
    cat > /etc/cron.daily/security-scan << 'EOL'
#!/bin/bash
# Run rootkit scans
rkhunter --check --skip-keypress --report-warnings-only
chkrootkit

# Update AIDE database
aide --check > /var/log/aide/aide.log 2>&1

# Run Lynis audit
lynis audit system --quiet --report-file /var/log/lynis-report.dat
EOL
    chmod +x /etc/cron.daily/security-scan

    # Configure auditd
    cat > /etc/audit/rules.d/audit.rules << 'EOL'
# Delete all existing rules
-D

# Set buffer size
-b 8192

# Monitor file system mounts
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -k mount

# Monitor system time changes
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Monitor user and group changes
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitor network environment changes
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale

# Monitor SSH configuration changes
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitor privileged command execution
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Monitor changes to important files
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Make the configuration immutable
-e 2
EOL

    # Restart auditd
    service auditd restart

    # Setup logrotate for security logs
    cat > /etc/logrotate.d/security << 'EOL'
/var/log/aide/aide.log
/var/log/lynis-report.dat
/var/log/rkhunter.log
/var/log/chkrootkit/
{
    rotate 7
    daily
    missingok
    notifempty
    compress
    delaycompress
    create 0640 root adm
    sharedscripts
    postrotate
        /usr/bin/systemctl reload rsyslog >/dev/null 2>&1 || true
    endscript
}
EOL

    log "Security configuration completed"
}
