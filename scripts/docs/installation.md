# IRSSH Panel Installation Guide

## System Requirements

### Minimum Hardware Requirements
- CPU: 1 core (2 cores recommended)
- RAM: 1GB (2GB recommended)
- Storage: 20GB
- Network: 100Mbps

### Software Requirements
- Ubuntu 20.04 LTS or higher
- Root access
- Domain name (recommended)

### Required Ports
- 22 (SSH)
- 80 (HTTP)
- 443 (HTTPS)
- Protocol-specific ports will be configured during installation

## Pre-Installation Steps

1. **Update System**
```bash
apt update && apt upgrade -y
```

2. **Check Server Time**
```bash
timedatectl set-timezone UTC
apt install -y ntp
systemctl start ntp
systemctl enable ntp
```

3. **Install Basic Requirements**
```bash
apt install -y curl wget git unzip
```

## Installation Methods

### Automatic Installation (Recommended)

1. **Download Installation Script**
```bash
wget https://raw.githubusercontent.com/your-repo/irssh-panel/main/scripts/install.sh
```

2. **Set Execute Permission**
```bash
chmod +x install.sh
```

3. **Run Installation**
```bash
./install.sh
```

### Manual Installation

1. **Clone Repository**
```bash
git clone https://github.com/your-repo/irssh-panel.git /opt/irssh-panel
```

2. **Install Dependencies**
```bash
apt install -y python3-pip nodejs npm postgresql nginx
pip3 install -r requirements.txt
```

3. **Setup Database**
```bash
sudo -u postgres psql -c "CREATE USER irssh_admin WITH PASSWORD 'your_password';"
sudo -u postgres psql -c "CREATE DATABASE irssh_panel OWNER irssh_admin;"
```

4. **Configure Environment**
```bash
cp .env.example .env
nano .env  # Edit configuration
```

## Post-Installation Setup

### 1. Initial Configuration

Access the web interface at `http://your-server-ip` and login with:
- Username: admin
- Password: (shown after installation)

### 2. SSL Configuration

1. **Using Let's Encrypt**
```bash
./ssl_manager.sh setup your-domain.com your@email.com
```

2. **Using Custom Certificate**
```bash
./ssl_manager.sh custom /path/to/cert /path/to/key
```

### 3. Protocol Setup

Run the following for each protocol you want to enable:
```bash
cd /opt/irssh-panel/modules
./[protocol]-script.py init
```

## Security Recommendations

1. **Change Default Passwords**
   - Admin panel password
   - Database password
   - API keys

2. **Configure Firewall**
```bash
ufw allow ssh
ufw allow http
ufw allow https
ufw enable
```

3. **Setup Fail2Ban**
```bash
apt install -y fail2ban
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
systemctl restart fail2ban
```

## Troubleshooting

### Common Issues

1. **Installation Script Fails**
- Check system requirements
- Ensure all required ports are available
- Check disk space
- Verify internet connection

2. **Database Connection Issues**
```bash
# Check PostgreSQL status
systemctl status postgresql

# Check logs
tail -f /var/log/postgresql/postgresql-*.log
```

3. **Web Interface Not Accessible**
```bash
# Check nginx status
systemctl status nginx

# Check logs
tail -f /var/log/nginx/error.log
```

4. **Protocol Issues**
```bash
# Check protocol status
cd /opt/irssh-panel/modules
./[protocol]-script.py status

# View logs
tail -f /var/log/irssh/[protocol].log
```

### Log Locations
- Main Panel: `/var/log/irssh/panel.log`
- Nginx: `/var/log/nginx/`
- PostgreSQL: `/var/log/postgresql/`
- Protocol Logs: `/var/log/irssh/`

## Maintenance

### Backup Configuration
```bash
# Create backup directory
mkdir -p /var/backups/irssh

# Setup automatic backups
cp /opt/irssh-panel/scripts/backup.sh /etc/cron.daily/
chmod +x /etc/cron.daily/backup.sh
```

### Updates
```bash
cd /opt/irssh-panel
git pull
./scripts/update.sh
```

### Database Maintenance
```bash
# Vacuum database
sudo -u postgres psql -d irssh_panel -c "VACUUM ANALYZE;"
```

## Uninstallation

If you need to remove IRSSH Panel:
```bash
cd /opt/irssh-panel
./scripts/uninstall.sh
```

## Additional Resources

- [GitHub Repository](https://github.com/your-repo/irssh-panel)
- [Bug Reports](https://github.com/your-repo/irssh-panel/issues)
- [Feature Requests](https://github.com/your-repo/irssh-panel/issues)
