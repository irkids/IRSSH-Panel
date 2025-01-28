# IRSSH Panel Configuration Guide

## Network Configuration
### Firewall Settings
```bash
# Allow SSH
ufw allow 22
# Allow Web Panel
ufw allow 80
ufw allow 443
```

### Protocol Ports
- SSH: 22
- L2TP: 1701, 500, 4500
- IKEv2: 500, 4500
- WireGuard: 51820
- SingBox: Custom ports

## SSL Configuration
### Using Let's Encrypt
```bash
./ssl_manager.sh setup your-domain.com your-email@domain.com
```

### Using Custom Certificate
```bash
./ssl_manager.sh custom /path/to/cert /path/to/key
```

### SSL Settings
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
```

## Database Configuration
### PostgreSQL Settings
```bash
DB_HOST=localhost
DB_PORT=5432
DB_NAME=irssh_panel
DB_USER=irssh_admin
DB_PASS=your_secure_password
```

### Database Maintenance
```sql
-- Vacuum database
VACUUM ANALYZE;

-- Reset user passwords
UPDATE users SET password_hash = 'new_hash' WHERE username = 'user';
```

## Backup Configuration
### Automated Backups
```bash
# Daily backups
0 0 * * * /opt/irssh-panel/scripts/backup.sh daily

# Weekly backups
0 0 * * 0 /opt/irssh-panel/scripts/backup.sh weekly
```

### Backup Locations
- Daily: /var/backups/irssh/daily/
- Weekly: /var/backups/irssh/weekly/
- Monthly: /var/backups/irssh/monthly/

### Backup Settings
```yaml
backup:
  retention:
    daily: 7
    weekly: 4
    monthly: 3
  compression: true
  encrypt: true
```

## Monitoring Configuration
### System Metrics
```bash
# Update interval
METRIC_INTERVAL=60

# Alert thresholds
CPU_THRESHOLD=80
MEMORY_THRESHOLD=90
DISK_THRESHOLD=85
```

### Log Settings
```bash
# Log rotation
/var/log/irssh/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
}
```

### Monitoring Alerts
```yaml
alerts:
  email:
    enabled: true
    recipients:
      - admin@example.com
  telegram:
    enabled: false
    bot_token: ""
    chat_id: ""
```

## Protocol Configurations

### SSH Configuration
```bash
Port 22
PermitRootLogin no
PasswordAuthentication yes
MaxAuthTries 3
MaxSessions 10
```

### L2TP Configuration
```bash
# IPSec configuration
conn L2TP-PSK
    authby=secret
    pfs=no
    auto=add
    keyingtries=3
    dpddelay=30
    dpdtimeout=120
```

### IKEv2 Configuration
```bash
# strongSwan configuration
connections {
    ikev2-vpn {
        local_addrs  = %any
        pools = vip-pool
        proposals = aes256-sha256-modp2048
    }
}
```

### WireGuard Configuration
```ini
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = server_private_key

[Peer]
PublicKey = client_public_key
AllowedIPs = 10.0.0.2/32
```

### SingBox Configuration
```json
{
  "inbounds": [
    {
      "type": "mixed",
      "listen": "::",
      "listen_port": 443
    }
  ],
  "outbounds": [
    {
      "type": "direct"
    }
  ]
}
```

## Security Configuration
### Access Control
```bash
# IP whitelist
ALLOWED_IPS="1.2.3.4,5.6.7.8"

# Rate limiting
RATE_LIMIT="30/minute"

# Failed login attempts
MAX_FAILED_ATTEMPTS=5
LOCKOUT_TIME=300
```

### Authentication
```yaml
auth:
  session_timeout: 3600
  jwt_secret: "your-secure-jwt-secret"
  password_policy:
    min_length: 12
    require_numbers: true
    require_special: true
