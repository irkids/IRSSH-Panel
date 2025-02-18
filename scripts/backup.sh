# /opt/irssh-panel/scripts/backup.sh
#!/bin/bash

BACKUP_DIR="/opt/irssh-backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/backup_$DATE.tar.gz"
DB_BACKUP="$BACKUP_DIR/db_backup_$DATE.sql"

# Backup configuration files
tar -czf "$BACKUP_FILE" \
    /etc/enhanced_ssh \
    /opt/irssh-panel/config \
    /etc/nginx/sites-available/irssh-panel \
    /etc/wireguard \
    /etc/sing-box

# Backup database
source /etc/enhanced_ssh/config.yaml
PGPASSWORD="${DB_PASS}" pg_dump -U "${DB_USER}" "${DB_NAME}" > "$DB_BACKUP"

# Remove old backups (keep last 7 days)
find "$BACKUP_DIR" -type f -mtime +7 -delete

# Check backup integrity
if [ -f "$BACKUP_FILE" ] && [ -f "$DB_BACKUP" ]; then
    echo "Backup completed successfully: $DATE"
else
    echo "Backup failed!"
    exit 1
fi
