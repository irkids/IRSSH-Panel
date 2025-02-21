#!/bin/bash

set -e

# Configuration
APP_NAME="irssh-panel"
BACKUP_DIR="/opt/backups/$APP_NAME"
RETENTION_DAYS=30
MONGODB_URI=${MONGODB_URI:-"mongodb://localhost:27017"}
DATABASE_NAME=${DATABASE_NAME:-"irssh"}

# Create timestamp
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_PATH="$BACKUP_DIR/$TIMESTAMP"

# Create backup directory
mkdir -p $BACKUP_PATH

# Backup MongoDB
echo "Backing up MongoDB..."
mongodump --uri=$MONGODB_URI --db=$DATABASE_NAME --out=$BACKUP_PATH/mongodb

# Backup Redis
echo "Backing up Redis..."
redis-cli SAVE
cp /var/lib/redis/dump.rdb $BACKUP_PATH/redis-dump.rdb

# Backup configuration files
echo "Backing up configuration..."
cp -r /opt/$APP_NAME/config $BACKUP_PATH/
cp /opt/$APP_NAME/.env $BACKUP_PATH/

# Backup uploads
echo "Backing up uploads..."
cp -r /opt/$APP_NAME/uploads $BACKUP_PATH/

# Create archive
echo "Creating archive..."
cd $BACKUP_DIR
tar -czf $TIMESTAMP.tar.gz $TIMESTAMP
rm -rf $TIMESTAMP

# Upload to S3
if [ ! -z "$AWS_BUCKET" ]; then
    echo "Uploading to S3..."
    aws s3 cp $TIMESTAMP.tar.gz s3://$AWS_BUCKET/backups/
fi

# Cleanup old backups
echo "Cleaning up old backups..."
find $BACKUP_DIR -type f -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed successfully!"
