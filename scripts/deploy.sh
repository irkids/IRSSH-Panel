#!/bin/bash

set -e

# Environment variables
ENV=${1:-production}
APP_NAME="irssh-panel"
DEPLOY_DIR="/opt/$APP_NAME"
BACKUP_DIR="/opt/backups/$APP_NAME"

# Load environment variables
source .env.$ENV

# Create backup
echo "Creating backup..."
BACKUP_FILE="$BACKUP_DIR/backup-$(date +%Y%m%d-%H%M%S).tar.gz"
tar -czf $BACKUP_FILE $DEPLOY_DIR

# Pull latest changes
echo "Pulling latest changes..."
git pull origin main

# Install dependencies
echo "Installing dependencies..."
npm install --production

# Build application
echo "Building application..."
npm run build

# Update configuration
echo "Updating configuration..."
cp config/$ENV.json $DEPLOY_DIR/config/current.json

# Restart services
echo "Restarting services..."
pm2 reload ecosystem.config.js --env $ENV

# Verify deployment
echo "Verifying deployment..."
sleep 5
if curl -s "http://localhost:3000/health" | grep -q "ok"; then
    echo "Deployment successful!"
else
    echo "Deployment failed!"
    echo "Rolling back..."
    tar -xzf $BACKUP_FILE -C /
    pm2 reload ecosystem.config.js --env $ENV
    exit 1
fi
