#!/bin/bash

set -e

# Configuration
APP_NAME="irssh-panel"
APP_DIR="/opt/$APP_NAME"
NODE_VERSION="16"

# Install system dependencies
echo "Installing system dependencies..."
apt-get update
apt-get install -y curl build-essential git

# Install Node.js
echo "Installing Node.js..."
curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash -
apt-get install -y nodejs

# Install MongoDB
echo "Installing MongoDB..."
wget -qO - https://www.mongodb.org/static/pgp/server-5.0.asc | apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/5.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-5.0.list
apt-get update
apt-get install -y mongodb-org

# Install Redis
echo "Installing Redis..."
apt-get install -y redis-server

# Create application directory
echo "Creating application directory..."
mkdir -p $APP_DIR
chown -R $USER:$USER $APP_DIR

# Install global npm packages
echo "Installing global npm packages..."
npm install -g pm2 typescript

# Setup environment variables
echo "Setting up environment variables..."
cp .env.example .env
source .env

# Initialize application
echo "Initializing application..."
npm install
npm run build

# Setup systemd services
echo "Setting up systemd services..."
cp systemd/* /etc/systemd/system/
systemctl daemon-reload
systemctl enable mongodb redis irssh-panel
systemctl start mongodb redis irssh-panel

# Setup Nginx
echo "Setting up Nginx..."
apt-get install -y nginx certbot python3-certbot-nginx
cp nginx/irssh-panel.conf /etc/nginx/sites-available/
ln -s /etc/nginx/sites-available/irssh-panel.conf /etc/nginx/sites-enabled/
nginx -t && systemctl restart nginx

# Setup firewall
echo "Setting up firewall..."
ufw allow ssh
ufw allow http
ufw allow https
ufw --force enable

echo "Environment setup completed successfully!"
