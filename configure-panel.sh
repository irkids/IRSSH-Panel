#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
LOG_DIR="/var/log/irssh"

# Logging
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
    exit 1
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Get server IP
SERVER_IP=$(curl -s ifconfig.me)
if [[ -z "$SERVER_IP" ]]; then
    SERVER_IP=$(ip route get 1 | awk '{print $7;exit}')
fi

# Configuration prompts
echo "IRSSH Panel Configuration"
echo "========================"
echo

# Port configuration
read -p "Enter web panel port (default: 80): " WEB_PORT
WEB_PORT=${WEB_PORT:-80}

# SSL configuration
echo
echo "SSL Configuration:"
echo "1. Use HTTP only (IP address)"
echo "2. Enable HTTPS with domain/subdomain"
read -p "Select SSL option (1-2): " SSL_OPTION

case $SSL_OPTION in
    2)
        read -p "Enter your domain (e.g., panel.example.com): " DOMAIN
        if [[ -z "$DOMAIN" ]]; then
            error "Domain cannot be empty for HTTPS setup"
        fi
        USE_SSL=true
        ;;
    *)
        USE_SSL=false
        DOMAIN=$SERVER_IP
        ;;
esac

# Admin credentials
echo
echo "Admin Account Setup:"
read -p "Enter admin username (default: admin): " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}

# Generate random password if not provided
read -s -p "Enter admin password (press Enter for random): " ADMIN_PASS
echo
if [[ -z "$ADMIN_PASS" ]]; then
    ADMIN_PASS=$(openssl rand -base64 12)
    echo "Generated admin password: $ADMIN_PASS"
fi

# Save configuration
log "Saving configuration..."
cat > "$CONFIG_DIR/panel.conf" << EOL
WEB_PORT=$WEB_PORT
USE_SSL=$USE_SSL
DOMAIN=$DOMAIN
ADMIN_USER=$ADMIN_USER
EOL

# Update Nginx configuration
log "Configuring Nginx..."
if [ "$USE_SSL" = true ]; then
    # HTTPS configuration
    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$host:$WEB_PORT\$request_uri;
}

server {
    listen $WEB_PORT ssl http2;
    server_name $DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;

    root $FRONTEND_DIR/build;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location /api {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    client_max_body_size 100M;
}
EOL

    # Install SSL certificate
    log "Installing SSL certificate..."
    certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email admin@$DOMAIN || error "SSL certificate installation failed"

else
    # HTTP configuration
    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen $WEB_PORT;
    server_name $SERVER_IP;

    root $FRONTEND_DIR/build;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location /api {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    client_max_body_size 100M;
}
EOL
fi

# Enable site configuration
ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Update frontend configuration
log "Updating frontend configuration..."
cat > "$FRONTEND_DIR/src/config.js" << EOL
export const API_URL = '${USE_SSL:+https://}${USE_SSL:+http://}$DOMAIN:$WEB_PORT/api';
EOL

# Create admin user
log "Creating admin user..."
cat > "$BACKEND_DIR/create_admin.py" << EOL
from app.core.security import get_password_hash
from app.models.user import User
from app.core.database import SessionLocal

def create_admin():
    db = SessionLocal()
    admin = User(
        username="$ADMIN_USER",
        hashed_password=get_password_hash("$ADMIN_PASS"),
        is_admin=True
    )
    db.add(admin)
    db.commit()
    db.close()

if __name__ == "__main__":
    create_admin()
EOL

# Execute admin creation
source "$PANEL_DIR/venv/bin/activate"
python "$BACKEND_DIR/create_admin.py"

# Restart services
log "Restarting services..."
systemctl restart nginx
supervisorctl restart irssh-panel

# Final output
echo
echo "IRSSH Panel Configuration Complete!"
echo "=================================="
echo
if [ "$USE_SSL" = true ]; then
    echo "Panel URL: https://$DOMAIN:$WEB_PORT"
else
    echo "Panel URL: http://$SERVER_IP:$WEB_PORT"
fi
echo
echo "Admin Credentials:"
echo "Username: $ADMIN_USER"
echo "Password: $ADMIN_PASS"
echo
echo "Please save these credentials securely!"
