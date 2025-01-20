#!/bin/bash

# IRSSH Panel Complete Setup Script

# Configuration
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
DOMAIN=""  # Will be set during execution

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

# Check if first installation is complete
if [ ! -d "$PANEL_DIR" ]; then
    error "Please run the main installation script first"
fi

# Setup Backend Structure
log "Setting up backend structure..."
mkdir -p "$BACKEND_DIR/app/"{core,api,models,schemas,utils}
mkdir -p "$BACKEND_DIR/app/api/v1/endpoints"

# Create __init__.py files
touch "$BACKEND_DIR/app/__init__.py"
touch "$BACKEND_DIR/app/core/__init__.py"
touch "$BACKEND_DIR/app/api/__init__.py"
touch "$BACKEND_DIR/app/api/v1/__init__.py"
touch "$BACKEND_DIR/app/models/__init__.py"
touch "$BACKEND_DIR/app/schemas/__init__.py"
touch "$BACKEND_DIR/app/utils/__init__.py"

# Copy backend files
log "Copying backend files..."
cp -r /root/irssh-panel/backend/* "$BACKEND_DIR/"

# Setup Frontend
log "Setting up frontend..."
cd "$PANEL_DIR"

# Install Node.js 18.x
if ! command -v node &> /dev/null; then
    log "Installing Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    apt-get install -y nodejs
fi

# Create React App
log "Creating React application..."
npx create-react-app frontend --template typescript

cd "$FRONTEND_DIR"

# Install frontend dependencies
log "Installing frontend dependencies..."
npm install \
    @headlessui/react \
    @heroicons/react \
    axios \
    react-router-dom \
    recharts \
    tailwindcss \
    @tailwindcss/forms \
    @types/recharts \
    lucide-react \
    @types/node \
    @types/react \
    @types/react-dom \
    postcss \
    autoprefixer

# Copy frontend files
log "Copying frontend files..."
cp -r /root/irssh-panel/frontend/src/* "$FRONTEND_DIR/src/"

# Setup Tailwind CSS
log "Configuring Tailwind CSS..."
npx tailwindcss init -p

# Build frontend
log "Building frontend..."
npm run build

# SSL Configuration
log "Configuring SSL..."
read -p "Enter your domain name (e.g., panel.example.com): " DOMAIN

if [ -z "$DOMAIN" ]; then
    error "Domain name is required"
fi

# Configure Nginx for domain
log "Configuring Nginx..."
cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    server_name $DOMAIN;

    root $FRONTEND_DIR/build;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
        add_header X-Frame-Options "SAMEORIGIN";
        add_header X-Content-Type-Options "nosniff";
        add_header X-XSS-Protection "1; mode=block";
        add_header Content-Security-Policy "default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data: https:; connect-src 'self' wss://$DOMAIN;";
    }

    location /api {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # CORS headers
        add_header 'Access-Control-Allow-Origin' 'https://$DOMAIN' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;
        add_header 'Access-Control-Expose-Headers' 'Content-Length,Content-Range' always;
    }

    location /ws {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    client_max_body_size 100M;
    keepalive_timeout 65;
    server_tokens off;
}
EOL

ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/

# Configure SSL with Certbot
log "Setting up SSL with Certbot..."
certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email admin@$DOMAIN

# Update CORS settings in backend
log "Updating CORS settings..."
cat > "$CONFIG_DIR/cors.env" << EOL
ALLOWED_ORIGINS=["https://$DOMAIN"]
ALLOWED_METHODS=["*"]
ALLOWED_HEADERS=["*"]
ALLOW_CREDENTIALS=true
EOL

# Initialize and configure modules
log "Setting up modules..."
for module in ssh l2tp ikev2 cisco wireguard singbox; do
    log "Initializing $module module..."
    "$PANEL_DIR/modules/$module-script.py" init || error "Failed to initialize $module module"
    
    # Generate default configuration
    "$PANEL_DIR/modules/$module-script.py" generate-config > "$CONFIG_DIR/$module.json"
    
    # Set correct permissions
    chmod 600 "$CONFIG_DIR/$module.json"
done

# Setup automatic module updates
log "Setting up automatic module updates..."
cat > /etc/cron.daily/irssh-modules << EOL
#!/bin/bash
cd $PANEL_DIR/modules
for script in *-script.py *-script.sh; do
    if [ -f "\$script" ]; then
        ./\$script update
    fi
done
EOL

chmod +x /etc/cron.daily/irssh-modules

# Restart services
log "Restarting services..."
systemctl restart nginx
supervisorctl restart irssh-panel
systemctl restart irssh-tasks

# Final checks
log "Performing final checks..."
curl -s -o /dev/null -w "%{http_code}" https://$DOMAIN/api/health

# Installation complete
log "Setup completed successfully!"
echo
echo "Your IRSSH Panel is now available at: https://$DOMAIN"
echo
echo "Please verify the following:"
echo "1. Frontend is accessible at https://$DOMAIN"
echo "2. API is accessible at https://$DOMAIN/api"
echo "3. All modules are running correctly"
echo
echo "Next steps:"
echo "1. Login with admin credentials"
echo "2. Change the default admin password"
echo "3. Configure each module as needed"
echo "4. Set up monitoring alerts"
echo
echo "For support, check the documentation or contact support."
