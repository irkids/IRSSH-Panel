#!/bin/bash

# Configuration
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
DOMAIN=""

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

# Install additional Python packages
log "Installing additional Python packages..."
source "$PANEL_DIR/venv/bin/activate"
pip install prometheus_client psutil geoip2 python-telegram-bot asyncio aiohttp

# Setup Frontend
log "Setting up frontend..."
cd "$PANEL_DIR"

# Install Node.js 18.x
if ! command -v node &> /dev/null; then
    log "Installing Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    apt-get install -y nodejs
fi

# Create React App with specific versions
log "Creating React application..."
mkdir -p "$FRONTEND_DIR"
cd "$FRONTEND_DIR"

# Initialize package.json with specific versions
cat > package.json << EOL
{
  "name": "irssh-panel-frontend",
  "version": "0.1.0",
  "private": true,
  "dependencies": {
    "@headlessui/react": "^1.7.17",
    "@heroicons/react": "^2.1.1",
    "@tailwindcss/forms": "^0.5.7",
    "@testing-library/jest-dom": "^5.17.0",
    "@testing-library/react": "^13.4.0",
    "@testing-library/user-event": "^13.5.0",
    "@types/jest": "^27.5.2",
    "@types/node": "^16.18.70",
    "@types/react": "^18.2.47",
    "@types/react-dom": "^18.2.18",
    "axios": "^1.6.5",
    "lucide-react": "^0.309.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.21.1",
    "react-scripts": "5.0.1",
    "recharts": "^2.10.3",
    "typescript": "^4.9.5",
    "web-vitals": "^2.1.4"
  },
  "scripts": {
    "start": "react-scripts start",
    "build": "react-scripts build",
    "test": "react-scripts test",
    "eject": "react-scripts eject"
  },
  "eslintConfig": {
    "extends": [
      "react-app",
      "react-app/jest"
    ]
  },
  "browserslist": {
    "production": [
      ">0.2%",
      "not dead",
      "not op_mini all"
    ],
    "development": [
      "last 1 chrome version",
      "last 1 firefox version",
      "last 1 safari version"
    ]
  },
  "devDependencies": {
    "autoprefixer": "^10.4.16",
    "postcss": "^8.4.33",
    "tailwindcss": "^3.4.1"
  }
}
EOL

# Install dependencies with legacy peer deps
log "Installing frontend dependencies..."
npm install --legacy-peer-deps

# Setup Tailwind CSS
log "Configuring Tailwind CSS..."
cat > tailwind.config.js << EOL
module.exports = {
  content: ["./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {},
  },
  plugins: [
    require('@tailwindcss/forms'),
  ],
}
EOL

cat > postcss.config.js << EOL
module.exports = {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
}
EOL

# Create basic React files
mkdir -p src/components src/pages src/utils

# Copy frontend files if they exist
if [ -d "/root/irssh-panel/frontend/src" ]; then
    log "Copying frontend files..."
    cp -r /root/irssh-panel/frontend/src/* "$FRONTEND_DIR/src/"
else
    log "Creating basic frontend structure..."
    # Create index.tsx
    cat > src/index.tsx << 'EOL'
import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';

const root = ReactDOM.createRoot(
  document.getElementById('root') as HTMLElement
);
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
EOL

    # Create index.css with Tailwind
    cat > src/index.css << 'EOL'
@tailwind base;
@tailwind components;
@tailwind utilities;
EOL

    # Create basic App.tsx
    cat > src/App.tsx << 'EOL'
import React from 'react';

function App() {
  return (
    <div className="min-h-screen bg-gray-100">
      <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          <h1 className="text-3xl font-bold text-gray-900">
            IRSSH Panel
          </h1>
        </div>
      </div>
    </div>
  );
}

export default App;
EOL
fi

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
    }

    location /ws {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }

    client_max_body_size 100M;
}
EOL

ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/

# Configure SSL with Certbot
log "Setting up SSL with Certbot..."
certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email admin@$DOMAIN

# Initialize modules
log "Setting up modules..."
cd "$PANEL_DIR/modules"

# Download GeoLite2 database
log "Downloading GeoLite2 database..."
mkdir -p "$PANEL_DIR/data"
wget -O "$PANEL_DIR/data/GeoLite2-City.mmdb" "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb"

# Initialize each module
for script in *-script.*; do
    if [ -f "$script" ]; then
        log "Initializing $script..."
        chmod +x "$script"
        if [[ "$script" == *.py ]]; then
            python3 "$script" init || log "Warning: Failed to initialize $script"
        else
            bash "$script" init || log "Warning: Failed to initialize $script"
        fi
    fi
done

# Restart services
log "Restarting services..."
systemctl restart nginx
supervisorctl reread
supervisorctl update
supervisorctl restart all

# Final checks
log "Performing final checks..."
curl -s -o /dev/null -w "%{http_code}" https://$DOMAIN/api/health

log "Setup completed successfully!"
echo
echo "Your IRSSH Panel is now available at: https://$DOMAIN"
echo
echo "Please verify the following:"
echo "1. Frontend is accessible at https://$DOMAIN"
echo "2. API is accessible at https://$DOMAIN/api"
echo "3. All modules are running correctly"
