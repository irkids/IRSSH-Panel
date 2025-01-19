#!/bin/bash

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

# Configuration
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"

# Install Node.js
log "Installing Node.js..."
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"

# Install specific Node.js version
nvm install 20
nvm use 20

# Clean up previous installation
log "Cleaning up previous installation..."
rm -rf "$FRONTEND_DIR"
mkdir -p "$FRONTEND_DIR"

# Create new React app
log "Creating new React app..."
cd "$PANEL_DIR"
npx create-react-app frontend --template typescript

cd "$FRONTEND_DIR"

# Install dependencies with correct versions
log "Installing dependencies..."
npm install --save \
    @headlessui/react@1.7.17 \
    @heroicons/react@2.1.1 \
    react-router-dom@6.21.1 \
    recharts@2.10.3 \
    axios@1.6.4 \
    @types/node@20.10.6 \
    @types/react@18.2.47 \
    @types/react-dom@18.2.18 \
    typescript@5.3.3

# Install dev dependencies
log "Installing development dependencies..."
npm install --save-dev \
    tailwindcss@3.4.1 \
    postcss@8.4.33 \
    autoprefixer@10.4.16

# Initialize Tailwind CSS
log "Setting up Tailwind CSS..."
npx tailwindcss init -p

# Create base Tailwind CSS config
cat > tailwind.config.js << 'EOL'
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}
EOL

# Update src/index.css
cat > src/index.css << 'EOL'
@tailwind base;
@tailwind components;
@tailwind utilities;
EOL

# Create base App.tsx
cat > src/App.tsx << 'EOL'
import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';

function App() {
  return (
    <Router>
      <div className="min-h-screen bg-gray-100">
        <Routes>
          <Route path="/" element={<div className="p-6">Welcome to IRSSH Panel</div>} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
EOL

# Build frontend
log "Building frontend..."
npm run build

# Setup nginx configuration
log "Configuring nginx..."
cat > /etc/nginx/sites-available/irssh-panel << 'EOL'
server {
    listen 80;
    server_name _;

    root /opt/irssh-panel/frontend/build;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
EOL

# Enable nginx site
ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Restart nginx
systemctl restart nginx

log "Frontend setup completed successfully!"
