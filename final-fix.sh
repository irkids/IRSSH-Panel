#!/bin/bash

# IRSSH Panel Final Fix Script

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
VENV_DIR="$PANEL_DIR/venv"
LOG_DIR="/var/log/irssh"

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

# Get domain
read -p "Enter your domain (e.g., panel.example.com): " DOMAIN
if [[ -z "$DOMAIN" ]]; then
    error "Domain cannot be empty"
fi

# Fix backend structure
log "Fixing backend structure..."
mkdir -p "$BACKEND_DIR/app/"{core,api,models,schemas,utils}
mkdir -p "$BACKEND_DIR/app/api/v1/endpoints"

# Create necessary backend files
log "Creating backend files..."

# Create router.py
cat > "$BACKEND_DIR/app/api/router.py" << 'EOL'
from fastapi import APIRouter, Depends, HTTPException
from app.core import security
from app.api.v1.endpoints import auth, users, protocols

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(protocols.router, prefix="/protocols", tags=["protocols"])

@api_router.get("/health")
def health_check():
    return {"status": "healthy"}
EOL

# Create auth.py
cat > "$BACKEND_DIR/app/api/v1/endpoints/auth.py" << 'EOL'
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

router = APIRouter()

@router.post("/login")
async def login():
    return {"message": "Login endpoint"}

@router.post("/logout")
async def logout():
    return {"message": "Logout endpoint"}
EOL

# Create users.py
cat > "$BACKEND_DIR/app/api/v1/endpoints/users.py" << 'EOL'
from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def get_users():
    return {"message": "Users list endpoint"}
EOL

# Create protocols.py
cat > "$BACKEND_DIR/app/api/v1/endpoints/protocols.py" << 'EOL'
from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def get_protocols():
    return {"message": "Protocols list endpoint"}
EOL

# Fix frontend
log "Fixing frontend..."
cd "$FRONTEND_DIR"

# Update package.json
cat > "$FRONTEND_DIR/package.json" << EOL
{
  "name": "irssh-panel",
  "version": "1.0.0",
  "private": true,
  "homepage": "https://$DOMAIN",
  "dependencies": {
    "@headlessui/react": "^1.7.0",
    "@heroicons/react": "^2.0.0",
    "axios": "^1.6.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.21.0",
    "react-scripts": "5.0.1",
    "tailwindcss": "^3.4.0"
  },
  "scripts": {
    "start": "react-scripts start",
    "build": "react-scripts build",
    "test": "react-scripts test",
    "eject": "react-scripts eject"
  }
}
EOL

# Create index.html
cat > "$FRONTEND_DIR/public/index.html" << EOL
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="theme-color" content="#000000" />
    <meta name="description" content="IRSSH Panel" />
    <title>IRSSH Panel</title>
  </head>
  <body>
    <noscript>You need to enable JavaScript to run this app.</noscript>
    <div id="root"></div>
  </body>
</html>
EOL

# Create App.js
cat > "$FRONTEND_DIR/src/App.js" << 'EOL'
import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';

function Dashboard() {
  return <h1 className="text-3xl font-bold text-center mt-10">Welcome to IRSSH Panel</h1>;
}

function App() {
  return (
    <Router>
      <div className="min-h-screen bg-gray-100">
        <Routes>
          <Route path="/" element={<Dashboard />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
EOL

# Create index.js
cat > "$FRONTEND_DIR/src/index.js" << 'EOL'
import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
EOL

# Create index.css with Tailwind
cat > "$FRONTEND_DIR/src/index.css" << 'EOL'
@tailwind base;
@tailwind components;
@tailwind utilities;
EOL

# Configure tailwind.config.js
cat > "$FRONTEND_DIR/tailwind.config.js" << 'EOL'
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

# Install dependencies and build
log "Installing frontend dependencies..."
npm install
npm run build

# Fix Nginx configuration
log "Updating Nginx configuration..."
cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    server_name $DOMAIN;

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

        # CORS headers
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' '*' always;
        add_header 'Access-Control-Expose-Headers' '*' always;
    }

    client_max_body_size 100M;
}
EOL

# Restart services
log "Restarting services..."
systemctl restart nginx
supervisorctl restart irssh-panel

# Final message
log "Fix completed! Please check:"
echo "1. Frontend: https://$DOMAIN"
echo "2. API: https://$DOMAIN/api/health"
echo "3. Logs: $LOG_DIR/uvicorn.err.log"
