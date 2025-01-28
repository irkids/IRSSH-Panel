#!/bin/bash

# IRSSH Panel Complete Installation Script
# Version: 3.4.0

# Directories
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
MODULES_DIR="$PANEL_DIR/modules"
LOG_DIR="/var/log/irssh"
BACKUP_DIR="/opt/irssh-backups"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Database Settings
DB_NAME="irssh_panel"
DB_USER="irssh_admin"
DB_PASS=$(openssl rand -base64 32)
ADMIN_PASS=$(openssl rand -base64 16)
JWT_SECRET=$(openssl rand -base64 32)

# Logging
setup_logging() {
    mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/install.log"
    exec &> >(tee -a "$LOG_FILE")
    chmod 640 "$LOG_FILE"
}

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
    [[ "${2:-}" != "no-exit" ]] && cleanup && exit 1
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Cleanup and Backup
cleanup() {
    if [[ $? -ne 0 ]]; then
        error "Installation failed. Attempting backup restore..." "no-exit"
        if [[ -d "$BACKUP_DIR" ]]; then
            warn "Attempting to restore from backup..."
            restore_backup
        fi
    fi
}

create_backup() {
    mkdir -p "$BACKUP_DIR"
    if [[ -d "$PANEL_DIR" ]]; then
        tar -czf "$BACKUP_DIR/panel-$(date +%Y%m%d-%H%M%S).tar.gz" -C "$(dirname "$PANEL_DIR")" "$(basename "$PANEL_DIR")"
    fi
}

restore_backup() {
    local latest_backup=$(ls -t "$BACKUP_DIR"/*.tar.gz 2>/dev/null | head -1)
    if [[ -n "$latest_backup" ]]; then
        rm -rf "$PANEL_DIR"
        tar -xzf "$latest_backup" -C "$(dirname "$PANEL_DIR")"
        log "Restored from backup: $latest_backup"
    fi
}

# Pre-Installation Checks
check_requirements() {
    # Check root
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi

    # Check system resources
    if [[ $(free -m | awk '/^Mem:/{print $2}') -lt 1024 ]]; then
        error "Minimum 1GB RAM required"
    fi

    if [[ $(df -m / | awk 'NR==2 {print $4}') -lt 2048 ]]; then
        error "Minimum 2GB free disk space required"
    fi

    # Check mandatory commands
    local required_commands=(curl wget git python3 pip3)
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            error "$cmd is required but not installed"
        fi
    done
}

# Initial Setup
setup_directories() {
    log "Setting up directories..."
    mkdir -p "$PANEL_DIR"/{frontend,backend,config,modules}
    mkdir -p "$FRONTEND_DIR"/{public,src/{components,styles}}
    mkdir -p "$BACKEND_DIR/app"
    chmod -R 755 "$PANEL_DIR"
}

# Install Dependencies
install_dependencies() {
    log "Installing system dependencies..."
    apt-get update

    # Install basic dependencies
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3 python3-pip python3-venv \
        postgresql postgresql-contrib \
        nginx certbot python3-certbot-nginx \
        git curl wget zip unzip \
        supervisor ufw fail2ban

    # Clean and Install Node.js
    log "Setting up Node.js..."
    apt-get remove -y nodejs npm || true
    apt-get autoremove -y || true
    rm -f /etc/apt/sources.list.d/nodesource.list*

    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs

    # Install specific npm version
    log "Installing compatible npm version..."
    npm install -g npm@8.19.4 || error "npm installation failed"

    # Verify installations
    log "Node.js version: $(node -v)"
    log "npm version: $(npm -v)"
}

# Setup Python Environment
setup_python() {
    log "Setting up Python environment..."
    python3 -m venv "$PANEL_DIR/venv"
    source "$PANEL_DIR/venv/bin/activate"
    
    pip install --upgrade pip wheel setuptools
    pip install \
        fastapi[all] uvicorn[standard] \
        sqlalchemy[asyncio] psycopg2-binary \
        python-jose[cryptography] passlib[bcrypt] \
        python-multipart aiofiles \
        python-telegram-bot psutil geoip2 asyncpg

    log "Setting up backend structure..."
    mkdir -p "$BACKEND_DIR/app/"{core,api/v1/endpoints,models,schemas,utils}

    # Create Backend Auth Files
    # main.py
    cat > "$BACKEND_DIR/app/main.py" << 'EOL'
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.endpoints import auth
from app.core.config import settings

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])

@app.get("/api/health")
def health_check():
    return {"status": "healthy"}
EOL

    # auth.py
    cat > "$BACKEND_DIR/app/api/v1/endpoints/auth.py" << 'EOL'
from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
import os

router = APIRouter()

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    admin_user = os.getenv("ADMIN_USER", "admin")
    admin_pass = os.getenv("ADMIN_PASS")

    if not admin_pass:
        raise HTTPException(status_code=500, detail="Admin password not configured")

    if form_data.username == admin_user and form_data.password == admin_pass:
        access_token = create_access_token(data={"sub": admin_user})
        return {"access_token": access_token, "token_type": "bearer"}

    raise HTTPException(status_code=401, detail="Invalid credentials")
EOL

    # config.py
    cat > "$BACKEND_DIR/app/core/config.py" << EOL
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "IRSSH Panel"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    JWT_SECRET_KEY: str = "$JWT_SECRET"
    ADMIN_USER: str = "admin"
    ADMIN_PASS: str = "$ADMIN_PASS"

settings = Settings()
EOL

    # Create supervisord config for backend
    cat > /etc/supervisor/conf.d/irssh-backend.conf << EOL
[program:irssh-backend]
directory=$BACKEND_DIR
command=$PANEL_DIR/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
user=root
autostart=true
autorestart=true
stderr_logfile=$LOG_DIR/backend.err.log
stdout_logfile=$LOG_DIR/backend.out.log
environment=
    PYTHONPATH="$BACKEND_DIR",
    JWT_SECRET_KEY="$JWT_SECRET",
    ADMIN_USER="admin",
    ADMIN_PASS="$ADMIN_PASS"
EOL

    supervisorctl reread
    supervisorctl update
    supervisorctl restart irssh-backend
}

# Setup Frontend
setup_frontend() {
    log "Setting up frontend..."
    cd "$FRONTEND_DIR"

    # Create package.json
    cat > package.json << 'EOL'
{
  "name": "irssh-panel-frontend",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "@headlessui/react": "^1.7.0",
    "@heroicons/react": "^2.0.0",
    "axios": "^1.6.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.21.0",
    "react-scripts": "5.0.1",
    "@babel/plugin-proposal-private-property-in-object": "^7.21.11",
    "tailwindcss": "^3.4.0"
  },
  "scripts": {
    "start": "react-scripts start",
    "build": "react-scripts build",
    "test": "react-scripts test",
    "eject": "react-scripts eject"
  },
  "browserslist": {
    "production": [
      ">0.2%",
      "not dead",
      "not op_mini all"
    ]
  }
}
EOL

    # Create index.html
    cat > public/index.html << 'EOL'
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="theme-color" content="#000000" />
    <title>IRSSH Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2/dist/tailwind.min.css" rel="stylesheet">
  </head>
  <body>
    <div id="root"></div>
  </body>
</html>
EOL

    # Create Login component
    mkdir -p src/components/Auth
    cat > src/components/Auth/Login.js << 'EOL'
import React, { useState } from 'react';
import axios from 'axios';

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const formData = new FormData();
      formData.append('username', username);
      formData.append('password', password);

      const response = await axios.post('/api/auth/login', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      if (response.data.access_token) {
        localStorage.setItem('token', response.data.access_token);
        window.location.href = '/dashboard';
      }
    } catch (error) {
      alert('Login failed. Please check your credentials.');
      console.error('Login error:', error);
    }
  };

  return (
    <div className="min-h-screen bg-gray-100 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
          IRSSH Panel Login
        </h2>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-white py-8 px-4 shadow sm:rounded-lg sm:px-10">
          <form className="space-y-6" onSubmit={handleSubmit}>
            <div>
              <label className="block text-sm font-medium text-gray-700">
                Username
              </label>
              <div className="mt-1">
                <input
                  type="text"
                  required
                  className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700">
                Password
              </label>
              <div className="mt-1">
                <input
                  type="password"
                  required
                  className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>
            </div>

            <div>
              <button
                type="submit"
                className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
              >
                Sign in
              </button>
            </div>
          </form>
        </div>
        </div>
      </div>
    </div>
  );
};

export default Login;
EOL

 # Create App.js
    cat > src/App.js << 'EOL'
import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Auth/Login';
import Dashboard from './components/Dashboard/Dashboard';
import PrivateRoute from './components/Auth/PrivateRoute';

const App = () => {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/dashboard" element={
          <PrivateRoute>
            <Dashboard />
          </PrivateRoute>
        } />
        <Route path="/" element={<Navigate to="/login" />} />
      </Routes>
    </BrowserRouter>
  );
};

export default App;
EOL

    # Create PrivateRoute component
    cat > src/components/Auth/PrivateRoute.js << 'EOL'
import React from 'react';
import { Navigate } from 'react-router-dom';

const PrivateRoute = ({ children }) => {
  const token = localStorage.getItem('token');
  return token ? children : <Navigate to="/login" />;
};

export default PrivateRoute;
EOL

    # Create Dashboard component
    mkdir -p src/components/Dashboard
    cat > src/components/Dashboard/Dashboard.js << 'EOL'
import React from 'react';

const Dashboard = () => {
  return (
    <div className="min-h-screen bg-gray-100">
      <nav className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex">
              <div className="flex-shrink-0 flex items-center">
                <h1 className="text-xl font-bold">IRSSH Panel</h1>
              </div>
            </div>
            <div className="flex items-center">
              <button
                onClick={() => {
                  localStorage.removeItem('token');
                  window.location.href = '/login';
                }}
                className="bg-red-600 px-4 py-2 text-white rounded-md"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>
      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          <div className="border-4 border-dashed border-gray-200 rounded-lg h-96 p-4">
            <h2 className="text-2xl font-bold mb-4">Welcome to IRSSH Panel</h2>
            <p>Your dashboard content will appear here.</p>
          </div>
        </div>
      </main>
    </div>
  );
};

export default Dashboard;
EOL

    # Create index.js
    cat > src/index.js << 'EOL'
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './styles/index.css';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
EOL

    # Create styles
    cat > src/styles/index.css << 'EOL'
@tailwind base;
@tailwind components;
@tailwind utilities;

body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen',
    'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue',
    sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}
EOL

    # Install dependencies and build
    log "Installing frontend dependencies..."
    npm install

    log "Building frontend..."
    npm run build
}

# Setup Modules
setup_modules() {
    log "Setting up modules..."
    mkdir -p "$MODULES_DIR"
    
    # Copy module scripts if they exist
    if [[ -d "/root/irssh-panel/modules" ]]; then
        cp -r /root/irssh-panel/modules/* "$MODULES_DIR/"
        chmod +x "$MODULES_DIR"/*.{py,sh}
    fi
}

# Configure Nginx
setup_nginx() {
    log "Configuring Nginx..."
    
    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen 80;
    listen [::]:80;
    server_name \$domain;

    root $FRONTEND_DIR/build;
    index index.html;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    
    location / {
        try_files \$uri \$uri/ /index.html;
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

        # Security
        proxy_set_header X-Frame-Options DENY;
        proxy_set_header X-Content-Type-Options nosniff;
        proxy_set_header Referrer-Policy 'strict-origin-when-cross-origin';
    }

    location /ws {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
    }

    client_max_body_size 100M;
}
EOL

    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/

    nginx -t || error "Nginx configuration test failed"
}

# Configure SSL
setup_ssl() {
    if [[ -n "$DOMAIN" ]]; then
        log "Setting up SSL..."
        certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --redirect \
            --email "admin@$DOMAIN" || error "SSL setup failed"
    fi
}

# Configure Firewall
setup_firewall() {
    log "Configuring firewall..."
    
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing

    ufw allow ssh
    ufw allow http
    ufw allow https
    ufw allow "$WEB_PORT"
    ufw allow "$SSH_PORT"
    ufw allow "$DROPBEAR_PORT"
    ufw allow "$BADVPN_PORT/udp"

    echo "y" | ufw enable
}

# Verify Installation
verify_installation() {
    log "Verifying installation..."

    # Check services
    local services=(nginx postgresql supervisor)
    for service in "${services[@]}"; do
        if ! systemctl is-active --quiet $service; then
            error "Service $service is not running"
        fi
    done

    # Check web server
    if ! curl -s "http://localhost" > /dev/null; then
        error "Web server is not responding"
    fi

    # Check database
    if ! pg_isready -h localhost -U "$DB_USER" -d "$DB_NAME" > /dev/null 2>&1; then
        error "Database is not accessible"
    fi

    # Verify backend API
    if ! curl -s "http://localhost:8000/api/health" > /dev/null; then
        error "Backend API is not responding"
    fi
}

# Main Installation
main() {
    trap cleanup EXIT
    
    setup_logging
    log "Starting IRSSH Panel installation..."
    
    # Get user input
    read -p "Enter domain name (e.g., panel.example.com): " DOMAIN
    read -p "Enter web panel port (default: 443): " WEB_PORT
    WEB_PORT=${WEB_PORT:-443}
    read -p "Enter SSH port (default: 22): " SSH_PORT
    SSH_PORT=${SSH_PORT:-22}
    read -p "Enter Dropbear port (default: 444): " DROPBEAR_PORT
    DROPBEAR_PORT=${DROPBEAR_PORT:-444}
    read -p "Enter BadVPN port (default: 7300): " BADVPN_PORT
    BADVPN_PORT=${BADVPN_PORT:-7300}
    
    check_requirements
    create_backup
    setup_directories
    install_dependencies
    setup_python
    setup_frontend
    setup_database
    setup_modules
    setup_nginx
    setup_ssl
    setup_firewall
    verify_installation
    
    log "Installation completed successfully!"
    echo
    echo "IRSSH Panel has been installed!"
    echo
    echo "Admin Credentials:"
    echo "Username: admin"
    echo "Password: $ADMIN_PASS"
    echo
    echo "Access URLs:"
    if [[ -n "$DOMAIN" ]]; then
        echo "Panel: https://$DOMAIN"
    else
        echo "Panel: http://YOUR-SERVER-IP"
    fi
    echo
    echo "Configured Ports:"
    echo "Web Panel: $WEB_PORT"
    echo "SSH: $SSH_PORT"
    echo "Dropbear: $DROPBEAR_PORT"
    echo "BadVPN: $BADVPN_PORT"
    echo
    echo "Installation Log: $LOG_DIR/install.log"
    echo
    echo "Important Notes:"
    echo "1. Please save these credentials securely"
    echo "2. Change the admin password after first login"
    echo "3. Configure additional security settings in the panel"
    echo "4. Check the installation log for any warnings"
}

# Start installation
main "$@"   
