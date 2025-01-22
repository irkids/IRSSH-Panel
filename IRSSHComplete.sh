#!/bin/bash

# IRSSH Panel Installation Script v2.1
# Comprehensive installation with all fixes applied

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration directories
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
LOG_DIR="/var/log/irssh"
VENV_DIR="$PANEL_DIR/venv"
BACKUP_DIR="/opt/irssh-backups"

# Default configuration
DEFAULT_HTTP_PORT=80
DEFAULT_HTTPS_PORT=443
DEFAULT_API_PORT=8000

# Generate random strings for security
generate_secure_key() {
    openssl rand -hex 32
}

JWT_SECRET=$(generate_secure_key)
ADMIN_TOKEN=$(generate_secure_key)

# Logging functions
setup_logging() {
    mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/install.log"
    exec 1> >(tee -a "$LOG_FILE")
    exec 2> >(tee -a "$LOG_FILE" >&2)
    chmod 640 "$LOG_FILE"
}

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" >&2
    [[ "${2:-}" != "no-exit" ]] && cleanup && exit 1
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Cleanup function
cleanup() {
    if [[ $? -ne 0 ]]; then
        error "Installation failed. Check $LOG_DIR/install.log for details" "no-exit"
        if [[ -d "$BACKUP_DIR" ]]; then
            warn "Attempting to restore from backup..."
            restore_backup
        fi
    fi
}

# Backup function
create_backup() {
    log "Creating backup..."
    mkdir -p "$BACKUP_DIR"
    if [[ -d "$PANEL_DIR" ]]; then
        tar -czf "$BACKUP_DIR/panel-$(date +%Y%m%d-%H%M%S).tar.gz" -C "$(dirname "$PANEL_DIR")" "$(basename "$PANEL_DIR")"
    fi
}

# Restore function
restore_backup() {
    local latest_backup=$(ls -t "$BACKUP_DIR"/*.tar.gz 2>/dev/null | head -1)
    if [[ -f "$latest_backup" ]]; then
        rm -rf "$PANEL_DIR"
        tar -xzf "$latest_backup" -C "$(dirname "$PANEL_DIR")"
        log "Backup restored from $latest_backup"
    else
        error "No backup found to restore" "no-exit"
    fi
}

# Check system requirements
check_requirements() {
    log "Checking system requirements..."
    
    # Check OS
    if [[ ! -f /etc/os-release ]]; then
        error "Unsupported operating system"
    fi
    
    # Check minimum system resources
    local mem_total=$(free -m | awk '/^Mem:/{print $2}')
    local disk_free=$(df -m / | awk 'NR==2 {print $4}')
    
    [[ $mem_total -lt 1024 ]] && error "Minimum 1GB RAM required"
    [[ $disk_free -lt 2048 ]] && error "Minimum 2GB free disk space required"
    
    # Check required commands
    local requirements=(curl wget git python3 pip3 nginx)
    for cmd in "${requirements[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            error "$cmd is required but not installed"
        fi
    done
}

# Install system packages
install_system_packages() {
    log "Installing system packages..."
    apt-get update || error "Failed to update package lists"
    
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        postgresql \
        postgresql-contrib \
        nginx \
        supervisor \
        curl \
        git \
        certbot \
        python3-certbot-nginx \
        ufw \
        fail2ban || error "Failed to install system packages"
}

# Setup Node.js using nvm
setup_node() {
    log "Setting up Node.js with nvm..."
    
    # Install nvm
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
    
    # Load nvm
    export NVM_DIR="$HOME/.nvm"
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
    
    # Install Node.js
    nvm install 18
    nvm use 18
    
    # Verify installation
    if ! command -v node &> /dev/null; then
        error "Node.js installation failed"
    fi
}

# Setup Python environment
setup_python_env() {
    log "Setting up Python environment..."
    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"
    
    pip install --upgrade pip

    # Install Python packages
    pip install \
        fastapi[all] \
        uvicorn[standard] \
        sqlalchemy[asyncio] \
        psycopg2-binary \
        python-jose[cryptography] \
        passlib[bcrypt] \
        python-multipart \
        aiofiles \
        python-dotenv \
        pydantic-settings \
        asyncpg \
        python-jose[cryptography] \
        bcrypt \
        python-multipart \
        pydantic \
        requests \
        aiohttp \
        psutil || error "Failed to install Python packages"
}

# Configure PostgreSQL
setup_database() {
    log "Setting up PostgreSQL..."
    
    systemctl start postgresql
    systemctl enable postgresql
    
    local DB_NAME="irssh"
    local DB_USER="irssh_admin"
    local DB_PASS=$(generate_secure_key)
    
    # Check if user exists
    if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" | grep -q 1; then
        sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';" || error "Failed to create database user"
    else
        sudo -u postgres psql -c "ALTER USER $DB_USER WITH PASSWORD '$DB_PASS';"
    fi
    
    # Check if database exists
    if ! sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
        sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;" || error "Failed to create database"
    else
        sudo -u postgres psql -c "ALTER DATABASE $DB_NAME OWNER TO $DB_USER;"
    fi
    
    # Save database configuration
    cat > "$CONFIG_DIR/database.env" << EOL
DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASS=$DB_PASS
EOL
    chmod 600 "$CONFIG_DIR/database.env"
}

# Setup backend structure
setup_backend() {
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

    # Create main.py
    cat > "$BACKEND_DIR/app/main.py" << 'EOL'
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
async def health_check():
    return {"status": "healthy"}
EOL

    # Create database.py
    cat > "$BACKEND_DIR/app/core/database.py" << 'EOL'
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

SQLALCHEMY_DATABASE_URL = f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASS')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
EOL

    # Create models
    cat > "$BACKEND_DIR/app/models/user.py" << 'EOL'
from sqlalchemy import Boolean, Column, Integer, String
from app.core.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
EOL
}

# Setup frontend structure
setup_frontend() {
    log "Setting up frontend..."
    
    # Create React app
    npx create-react-app "$FRONTEND_DIR" --template typescript
    cd "$FRONTEND_DIR"
    
    # Install dependencies
    npm install \
        @headlessui/react \
        @heroicons/react \
        axios \
        react-router-dom \
        tailwindcss \
        @types/node \
        @types/react \
        @types/react-dom

    # Create components directory
    mkdir -p src/components/{Auth,Layout,Dashboard}

    # Create Login component
    cat > src/components/Auth/Login.js << 'EOL'
import React, { useState } from 'react';
import axios from 'axios';

function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const formData = new FormData();
      formData.append('username', username);
      formData.append('password', password);
      
      const response = await axios.post('/api/auth/token', formData);
      
      if (response.data.access_token) {
        localStorage.setItem('token', response.data.access_token);
        localStorage.setItem('username', response.data.username);
        window.location.href = '/dashboard';
      }
    } catch (error) {
      setError('Invalid username or password');
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      backgroundColor: '#f3f4f6'
    }}>
      <div style={{
        width: '100%',
        maxWidth: '400px',
        padding: '20px',
        backgroundColor: 'white',
        borderRadius: '8px',
        boxShadow: '0 2px 4px rgba(0, 0, 0, 0.1)'
      }}>
        <h2 style={{
          textAlign: 'center',
          fontSize: '24px',
          fontWeight: 'bold',
          marginBottom: '20px'
        }}>Sign in to IRSSH Panel</h2>
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '15px' }}>
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              style={{
                width: '100%',
                padding: '10px',
                border: '1px solid #ddd',
                borderRadius: '4px'
              }}
            />
          </div>
          <div style={{ marginBottom: '15px' }}>
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={{
                width: '100%',
                padding: '10px',
                border: '1px solid #ddd',
                borderRadius: '4px'
              }}
            />
          </div>
          {error && (
            <div style={{
              color: '#dc2626',
              textAlign: 'center',
              marginBottom: '15px',
              fontSize: '14px'
            }}>
              {error}
            </div>
          )}
          <button
            type="submit"
            style={{
              width: '100%',
              padding: '10px',
              backgroundColor: '#2563eb',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer'
            }}
          >
            Sign in
          </button>
        </form>
      </div>
    </div>
  );
}

export default Login;
EOL

    # Update App.js
    cat > src/App.js << 'EOL'
import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Auth/Login';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<Navigate to="/login" />} />
      </Routes>
    </Router>
  );
}

export default App;
EOL

    # Build React app
    npm run build
}

# Configure Nginx
setup_nginx() {
    log "Configuring Nginx..."
    
    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen 80;
    server_name _;

    root $FRONTEND_DIR/build;
    index index.html;

    # CORS headers
    add_header 'Access-Control-Allow-Origin' '*' always;
    add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;
    add_header 'Access-Control-Allow-Headers' '*' always;

    location / {
        try_files \$uri \$uri/ /index.html;
        add_header Cache-Control "no-cache";
    }

    location /api {
        proxy_pass http://localhost:$DEFAULT_API_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 90;
        proxy_redirect off;
    }
}
EOL

    # Remove default and enable our site
    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/

    # Test configuration
    nginx -t || error "Nginx configuration test failed"
}

# Configure Supervisor
setup_supervisor() {
    log "Configuring Supervisor..."
    
    cat > /etc/supervisor/conf.d/irssh-panel.conf << EOL
[program:irssh-panel]
directory=$BACKEND_DIR
command=$VENV_DIR/bin/uvicorn app.main:app --host 0.0.0.0 --port $DEFAULT_API_PORT --reload
user=root
autostart=true
autorestart=true
stdout_logfile=$LOG_DIR/uvicorn.out.log
stderr_logfile=$LOG_DIR/uvicorn.err.log
environment=
    PATH="$VENV_DIR/bin:/usr/local/bin:/usr/bin:/bin",
    PYTHONPATH="$BACKEND_DIR",
    DB_NAME="irssh",
    DB_USER="irssh_admin",
    DB_PASS="$(grep DB_PASS $CONFIG_DIR/database.env | cut -d= -f2)",
    DB_HOST="localhost"
EOL

    supervisorctl reread
    supervisorctl update
}

# Configure Firewall
setup_firewall() {
    log "Configuring firewall..."
    
    ufw allow ssh
    ufw allow http
    ufw allow https
    ufw allow $DEFAULT_API_PORT
    
    echo "y" | ufw enable
}

# Create admin user
create_admin_user() {
    log "Creating admin user..."
    
    read -p "Enter admin username (default: admin): " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-admin}
    
    read -s -p "Enter admin password (default: admin123): " ADMIN_PASS
    echo
    ADMIN_PASS=${ADMIN_PASS:-admin123}
    
    source "$VENV_DIR/bin/activate"
    python3 -c "
from app.core.security import get_password_hash
from app.models.user import User
from app.core.database import engine, SessionLocal, Base

# Create tables
Base.metadata.create_all(bind=engine)

# Create session
db = SessionLocal()

try:
    # Create admin user
    admin = User(
        username='$ADMIN_USER',
        hashed_password=get_password_hash('$ADMIN_PASS'),
        is_active=True,
        is_admin=True
    )
    db.add(admin)
    db.commit()
except Exception as e:
    print(f'Error creating admin user: {str(e)}')
finally:
    db.close()
"
}

# Main installation function
main() {
    trap cleanup EXIT
    
    setup_logging
    log "Starting IRSSH Panel installation..."
    
    check_requirements
    create_backup
    install_system_packages
    setup_node
    setup_python_env
    setup_database
    setup_backend
    setup_frontend
    setup_nginx
    setup_supervisor
    setup_firewall
    create_admin_user
    
    # Restart services
    systemctl restart nginx
    supervisorctl restart irssh-panel
    
    # Test installation
    log "Testing installation..."
    sleep 5
    
    response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:$DEFAULT_API_PORT/api/health)
    if [ "$response" = "200" ]; then
        log "API is responding correctly"
    else
        warn "API is not responding correctly (HTTP $response)"
    fi
    
    log "Installation completed successfully!"
    echo
    echo "IRSSH Panel has been installed!"
    echo
    echo "Admin Credentials:"
    echo "Username: $ADMIN_USER"
    echo "Password: $ADMIN_PASS"
    echo
    echo "Panel URL: http://YOUR-IP"
    echo "API URL: http://YOUR-IP/api"
    echo
    echo "Please change the admin password after first login."
}

# Start installation
main "$@"
