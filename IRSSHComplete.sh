#!/bin/bash

# IRSSH Panel Installation Script v2.5
# Updated with fixed authentication system

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

# Default configuration
DEFAULT_HTTP_PORT=80
DEFAULT_HTTPS_PORT=443
DEFAULT_API_PORT=8000

# Generate random strings for security
generate_secure_key() {
    openssl rand -hex 32
}

JWT_SECRET=$(generate_secure_key)

# Logging functions
setup_logging() {
    mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/install.log"
    exec 1> >(tee -a "$LOG_FILE")
    exec 2> >(tee -a "$LOG_FILE" >&2)
    chmod 644 "$LOG_FILE"
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

# Check system requirements and install packages
check_requirements() {
    log "Checking system requirements..."
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
        python3-certbot-nginx || error "Failed to install system packages"
}

# Setup Node.js using nvm
setup_node() {
    log "Setting up Node.js with nvm..."
    
    export NVM_DIR="$HOME/.nvm"
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
    
    # Load nvm
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
    
    # Install Node.js
    nvm install 18
    nvm use 18
    
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
    pip uninstall bcrypt -y

    # Install the packages in order
    pip install \
        bcrypt==3.2.0 \
        fastapi[all] \
        uvicorn[standard] \
        sqlalchemy[asyncio] \
        psycopg2-binary \
        python-jose[cryptography] \
        passlib \
        python-multipart \
        aiofiles \
        python-dotenv \
        pydantic-settings \
        asyncpg \
        pydantic \
        requests \
        aiohttp \
        psutil
}

# Configure PostgreSQL
setup_database() {
    log "Setting up PostgreSQL..."
    
    systemctl start postgresql
    systemctl enable postgresql
    
    local DB_NAME="irssh"
    local DB_USER="irssh_admin"
    local DB_PASS=$(generate_secure_key)
    
    sudo -u postgres psql -c "DO \$\$ 
    BEGIN 
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$DB_USER') THEN
            CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';
        END IF;
    END
    \$\$;"
    
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME;"
    sudo -u postgres psql -c "ALTER DATABASE $DB_NAME OWNER TO $DB_USER;"
}

# Setup backend structure
setup_backend() {
    log "Setting up backend structure..."
    
cat > "$BACKEND_DIR/app/core/admin.py" << 'EOL'
from sqlalchemy.orm import Session
import bcrypt
from app.models import User

def create_admin(db: Session, username: str, password: str):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt).decode()
    
    admin = User(
        username=username,
        hashed_password=hashed_password,
        role="admin",
        is_active=True
    )
    
    db.add(admin)
    db.commit()
    db.refresh(admin)
    return admin
EOL

    rm -rf "$BACKEND_DIR"
    mkdir -p "$BACKEND_DIR"
    cd "$BACKEND_DIR"
    
    mkdir -p app/{core,api,models,schemas,utils}
    mkdir -p app/api/v1/endpoints
    
    # Create Python package files
    find "$BACKEND_DIR/app" -type d -exec touch {}/__init__.py \;

    # Create config.py
    cat > app/core/config.py << EOL
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    SECRET_KEY: str = "$(generate_secure_key)"  # Replace in production
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    DB_NAME: str = "irssh"
    DB_USER: str = "irssh_admin"
    DB_PASS: str = "$(grep DB_PASS "$CONFIG_DIR/database.env" | cut -d= -f2)"

settings = Settings()
EOL

    # Create security.py
    cat > app/core/security.py << 'EOL'
from datetime import datetime, timedelta
from typing import Optional
from passlib.context import CryptContext
from jose import jwt
from .config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
EOL

    # Create database.py
    cat > app/core/database.py << 'EOL'
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from .config import settings

SQLALCHEMY_DATABASE_URL = f"postgresql://{settings.DB_USER}:{settings.DB_PASS}@{settings.DB_HOST}:{settings.DB_PORT}/{settings.DB_NAME}"

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

    # Create user model
    cat > app/models/user.py << 'EOL'
from sqlalchemy import Boolean, Column, Integer, String, DateTime
from sqlalchemy.sql import func
from app.core.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
EOL

    # Create main.py
    cat > app/main.py << 'EOL'
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
import logging

from app.core.database import get_db, engine, Base
from app.core.security import verify_password, create_access_token
from app.models.user import User

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/auth/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    access_token = create_access_token(data={"sub": user.username})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user.username
    }

@app.get("/api/health")
def health_check():
    return {"status": "healthy"}
EOL

    # Create first admin user
    read -p "Enter admin username (default: admin): " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-admin}
    
    read -s -p "Enter admin password (press Enter for random): " ADMIN_PASS
    echo
    if [[ -z "$ADMIN_PASS" ]]; then
        ADMIN_PASS=$(openssl rand -base64 12)
        echo "Generated admin password: $ADMIN_PASS"
    fi
    
    cat > create_admin.py << EOL
from app.core.security import get_password_hash
from app.models.user import User
from app.core.database import SessionLocal, Base, engine

def create_admin():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    
    admin = User(
        username='$ADMIN_USER',
        hashed_password=get_password_hash('$ADMIN_PASS'),
        is_active=True,
        is_admin=True
    )
    
    db.add(admin)
    db.commit()
    db.close()

if __name__ == "__main__":
    create_admin()
EOL

    source "$VENV_DIR/bin/activate"
    python create_admin.py
}

# Setup frontend
setup_frontend() {
    log "Setting up frontend..."
    
    rm -rf "$FRONTEND_DIR"
    cd "$PANEL_DIR"
    
    npx create-react-app frontend --template typescript
    cd "$FRONTEND_DIR"
    
    npm install \
        react-router-dom \
        axios \
        @headlessui/react \
        @heroicons/react --legacy-peer-deps

    # Create App.js with login form
    cat > src/App.js << 'EOL'
import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
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
      
      const response = await axios.post('/api/auth/login', formData);
      
      if (response.data.access_token) {
        localStorage.setItem('token', response.data.access_token);
        localStorage.setItem('username', response.data.username);
        window.location.href = '/dashboard';
      }
    } catch (error) {
      console.error('Login error:', error);
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
        boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
      }}>
        <h2 style={{
          textAlign: 'center',
          fontSize: '24px',
          fontWeight: 'bold',
          marginBottom: '20px'
        }}>Login to IRSSH Panel</h2>
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

function Dashboard() {
  return <h1>Welcome to Dashboard</h1>;
}

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/" element={<Navigate to="/login" />} />
      </Routes>
    </Router>
  );
}

export default App;
EOL

    # Create index.js
    cat > src/index.js << 'EOL'
import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';

const container = document.getElementById('root');
const root = createRoot(container);
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
EOL

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
    
    location / {
        try_files \$uri \$uri/ /index.html;
    }
    
    location /api {
        proxy_pass http://localhost:$DEFAULT_API_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        
        # Fix CORS issues
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' '*' always;
        
        if (\$request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' '*';
            add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS';
            add_header 'Access-Control-Allow-Headers' '*';
            add_header 'Access-Control-Max-Age' 1728000;
            add_header 'Content-Type' 'text/plain charset=UTF-8';
            add_header 'Content-Length' 0;
            return 204;
        }
    }
}
EOL

    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
    
    nginx -t || error "Nginx configuration test failed"
}

# Configure Supervisor
setup_supervisor() {
    log "Configuring Supervisor..."
    
    mkdir -p /var/log/irssh
    
    cat > /etc/supervisor/conf.d/irssh-panel.conf << EOL
[program:irssh-panel]
directory=$BACKEND_DIR
command=$VENV_DIR/bin/uvicorn app.main:app --host 0.0.0.0 --port $DEFAULT_API_PORT --reload
user=root
autostart=true
autorestart=true
stdout_logfile=/var/log/irssh/uvicorn.out.log
stderr_logfile=/var/log/irssh/uvicorn.err.log
environment=
    PYTHONPATH="$BACKEND_DIR",
    DB_HOST="localhost",
    DB_PORT="5432",
    DB_NAME="irssh",
    DB_USER="irssh_admin",
    DB_PASS="$(grep DB_PASS $CONFIG_DIR/database.env | cut -d= -f2)"
EOL

    supervisorctl reread
    supervisorctl update
}

# Configure firewall
setup_firewall() {
    log "Setting up firewall rules..."
    
    ufw allow ssh
    ufw allow http
    ufw allow https
    ufw allow $DEFAULT_API_PORT
}

# Main installation function
main() {
    setup_logging
    log "Starting IRSSH Panel installation..."
    
    check_requirements
    install_system_packages
    setup_node
    setup_python_env
    setup_database
    setup_backend
    setup_frontend
    setup_nginx
    setup_supervisor
    setup_firewall
    
    # Restart services
    systemctl restart nginx
    supervisorctl restart irssh-panel
    
    # Print installation details
    log "Installation completed successfully!"
    echo
    echo "IRSSH Panel has been installed!"
    echo
    echo "Admin credentials:"
    echo "Username: $ADMIN_USER"
    echo "Password: $ADMIN_PASS"
    echo
    echo "Panel URL: http://YOUR-IP"
    echo "API URL: http://YOUR-IP/api"
    echo
    echo "Please save these credentials and change the password after first login!"
}

# Start installation
main "$@"
