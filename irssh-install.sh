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
VENV_DIR="$PANEL_DIR/venv"
DEFAULT_API_PORT=8000

# Logging
log() { echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Setup basics
setup_logging() {
    mkdir -p "$LOG_DIR"
    touch "$LOG_DIR/install.log"
    chmod 644 "$LOG_DIR/install.log"
    exec 1> >(tee -a "$LOG_DIR/install.log")
    exec 2> >(tee -a "$LOG_DIR/install.log")
}

install_system_packages() {
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3 python3-pip python3-venv postgresql postgresql-contrib \
        nginx supervisor curl git certbot python3-certbot-nginx
}

setup_node() {
    export NVM_DIR="$HOME/.nvm"
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
    nvm install 18 && nvm use 18
}

setup_python_env() {
    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"
    pip install \
        fastapi[all] uvicorn[standard] sqlalchemy[asyncio] \
        psycopg2-binary python-jose[cryptography] passlib[bcrypt] \
        python-multipart aiofiles python-dotenv pydantic-settings \
        asyncpg bcrypt==3.2.0 pydantic requests aiohttp psutil
}

setup_database() {
    log "Setting up PostgreSQL..."
    systemctl start postgresql
    systemctl enable postgresql
    
    local DB_NAME="irssh"
    local DB_USER="irssh_admin"
    local DB_PASS=$(openssl rand -hex 32)
    
    sudo -u postgres psql << EOSQL
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$DB_USER') THEN
            CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';
        ELSE
            ALTER USER $DB_USER WITH PASSWORD '$DB_PASS';
        END IF;
    END
    \$\$;
    DROP DATABASE IF EXISTS $DB_NAME;
    CREATE DATABASE $DB_NAME;
    ALTER DATABASE $DB_NAME OWNER TO $DB_USER;
EOSQL

    echo "DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASS=$DB_PASS" > "$CONFIG_DIR/database.env"
    chmod 600 "$CONFIG_DIR/database.env"
}

setup_backend() {
    log "Setting up backend..."
    mkdir -p "$BACKEND_DIR/app"/{core,api,models,schemas,utils}
    mkdir -p "$BACKEND_DIR/app/api/v1/endpoints"
    
    cat > "$BACKEND_DIR/app/core/database.py" << 'EOL'
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

DATABASE_URL = f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASS')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    Base.metadata.create_all(bind=engine)
EOL

    cat > "$BACKEND_DIR/app/models/user.py" << 'EOL'
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
EOL

    cat > "$BACKEND_DIR/app/core/security.py" << 'EOL'
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "your-secret-key"  # Change in production
ALGORITHM = "HS256"

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=30))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
EOL

    cat > "$BACKEND_DIR/app/api/v1/endpoints/auth.py" << 'EOL'
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
import logging
from app.core.database import get_db
from app.core.security import verify_password, create_token
from app.models.user import User

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        logger.warning(f"Failed login attempt for user: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    token = create_token({"sub": user.username})
    logger.info(f"Successful login for user: {user.username}")
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user.username
    }
EOL

    cat > "$BACKEND_DIR/app/main.py" << 'EOL'
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.endpoints import auth
from app.core.database import init_db

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])

@app.on_event("startup")
async def startup():
    init_db()

@app.get("/api/health")
async def health_check():
    return {"status": "healthy"}
EOL

    # Create admin user
    read -p "Enter admin username (default: admin): " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-admin}
    read -s -p "Enter admin password (press Enter for random): " ADMIN_PASS
    echo
    if [[ -z "$ADMIN_PASS" ]]; then
        ADMIN_PASS=$(openssl rand -base64 12)
        echo "Generated admin password: $ADMIN_PASS"
    fi

    cat > "$CONFIG_DIR/admin.env" << EOL
ADMIN_USER=$ADMIN_USER
ADMIN_PASS=$ADMIN_PASS
EOL
    chmod 600 "$CONFIG_DIR/admin.env"

    # Create admin user in database
    cat > "$BACKEND_DIR/create_admin.py" << EOL
from app.core.database import SessionLocal, init_db
from app.core.security import get_password_hash
from app.models.user import User

def create_admin():
    init_db()
    db = SessionLocal()
    admin = User(
        username='$ADMIN_USER',
        hashed_password=get_password_hash('$ADMIN_PASS'),
        is_active=True,
        is_admin=True
    )
    db.add(admin)
    db.commit()

if __name__ == "__main__":
    create_admin()
EOL

    source "$VENV_DIR/bin/activate"
    python "$BACKEND_DIR/create_admin.py"
}

setup_frontend() {
    log "Setting up frontend..."
    rm -rf "$FRONTEND_DIR"
    cd "$PANEL_DIR"
    
    npx create-react-app frontend --template typescript
    cd "$FRONTEND_DIR"
    
    npm install --legacy-peer-deps
    npm install --legacy-peer-deps \
        react-router-dom \
        axios \
        @headlessui/react \
        @heroicons/react

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
      
      const response = await axios.post('/api/auth/token', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      
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

setup_supervisor() {
   log "Configuring Supervisor..."
   cat > /etc/supervisor/conf.d/irssh-panel.conf << EOL
[program:irssh-panel]
directory=$BACKEND_DIR
command=$VENV_DIR/bin/uvicorn app.main:app --host 0.0.0.0 --port $DEFAULT_API_PORT
user=root
autostart=true
autorestart=true
stdout_logfile=$LOG_DIR/uvicorn.out.log
stderr_logfile=$LOG_DIR/uvicorn.err.log
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

main() {
   mkdir -p "$CONFIG_DIR"
   setup_logging
   log "Starting IRSSH Panel installation..."
   
   install_system_packages
   setup_node
   setup_python_env
   setup_database
   setup_backend
   setup_frontend
   setup_nginx
   setup_supervisor
   
   systemctl restart nginx
   supervisorctl restart irssh-panel
   
   log "Installation completed successfully!"
   echo
   echo "IRSSH Panel has been installed!"
   echo
   echo "Admin credentials:"
   echo "Username: $(grep ADMIN_USER $CONFIG_DIR/admin.env | cut -d= -f2)"
   echo "Password: $(grep ADMIN_PASS $CONFIG_DIR/admin.env | cut -d= -f2)"
   echo
   echo "Panel URL: http://YOUR-IP"
   echo "API URL: http://YOUR-IP/api"
}

main "$@"
