#!/bin/bash

# IRSSH Panel Installation Script v2.6
# Updated with enhanced authentication system and fixes

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

# Check system requirements
check_requirements() {
    log "Checking system requirements..."
    # Check minimum system resources
    local mem_total=$(free -m | awk '/^Mem:/{print $2}')
    local disk_free=$(df -m / | awk 'NR==2 {print $4}')
    
    [[ $mem_total -lt 1024 ]] && error "Minimum 1GB RAM required"
    [[ $disk_free -lt 2048 ]] && error "Minimum 2GB free disk space required"
    
    # Check required commands
    local requirements=(curl wget git python3 pip3)
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
        net-tools || error "Failed to install system packages"
}

# Setup Node.js
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
    
    pip install --upgrade pip wheel setuptools

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
        bcrypt \
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
    sleep 5
    
    local DB_NAME="irssh"
    local DB_USER="irssh_admin"
    local DB_PASS=$(generate_secure_key)

    # مستقیم با سوکت یونیکس وصل میشیم
    sudo -i -u postgres psql <<EOF
DROP DATABASE IF EXISTS $DB_NAME;
DROP USER IF EXISTS $DB_USER;
CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';
CREATE DATABASE $DB_NAME OWNER $DB_USER;
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
EOF

    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_DIR/database.env" << EOL
DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASS=$DB_PASS
EOL
    chmod 600 "$CONFIG_DIR/database.env"
}

# Setup backend
setup_backend() {
    log "Setting up backend structure..."
    
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
from datetime import timedelta

class Settings(BaseSettings):
    SECRET_KEY: str = "$(generate_secure_key)"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    DB_NAME: str = "irssh"
    DB_USER: str = "irssh_admin"
    DB_PASS: str = "$(grep DB_PASS "$CONFIG_DIR/database.env" | cut -d= -f2)"

    # Enhanced security settings
    MINIMUM_PASSWORD_LENGTH: int = 8
    PASSWORD_RESET_TOKEN_EXPIRE_HOURS: int = 24
    MAX_LOGIN_ATTEMPTS: int = 5
    LOGIN_ATTEMPT_WINDOW: timedelta = timedelta(minutes=15)
    SESSION_LIFETIME: timedelta = timedelta(hours=24)

settings = Settings()
EOL

    # Create security.py
    cat > app/core/security.py << 'EOL'
from datetime import datetime, timedelta
from typing import Optional, Dict
from passlib.context import CryptContext
from jose import jwt
from .config import settings
import time
from collections import defaultdict

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

login_attempts: Dict[str, list] = defaultdict(list)

def clean_old_attempts(username: str) -> None:
    current_time = time.time()
    window = settings.LOGIN_ATTEMPT_WINDOW.total_seconds()
    login_attempts[username] = [
        attempt for attempt in login_attempts[username]
        if current_time - attempt < window
    ]

def check_login_attempts(username: str) -> bool:
    clean_old_attempts(username)
    return len(login_attempts[username]) < settings.MAX_LOGIN_ATTEMPTS

def record_login_attempt(username: str) -> None:
    login_attempts[username].append(time.time())

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    if len(password) < settings.MINIMUM_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {settings.MINIMUM_PASSWORD_LENGTH} characters long")
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access"
    })
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + settings.SESSION_LIFETIME
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "refresh"
    })
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except jwt.JWTError:
        return None
EOL

    # Create database.py with proper SQLAlchemy setup
    cat > app/core/database.py << 'EOL'
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from .config import settings
import contextlib

SQLALCHEMY_DATABASE_URL = f"postgresql://{settings.DB_USER}:{settings.DB_PASS}@{settings.DB_HOST}:{settings.DB_PORT}/{settings.DB_NAME}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def init_db():
    Base.metadata.create_all(bind=engine)

@contextlib.contextmanager
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
EOL

    # Create user model with proper timestamp columns
    cat > app/models/user.py << 'EOL'
from sqlalchemy import Boolean, Column, Integer, String, DateTime, Text, func
from app.core.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True, nullable=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    last_failed_login = Column(DateTime(timezone=True), nullable=True)
    refresh_token = Column(Text, nullable=True)
EOL

    # Create main.py
    cat > app/main.py << 'EOL'
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime
import logging

from app.core.database import get_db, init_db
from app.core.security import (
    verify_password, create_access_token, create_refresh_token,
    check_login_attempts, record_login_attempt, verify_token
)
from app.models.user import User

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/irssh/app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI(title="IRSSH Panel API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    init_db()
    logger.info("Application started, database initialized")

@app.post("/api/auth/login")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    if not check_login_attempts(form_data.username):
        logger.warning(f"Too many login attempts for user: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please try again later."
        )

    user = db.query(User).filter(User.username == form_data.username).first()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        record_login_attempt(form_data.username)
        if user:
            user.failed_login_attempts += 1
            user.last_failed_login = datetime.utcnow()
            db.commit()
        
        logger.warning(f"Failed login attempt for user: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )

    if not user.is_active:
        logger.warning(f"Inactive user attempted login: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is disabled"
        )

    # Reset failed login attempts on successful login
    user.failed_login_attempts = 0
    user.last_login = datetime.utcnow()
    
    # Generate tokens
    access_token = create_access_token(data={"sub": user.username})
    refresh_token = create_refresh_token(data={"sub": user.username})
    
    # Store refresh token in database
    user.refresh_token = refresh_token
    db.commit()
    
    logger.info(f"Successful login for user: {user.username}")
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "username": user.username,
        "is_admin": user.is_admin
    }

@app.post("/api/auth/refresh")
async def refresh_token(request: Request, db: Session = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )
    
    refresh_token = auth_header.split(" ")[1]
    payload = verify_token(refresh_token)
    
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    username = payload.get("sub")
    user = db.query(User).filter(User.username == username).first()
    
    if not user or user.refresh_token != refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    # Generate new tokens
    access_token = create_access_token(data={"sub": user.username})
    new_refresh_token = create_refresh_token(data={"sub": user.username})
    
    user.refresh_token = new_refresh_token
    db.commit()
    
    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer"
    }

@app.post("/api/auth/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )
    
    token = auth_header.split(" ")[1]
    payload = verify_token(token)
    
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )
    
    username = payload.get("sub")
    user = db.query(User).filter(User.username == username).first()
    
    if user:
        user.refresh_token = None
        db.commit()
    
    return {"message": "Successfully logged out"}

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

# Setup frontend with enhanced error handling
setup_frontend() {
    log "Setting up frontend..."
    
    cd "$PANEL_DIR"
    rm -rf "$FRONTEND_DIR"
    
    # نصب Node.js و yarn
    export NVM_DIR="$HOME/.nvm"
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
    nvm use 18
    npm install -g yarn

    # ایجاد پروژه React با TypeScript
    yarn create react-app frontend --template typescript
    cd "$FRONTEND_DIR"

    # نصب وابستگی‌ها
    yarn add @mantine/core @mantine/hooks @emotion/react axios js-cookie react-router-dom @mantine/form @tabler/icons-react

    # ایجاد index.html سفارشی
    cat > public/index.html << 'EOL'
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <link rel="icon" href="%PUBLIC_URL%/favicon.ico" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>IRSSH Panel</title>
  </head>
  <body>
    <noscript>You need to enable JavaScript to run this app.</noscript>
    <div id="root"></div>
  </body>
</html>
EOL

    # کامپایل و بیلد
    yarn build
}
    
    # Create React app with specific Node version
    export NVM_DIR="$HOME/.nvm"
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
    nvm use 18
    
    npx create-react-app frontend --template typescript || error "Failed to create React app"
    cd "$FRONTEND_DIR" || error "Failed to enter frontend directory"
    
    # Install dependencies with error handling
    npm install \
        react-router-dom \
        axios \
        @headlessui/react \
        @heroicons/react \
        js-cookie \
        tailwindcss \
        @tailwindcss/forms \
        --legacy-peer-deps || error "Failed to install frontend dependencies"

    # Initialize Tailwind CSS
    npx tailwindcss init -p

    # Create enhanced App.js
    cat > src/App.js << 'EOL'
import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import axios from 'axios';
import Cookies from 'js-cookie';

function Login() {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setIsLoading(true);
        setError('');

        try {
            const formData = new FormData();
            formData.append('username', username);
            formData.append('password', password);
            
            const response = await axios.post('/api/auth/login', formData);
            
            if (response.data.access_token) {
                Cookies.set('access_token', response.data.access_token, { secure: true });
                Cookies.set('refresh_token', response.data.refresh_token, { secure: true });
                localStorage.setItem('username', response.data.username);
                localStorage.setItem('is_admin', response.data.is_admin);
                
                // Setup axios interceptor for token refresh
                axios.interceptors.response.use(
                    (response) => response,
                    async (error) => {
                        const originalRequest = error.config;
                        
                        if (error.response.status === 401 && !originalRequest._retry) {
                            originalRequest._retry = true;
                            
                            try {
                                const refreshToken = Cookies.get('refresh_token');
                                const refreshResponse = await axios.post('/api/auth/refresh', {}, {
                                    headers: { Authorization: `Bearer ${refreshToken}` }
                                });
                                
                                const { access_token, refresh_token } = refreshResponse.data;
                                Cookies.set('access_token', access_token, { secure: true });
                                Cookies.set('refresh_token', refresh_token, { secure: true });
                                
                                originalRequest.headers['Authorization'] = `Bearer ${access_token}`;
                                return axios(originalRequest);
                            } catch (refreshError) {
                                // If refresh fails, logout user
                                Cookies.remove('access_token');
                                Cookies.remove('refresh_token');
                                localStorage.removeItem('username');
                                localStorage.removeItem('is_admin');
                                window.location.href = '/login';
                                return Promise.reject(refreshError);
                            }
                        }
                        return Promise.reject(error);
                    }
                );
                
                window.location.href = '/dashboard';
            }
        } catch (error) {
            console.error('Login error:', error);
            if (error.response?.status === 429) {
                setError('Too many failed attempts. Please try again later.');
            } else if (error.response?.status === 401) {
                setError('Invalid username or password');
            } else {
                setError('An error occurred during login. Please try again.');
            }
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50">
            <div className="max-w-md w-full space-y-8 p-8 bg-white rounded-lg shadow">
                <div>
                    <h2 className="text-center text-3xl font-extrabold text-gray-900">
                        Login to IRSSH Panel
                    </h2>
                </div>
                <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
                    <div className="rounded-md shadow-sm -space-y-px">
                        <div>
                            <input
                                type="text"
                                required
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                                className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-t-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                                placeholder="Username"
                            />
                        </div>
                        <div>
                            <input
                                type="password"
                                required
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-b-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                                placeholder="Password"
                            />
                        </div>
                    </div>

                    {error && (
                        <div className="text-red-600 text-sm text-center">
                            {error}
                        </div>
                    )}

                    <div>
                        <button
                            type="submit"
                            disabled={isLoading}
                            className={`group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 ${
                                isLoading ? 'opacity-50 cursor-not-allowed' : ''
                            }`}
                        >
                            {isLoading ? (
                                <>
                                    <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                    </svg>
                                    Signing in...
                                </>
                            ) : (
                                'Sign in'
                            )}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}

function Dashboard() {
    const username = localStorage.getItem('username');
    const isAdmin = localStorage.getItem('is_admin') === 'true';

    const handleLogout = async () => {
        try {
            const token = Cookies.get('access_token');
            await axios.post('/api/auth/logout', {}, {
                headers: { Authorization: `Bearer ${token}` }
            });
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            Cookies.remove('access_token');
            Cookies.remove('refresh_token');
            localStorage.removeItem('username');
            localStorage.removeItem('is_admin');
            window.location.href = '/login';
        }
    };

    return (
        <div className="min-h-screen bg-gray-100">
            <nav className="bg-white shadow-sm">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex justify-between h-16">
                        <div className="flex items-center">
                            <span className="text-lg font-semibold">IRSSH Panel</span>
                        </div>
                        <div className="flex items-center space-x-4">
                            <span className="text-gray-700">Welcome, {username}</span>
                            {isAdmin && (
                                <span className="bg-blue-100 text-blue-800 text-xs font-medium px-2.5 py-0.5 rounded">
                                    Admin
                                </span>
                            )}
                            <button
                                onClick={handleLogout}
                                className="text-gray-700 hover:text-gray-900 font-medium"
                            >
                                Logout
                            </button>
                        </div>
                    </div>
                </div>
            </nav>
            <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
                <div className="px-4 py-6 sm:px-0">
                    <h1 className="text-2xl font-semibold text-gray-900">Dashboard</h1>
                    <p className="mt-4">Welcome to your dashboard!</p>
                </div>
            </main>
        </div>
    );
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
import './index.css';
import App from './App';

const container = document.getElementById('root');
const root = createRoot(container);
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
EOL

    # Build frontend application
    npm run build || error "Failed to build frontend application"
}

# Configure Nginx with enhanced security
setup_nginx() {
    log "Configuring Nginx..."
    
    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen 80;
    server_name _;
    
    root $FRONTEND_DIR/build;
    index index.html;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';" always;
    
    location / {
        try_files \$uri \$uri/ /index.html;
        autoindex off;
        
        # Basic DoS protection
        limit_req zone=one burst=10 nodelay;
        limit_conn perip 10;
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
        proxy_cache_bypass \$http_upgrade;
        
        # CORS headers
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' '*' always;
        
        # Handle preflight requests
        if (\$request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' '*';
            add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS';
            add_header 'Access-Control-Allow-Headers' '*';
            add_header 'Access-Control-Max-Age' 1728000;
            add_header 'Content-Type' 'text/plain charset=UTF-8';
            add_header 'Content-Length' 0;
            return 204;
        }
        
        # Rate limiting for API
        limit_req zone=api burst=20 nodelay;
    }
    
    # Deny access to sensitive files
    location ~ /\. {
        deny all;
    }
    
    location ~ ^/(config|database\.env) {
        deny all;
    }
}

# Rate limiting zones
limit_req_zone \$binary_remote_addr zone=one:10m rate=1r/s;
limit_req_zone \$binary_remote_addr zone=api:10m rate=5r/s;
limit_conn_zone \$binary_remote_addr zone=perip:10m;
EOL

    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
    
    nginx -t || error "Nginx configuration test failed"
}

# Configure Supervisor with enhanced monitoring
setup_supervisor() {
    log "Configuring Supervisor..."
    
    mkdir -p /var/log/irssh
    chown -R root:root /var/log/irssh
    chmod -R 750 /var/log/irssh
    
    cat > /etc/supervisor/conf.d/irssh-panel.conf << EOL
[program:irssh-panel]
directory=$BACKEND_DIR
command=$VENV_DIR/bin/uvicorn app.main:app --host 0.0.0.0 --port $DEFAULT_API_PORT --reload
user=root
autostart=true
autorestart=true
startretries=3
startsecs=5
redirect_stderr=true
stdout_logfile=/var/log/irssh/uvicorn.out.log
stderr_logfile=/var/log/irssh/uvicorn.err.log
environment=
    PYTHONPATH="$BACKEND_DIR",
    DB_HOST="localhost",
    DB_PORT="5432",
    DB_NAME="irssh",
    DB_USER="irssh_admin",
    DB_PASS="$(grep DB_PASS $CONFIG_DIR/database.env | cut -d= -f2)"

# Monitor for crashes and high memory usage
startretries=3
stopwaitsecs=10
stopsignal=TERM
stopasgroup=true
killasgroup=true
exitcodes=0,2
stdout_logfile_maxbytes=50MB
stdout_logfile_backups=5
stderr_logfile_maxbytes=50MB
stderr_logfile_backups=5
EOL

    # Reload supervisor configuration
    supervisorctl reread
    supervisorctl update
}

# Configure enhanced firewall
setup_firewall() {
    log "Setting up firewall rules..."
    
    # Ensure UFW is installed
    apt-get install -y ufw || error "Failed to install UFW"
    
    # Reset UFW to default
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (before enabling UFW)
    ufw allow ssh
    
    # Allow HTTP and HTTPS
    ufw allow http
    ufw allow https
    
    # Allow API port with rate limiting
    ufw limit $DEFAULT_API_PORT/tcp comment 'API port with rate limiting'
    
    # Enable UFW
    ufw --force enable
}

# Main installation function
main() {
    # Verify root privileges
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi

    setup_logging
    log "Starting IRSSH Panel installation..."
    
    # Create installation directory
    mkdir -p "$PANEL_DIR"
    
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
    
    # Set correct permissions
    chown -R root:root "$PANEL_DIR"
    chmod -R 755 "$PANEL_DIR"
    chmod 600 "$CONFIG_DIR/database.env"
    
    # Restart services
    systemctl restart postgresql
    systemctl restart nginx
    supervisorctl restart irssh-panel
    
    # Verify service status
    local services=(postgresql nginx supervisor)
    for service in "${services[@]}"; do
        if ! systemctl is-active --quiet $service; then
            error "$service failed to start"
        fi
    done
    
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
    echo "Installation log is available at: $LOG_FILE"
    echo
    echo "Please save these credentials and change the password after first login!"
    echo
    echo "Note: Allow a few minutes for all services to fully initialize."
}

# Cleanup function
cleanup() {
    log "Cleaning up..."
    # Stop services
    supervisorctl stop irssh-panel
    systemctl stop nginx
    systemctl stop postgresql
    
    # Remove installation if it failed
    if [[ $? -ne 0 ]]; then
        rm -rf "$PANEL_DIR"
        rm -f /etc/nginx/sites-enabled/irssh-panel
        rm -f /etc/supervisor/conf.d/irssh-panel.conf
        
        # Drop database and user
        sudo -u postgres psql -c "DROP DATABASE IF EXISTS irssh;"
        sudo -u postgres psql -c "DROP USER IF EXISTS irssh_admin;"
    fi
}

# Trap signals
trap cleanup SIGINT SIGTERM

# Start installation
main "$@"
