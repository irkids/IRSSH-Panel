#!/bin/bash

# IRSSH Panel Installation Script v3.0
# Enhanced with improved authentication system

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

# Database configuration
DB_NAME="irssh_panel"
DB_USER="irssh_panel_admin"
DB_PASS=$(openssl rand -hex 32)
JWT_SECRET=$(openssl rand -hex 32)

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
    local mem_total=$(free -m | awk '/^Mem:/{print $2}')
    local disk_free=$(df -m / | awk 'NR==2 {print $4}')
    
    [[ $mem_total -lt 1024 ]] && error "Minimum 1GB RAM required"
    [[ $disk_free -lt 2048 ]] && error "Minimum 2GB free disk space required"
    
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

# Setup Node.js
setup_node() {
    log "Setting up Node.js with nvm..."
    export NVM_DIR="$HOME/.nvm"
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
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

# Setup database with enhanced schema
setup_database() {
    log "Setting up PostgreSQL..."
    systemctl start postgresql
    systemctl enable postgresql

    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME;" || log "Database exists"
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';" || log "User exists"
    sudo -u postgres psql -c "ALTER DATABASE $DB_NAME OWNER TO $DB_USER;"

    # Create enhanced database schema
    sudo -u postgres psql -d $DB_NAME << EOL
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE,
    is_active BOOLEAN DEFAULT TRUE,
    is_admin BOOLEAN DEFAULT FALSE,
    last_login TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auth_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    token VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    session_id VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
EOL

    cat > "$CONFIG_DIR/database.env" << EOL
DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASS=$DB_PASS
EOL
    chmod 600 "$CONFIG_DIR/database.env"
}

# Setup backend with enhanced authentication
setup_backend() {
    log "Setting up backend..."
    mkdir -p "$BACKEND_DIR/app/"{core,api,models,schemas,utils}
    mkdir -p "$BACKEND_DIR/app/api/v1/endpoints"

    # Create all necessary __init__.py files
    find "$BACKEND_DIR/app" -type d -exec touch {}/__init__.py \;

    # Create config.py with enhanced settings
    cat > "$BACKEND_DIR/app/core/config.py" << EOL
from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    PROJECT_NAME: str = "IRSSH Panel"
    VERSION: str = "3.0.0"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = "$JWT_SECRET"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    CORS_ORIGINS: List[str] = ["*"]
    
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    DB_NAME: str = "$DB_NAME"
    DB_USER: str = "$DB_USER"
    DB_PASS: str = "$DB_PASS"

    class Config:
        case_sensitive = True

settings = Settings()
EOL

    # Create enhanced security.py
    cat > "$BACKEND_DIR/app/core/security.py" << 'EOL'
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from .config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def verify_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        token_data = {"username": username}
        return token_data
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
EOL

    # Create user model
    cat > "$BACKEND_DIR/app/models/user.py" << 'EOL'
from sqlalchemy import Boolean, Column, Integer, String, DateTime
from sqlalchemy.sql import func
from app.core.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    email = Column(String, unique=True, index=True, nullable=True)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    last_login = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
EOL

    # Create auth endpoints
    cat > "$BACKEND_DIR/app/api/v1/endpoints/auth.py" << 'EOL'
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Any
from app.core.security import create_access_token, verify_password
from app.core.config import settings
from app.core.database import get_db
from app.models.user import User

router = APIRouter()

@router.post("/login")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
) -> Any:
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "admin": user.is_admin},
        expires_delta=access_token_expires
    )
    
    user.last_login = datetime.utcnow()
    db.commit()
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "username": user.username,
            "is_admin": user.is_admin
        }
    }

@router.post("/logout")
async def logout(current_user: User = Depends(get_current_user)):
    # Implement session cleanup here
    return {"message": "Successfully logged out"}
EOL

    # Create main FastAPI application
    cat > "$BACKEND_DIR/app/main.py" << 'EOL'
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.v1.endpoints import auth

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix=f"{settings.API_V1_STR}/auth", tags=["auth"])

@app.get("/health")
def health_check():
    return {"status": "healthy"}
EOL
}

# Setup enhanced frontend
setup_frontend() {
    log "Setting up frontend..."
    rm -rf "$FRONTEND_DIR"
    cd "$PANEL_DIR"
    
    npx create-react-app frontend --template typescript
    cd "$FRONTEND_DIR"
    
    npm install \
        @headlessui/react \
        @heroicons/react \
        axios \
        react-router-dom \
        tailwindcss \
        @tailwindcss/forms || error "Failed to install frontend dependencies"

    # Configure Tailwind CSS
    cat > tailwind.config.js << 'EOL'
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {},
  },
  plugins: [
    require('@tailwindcss/forms'),
  ],
}
EOL

    # Create enhanced App.tsx
    cat > src/App.tsx << 'EOL'
import React, { useState, useContext, createContext } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import axios from 'axios';

interface AuthContextType {
  user: any;
  token: string | null;
  login: (username: string, password: string) => Promise<any>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | null>(null);

function AuthProvider({ children }: { children: React.ReactNode }) {
    const [user, setUser] = useState<any>(JSON.parse(localStorage.getItem('user') || 'null'));
    const [token, setToken] = useState<string | null>(localStorage.getItem('token'));

    const login = async (username: string, password: string) => {
        try {
            const formData = new FormData();
            formData.append('username', username);
            formData.append('password', password);
            
            const response = await axios.post('/api/v1/auth/login', formData);
            
            if (response.data.access_token) {
                localStorage.setItem('token', response.data.access_token);
                localStorage.setItem('user', JSON.stringify(response.data.user));
                setToken(response.data.access_token);
                setUser(response.data.user);
                return { success: true };
            }
        } catch (error) {
            console.error('Login error:', error);
            return { 
                success: false, 
                error: error.response?.data?.detail || 'Login failed'
            };
        }
    };

    const logout = () => {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        setToken(null);
        setUser(null);
    };

    return (
        <AuthContext.Provider value={{ user, token, login, logout }}>
            {children}
        </AuthContext.Provider>
    );
}

function Login() {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const auth = useContext(AuthContext);

    if (!auth) throw new Error('AuthContext must be used within AuthProvider');

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        const result = await auth.login(username, password);
        
        if (result.success) {
            window.location.href = '/dashboard';
        } else {
            setError(result.error);
        }
        
        setLoading(false);
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-100">
            <div className="max-w-md w-full bg-white rounded-lg shadow-md p-8">
                <h2 className="text-2xl font-bold text-center mb-8">
                    IRSSH Panel Login
                </h2>
                
                <form onSubmit={handleSubmit} className="space-y-6">
                    <div>
                        <label className="block text-sm font-medium text-gray-700">
                            Username
                        </label>
                        <input
                            type="text"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                            required
                        />
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-gray-700">
                            Password
                        </label>
                        <input
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                            required
                        />
                    </div>

                    {error && (
                        <div className="bg-red-50 text-red-500 p-3 rounded text-sm">
                            {error}
                        </div>
                    )}

                    <button
                        type="submit"
                        disabled={loading}
                        className={`w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 ${
                            loading ? 'opacity-50 cursor-not-allowed' : ''
                        }`}
                    >
                        {loading ? 'Signing in...' : 'Sign in'}
                    </button>
                </form>
            </div>
        </div>
    );
}

function PrivateRoute({ children }: { children: React.ReactNode }) {
    const auth = useContext(AuthContext);
    if (!auth) throw new Error('AuthContext must be used within AuthProvider');
    return auth.token ? children : <Navigate to="/login" />;
}

function Dashboard() {
    const auth = useContext(AuthContext);
    if (!auth) throw new Error('AuthContext must be used within AuthProvider');

    return (
        <div className="min-h-screen bg-gray-100">
            <nav className="bg-white shadow-sm">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex justify-between h-16">
                        <div className="flex items-center">
                            <span className="text-lg font-semibold">
                                IRSSH Panel
                            </span>
                        </div>
                        <div className="flex items-center">
                            <span className="mr-4">
                                Welcome, {auth.user?.username}
                            </span>
                            <button
                                onClick={auth.logout}
                                className="bg-red-500 text-white px-4 py-2 rounded-md text-sm hover:bg-red-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500"
                            >
                                Logout
                            </button>
                        </div>
                    </div>
                </div>
            </nav>
            
            <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
                <div className="px-4 py-6 sm:px-0">
                    <h1 className="text-2xl font-semibold text-gray-900">
                        Dashboard
                    </h1>
                    <div className="mt-4 bg-white shadow rounded-lg p-6">
                        {/* Add your dashboard content here */}
                        <p className="text-gray-600">
                            Welcome to your IRSSH Panel dashboard.
                        </p>
                    </div>
                </div>
            </main>
        </div>
    );
}

function App() {
    return (
        <AuthProvider>
            <Router>
                <Routes>
                    <Route path="/login" element={<Login />} />
                    <Route
                        path="/dashboard"
                        element={
                            <PrivateRoute>
                                <Dashboard />
                            </PrivateRoute>
                        }
                    />
                    <Route path="/" element={<Navigate to="/login" />} />
                </Routes>
            </Router>
        </AuthProvider>
    );
}

export default App;
EOL

    # Create index.css
    cat > src/index.css << 'EOL'
@tailwind base;
@tailwind components;
@tailwind utilities;
EOL

    # Create index.tsx
    cat > src/index.tsx << 'EOL'
import React from 'react';
import { createRoot } from 'react-dom/client';
import './index.css';
import App from './App';

const container = document.getElementById('root');
if (!container) throw new Error('Failed to find root element');
const root = createRoot(container);

root.render(
    <React.StrictMode>
        <App />
    </React.StrictMode>
);
EOL

    # Build frontend
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
        
        # CORS headers
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

    client_max_body_size 100M;
    keepalive_timeout 65;
}
EOL

    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
    
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
stdout_logfile=/var/log/irssh/uvicorn.out.log
stderr_logfile=/var/log/irssh/uvicorn.err.log
environment=
    PYTHONPATH="$BACKEND_DIR",
    DB_HOST="localhost",
    DB_PORT="5432",
    DB_NAME="$DB_NAME",
    DB_USER="$DB_USER",
    DB_PASS="$DB_PASS",
    JWT_SECRET="$JWT_SECRET"
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
    ufw --force enable
}

# Run installation
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
    
    systemctl restart nginx
    supervisorctl restart irssh-panel
    
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
