async def login(form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)):
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

    # Reset failed login attempts
    user.failed_login_attempts = 0
    user.last_login = datetime.utcnow()
    
    # Generate tokens
    access_token = create_access_token(data={"sub": user.username})
    refresh_token = create_refresh_token(data={"sub": user.username})
    
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
    
    try:
        db.add(admin)
        db.commit()
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

if __name__ == "__main__":
    create_admin()
EOL

    source "$VENV_DIR/bin/activate"
    python create_admin.py || error "Failed to create admin user"
}

# Setup frontend with file structure
setup_frontend() {
    log "Setting up frontend..."
    
    # Clean previous installation
    rm -rf "$FRONTEND_DIR"
    mkdir -p "$FRONTEND_DIR"
    cd "$PANEL_DIR"
    
    # Setup Node.js environment
    export NVM_DIR="$HOME/.nvm"
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
    nvm use 18 || error "Failed to switch to Node.js 18"
    
    # Create frontend directory structure
    cd "$FRONTEND_DIR"
    mkdir -p src public
    
    # Create package.json
    cat > package.json << 'EOL'
{
    "name": "irssh-panel",
    "version": "1.0.0",
    "private": true,
    "dependencies": {
        "@mantine/core": "^7.0.0",
        "@mantine/hooks": "^7.0.0",
        "axios": "^1.6.0",
        "react": "^18.2.0",
        "react-dom": "^18.2.0",
        "react-router-dom": "^6.20.0",
        "react-scripts": "5.0.1"
    },
    "scripts": {
        "start": "react-scripts start",
        "build": "react-scripts build"
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
    <title>IRSSH Panel</title>
</head>
<body>
    <div id="root"></div>
</body>
</html>
EOL

    # Create index.js
    cat > src/index.js << 'EOL'
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
EOL

    # Create App.js with enhanced login
    cat > src/App.js << 'EOL'
import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import axios from 'axios';

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
                localStorage.setItem('token', response.data.access_token);
                localStorage.setItem('username', response.data.username);
                localStorage.setItem('is_admin', response.data.is_admin);
                window.location.href = '/dashboard';
            }
        } catch (error) {
            console.error('Login error:', error);
            if (error.response?.status === 429) {
                setError('Too many failed attempts. Please try again later.');
            } else {
                setError('Invalid username or password');
            }
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div style={{
            minHeight: '100vh',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            background: '#f5f5f5'
        }}>
            <div style={{
                width: '100%',
                maxWidth: '400px',
                padding: '2rem',
                background: 'white',
                borderRadius: '8px',
                boxShadow: '0 2px 4px rgba(0, 0, 0, 0.1)'
            }}>
                <h1 style={{
                    textAlign: 'center',
                    marginBottom: '2rem',
                    color: '#333'
                }}>IRSSH Panel Login</h1>
                <form onSubmit={handleSubmit}>
                    <div style={{ marginBottom: '1rem' }}>
                        <input
                            type="text"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            placeholder="Username"
                            style={{
                                width: '100%',
                                padding: '0.75rem',
                                borderRadius: '4px',
                                border: '1px solid #ddd'
                            }}
                        />
                    </div>
                    <div style={{ marginBottom: '1rem' }}>
                        <input
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            placeholder="Password"
                            style={{
                                width: '100%',
                                padding: '0.75rem',
                                borderRadius: '4px',
                                border: '1px solid #ddd'
                            }}
                        />
                    </div>
                    {error && (
                        <div style={{
                            color: '#dc2626',
                            textAlign: 'center',
                            marginBottom: '1rem'
                        }}>
                            {error}
                        </div>
                    )}
                    <button
                        type="submit"
                        disabled={isLoading}
                        style={{
                            width: '100%',
                            padding: '0.75rem',
                            background: '#2563eb',
                            color: 'white',
                            border: 'none',
                            borderRadius: '4px',
                            cursor: isLoading ? 'not-allowed' : 'pointer',
                            opacity: isLoading ? 0.7 : 1
                        }}
                    >
                        {isLoading ? 'Signing in...' : 'Sign in'}
                    </button>
                </form>
            </div>
        </div>
    );
}

function Dashboard() {
    const username = localStorage.getItem('username');
    const isAdmin = localStorage.getItem('is_admin') === 'true';

    const handleLogout = () => {
        localStorage.removeItem('token');
        localStorage.removeItem('username');
        localStorage.removeItem('is_admin');
        window.location.href = '/login';
    };

    return (
        <div>
            <nav style={{
                background: '#fff',
                padding: '1rem',
                boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
            }}>
                <div style={{
                    maxWidth: '1200px',
                    margin: '0 auto',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center'
                }}>
                    <h1>IRSSH Panel</h1>
                    <div>
                        <span>Welcome, {username}</span>
                        {isAdmin && (
                            <span style={{
                                background: '#3b82f6',
                                color: 'white',
                                padding: '0.25rem 0.5rem',
                                borderRadius: '4px',
                                marginLeft: '0.5rem'
                            }}>Admin</span>
                        )}
                        <button
                            onClick={handleLogout}
                            style={{
                                marginLeft: '1rem',
                                padding: '0.5rem 1rem',
                                background: '#dc2626',
                                color: 'white',
                                border: 'none',
                                borderRadius: '4px',
                                cursor: 'pointer'
                            }}
                        >
                            Logout
                        </button>
                    </div>
                </div>
            </nav>
            <main style={{
                maxWidth: '1200px',
                margin: '2rem auto',
                padding: '0 1rem'
            }}>
                <h2>Dashboard</h2>
                <p>Welcome to your IRSSH Panel dashboard!</p>
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

    # Install dependencies and build
    npm install --legacy-peer-deps || error "Failed to install frontend dependencies"
    npm install @babel/plugin-proposal-private-property-in-object --save-dev || error "Failed to install babel plugin"
    npm run build || error "Failed to build frontend"
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
        add_header X-Frame-Options "SAMEORIGIN";
        add_header X-XSS-Protection "1; mode=block";
        add_header X-Content-Type-Options "nosniff";
    }
    
    location /api {
        proxy_pass http://localhost:$DEFAULT_API_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        
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
    chown -R root:root /var/log/irssh
    chmod -R 755 /var/log/irssh
    
    cat > /etc/supervisor/conf.d/irssh-panel.conf << EOL
[program:irssh-panel]
directory=$BACKEND_DIR
command=$VENV_DIR/bin/uvicorn app.main:app --host 0.0.0.0 --port $DEFAULT_API_PORT
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
EOL

    supervisorctl reread
    supervisorctl update
}

# Configure firewall
setup_firewall() {
    log "Setting up firewall rules..."
    
    # Ensure UFW is installed
    apt-get install -y ufw || error "Failed to install UFW"
    
    # Reset UFW
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH
    ufw allow ssh
    
    # Allow HTTP/HTTPS
    ufw allow http
    ufw allow https
    
    # Allow API port
    ufw allow $DEFAULT_API_PORT/tcp
    
    # Enable UFW
    ufw --force enable
}

# Main installation function
main() {
    # Check if script is run as root
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi

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
    systemctl restart postgresql
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
    echo "Installation log: $LOG_FILE"
}

# Start installation
trap cleanup SIGINT SIGTERM
main "$@"true
autorestart=#!/bin/bash

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

# Cleanup function must be defined early
cleanup() {
    log "Cleaning up..."
    systemctl stop nginx 2>/dev/null || true
    systemctl stop postgresql 2>/dev/null || true
    supervisorctl stop irssh-panel 2>/dev/null || true
    
    if [[ $? -ne 0 ]]; then
        for dir in "$FRONTEND_DIR" "$BACKEND_DIR" "$CONFIG_DIR"; do
            if [[ -d "$dir" ]]; then
                rm -rf "$dir"
            fi
        done
        rm -f /etc/nginx/sites-enabled/irssh-panel
        rm -f /etc/supervisor/conf.d/irssh-panel.conf
    fi
}

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
    local mem_total=$(free -m | awk '/^Mem:/{print $2}')
    local disk_free=$(df -m / | awk 'NR==2 {print $4}')
    
    [[ $mem_total -lt 1024 ]] && error "Minimum 1GB RAM required"
    [[ $disk_free -lt 2048 ]] && error "Minimum 2GB free disk space required"
    
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
    
    # Install global packages
    npm install -g npm@latest
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

# Configure PostgreSQL with enhanced setup
setup_database() {
    log "Setting up PostgreSQL..."
    
    systemctl start postgresql
    systemctl enable postgresql
    sleep 5 # Wait for PostgreSQL to start
    
    local DB_NAME="irssh"
    local DB_USER="irssh_admin"
    local DB_PASS=$(generate_secure_key)

    # Update pg_hba.conf
    local PG_HBA_CONF="/etc/postgresql/*/main/pg_hba.conf"
    local PG_CONF_FILE=$(ls $PG_HBA_CONF 2>/dev/null | head -n 1)
    
    if [[ -f "$PG_CONF_FILE" ]]; then
        # Backup original
        cp "$PG_CONF_FILE" "${PG_CONF_FILE}.bak"
        
        # Configure local authentication to trust for setup
        sed -i 's/peer/trust/g' "$PG_CONF_FILE"
        sed -i 's/md5/trust/g' "$PG_CONF_FILE"
        
        systemctl restart postgresql
        sleep 3
    fi

    # Setup database as postgres user
    su - postgres -c "psql -c \"DROP DATABASE IF EXISTS $DB_NAME;\"" || true
    su - postgres -c "psql -c \"DROP USER IF EXISTS $DB_USER;\"" || true
    su - postgres -c "psql -c \"CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';\"" 
    su - postgres -c "psql -c \"CREATE DATABASE $DB_NAME OWNER $DB_USER;\""
    su - postgres -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;\""

    # Restore pg_hba.conf to md5
    if [[ -f "$PG_CONF_FILE" ]]; then
        sed -i 's/trust/md5/g' "$PG_CONF_FILE"
        systemctl restart postgresql
    fi
    
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

# Setup backend structure with enhanced security
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

    # Create security.py with enhanced token handling
    cat > app/core/security.py << 'EOL'
from datetime import datetime, timedelta
from typing import Optional, Dict
from passlib.context import CryptContext
from jose import jwt
from .config import settings
import time
from collections import defaultdict

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Track login attempts
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

    # Create database.py with connection pooling
    cat > app/core/database.py << 'EOL'
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from .config import settings

SQLALCHEMY_DATABASE_URL = f"postgresql://{settings.DB_USER}:{settings.DB_PASS}@{settings.DB_HOST}:{settings.DB_PORT}/{settings.DB_NAME}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
EOL

    # Create user model with enhanced security fields
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

    # Create main.py with enhanced authentication
    cat > app/main.py << 'EOL'
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime
import logging

from app.core.database import get_db, init_db
from app.core.security import (
    verify_password, create_access_token, create_refresh_token,
    check_login_attempts, record_login_attempt
)
from app.models.user import User

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
async def login(form_data: OAuth2PasswordRequestForm = Depends(),
