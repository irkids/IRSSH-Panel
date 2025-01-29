#!/bin/bash

# Setup backend
setup_backend() {
    log "Setting up backend..."
    
    # Create virtual environment and activate it
    python3 -m venv "$PANEL_DIR/venv"
    source "$PANEL_DIR/venv/bin/activate"

    # Install Python packages
    pip install --upgrade pip wheel setuptools
    pip install \
        fastapi[all] uvicorn[standard] \
        sqlalchemy[asyncio] psycopg2-binary \
        python-jose[cryptography] passlib[bcrypt] \
        python-multipart aiofiles \
        psutil prometheus_client \
        python-telegram-bot geoip2 asyncpg \
        || error "Failed to install Python packages"

    # Create backend structure
    mkdir -p "$BACKEND_DIR/app/"{api/v1/endpoints,core,models,schemas,utils}

    # Create main application file
    cat > "$BACKEND_DIR/app/main.py" << 'EOL'
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
import os
from app.api import monitoring

app = FastAPI(title="IRSSH Panel API", version="3.4.5")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security settings
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/api/auth/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username == os.getenv("ADMIN_USER") and form_data.password == os.getenv("ADMIN_PASS"):
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": form_data.username}, expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

@app.get("/api/health")
async def health_check():
    return {"status": "healthy"}

# Include routers
app.include_router(monitoring.router, prefix="/api/monitoring", tags=["monitoring"])
EOL

    # Create monitoring module
    cat > "$BACKEND_DIR/app/api/monitoring.py" << 'EOL'
from fastapi import APIRouter, Depends
from datetime import datetime
import psutil
import os

router = APIRouter()

def get_system_stats():
    cpu = psutil.cpu_percent()
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    return {
        "cpu": cpu,
        "memory": memory.percent,
        "disk": disk.percent
    }

def get_network_stats():
    net = psutil.net_io_counters()
    return {
        "bytes_sent": net.bytes_sent,
        "bytes_recv": net.bytes_recv
    }

def get_protocol_stats():
    return [
        {
            "name": "SSH",
            "onlineUsers": 0,
            "port": 22,
            "incomingTraffic": "0 Mbps",
            "outgoingTraffic": "0 Mbps",
            "timeOnline": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        {
            "name": "L2TP",
            "onlineUsers": 0,
            "port": 1701,
            "incomingTraffic": "0 Mbps",
            "outgoingTraffic": "0 Mbps",
            "timeOnline": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        # Add other protocols here
    ]

@router.get("/system")
async def get_system_info():
    return {
        "resources": get_system_stats(),
        "network": get_network_stats(),
        "protocols": get_protocol_stats(),
        "users": {
            "active": 5,
            "expired": 2,
            "expiredSoon": 1,
            "deactive": 0,
            "online": 3
        }
    }

@router.get("/protocols")
async def get_protocols():
    return get_protocol_stats()

@router.get("/bandwidth")
async def get_bandwidth():
    net_stats = get_network_stats()
    return {
        "current": {
            "upload": net_stats["bytes_sent"] / 1024 / 1024,  # MB
            "download": net_stats["bytes_recv"] / 1024 / 1024  # MB
        }
    }
EOL

    # Create database models
    cat > "$BACKEND_DIR/app/models/models.py" << 'EOL'
from sqlalchemy import Boolean, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    protocol = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    is_active = Column(Boolean, default=True)

class Traffic(Base):
    __tablename__ = "traffic"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    upload = Column(Integer, default=0)
    download = Column(Integer, default=0)
    date = Column(DateTime, default=datetime.utcnow)

class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    ip_address = Column(String)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime)
    is_active = Column(Boolean, default=True)
EOL

    # Create database configuration
    cat > "$BACKEND_DIR/app/core/database.py" << 'EOL'
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://user:pass@localhost/dbname")

engine = create_async_engine(DATABASE_URL, echo=True)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
EOL

    # Setup supervisor configuration
    cat > /etc/supervisor/conf.d/irssh-backend.conf << EOL
[program:irssh-backend]
directory=$BACKEND_DIR
command=$PANEL_DIR/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
user=root
autostart=true
autorestart=true
stderr_logfile=$LOG_DIR/backend.err.log
stdout_logfile=$LOG_DIR/backend.out.log
environment=
    PYTHONPATH="$BACKEND_DIR",
    JWT_SECRET_KEY="$JWT_SECRET",
    ADMIN_USER="admin",
    ADMIN_PASS="$ADMIN_PASS",
    DATABASE_URL="postgresql+asyncpg://$DB_USER:$DB_PASS@localhost/$DB_NAME"
EOL

    # Reload and restart supervisor
    supervisorctl reread
    supervisorctl update
    supervisorctl restart irssh-backend

    log "Backend setup completed successfully"
}
