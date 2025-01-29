#!/bin/bash

# IRSSH Panel Complete Installation Script
# Version: 3.4.3

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

# Generate secure keys and passwords
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

# Pre-Installation Checks
check_requirements() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi

    if [[ $(free -m | awk '/^Mem:/{print $2}') -lt 1024 ]]; then
        error "Minimum 1GB RAM required"
    fi

    if [[ $(df -m / | awk 'NR==2 {print $4}') -lt 2048 ]]; then
        error "Minimum 2GB free disk space required"
    fi

    local required_commands=(curl wget git python3 pip3)
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            error "$cmd is required but not installed"
        fi
    done
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

# Initial Setup
setup_directories() {
    log "Setting up directories..."
    mkdir -p "$PANEL_DIR"/{frontend,backend,config,modules}
    mkdir -p "$FRONTEND_DIR"/{public,src/{components,styles,config,utils,hooks}}
    mkdir -p "$BACKEND_DIR"/{app/{api,core,models,schemas,utils},migrations}
    chmod -R 755 "$PANEL_DIR"
}

# Install Dependencies
install_dependencies() {
    log "Installing system dependencies..."
    apt-get update

    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3 python3-pip python3-venv \
        postgresql postgresql-contrib \
        nginx certbot python3-certbot-nginx \
        git curl wget zip unzip \
        supervisor ufw fail2ban \
        sysstat iftop vnstat

    log "Setting up Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs

    npm install -g npm@8.19.4 || error "npm installation failed"

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
        python-telegram-bot psutil geoip2 asyncpg \
        prometheus_client

    # Create Backend API
    cat > "$BACKEND_DIR/app/api/monitoring.py" << 'EOL'
import psutil
import time
from fastapi import APIRouter
from datetime import datetime, timedelta
import json
import os

router = APIRouter()

class SystemStats:
    def __init__(self):
        self.start_time = time.time()
        self.bandwidth_data = {
            "daily": [],
            "monthly": []
        }
        self.protocols = {
            "SSH": {"port": 22, "users": 0},
            "WireGuard": {"port": 51820, "users": 0},
            "SingBox": {"port": 1080, "users": 0},
            "Cisco": {"port": 443, "users": 0},
            "IKEv2": {"port": 500, "users": 0}
        }

    def get_system_resources(self):
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        
        return {
            "cpu": cpu,
            "ram": ram,
            "disk": disk
        }

    def get_bandwidth_stats(self):
        # In a real implementation, this would read from actual network interfaces
        return {
            "incoming": "1.2 Mbps",
            "outgoing": "0.8 Mbps",
            "daily_chart": self.bandwidth_data["daily"],
            "monthly_chart": self.bandwidth_data["monthly"]
        }

    def get_protocol_stats(self):
        stats = []
        for protocol, data in self.protocols.items():
            stats.append({
                "protocol": protocol,
                "onlineUsers": data["users"],
                "port": data["port"],
                "incomingTraffic": "0.5 Mbps",
                "outgoingTraffic": "0.3 Mbps",
                "timeOnline": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
        return stats

    def get_user_stats(self):
        return {
            "active": 5,
            "expired": 2,
            "expiredSoon": 1,
            "deactive": 0,
            "online": 3,
            "total": 8
        }

system_stats = SystemStats()

@router.get("/system")
async def get_system_info():
    resources = system_stats.get_system_resources()
    bandwidth = system_stats.get_bandwidth_stats()
    protocols = system_stats.get_protocol_stats()
    users = system_stats.get_user_stats()
    
    return {
        "resources": resources,
        "bandwidth": bandwidth,
        "protocols": protocols,
        "users": users
    }

@router.get("/bandwidth")
async def get_bandwidth():
    return system_stats.get_bandwidth_stats()

@router.get("/protocols")
async def get_protocols():
    return system_stats.get_protocol_stats()

@router.get("/users")
async def get_users():
    return system_stats.get_user_stats()
EOL

    # Create main.py
    cat > "$BACKEND_DIR/app/main.py" << 'EOL'
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
import os
from app.api import monitoring

app = FastAPI(title="IRSSH Panel API", version="3.4.3")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security settings
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/api/auth/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username == os.getenv("ADMIN_USER") and form_data.password == os.getenv("ADMIN_PASS"):
        access_token = create_access_token(data={"sub": form_data.username})
        return {"access_token": access_token, "token_type": "bearer"}
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

# Include monitoring routes
app.include_router(monitoring.router, prefix="/api/monitoring", tags=["monitoring"])

@app.get("/api/health")
async def health_check():
    return {"status": "healthy"}
EOL

    # Create supervisor config
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
  "version": "3.4.3",
  "private": true,
  "dependencies": {
    "@headlessui/react": "^1.7.0",
    "@heroicons/react": "^2.0.0",
    "axios": "^1.6.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.21.0",
    "react-scripts": "5.0.1",
    "recharts": "^2.5.0",
    "@babel/plugin-proposal-private-property-in-object": "^7.21.11",
    "tailwindcss": "^3.4.0"
  },
  "scripts": {
    "start": "react-scripts start",
    "build": "GENERATE_SOURCEMAP=false react-scripts build",
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

    # Create axios config
    mkdir -p src/config
    cat > src/config/axios.js << 'EOL'
import axios from 'axios';

const instance = axios.create({
    baseURL: '/',
    timeout: 5000,
});

instance.interceptors.request.use(
    config => {
        const token = localStorage.getItem('token');
        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
    },
    error => Promise.reject(error)
);

instance.interceptors.response.use(
    response => response,
    error => {
        if (error.response?.status === 401) {
            localStorage.removeItem('token');
            window.location.href = '/login';
        }
        return Promise.reject(error);
    }
);

export default instance;
EOL

    # Create auth utils
    mkdir -p src/utils
    cat > src/utils/auth.js << 'EOL'
export const setToken = (token) => {
    localStorage.setItem('token', token);
};

export const getToken = () => {
    return localStorage.getItem('token');
};

export const removeToken = () => {
    localStorage.removeItem('token');
};

export const isAuthenticated = () => {
    return !!getToken();
};
EOL

    # Create hooks
    mkdir -p src/hooks
    cat > src/hooks/useSystemStats.js << 'EOL'
import { useState, useEffect } from 'react';
import axios from '../config/axios';

export const useSystemStats = () => {
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const response = await axios.get('/api/monitoring/system');
                setData(response.data);
                setError(null);
            } catch (err) {
                setError(err.message);
            } finally {
                setLoading(false);
            }
        };

        fetchData();
        const interval = setInterval(fetchData, 30000);
        return () => clearInterval(interval);
    }, []);

    return { data, error, loading };
};
EOL

    # Create components
    mkdir -p src/components/{Auth,Dashboard,Common}

    # Create Dashboard components
    cat > src/components/Dashboard/ResourceStats.js << 'EOL'
import React from 'react';
import { IconCPU, IconRAM, IconDisk } from '../Common/Icons';

const ResourceCircle = ({ value, label, icon }) => (
    <div className="text-center">
        <div className="relative inline-block w-32 h-32">
            <svg className="transform -rotate-90 w-32 h-32">
                <circle
                    cx="64"
                    cy="64"
                    r="54"
                    stroke="#e5e7eb"
                    strokeWidth="12"
                    fill="none"
                />
                <circle
                    cx="64"
                    cy="64"
                    r="54"
                    stroke="#10b981"
                    strokeWidth="12"
                    fill="none"
                    strokeLinecap="round"
                    strokeDasharray={`${value * 3.39} 339.292`}
                />
            </svg>
            <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2">
                <span className="text-2xl font-bold">{value}%</span>
            </div>
        </div>
        <div className="mt-2">
            <div className="text-gray-700">{label}</div>
            {icon}
        </div>
    </div>
);

const ResourceStats = ({ cpuUsage, ramUsage, diskUsage }) => {
    return (
        <div className="bg-white rounded-lg shadow-md p-6">
            <h2 className="text-xl font-semibold mb-6">Server Resource Statistics</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8 justify-items-center">
                <ResourceCircle
                    value={cpuUsage}
                    label="CPU Usage"
                    icon={<IconCPU className="mx-auto mt-2" />}
                />
                <ResourceCircle
                    value={ramUsage}
                    label="RAM Usage"
                    icon={<IconRAM className="mx-auto mt-2" />}
                />
                <ResourceCircle
                    value={diskUsage}
                    label="Disk Usage"
                    icon={<IconDisk className="mx-auto mt-2" />}
                />
            </div>
        </div>
    );
};

export default ResourceStats;
EOL

    cat > src/components/Dashboard/BandwidthStats.js << 'EOL'
import React from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const BandwidthStats = ({ monthlyData, dailyData }) => {
    return (
        <div className="bg-white rounded-lg shadow-md p-6">
            <h2 className="text-xl font-semibold mb-6">Bandwidth Statistics</h2>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div>
                    <h3 className="text-lg font-medium mb-4">Monthly Chart</h3>
                    <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                            <LineChart data={monthlyData}>
                                <CartesianGrid strokeDasharray="3 3" />
                                <XAxis dataKey="date" />
                                <YAxis />
                                <Tooltip />
                                <Line type="monotone" dataKey="send" stroke="#3b82f6" />
                                <Line type="monotone" dataKey="receive" stroke="#10b981" />
                                <Line type="monotone" dataKey="total" stroke="#6366f1" />
                            </LineChart>
                        </ResponsiveContainer>
                    </div>
                </div>
                <div>
                    <h3 className="text-lg font-medium mb-4">Daily Chart</h3>
                    <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                            <LineChart data={dailyData}>
                                <CartesianGrid strokeDasharray="3 3" />
                                <XAxis dataKey="date" />
                                <YAxis />
                                <Tooltip />
                                <Line type="monotone" dataKey="send" stroke="#3b82f6" />
                                <Line type="monotone" dataKey="receive" stroke="#10b981" />
                                <Line type="monotone" dataKey="total" stroke="#6366f1" />
                            </LineChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default BandwidthStats;
EOL

    cat > src/components/Dashboard/UserStats.js << 'EOL'
import React from 'react';

const StatBox = ({ label, value, color }) => (
    <div className="text-center">
        <div className={`text-${color}-600 font-medium`}>{label}</div>
        <div className="text-2xl font-bold mt-1">{value}</div>
    </div>
);

const UserStats = ({ stats }) => {
    return (
        <div className="bg-white rounded-lg shadow-md p-6">
            <h2 className="text-xl font-semibold mb-6">Users Statistics</h2>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <StatBox label="Active" value={stats.active} color="green" />
                <StatBox label="Expired" value={stats.expired} color="red" />
                <StatBox label="Expired in 24h" value={stats.expiredSoon} color="yellow" />
                <StatBox label="Deactive" value={stats.deactive} color="gray" />
                <StatBox label="Online" value={stats.online} color="blue" />
            </div>
        </div>
    );
};

export default UserStats;
EOL

    cat > src/components/Dashboard/ProtocolStats.js << 'EOL'
import React from 'react';

const ProtocolStats = ({ protocols }) => {
    return (
        <div className="bg-white rounded-lg shadow-md p-6">
            <h2 className="text-xl font-semibold mb-6">Protocol Statistics</h2>
            <div className="overflow-x-auto">
                <table className="min-w-full">
                    <thead className="bg-gray-50">
                        <tr>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Protocol</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Online Users</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Protocol port</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Incoming Traffic</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Outgoing Traffic</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time Of Being Online</th>
                        </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                        {protocols.map((protocol, index) => (
                            <tr key={index}>
                                <td className="px-6 py-4 whitespace-nowrap">{protocol.protocol}</td>
                                <td className="px-6 py-4 whitespace-nowrap">{protocol.onlineUsers}</td>
                                <td className="px-6 py-4 whitespace-nowrap">{protocol.port}</td>
                                <td className="px-6 py-4 whitespace-nowrap">{protocol.incomingTraffic}</td>
                                <td className="px-6 py-4 whitespace-nowrap">{protocol.outgoingTraffic}</td>
                                <td className="px-6 py-4 whitespace-nowrap">{protocol.timeOnline}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default ProtocolStats;
EOL

    cat > src/components/Common/Icons.js << 'EOL'
export const IconCPU = ({ className = "w-6 h-6" }) => (
    <svg xmlns="http://www.w3.org/2000/svg" className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
    </svg>
);

export const IconRAM = ({ className = "w-6 h-6" }) => (
    <svg xmlns="http://www.w3.org/2000/svg" className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />
    </svg>
);

export const IconDisk = ({ className = "w-6 h-6" }) => (
    <svg xmlns="http://www.w3.org/2000/svg" className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4" />
    </svg>
);
EOL

    cat > src/components/Dashboard/index.js << 'EOL'
import React from 'react';
import { useSystemStats } from '../../hooks/useSystemStats';
import ResourceStats from './ResourceStats';
import BandwidthStats from './BandwidthStats';
import UserStats from './UserStats';
import ProtocolStats from './ProtocolStats';
import { removeToken } from '../../utils/auth';

const Dashboard = () => {
    const { data, error, loading } = useSystemStats();

    const handleLogout = () => {
        removeToken();
        window.location.href = '/login';
    };

    if (loading) {
        return (
            <div className="min-h-screen bg-gray-100 flex justify-center items-center">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-gray-900"></div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="min-h-screen bg-gray-100 flex justify-center items-center">
                <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
                    Failed to load dashboard data
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-gray-100">
            {/* Header */}
            <nav className="bg-white shadow">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex justify-between h-16">
                        <div className="flex items-center">
                            <img src="/logo.png" alt="IRSSH" className="h-8 w-8 mr-2" />
                            <h1 className="text-xl font-bold">Dashboard</h1>
                            <span className="ml-2 text-sm text-gray-500">Administrator</span>
                        </div>
                        <div className="flex items-center space-x-4">
                            <button
                                onClick={handleLogout}
                                className="bg-red-600 px-4 py-2 text-white rounded-md hover:bg-red-700"
                            >
                                Logout
                            </button>
                        </div>
                    </div>
                </div>
            </nav>

            {/* Main Content */}
            <main className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8 space-y-6">
                <ResourceStats
                    cpuUsage={data.resources.cpu}
                    ramUsage={data.resources.ram}
                    diskUsage={data.resources.disk}
                />
                <BandwidthStats
                    monthlyData={data.bandwidth.monthly_chart}
                    dailyData={data.bandwidth.daily_chart}
                />
                <ProtocolStats protocols={data.protocols} />
                <UserStats stats={data.users} />
            </main>
        </div>
    );
};

export default Dashboard;
EOL

    cat > src/components/Auth/Login.js << 'EOL'
import React, { useState } from 'react';
import axios from '../../config/axios';

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const formData = new URLSearchParams();
      formData.append('username', username);
      formData.append('password', password);

      const response = await axios.post('/api/auth/login', formData, {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      });

      if (response.data && response.data.access_token) {
        localStorage.setItem('token', response.data.access_token);
        window.location.href = '/dashboard';
      } else {
        throw new Error('Invalid response from server');
      }
    } catch (error) {
      console.error('Login error:', error.response || error);
      setError(error.response?.data?.detail || 'Login failed. Please try again.');
    } finally {
      setLoading(false);
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
          {error && (
            <div className="mb-4 bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative">
              {error}
            </div>
          )}
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
                disabled={loading}
                className={`w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white ${
                  loading ? 'bg-indigo-400' : 'bg-indigo-600 hover:bg-indigo-700'
                } focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500`}
              >
                {loading ? 'Signing in...' : 'Sign in'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default Login;
EOL

    cat > src/components/Auth/PrivateRoute.js << 'EOL'
import React from 'react';
import { Navigate } from 'react-router-dom';
import { isAuthenticated } from '../../utils/auth';

const PrivateRoute = ({ children }) => {
  return isAuthenticated() ? children : <Navigate to="/login" />;
};

export default PrivateRoute;
EOL

    cat > src/App.js << 'EOL'
import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Auth/Login';
import Dashboard from './components/Dashboard';
import PrivateRoute from './components/Auth/PrivateRoute';

const App = () => {
  return (
    <BrowserRouter>
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
    </BrowserRouter>
  );
};

export default App;
EOL

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

code {
  font-family: source-code-pro, Menlo, Monaco, Consolas, 'Courier New',
    monospace;
}
EOL

    # Install dependencies and build
    log "Installing frontend dependencies..."
    npm install

    log "Building frontend..."
    GENERATE_SOURCEMAP=false npm run build

    if [ $? -eq 0 ]; then
        log "Frontend built successfully"
    else
        error "Frontend build failed"
    fi
}

# Setup Database
setup_database() {
    log "Setting up database..."
    systemctl start postgresql
    systemctl enable postgresql

    # Wait for PostgreSQL to start
    for i in {1..30}; do
        if pg_isready -q; then
            break
        fi
        sleep 1
    done

    # Create database and user
    sudo -u postgres psql -c "DROP DATABASE IF EXISTS $DB_NAME;"
    sudo -u postgres psql -c "DROP USER IF EXISTS $DB_USER;"
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"

    # Save configuration
    cat > "$CONFIG_DIR/database.env" << EOL
DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASS=$DB_PASS
EOL
    chmod 600 "$CONFIG_DIR/database.env"
}

# Setup Nginx
setup_nginx() {
    log "Configuring Nginx..."
    
    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    root ${FRONTEND_DIR}/build;
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

        # CORS headers
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE' always;
        add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;
        add_header 'Access-Control-Expose-Headers' 'Content-Length,Content-Range' always;

        if (\$request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' '*';
            add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE';
            add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization';
            add_header 'Access-Control-Max-Age' 1728000;
            add_header 'Content-Type' 'text/plain; charset=utf-8';
            add_header 'Content-Length' 0;
            return 204;
        }
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

# Setup SSL
setup_ssl() {
    if [[ -n "$DOMAIN" ]]; then
        log "Setting up SSL..."
        
        systemctl stop nginx

        # Request certificate
        certbot certonly --standalone \
            -d "$DOMAIN" \
            --non-interactive \
            --agree-tos \
            --email "admin@$DOMAIN" \
            --http-01-port=80 || error "SSL certificate request failed"

        # Update Nginx configuration for SSL
        cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    root ${FRONTEND_DIR}/build;
    index index.html;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000" always;
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

        # CORS headers
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE' always;
        add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;
        add_header 'Access-Control-Expose-Headers' 'Content-Length,Content-Range' always;

        if (\$request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' '*';
            add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE';
            add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization';
            add_header 'Access-Control-Max-Age' 1728000;
            add_header 'Content-Type' 'text/plain; charset=utf-8';
            add_header 'Content-Length' 0;
            return 204;
        }
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

        systemctl start nginx
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

# Setup Security
setup_security() {
    log "Setting up security..."

    # Configure fail2ban
    cat > /etc/fail2ban/jail.local << EOL
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = $SSH_PORT
logpath = /var/log/auth.log

[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
EOL

    systemctl restart fail2ban

    # Secure SSH configuration
    sed -i 's/#PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
}

# Setup System Monitoring
setup_monitoring() {
    log "Setting up system monitoring..."
    
    # Create monitoring script
    cat > "$MODULES_DIR/monitor.sh" << 'EOL'
#!/bin/bash

get_cpu_usage() {
    top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}'
}

get_mem_usage() {
    free | grep Mem | awk '{print ($3/$2) * 100}'
}

get_disk_usage() {
    df -h / | awk 'NR==2 {print $5}' | sed 's/%//'
}

get_network_stats() {
    if command -v vnstat &> /dev/null; then
        vnstat -h 1
    else
        echo "vnstat not installed"
    fi
}

echo "{"
echo "  \"cpu\": $(get_cpu_usage),"
echo "  \"memory\": $(get_mem_usage | xargs printf "%.1f"),"
echo "  \"disk\": $(get_disk_usage),"
echo "  \"network\": \"$(get_network_stats)\""
echo "}"
EOL

    chmod +x "$MODULES_DIR/monitor.sh"

    # Create cron job for monitoring
    echo "* * * * * root $MODULES_DIR/monitor.sh > /tmp/system_stats.json" > /etc/cron.d/irssh-monitor
    chmod 644 /etc/cron.d/irssh-monitor
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

    # Check backend API
    if ! curl -s "http://localhost:8000/api/health" > /dev/null; then
        error "Backend API is not responding"
    fi

    # Check monitoring script
    if [ ! -x "$MODULES_DIR/monitor.sh" ]; then
        error "Monitoring script is not executable"
    fi

    log "All services verified successfully"
}

# Save Installation Info
save_installation_info() {
    log "Saving installation information..."
    
    cat > "$CONFIG_DIR/installation.info" << EOL
Installation Date: $(date +"%Y-%m-%d %H:%M:%S")
Version: 3.4.3
Domain: ${DOMAIN}
Web Port: ${WEB_PORT}
SSH Port: ${SSH_PORT}
Dropbear Port: ${DROPBEAR_PORT}
BadVPN Port: ${BADVPN_PORT}
Admin Username: admin
Admin Password: ${ADMIN_PASS}
Database Name: ${DB_NAME}
Database User: ${DB_USER}
Database Password: ${DB_PASS}
JWT Secret: ${JWT_SECRET}
EOL
    chmod 600 "$CONFIG_DIR/installation.info"

    # Create environment file for easy access
    cat > "$CONFIG_DIR/env" << EOL
ADMIN_USER=admin
ADMIN_PASS=${ADMIN_PASS}
JWT_SECRET_KEY=${JWT_SECRET}
DB_HOST=localhost
DB_PORT=5432
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASS=${DB_PASS}
EOL
    chmod 600 "$CONFIG_DIR/env"
}

# Main Installation
main() {
    trap cleanup EXIT
    
    setup_logging
    log "Starting IRSSH Panel installation v3.4.3"
    
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
    
    # Run installation steps
    check_requirements
    create_backup
    setup_directories
    install_dependencies
    setup_python
    setup_frontend
    setup_database
    setup_monitoring
    setup_modules
    setup_nginx
    setup_ssl
    setup_firewall
    setup_security
    verify_installation
    save_installation_info
    
    # Final output
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
    echo "Installation Info: $CONFIG_DIR/installation.info"
    echo
    echo "Important Notes:"
    echo "1. Please save these credentials securely"
    echo "2. Change the admin password after first login"
    echo "3. Configure additional security settings in the panel"
    echo "4. Check the installation log for any warnings"
    echo "5. A backup of the previous installation (if any) has been saved in: $BACKUP_DIR"
}

# Start installation
main "$@"
