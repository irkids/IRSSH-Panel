#!/bin/bash

# تنظیمات رنگ‌ها
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# مسیرهای پیکربندی
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
LOG_DIR="/var/log/irssh"
VENV_DIR="$PANEL_DIR/venv"

# پورت پیش‌فرض
DEFAULT_API_PORT=8000

# تولید کلیدهای امنیتی
generate_secure_key() {
    openssl rand -hex 32
}

JWT_SECRET=$(generate_secure_key)

# توابع لاگینگ
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# نصب پکیج‌های سیستمی
install_system_packages() {
    log "نصب پکیج‌های سیستمی..."
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3 python3-pip python3-venv postgresql postgresql-contrib \
        nginx supervisor curl git certbot python3-certbot-nginx
}

# راه‌اندازی Node.js
setup_node() {
    log "راه‌اندازی Node.js..."
    export NVM_DIR="$HOME/.nvm"
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
    nvm install 18
    nvm use 18
}

# راه‌اندازی محیط Python
setup_python_env() {
    log "راه‌اندازی محیط Python..."
    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"
    
    pip install \
        fastapi[all] uvicorn[standard] sqlalchemy[asyncio] \
        psycopg2-binary python-jose[cryptography] passlib[bcrypt] \
        python-multipart aiofiles python-dotenv pydantic-settings \
        asyncpg bcrypt pydantic requests aiohttp psutil
}

# راه‌اندازی دیتابیس
setup_database() {
    log "راه‌اندازی PostgreSQL..."
    systemctl start postgresql
    systemctl enable postgresql
    
    local DB_NAME="irssh"
    local DB_USER="irssh_admin"
    local DB_PASS=$(generate_secure_key)
    
    # ایجاد کاربر و دیتابیس
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

    # ذخیره تنظیمات دیتابیس
    mkdir -p "$CONFIG_DIR"
    echo "DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASS=$DB_PASS" > "$CONFIG_DIR/database.env"
    chmod 600 "$CONFIG_DIR/database.env"
}

# راه‌اندازی بک‌اند
setup_backend() {
    log "راه‌اندازی بک‌اند..."
    mkdir -p "$BACKEND_DIR/app"/{core,api,models,schemas,utils}
    mkdir -p "$BACKEND_DIR/app/api/v1/endpoints"

    # ایجاد فایل‌های بک‌اند
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

    # ایجاد مدل‌های کاربری
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

    # ایجاد سیستم احراز هویت
    cat > "$BACKEND_DIR/app/core/auth.py" << 'EOL'
from datetime import datetime, timedelta
from typing import Optional
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.user import User
from app.core.database import get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401)
    except JWTError:
        raise HTTPException(status_code=401)
        
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(status_code=401)
    return user
EOL

    # فایل اصلی برنامه
    cat > "$BACKEND_DIR/app/main.py" << 'EOL'
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
import psutil
from typing import Dict

from app.core.database import init_db
from app.core.auth import get_current_user
from app.models.user import User

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    init_db()

@app.get("/api/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/api/stats")
async def get_stats(current_user: User = Depends(get_current_user)) -> Dict:
    return {
        "cpu_percent": psutil.cpu_percent(),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": psutil.disk_usage('/').percent,
        "connections": len(psutil.net_connections())
    }

@app.get("/api/user/me")
async def get_user_info(current_user: User = Depends(get_current_user)):
    return {
        "username": current_user.username,
        "is_admin": current_user.is_admin
    }
EOL

    # ایجاد کاربر مدیر
    log "ایجاد کاربر مدیر..."
    read -p "نام کاربری مدیر (پیش‌فرض: admin): " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-admin}
    
    read -s -p "رمز عبور مدیر (Enter برای تولید تصادفی): " ADMIN_PASS
    echo
    if [[ -z "$ADMIN_PASS" ]]; then
        ADMIN_PASS=$(openssl rand -base64 12)
        echo "رمز عبور تولید شده: $ADMIN_PASS"
    fi

    cat > "$CONFIG_DIR/admin.env" << EOL
ADMIN_USER=$ADMIN_USER
ADMIN_PASS=$ADMIN_PASS
EOL
    chmod 600 "$CONFIG_DIR/admin.env"

    # ایجاد کاربر مدیر در دیتابیس
    cat > "$BACKEND_DIR/create_admin.py" << EOL
from app.core.database import SessionLocal, init_db
from app.core.auth import get_password_hash
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
    db.close()

if __name__ == "__main__":
    create_admin()
EOL

    source "$VENV_DIR/bin/activate"
    python "$BACKEND_DIR/create_admin.py"
}

# راه‌اندازی فرانت‌اند
setup_frontend() {
    log "راه‌اندازی فرانت‌اند..."
    rm -rf "$FRONTEND_DIR"
    cd "$PANEL_DIR"
    
    npx create-react-app frontend --template typescript
    cd "$FRONTEND_DIR"
    
    npm install --legacy-peer-deps
    npm install --legacy-peer-deps \
        react-router-dom \
        axios \
        @headlessui/react \
        @heroicons/react \
        @tailwindcss/forms \
        recharts

    # ساخت کامپوننت‌های فرانت‌اند
    mkdir -p src/components/{Auth,Dashboard,Layout}
    
    # کامپوننت لاگین
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
      
      const response = await axios.post('/api/auth/login', formData);
      
      if (response.data.access_token) {
        localStorage.setItem('token', response.data.access_token);
        localStorage.setItem('username', response.data.username);
        window.location.href = '/dashboard';
      }
    } catch (error) {
      setError('نام کاربری یا رمز عبور اشتباه است');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            ورود به پنل IRSSH
          </h2>
        </div>
        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <div className="rounded-md shadow-sm -space-y-px">
            <div>
              <label htmlFor="username" className="sr-only">نام کاربری</label>
              <input
                id="username"
                name="username"
                type="text"
                required
                className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-t-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                placeholder="نام کاربری"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </div>
            <div>
              <label htmlFor="password" className="sr-only">رمز عبور</label>
              <input
                id="password"
                name="password"
                type="password"
                required
                className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-b-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                placeholder="رمز عبور"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
          </div>

         {error && (
           <div className="text-red-600 text-sm text-center">{error}</div>
         )}

         <button
           type="submit"
           className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
         >
           ورود
         </button>
       </form>
     </div>
   </div>
 );
}

export default Login;
EOL

   # کامپوننت داشبورد
   cat > src/components/Dashboard/Dashboard.js << 'EOL'
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
 LineChart,
 Line,
 XAxis,
 YAxis,
 CartesianGrid,
 Tooltip,
 ResponsiveContainer
} from 'recharts';

function Dashboard() {
 const [stats, setStats] = useState({
   cpu_percent: 0,
   memory_percent: 0,
   disk_percent: 0,
   connections: 0
 });

 useEffect(() => {
   const fetchStats = async () => {
     try {
       const response = await axios.get('/api/stats', {
         headers: {
           'Authorization': `Bearer ${localStorage.getItem('token')}`
         }
       });
       setStats(response.data);
     } catch (error) {
       console.error('Error fetching stats:', error);
     }
   };

   fetchStats();
   const interval = setInterval(fetchStats, 5000);
   return () => clearInterval(interval);
 }, []);

 return (
   <div className="p-6">
     <h1 className="text-2xl font-bold mb-6">پنل مدیریت</h1>
     
     <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
       <div className="bg-white rounded-lg shadow p-6">
         <h3 className="text-lg font-medium text-gray-900">CPU</h3>
         <p className="mt-2 text-3xl font-bold text-indigo-600">{stats.cpu_percent}%</p>
       </div>
       
       <div className="bg-white rounded-lg shadow p-6">
         <h3 className="text-lg font-medium text-gray-900">حافظه</h3>
         <p className="mt-2 text-3xl font-bold text-indigo-600">{stats.memory_percent}%</p>
       </div>
       
       <div className="bg-white rounded-lg shadow p-6">
         <h3 className="text-lg font-medium text-gray-900">دیسک</h3>
         <p className="mt-2 text-3xl font-bold text-indigo-600">{stats.disk_percent}%</p>
       </div>
       
       <div className="bg-white rounded-lg shadow p-6">
         <h3 className="text-lg font-medium text-gray-900">اتصالات</h3>
         <p className="mt-2 text-3xl font-bold text-indigo-600">{stats.connections}</p>
       </div>
     </div>

     <div className="mt-8 bg-white rounded-lg shadow p-6">
       <h2 className="text-lg font-medium text-gray-900 mb-4">نمودار منابع سیستم</h2>
       <div style={{ height: '400px' }}>
         <ResponsiveContainer width="100%" height="100%">
           <LineChart data={[stats]}>
             <CartesianGrid strokeDasharray="3 3" />
             <XAxis dataKey="name" />
             <YAxis />
             <Tooltip />
             <Line type="monotone" dataKey="cpu_percent" name="CPU" stroke="#6366F1" />
             <Line type="monotone" dataKey="memory_percent" name="حافظه" stroke="#10B981" />
           </LineChart>
         </ResponsiveContainer>
       </div>
     </div>
   </div>
 );
}

export default Dashboard;
EOL

   # کامپوننت Layout
   cat > src/components/Layout/Layout.js << 'EOL'
import React from 'react';
import { Link } from 'react-router-dom';

function Layout({ children }) {
 return (
   <div className="min-h-screen bg-gray-100">
     <nav className="bg-white shadow-sm">
       <div className="max-w-7xl mx-auto px-4">
         <div className="flex justify-between h-16">
           <div className="flex">
             <Link to="/dashboard" className="flex-shrink-0 flex items-center">
               <span className="text-xl font-bold text-indigo-600">IRSSH Panel</span>
             </Link>
             <div className="hidden sm:ml-6 sm:flex sm:space-x-8">
               <Link 
                 to="/dashboard"
                 className="text-gray-900 inline-flex items-center px-1 pt-1 border-b-2 border-indigo-500 text-sm font-medium"
               >
                 داشبورد
               </Link>
               <Link 
                 to="/users"
                 className="text-gray-500 hover:text-gray-700 inline-flex items-center px-1 pt-1 border-b-2 border-transparent text-sm font-medium"
               >
                 کاربران
               </Link>
               <Link 
                 to="/protocols"
                 className="text-gray-500 hover:text-gray-700 inline-flex items-center px-1 pt-1 border-b-2 border-transparent text-sm font-medium"
               >
                 پروتکل‌ها
               </Link>
             </div>
           </div>
           <div className="flex items-center">
             <button 
               onClick={() => {
                 localStorage.removeItem('token');
                 localStorage.removeItem('username');
                 window.location.href = '/login';
               }}
               className="ml-8 whitespace-nowrap inline-flex items-center justify-center px-4 py-2 border border-transparent rounded-md shadow-sm text-base font-medium text-white bg-indigo-600 hover:bg-indigo-700"
             >
               خروج
             </button>
           </div>
         </div>
       </div>
     </nav>

     <main className="py-10">
       <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
         {children}
       </div>
     </main>
   </div>
 );
}

export default Layout;
EOL

   # فایل اصلی App.js
   cat > src/App.js << 'EOL'
import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Auth/Login';
import Dashboard from './components/Dashboard/Dashboard';
import Layout from './components/Layout/Layout';

function PrivateRoute({ children }) {
 const token = localStorage.getItem('token');
 return token ? <Layout>{children}</Layout> : <Navigate to="/login" />;
}

function App() {
 return (
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
       <Route path="/" element={<Navigate to="/dashboard" replace />} />
     </Routes>
   </Router>
 );
}

export default App;
EOL

   # کانفیگ Tailwind
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

   npm run build
}

# راه‌اندازی Nginx
setup_nginx() {
   log "راه‌اندازی Nginx..."
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
}

# راه‌اندازی Supervisor
setup_supervisor() {
   log "راه‌اندازی Supervisor..."
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

# تابع اصلی
main() {
   mkdir -p "$CONFIG_DIR"
   mkdir -p "$LOG_DIR"
   
   log "شروع نصب IRSSH Panel..."
   
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
   
   log "نصب با موفقیت انجام شد!"
   echo
   echo "پنل IRSSH با موفقیت نصب شد!"
   echo
   echo "اطلاعات ورود مدیر:"
   echo "نام کاربری: $(grep ADMIN_USER $CONFIG_DIR/admin.env | cut -d= -f2)"
   echo "رمز عبور: $(grep ADMIN_PASS $CONFIG_DIR/admin.env | cut -d= -f2)"
   echo
   echo "آدرس پنل: http://YOUR-IP"
   echo "آدرس API: http://YOUR-IP/api"
}

main "$@"
