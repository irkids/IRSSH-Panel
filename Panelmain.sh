#!/bin/bash

# Configuration
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Create React app structure
log "Setting up frontend..."
cd "$FRONTEND_DIR"

# Install dependencies
npm install @headlessui/react @heroicons/react axios react-router-dom

# Create frontend files
mkdir -p src/components/{Auth,Dashboard,Layout}

# Create MainLayout component
cat > src/components/Layout/MainLayout.js << 'EOL'
import React from 'react';
import { Link } from 'react-router-dom';

export default function MainLayout({ children }) {
  return (
    <div className="min-h-screen bg-gray-100">
      <nav className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex">
              <Link to="/dashboard" className="flex-shrink-0 flex items-center">
                IRSSH Panel
              </Link>
              <div className="hidden sm:ml-6 sm:flex sm:space-x-8">
                <Link to="/dashboard" className="px-3 py-2 text-sm font-medium">
                  Dashboard
                </Link>
                <Link to="/users" className="px-3 py-2 text-sm font-medium">
                  Users
                </Link>
                <Link to="/settings" className="px-3 py-2 text-sm font-medium">
                  Settings
                </Link>
              </div>
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
EOL

# Create Dashboard component
cat > src/components/Dashboard/Dashboard.js << 'EOL'
import React, { useState, useEffect } from 'react';
import axios from 'axios';

export default function Dashboard() {
  const [stats, setStats] = useState({
    usersCount: 0,
    activeConnections: 0,
    systemLoad: 0
  });

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const response = await axios.get('/api/stats');
        setStats(response.data);
      } catch (error) {
        console.error('Error fetching stats:', error);
      }
    };

    fetchStats();
  }, []);

  return (
    <div>
      <h1 className="text-3xl font-bold mb-8">Dashboard</h1>
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-3">
        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <dt className="text-sm font-medium text-gray-500 truncate">
              Total Users
            </dt>
            <dd className="mt-1 text-3xl font-semibold text-gray-900">
              {stats.usersCount}
            </dd>
          </div>
        </div>
        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <dt className="text-sm font-medium text-gray-500 truncate">
              Active Connections
            </dt>
            <dd className="mt-1 text-3xl font-semibold text-gray-900">
              {stats.activeConnections}
            </dd>
          </div>
        </div>
        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <dt className="text-sm font-medium text-gray-500 truncate">
              System Load
            </dt>
            <dd className="mt-1 text-3xl font-semibold text-gray-900">
              {stats.systemLoad}%
            </dd>
          </div>
        </div>
      </div>
    </div>
  );
}
EOL

# Update App.js
cat > src/App.js << 'EOL'
import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import MainLayout from './components/Layout/MainLayout';
import Dashboard from './components/Dashboard/Dashboard';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/dashboard" element={
          <MainLayout>
            <Dashboard />
          </MainLayout>
        } />
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Router>
  );
}

export default App;
EOL

# Create API endpoints
log "Setting up backend endpoints..."

# Create stats endpoint
cat > "$BACKEND_DIR/app/api/v1/endpoints/stats.py" << 'EOL'
from fastapi import APIRouter
import psutil

router = APIRouter()

@router.get("/")
async def get_stats():
    return {
        "usersCount": 0,  # Will be implemented with database
        "activeConnections": len(psutil.net_connections()),
        "systemLoad": psutil.cpu_percent()
    }
EOL

# Update main.py to include new endpoint
cat > "$BACKEND_DIR/app/main.py" << 'EOL'
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.endpoints import stats

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(stats.router, prefix="/api/stats", tags=["stats"])

@app.get("/api/health")
async def health_check():
    return {"status": "healthy"}
EOL

# Build frontend
log "Building frontend..."
npm run build

# Restart services
log "Restarting services..."
systemctl restart nginx
supervisorctl restart irssh-panel

echo
echo "Panel has been set up!"
echo "Access it at: http://77.239.124.50:8675"
echo
echo "Next steps:"
echo "1. Test the dashboard functionality"
echo "2. Add user authentication"
echo "3. Implement VPN protocol modules"
