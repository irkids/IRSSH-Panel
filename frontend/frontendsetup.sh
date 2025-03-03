#!/bin/bash

# Setup React Frontend for IRSSH Panel
# This script sets up a complete React-based dashboard for IRSSH Panel

# Colors for terminal output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Base directories
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="${PANEL_DIR}/frontend"
CONFIG_DIR="/etc/enhanced_ssh"
LOG_DIR="/var/log/irssh"

# Admin credentials from environment or config file
ADMIN_USER=${ADMIN_USER:-"admin"}
SERVER_IPv4=${SERVER_IPv4:-$(curl -s4 ifconfig.me || curl -s4 icanhazip.com)}
WEB_PORT=${WEB_PORT:-8080}

# Logging functions
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
fi

# Check if Node.js is installed
check_prerequisites() {
    log "Checking prerequisites..."
    
    if ! command -v node &> /dev/null; then
        log "Node.js not found, installing..."
        curl -fsSL https://deb.nodesource.com/setup_16.x | bash -
        apt-get install -y nodejs
    fi
    
    if ! command -v npm &> /dev/null; then
        error "npm is not installed even after installing Node.js. Please check your system."
    fi
    
    # Check Node.js version
    node_version=$(node --version | cut -d 'v' -f 2)
    node_major_version=$(echo $node_version | cut -d '.' -f 1)
    
    if [ "$node_major_version" -lt "16" ]; then
        warn "Node.js version $node_version detected. It's recommended to use Node.js 16 or newer."
    fi
    
    log "All prerequisites are met."
}

# Create and set up the frontend directory structure
setup_directory_structure() {
    log "Setting up directory structure..."
    
    # Remove existing directory if it exists
    if [ -d "$FRONTEND_DIR" ]; then
        log "Frontend directory already exists. Backing up and recreating..."
        backup_dir="${FRONTEND_DIR}_backup_$(date +%Y%m%d%H%M%S)"
        mv "$FRONTEND_DIR" "$backup_dir"
    fi
    
    mkdir -p "$FRONTEND_DIR"
    mkdir -p "$FRONTEND_DIR/src"
    mkdir -p "$FRONTEND_DIR/src/components"
    mkdir -p "$FRONTEND_DIR/src/pages"
    mkdir -p "$FRONTEND_DIR/src/layouts"
    mkdir -p "$FRONTEND_DIR/src/contexts"
    mkdir -p "$FRONTEND_DIR/src/hooks"
    mkdir -p "$FRONTEND_DIR/src/utils"
    mkdir -p "$FRONTEND_DIR/src/assets"
    mkdir -p "$FRONTEND_DIR/public"
    
    log "Directory structure created."
}

# Create configuration files for React app
create_config_files() {
    log "Creating configuration files..."
    
    # Create package.json
    cat > "$FRONTEND_DIR/package.json" << 'EOF'
{
  "name": "irssh-panel-frontend",
  "private": true,
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "@tanstack/react-query": "^4.29.15",
    "axios": "^1.4.0",
    "date-fns": "^2.30.0",
    "lucide-react": "^0.263.1",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-hot-toast": "^2.4.1",
    "react-router-dom": "^6.15.0",
    "recharts": "^2.7.2"
  },
  "devDependencies": {
    "@types/react": "^18.2.15",
    "@types/react-dom": "^18.2.7",
    "@vitejs/plugin-react": "^4.0.3",
    "autoprefixer": "^10.4.14",
    "postcss": "^8.4.27",
    "tailwindcss": "^3.3.3",
    "vite": "^4.4.9"
  }
}
EOF
    
    # Create vite.config.js
    cat > "$FRONTEND_DIR/vite.config.js" << 'EOF'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:3001',
        changeOrigin: true
      }
    }
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true
  }
})
EOF
    
    # Create tailwind.config.js
    cat > "$FRONTEND_DIR/tailwind.config.js" << 'EOF'
/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {},
  },
  plugins: [],
}
EOF
    
    # Create postcss.config.js
    cat > "$FRONTEND_DIR/postcss.config.js" << 'EOF'
export default {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
}
EOF
    
    # Create index.html
    cat > "$FRONTEND_DIR/index.html" << 'EOF'
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IRSSH Panel</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.jsx"></script>
  </body>
</html>
EOF
    
    log "Configuration files created."
}

# Create React components
create_react_components() {
    log "Creating React components..."
    
    # Create src/index.css for tailwind
    cat > "$FRONTEND_DIR/src/index.css" << 'EOF'
@tailwind base;
@tailwind components;
@tailwind utilities;

:root {
  --foreground-rgb: 0, 0, 0;
  --background-start-rgb: 214, 219, 220;
  --background-end-rgb: 255, 255, 255;
}

@media (prefers-color-scheme: dark) {
  :root {
    --foreground-rgb: 255, 255, 255;
    --background-start-rgb: 0, 0, 0;
    --background-end-rgb: 0, 0, 0;
  }
}

body {
  @apply bg-gray-100 dark:bg-gray-900;
}

.loading {
  @apply flex justify-center items-center h-screen;
}

.loading:after {
  content: " ";
  display: block;
  width: 48px;
  height: 48px;
  margin: 8px;
  border-radius: 50%;
  border: 6px solid #3b82f6;
  border-color: #3b82f6 transparent #3b82f6 transparent;
  animation: loading 1.2s linear infinite;
}

@keyframes loading {
  0% {
    transform: rotate(0deg);
  }
  100% {
    transform: rotate(360deg);
  }
}
EOF
    
    # Create main.jsx
    cat > "$FRONTEND_DIR/src/main.jsx" << 'EOF'
import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'
import axios from 'axios'

// Configure axios defaults
axios.defaults.baseURL = window.location.origin
axios.defaults.headers.common['Content-Type'] = 'application/json'

// Add response interceptor for error handling
axios.interceptors.response.use(
  response => response,
  error => {
    if (error.response && error.response.status === 401) {
      // Handle unauthorized access - redirect to login
      localStorage.removeItem('auth_token')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
EOF
    
    # Create App.jsx
    cat > "$FRONTEND_DIR/src/App.jsx" << 'EOF'
import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'react-hot-toast';

// Layouts
import DashboardLayout from './layouts/DashboardLayout';
import AuthLayout from './layouts/AuthLayout';

// Pages
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import UserManagement from './pages/UserManagement';
import ActiveConnections from './pages/ActiveConnections';
import ProtocolSettings from './pages/ProtocolSettings';
import SystemSettings from './pages/SystemSettings';
import Statistics from './pages/Statistics';
import UserProfile from './pages/UserProfile';
import NotFound from './pages/NotFound';

// Contexts
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { ThemeProvider } from './contexts/ThemeContext';

// Create React Query client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 30000,
    },
  },
});

// Protected route component
const ProtectedRoute = ({ children }) => {
  const { isAuthenticated, loading } = useAuth();
  
  if (loading) {
    return <div className="loading"></div>;
  }
  
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  
  return children;
};

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <AuthProvider>
          <Toaster position="top-right" />
          <Router>
            <Routes>
              {/* Auth routes */}
              <Route path="/" element={<AuthLayout />}>
                <Route index element={<Navigate to="/dashboard" replace />} />
                <Route path="login" element={<Login />} />
              </Route>
              
              {/* Dashboard routes */}
              <Route path="/" element={
                <ProtectedRoute>
                  <DashboardLayout />
                </ProtectedRoute>
              }>
                <Route path="dashboard" element={<Dashboard />} />
                <Route path="users" element={<UserManagement />} />
                <Route path="connections" element={<ActiveConnections />} />
                <Route path="protocols" element={<ProtocolSettings />} />
                <Route path="system" element={<SystemSettings />} />
                <Route path="statistics" element={<Statistics />} />
                <Route path="profile" element={<UserProfile />} />
              </Route>
              
              {/* 404 route */}
              <Route path="*" element={<NotFound />} />
            </Routes>
          </Router>
        </AuthProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
EOF

    # Create AuthContext
    cat > "$FRONTEND_DIR/src/contexts/AuthContext.jsx" << 'EOF'
import React, { createContext, useContext, useState, useEffect } from 'react';
import axios from 'axios';
import { toast } from 'react-hot-toast';

const AuthContext = createContext(null);

export const useAuth = () => useContext(AuthContext);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [token, setToken] = useState(localStorage.getItem('auth_token'));

  // Initialize auth state on load
  useEffect(() => {
    const initAuth = async () => {
      const storedToken = localStorage.getItem('auth_token');
      
      if (storedToken) {
        // Set default auth header
        axios.defaults.headers.common['Authorization'] = `Bearer ${storedToken}`;
        
        try {
          // Verify token validity by fetching user data
          const response = await axios.get('/api/users/me');
          
          if (response.status === 200) {
            setUser(response.data);
            setIsAuthenticated(true);
          } else {
            // Token is invalid or expired
            localStorage.removeItem('auth_token');
            delete axios.defaults.headers.common['Authorization'];
          }
        } catch (error) {
          console.error('Auth initialization error:', error);
          localStorage.removeItem('auth_token');
          delete axios.defaults.headers.common['Authorization'];
        }
      }
      
      setLoading(false);
    };

    initAuth();
  }, []);

  // Login function
  const login = async (username, password) => {
    try {
      const response = await axios.post('/api/auth/login', { username, password });
      
      if (response.data && response.data.token) {
        localStorage.setItem('auth_token', response.data.token);
        axios.defaults.headers.common['Authorization'] = `Bearer ${response.data.token}`;
        
        setToken(response.data.token);
        setUser(response.data.user);
        setIsAuthenticated(true);
        
        return { success: true };
      } else {
        return { success: false, message: 'Invalid response from server' };
      }
    } catch (error) {
      console.error('Login error:', error);
      return { 
        success: false, 
        message: error.response?.data?.error || 'Authentication failed'
      };
    }
  };

  // Logout function
  const logout = () => {
    localStorage.removeItem('auth_token');
    delete axios.defaults.headers.common['Authorization'];
    
    setToken(null);
    setUser(null);
    setIsAuthenticated(false);
    
    toast.success('Logged out successfully');
  };

  // Auth context value
  const value = {
    user,
    isAuthenticated,
    loading,
    token,
    login,
    logout
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
EOF

    # Create ThemeContext
    cat > "$FRONTEND_DIR/src/contexts/ThemeContext.jsx" << 'EOF'
import React, { createContext, useContext, useState, useEffect } from 'react';

const ThemeContext = createContext(null);

export const useTheme = () => useContext(ThemeContext);

export const ThemeProvider = ({ children }) => {
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'light');

  useEffect(() => {
    // Apply theme to document
    document.documentElement.setAttribute('data-theme', theme);
    
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    
    localStorage.setItem('theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prevTheme => prevTheme === 'light' ? 'dark' : 'light');
  };

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
};
EOF

    # Create layouts
    create_layouts
    
    # Create pages
    create_pages
    
    log "React components created."
}

# Create layouts
create_layouts() {
    log "Creating layout components..."
    
    # Create AuthLayout.jsx
    cat > "$FRONTEND_DIR/src/layouts/AuthLayout.jsx" << 'EOF'
import React from 'react';
import { Outlet, Navigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

const AuthLayout = () => {
  const { isAuthenticated, loading } = useAuth();
  
  if (loading) {
    return <div className="loading"></div>;
  }
  
  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }
  
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <Outlet />
      </div>
    </div>
  );
};

export default AuthLayout;
EOF

    # Create DashboardLayout.jsx
    cat > "$FRONTEND_DIR/src/layouts/DashboardLayout.jsx" << 'EOF'
import React, { useState } from 'react';
import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useTheme } from '../contexts/ThemeContext';

const DashboardLayout = () => {
  const { user, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const navigate = useNavigate();
  const [sidebarOpen, setSidebarOpen] = useState(true);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };
  
  const toggleSidebar = () => {
    setSidebarOpen(!sidebarOpen);
  };

  return (
    <div className="flex h-screen bg-gray-100 dark:bg-gray-900">
      {/* Sidebar */}
      <aside 
        className={`fixed inset-y-0 z-10 flex flex-col flex-shrink-0 w-64 bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 shadow-sm transition-all duration-300 ${
          sidebarOpen ? 'left-0' : '-left-64'
        }`}
      >
        {/* Logo */}
        <div className="flex items-center justify-between h-16 px-4 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center">
            <div className="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center text-white font-bold">
              IR
            </div>
            <span className="ml-2 text-lg font-semibold dark:text-white">IRSSH Panel</span>
          </div>
          <button 
            onClick={toggleSidebar}
            className="md:hidden p-1 rounded-md hover:bg-gray-100 dark:hover:bg-gray-700"
          >
            <svg className="w-6 h-6 text-gray-500 dark:text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        
        {/* User info */}
        <div className="flex flex-col px-4 py-4 border-b border-gray-200 dark:border-gray-700">
          <div className="text-xs text-gray-500 dark:text-gray-400 uppercase">
            {user?.role || 'User'}
          </div>
          <div className="text-sm font-medium text-gray-900 dark:text-white">
            {user?.username || 'Admin'}
          </div>
        </div>
        
        {/* Navigation */}
        <nav className="px-2 py-4 flex-1 overflow-y-auto">
          <ul className="space-y-1">
            <li>
              <NavLink
                to="/dashboard"
                className={({ isActive }) =>
                  `flex items-center px-4 py-2 text-sm font-medium rounded-md ${
                    isActive
                      ? 'bg-blue-50 text-blue-700 dark:bg-blue-900 dark:text-blue-200'
                      : 'text-gray-700 hover:bg-gray-100 dark:text-gray-200 dark:hover:bg-gray-700'
                  }`
                }
              >
                <svg className="mr-3 flex-shrink-0 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
                </svg>
                Dashboard
              </NavLink>
            </li>
            <li>
              <NavLink
                to="/users"
                className={({ isActive }) =>
                  `flex items-center px-4 py-2 text-sm font-medium rounded-md ${
                    isActive
                      ? 'bg-blue-50 text-blue-700 dark:bg-blue-900 dark:text-blue-200'
                      : 'text-gray-700 hover:bg-gray-100 dark:text-gray-200 dark:hover:bg-gray-700'
                  }`
                }
              >
                <svg className="mr-3 flex-shrink-0 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
                </svg>
                User Management
              </NavLink>
            </li>
            <li>
              <NavLink
                to="/connections"
                className={({ isActive }) =>
                  `flex items-center px-4 py-2 text-sm font-medium rounded-md ${
                    isActive
                      ? 'bg-blue-50 text-blue-700 dark:bg-blue-900 dark:text-blue-200'
                      : 'text-gray-700 hover:bg-gray-100 dark:text-gray-200 dark:hover:bg-gray-700'
                  }`
                }
              >
                <svg className="mr-3 flex-shrink-0 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
                Active Connections
              </NavLink>
            </li>
            <li>
              <NavLink
                to="/protocols"
                className={({ isActive }) =>
                  `flex items-center px-4 py-2 text-sm font-medium rounded-md ${
                    isActive
                      ? 'bg-blue-50 text-blue-700 dark:bg-blue-900 dark:text-blue-200'
                      : 'text-gray-700 hover:bg-gray-100 dark:text-gray-200 dark:hover:bg-gray-700'
                  }`
                }
              >
                <svg className="mr-3 flex-shrink-0 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
                </svg>
                Protocol Settings
              </NavLink>
            </li>
            <li>
              <NavLink
                to="/statistics"
                className={({ isActive }) =>
                  `flex items-center px-4 py-2 text-sm font-medium rounded-md ${
                    isActive
                      ? 'bg-blue-50 text-blue-700 dark:bg-blue-900 dark:text-blue-200'
                      : 'text-gray-700 hover:bg-gray-100 dark:text-gray-200 dark:hover:bg-gray-700'
                  }`
                }
              >
                <svg className="mr-3 flex-shrink-0 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
                Statistics
              </NavLink>
            </li>
            <li>
              <NavLink
                to="/system"
                className={({ isActive }) =>
                  `flex items-center px-4 py-2 text-sm font-medium rounded-md ${
                    isActive
                      ? 'bg-blue-50 text-blue-700 dark:bg-blue-900 dark:text-blue-200'
                      : 'text-gray-700 hover:bg-gray-100 dark:text-gray-200 dark:hover:bg-gray-700'
                  }`
                }
              >
                <svg className="mr-3 flex-shrink-0 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                </svg>
                System Settings
              </NavLink>
            </li>
          </ul>
        </nav>
        
        {/* Footer */}
        <div className="px-4 py-2 border-t border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between">
            <button 
              onClick={toggleTheme}
              className="p-2 rounded-md hover:bg-gray-100 dark:hover:bg-gray-700"
            >
              {theme === 'dark' ? (
                <svg className="h-5 w-5 text-gray-500 dark:text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
                </svg>
              ) : (
                <svg className="h-5 w-5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
                </svg>
              )}
            </button>
            
            <NavLink
              to="/profile"
              className={({ isActive }) =>
                `p-2 rounded-md ${
                  isActive
                    ? 'bg-blue-50 text-blue-700 dark:bg-blue-900 dark:text-blue-200'
                    : 'text-gray-500 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-gray-700'
                }`
              }
            >
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
              </svg>
            </NavLink>
            
            <button 
              onClick={handleLogout}
              className="p-2 rounded-md text-gray-500 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-gray-700"
            >
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
              </svg>
            </button>
          </div>
        </div>
      </aside>
      
      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <div 
          className="fixed inset-0 z-0 bg-gray-800 bg-opacity-50 lg:hidden"
          onClick={toggleSidebar}
        />
      )}
      
      {/* Main content */}
      <div className={`flex flex-col flex-1 ${sidebarOpen ? 'ml-64' : 'ml-0'} transition-all duration-300`}>
        {/* Header */}
        <header className="z-10 py-4 bg-white dark:bg-gray-800 shadow-sm">
          <div className="px-4 mx-auto sm:px-6 lg:px-8">
            <div className="flex items-center justify-between">
              <button
                onClick={toggleSidebar}
                className="p-2 rounded-md md:hidden text-gray-500 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-gray-700"
              >
                <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                </svg>
              </button>
              
              <div className="text-xl font-semibold text-gray-800 dark:text-white md:hidden">
                IRSSH Panel
              </div>
            </div>
          </div>
        </header>
        
        {/* Page content */}
        <main className="flex-1 p-4 md:p-6 bg-gray-100 dark:bg-gray-900">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default DashboardLayout;
EOF
}

# Create pages
create_pages() {
    log "Creating page components..."
    
    # Create Login.jsx
    cat > "$FRONTEND_DIR/src/pages/Login.jsx" << 'EOF'
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-hot-toast';
import { useAuth } from '../contexts/AuthContext';

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!username || !password) {
      toast.error('Please enter both username and password');
      return;
    }
    
    setIsLoading(true);
    
    try {
      const result = await login(username, password);
      
      if (result.success) {
        toast.success('Login successful');
        navigate('/dashboard');
      } else {
        toast.error(result.message || 'Invalid username or password');
      }
    } catch (error) {
      console.error(error);
      toast.error('An error occurred during login');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="bg-white dark:bg-gray-800 shadow-md rounded-lg p-8">
      <div className="text-center mb-8">
        <h2 className="text-3xl font-bold text-gray-900 dark:text-white">IRSSH Panel</h2>
        <p className="mt-2 text-gray-600 dark:text-gray-400">
          Sign in to your account
        </p>
      </div>
      
      <form className="space-y-6" onSubmit={handleSubmit}>
        <div>
          <label htmlFor="username" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            Username
          </label>
          <input
            id="username"
            name="username"
            type="text"
            autoComplete="username"
            required
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
          />
        </div>

        <div>
          <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            Password
          </label>
          <input
            id="password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
          />
        </div>

        <div>
          <button
            type="submit"
            disabled={isLoading}
            className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isLoading ? 'Signing in...' : 'Sign in'}
          </button>
        </div>
      </form>
    </div>
  );
};

export default Login;
EOF

    # Create Dashboard.jsx (basic version)
    cat > "$FRONTEND_DIR/src/pages/Dashboard.jsx" << 'EOF'
import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { toast } from 'react-hot-toast';

const Dashboard = () => {
  const [systemStats, setSystemStats] = useState({
    cpuUsage: 0,
    memoryUsage: 0,
    diskUsage: 0,
    uptime: '0h',
    load: [0, 0, 0]
  });
  
  const [userStats, setUserStats] = useState({
    totalUsers: 0,
    activeUsers: 0,
    expiredUsers: 0
  });
  
  const [connectionStats, setConnectionStats] = useState({
    activeConnections: 0,
    protocols: {}
  });
  
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        
        // Fetch system stats
        const systemResponse = await axios.get('/api/system/info');
        if (systemResponse.data && systemResponse.data.system) {
          setSystemStats({
            cpuUsage: systemResponse.data.system.cpu_usage || 0,
            memoryUsage: systemResponse.data.system.memory.usage || 0,
            diskUsage: parseInt(systemResponse.data.system.disk_usage) || 0,
            uptime: systemResponse.data.system.uptime || '0h',
            load: systemResponse.data.system.load || [0, 0, 0]
          });
        }
        
        // Fetch user stats
        const userResponse = await axios.get('/api/users/stats');
        if (userResponse.data) {
          setUserStats({
            totalUsers: userResponse.data.total || 0,
            activeUsers: userResponse.data.active || 0,
            expiredUsers: userResponse.data.expired || 0
          });
        }
        
        // Fetch connection stats
        const connectionResponse = await axios.get('/api/connections/stats');
        if (connectionResponse.data) {
          setConnectionStats({
            activeConnections: connectionResponse.data.active || 0,
            protocols: connectionResponse.data.protocols || {}
          });
        }
      } catch (error) {
        console.error('Error fetching dashboard data:', error);
        toast.error('Failed to load dashboard data');
      } finally {
        setLoading(false);
      }
    };
    
    fetchData();
    
    // Set up auto-refresh interval
    const intervalId = setInterval(fetchData, 30000); // Refresh every 30 seconds
    
    return () => clearInterval(intervalId);
  }, []);
  
  // Format protocol data for display
  const protocolData = Object.entries(connectionStats.protocols).map(([name, count]) => ({
    name,
    count
  }));
  
  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Dashboard</h1>
        <p className="text-gray-500 dark:text-gray-400">Overview of your IRSSH Panel</p>
      </div>
      
      {loading ? (
        <div className="flex justify-center items-center h-64">
          <div className="loading"></div>
        </div>
      ) : (
        <>
          {/* System stats */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
              <div className="flex items-center">
                <div className="p-3 rounded-full bg-blue-100 dark:bg-blue-900 text-blue-500 dark:text-blue-300 mr-4">
                  <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
                  </svg>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-500 dark:text-gray-400">CPU Usage</p>
                  <p className="text-2xl font-semibold text-gray-900 dark:text-white">{systemStats.cpuUsage}%</p>
                </div>
              </div>
              <div className="mt-4 h-2 bg-gray-200 dark:bg-gray-700 rounded-full">
                <div
                  className="h-2 bg-blue-500 rounded-full"
                  style={{ width: `${systemStats.cpuUsage}%` }}
                ></div>
              </div>
            </div>
            
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
              <div className="flex items-center">
                <div className="p-3 rounded-full bg-green-100 dark:bg-green-900 text-green-500 dark:text-green-300 mr-4">
                  <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
                  </svg>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Memory Usage</p>
                  <p className="text-2xl font-semibold text-gray-900 dark:text-white">{systemStats.memoryUsage}%</p>
                </div>
              </div>
              <div className="mt-4 h-2 bg-gray-200 dark:bg-gray-700 rounded-full">
                <div
                  className="h-2 bg-green-500 rounded-full"
                  style={{ width: `${systemStats.memoryUsage}%` }}
                ></div>
              </div>
            </div>
            
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
              <div className="flex items-center">
                <div className="p-3 rounded-full bg-purple-100 dark:bg-purple-900 text-purple-500 dark:text-purple-300 mr-4">
                  <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
                  </svg>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Disk Usage</p>
                  <p className="text-2xl font-semibold text-gray-900 dark:text-white">{systemStats.diskUsage}%</p>
                </div>
              </div>
              <div className="mt-4 h-2 bg-gray-200 dark:bg-gray-700 rounded-full">
                <div
                  className="h-2 bg-purple-500 rounded-full"
                  style={{ width: `${systemStats.diskUsage}%` }}
                ></div>
              </div>
            </div>
          </div>
          
          {/* Usage stats */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
              <div className="flex items-center">
                <div className="p-3 rounded-full bg-indigo-100 dark:bg-indigo-900 text-indigo-500 dark:text-indigo-300 mr-4">
                  <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
                  </svg>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Total Users</p>
                  <p className="text-2xl font-semibold text-gray-900 dark:text-white">{userStats.totalUsers}</p>
                </div>
              </div>
              <div className="mt-4 text-sm text-gray-500 dark:text-gray-400">
                <span className="text-green-500 dark:text-green-400">{userStats.activeUsers} active</span> • 
                <span className="text-red-500 dark:text-red-400 ml-2">{userStats.expiredUsers} expired</span>
              </div>
            </div>
            
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
              <div className="flex items-center">
                <div className="p-3 rounded-full bg-amber-100 dark:bg-amber-900 text-amber-500 dark:text-amber-300 mr-4">
                  <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                  </svg>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Active Connections</p>
                  <p className="text-2xl font-semibold text-gray-900 dark:text-white">{connectionStats.activeConnections}</p>
                </div>
              </div>
              <div className="mt-4 text-sm">
                {protocolData.length > 0 ? (
                  <div className="space-y-1">
                    {protocolData.slice(0, 3).map(protocol => (
                      <div key={protocol.name} className="flex justify-between">
                        <span className="text-gray-500 dark:text-gray-400">{protocol.name}</span>
                        <span className="text-gray-900 dark:text-white font-medium">{protocol.count}</span>
                      </div>
                    ))}
                    {protocolData.length > 3 && (
                      <div className="text-blue-500 dark:text-blue-400 text-xs mt-1">
                        +{protocolData.length - 3} more protocols
                      </div>
                    )}
                  </div>
                ) : (
                  <span className="text-gray-500 dark:text-gray-400">No active connections</span>
                )}
              </div>
            </div>
            
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
              <div className="flex items-center">
                <div className="p-3 rounded-full bg-rose-100 dark:bg-rose-900 text-rose-500 dark:text-rose-300 mr-4">
                  <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
                  </svg>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Server Uptime</p>
                  <p className="text-2xl font-semibold text-gray-900 dark:text-white">{systemStats.uptime}</p>
                </div>
              </div>
              <div className="mt-4 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-500 dark:text-gray-400">Load Average</span>
                  <span className="text-gray-900 dark:text-white font-medium">
                    {systemStats.load.join(' / ')}
                  </span>
                </div>
              </div>
            </div>
          </div>
          
          {/* Protocol distribution */}
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Protocol Distribution</h3>
            
            {protocolData.length > 0 ? (
              <div className="space-y-4">
                {protocolData.map(protocol => (
                  <div key={protocol.name} className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-500 dark:text-gray-400">{protocol.name}</span>
                      <span className="text-gray-900 dark:text-white font-medium">{protocol.count}</span>
                    </div>
                    <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full">
                      <div
                        className="h-2 bg-blue-500 rounded-full"
                        style={{ 
                          width: `${(protocol.count / connectionStats.activeConnections) * 100}%` 
                        }}
                      ></div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-gray-500 dark:text-gray-400 text-center py-8">
                No active connections
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
};

export default Dashboard;
EOF

    # Create placeholder pages
    for page in UserManagement ActiveConnections ProtocolSettings SystemSettings Statistics UserProfile NotFound; do
        cat > "$FRONTEND_DIR/src/pages/${page}.jsx" << EOF
import React from 'react';

const ${page} = () => {
  return (
    <div>
      <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-6">${page}</h1>
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-8">
        <p className="text-gray-500 dark:text-gray-400">This page is under construction.</p>
      </div>
    </div>
  );
};

export default ${page};
EOF
    done
}

# Install dependencies and build the React frontend
build_frontend() {
    log "Installing dependencies and building frontend..."
    
    cd "$FRONTEND_DIR" || error "Failed to access frontend directory"
    
    # Install dependencies
    npm install || error "Failed to install dependencies"
    
    # Create a build script
    cat > "$FRONTEND_DIR/build.sh" << 'EOF'
#!/bin/bash
echo "Building IRSSH Panel frontend..."
npm run build
EOF
    chmod +x "$FRONTEND_DIR/build.sh"
    
    # Build the frontend
    ./build.sh || error "Failed to build frontend"
    
    log "Frontend built successfully."
}

# Configure Nginx to serve the React frontend
configure_nginx() {
    log "Configuring nginx..."
    
    # Create nginx configuration
    cat > /etc/nginx/sites-available/irssh-panel << EOF
server {
    listen ${WEB_PORT};
    listen [::]:${WEB_PORT};
    
    server_name _;
    
    root ${FRONTEND_DIR}/dist;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ /index.html;
    }
    
    location /api {
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF
    
    # Enable the site
    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null
    
    # Test nginx configuration
    nginx -t || error "Nginx configuration test failed"
    
    # Restart nginx
    systemctl restart nginx
    
    log "Nginx configured successfully."
}

# Run the setup
check_prerequisites
setup_directory_structure
create_config_files
create_react_components
build_frontend
configure_nginx

log "React frontend setup completed successfully!"
log "You can access the web panel at: http://${SERVER_IPv4}:${WEB_PORT}"
