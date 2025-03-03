#!/bin/bash

# IRSSH Panel Modular Installer
# Version: 4.2.0

# Define colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Base directories
TEMP_DIR="/tmp/irssh-installer"
FINAL_DIR="/opt/irssh-panel"
MODULES_DIR="${FINAL_DIR}/modules"
SCRIPTS_DIR="${FINAL_DIR}/scripts"
CONFIG_DIR="/etc/enhanced_ssh"
LOG_DIR="/var/log/irssh"
BACKUP_DIR="/opt/irssh-backups"

# Repository info
REPO_URL="https://github.com/irkids/IRSSH-Panel"
REPO_BRANCH="main"
RAW_REPO_URL="https://raw.githubusercontent.com/irkids/IRSSH-Panel/${REPO_BRANCH}"

# Module files
CORE_UTILS="core-utils.sh"
INSTALL_CONFIG="install-config.sh"
DEPENDENCY_INSTALLER="dependency-installer.sh"
DATABASE_SETUP="database-setup.sh"
WEB_SERVER_SETUP="web-server-setup.sh"
USER_MANAGEMENT="user-management.sh"
MONITORING_SETUP="monitoring-setup.sh"
GEOLOCATION_SETUP="geolocation-setup.sh"
ADMIN_CLI="admin-cli.sh"
WEB_UI_SETUP="web-ui-setup.sh"

# Protocol modules
SSH_MODULE="protocol-ssh.sh"
WIREGUARD_MODULE="protocol-wireguard.sh"
L2TP_MODULE="protocol-l2tp.sh"
IKEV2_MODULE="protocol-ikev2.sh"
CISCO_MODULE="protocol-cisco.sh"
SINGBOX_MODULE="protocol-singbox.sh"
SSLVPN_MODULE="protocol-sslvpn.sh"
NORDWHISPER_MODULE="protocol-nordwhisper.sh"

# Protocol monitor modules
SSH_MONITOR="monitor-ssh.py"
WIREGUARD_MONITOR="monitor-wireguard.py"
L2TP_MONITOR="monitor-l2tp.py"
IKEV2_MONITOR="monitor-ikev2.py"
CISCO_MONITOR="monitor-cisco.py"
SINGBOX_MONITOR="monitor-singbox.py"
SSLVPN_MONITOR="monitor-sslvpn.py"
NORDWHISPER_MONITOR="monitor-nordwhisper.py"

# Installation configuration
USE_LOCAL_FILES=false
LOCAL_FILES_DIR=""
CREATE_MODULES=true

# Configuration variables
ADMIN_USER=""
ADMIN_PASS=""
DB_NAME="irssh_panel"
DB_USER=""
DB_USER_PASSWORD=""
SERVER_IPv4=""
SERVER_IPv6=""
WEB_PORT=8080
ENABLE_MONITORING=false
INSTALL_USER_MANAGEMENT=true

# Protocol installation flags
INSTALL_SSH=true
INSTALL_WIREGUARD=true
INSTALL_L2TP=true
INSTALL_IKEV2=true
INSTALL_CISCO=true
INSTALL_SINGBOX=true
INSTALL_SSLVPN=true
INSTALL_NORDWHISPER=true

# Protocol ports
SSH_PORT=22
WIREGUARD_PORT=51820
L2TP_PORT=1701
IKEV2_PORT=500
CISCO_PORT=443
SINGBOX_PORT=1080
SSLVPN_PORT=1194
NORDWHISPER_PORT=1195

# Logging functions
log() {
    local level=$1
    local message=$2
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    echo -e "${!level}[$timestamp] [$level] $message${NC}"
    
    # Check if LOG_DIR exists, if not create it
    if [ ! -d "$LOG_DIR" ]; then
        mkdir -p "$LOG_DIR"
    fi
    
    echo "[$timestamp] [$level] $message" >> "$LOG_DIR/installation.log"
}

info() {
    log "GREEN" "$1"
}

warn() {
    log "YELLOW" "$1"
}

error() {
    log "RED" "$1"
    if [[ "${2:-}" != "no-exit" ]]; then
        cleanup
        exit 1
    fi
}

debug() {
    log "BLUE" "$1"
}

# Function to clean up temporary files
cleanup() {
    info "Cleaning up temporary files..."
    if [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
}

# Function to check if script is run as root
check_root() {
    if [ "$(id -u)" != "0" ]; then
        error "This script must be run as root"
    fi
}

# Function to create necessary directories
create_dirs() {
    info "Creating necessary directories..."
    
    mkdir -p "$TEMP_DIR"
    mkdir -p "$FINAL_DIR"
    mkdir -p "$MODULES_DIR"
    mkdir -p "$SCRIPTS_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$BACKUP_DIR"
    
    info "Directories created successfully"
}

# Function to download a file from repository
download_file() {
    local file_path=$1
    local output_file=$2
    
    if [ "$USE_LOCAL_FILES" = true ] && [ -f "${LOCAL_FILES_DIR}/${file_path}" ]; then
        # Copy from local directory
        cp "${LOCAL_FILES_DIR}/${file_path}" "$output_file"
        return $?
    else
        # Download from repository
        curl -s -o "$output_file" "${RAW_REPO_URL}/${file_path}"
        return $?
    fi
}

# Function to extract module from main script
extract_module() {
    local start_pattern=$1
    local end_pattern=$2
    local output_file=$3
    local input_file=$4
    
    if [ -z "$input_file" ]; then
        input_file="${TEMP_DIR}/IRSSHCompleteInstall.sh"
    fi
    
    if [ ! -f "$input_file" ]; then
        error "Input file not found: $input_file"
        return 1
    fi
    
    # Add shebang and generated warning
    echo '#!/bin/bash' > "$output_file"
    echo '' >> "$output_file"
    echo '# This file was automatically generated from the main installer script' >> "$output_file"
    echo '# Any changes made to this file may be overwritten' >> "$output_file"
    echo '' >> "$output_file"
    
    # Extract section from the main script
    awk "/$start_pattern/{flag=1;next} /$end_pattern/{flag=0} flag" "$input_file" >> "$output_file"
    
    # Make the file executable
    chmod +x "$output_file"
    
    # Check if extraction was successful
    if [ ! -s "$output_file" ]; then
        warn "Failed to extract module: $output_file may be empty"
        return 1
    fi
    
    return 0
}

# Create monitoring script file
create_monitor_script() {
    local script_name=$1
    local start_pattern=$2
    local end_pattern=$3
    local output_file="${SCRIPTS_DIR}/monitoring/${script_name}"
    
    mkdir -p "${SCRIPTS_DIR}/monitoring"
    
    if [ "$USE_LOCAL_FILES" = true ] && [ -f "${LOCAL_FILES_DIR}/monitoring/${script_name}" ]; then
        # Copy from local directory
        cp "${LOCAL_FILES_DIR}/monitoring/${script_name}" "$output_file"
    else
        # Extract from main script
        extract_module "$start_pattern" "$end_pattern" "$output_file" "${TEMP_DIR}/IRSSHCompleteInstall.sh"
    fi
    
    # Set proper permissions
    chmod +x "$output_file"
}

# Function to download main installer script
download_installer() {
    info "Downloading main installer script..."
    
    if [ "$USE_LOCAL_FILES" = true ] && [ -f "${LOCAL_FILES_DIR}/IRSSHCompleteInstall.sh" ]; then
        # Copy from local directory
        cp "${LOCAL_FILES_DIR}/IRSSHCompleteInstall.sh" "${TEMP_DIR}/IRSSHCompleteInstall.sh"
    else
        # Download from repository
        curl -s -o "${TEMP_DIR}/IRSSHCompleteInstall.sh" "${RAW_REPO_URL}/IRSSHCompleteInstall.sh"
    fi
    
    if [ $? -ne 0 ]; then
        error "Failed to download main installer script"
    fi
    
    chmod +x "${TEMP_DIR}/IRSSHCompleteInstall.sh"
    info "Main installer script downloaded successfully"
}

# Function to create module files from main script
create_modules() {
    if [ "$CREATE_MODULES" != true ]; then
        info "Skipping module creation"
        return 0
    fi
    
    info "Creating module files..."
    
    # Create core utilities module
    info "Creating core utilities module..."
    extract_module "^# Logging functions" "^# Function to get server IP" "${MODULES_DIR}/${CORE_UTILS}"
    
    # Create installation configuration module
    info "Creating installation configuration module..."
    extract_module "^# Function to get server IP" "^# Function to get configuration" "${MODULES_DIR}/${INSTALL_CONFIG}"
    
    # Create dependency installer module
    info "Creating dependency installer module..."
    extract_module "^# Function to setup dependencies" "^# Function to setup database" "${MODULES_DIR}/${DEPENDENCY_INSTALLER}"
    
    # Create database setup module
    info "Creating database setup module..."
    extract_module "^# Function to setup database" "^# Function to setup web server" "${MODULES_DIR}/${DATABASE_SETUP}"
    
    # Create web server setup module
    info "Creating web server setup module..."
    extract_module "^# Function to setup web server" "^# Function to install SSH" "${MODULES_DIR}/${WEB_SERVER_SETUP}"
    
    # Create SSH protocol module
    info "Creating SSH protocol module..."
    extract_module "^# Function to install SSH" "^# Function to install L2TP" "${MODULES_DIR}/${SSH_MODULE}"
    
    # Create L2TP protocol module
    info "Creating L2TP protocol module..."
    extract_module "^# Function to install L2TP" "^# Function to install IKEv2" "${MODULES_DIR}/${L2TP_MODULE}"
    
    # Create IKEv2 protocol module
    info "Creating IKEv2 protocol module..."
    extract_module "^# Function to install IKEv2" "^# Function to install Cisco" "${MODULES_DIR}/${IKEV2_MODULE}"
    
    # Create Cisco AnyConnect protocol module
    info "Creating Cisco AnyConnect protocol module..."
    extract_module "^# Function to install Cisco" "^# Function to install WireGuard" "${MODULES_DIR}/${CISCO_MODULE}"
    
    # Create WireGuard protocol module
    info "Creating WireGuard protocol module..."
    extract_module "^# Function to install WireGuard" "^# Function to install SingBox" "${MODULES_DIR}/${WIREGUARD_MODULE}"
    
    # Create SingBox protocol module
    info "Creating SingBox protocol module..."
    extract_module "^# Function to install SingBox" "^# Function to setup monitoring" "${MODULES_DIR}/${SINGBOX_MODULE}"
    
    # Create monitoring setup module
    info "Creating monitoring setup module..."
    extract_module "^# Function to setup monitoring" "^# Function to create protocol monitoring scripts" "${MODULES_DIR}/${MONITORING_SETUP}"
    
    # Create user management module
    info "Creating user management module..."
    extract_module "^# Function to create user management service" "^# Function to create admin CLI tool" "${MODULES_DIR}/${USER_MANAGEMENT}"
    
    # Create admin CLI tool module
    info "Creating admin CLI tool module..."
    extract_module "^# Function to create admin CLI tool" "^# Install advanced user management module" "${MODULES_DIR}/${ADMIN_CLI}"
    
    # Create geolocation module
    info "Creating geolocation module..."
    extract_module "^# Function to setup geolocation" "^# Function to create user management service" "${MODULES_DIR}/${GEOLOCATION_SETUP}"
    
    # Create web UI setup module
    info "Creating web UI setup module..."
    cat > "${MODULES_DIR}/${WEB_UI_SETUP}" << 'EOF'
#!/bin/bash

# Web UI Setup Module for IRSSH Panel
# This module sets up the advanced web user interface

setup_web_ui() {
    info "Setting up advanced web user interface..."
    
    # Create frontend directory if it doesn't exist
    mkdir -p "$FINAL_DIR/frontend/src"
    
    # Create UI component directories
    mkdir -p "$FINAL_DIR/frontend/src/components"
    mkdir -p "$FINAL_DIR/frontend/src/pages"
    mkdir -p "$FINAL_DIR/frontend/src/layouts"
    mkdir -p "$FINAL_DIR/frontend/src/hooks"
    mkdir -p "$FINAL_DIR/frontend/src/utils"
    mkdir -p "$FINAL_DIR/frontend/src/assets"
    mkdir -p "$FINAL_DIR/frontend/src/contexts"
    
    # Create main App component
    cat > "$FINAL_DIR/frontend/src/App.jsx" << 'APPEOF'
import React, { useState, useEffect } from 'react';
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
import Geolocation from './pages/Geolocation';

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
    return <div className="loading">Loading...</div>;
  }
  
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  
  return children;
};

// Main App component
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
                <Route path="geolocation" element={<Geolocation />} />
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
APPEOF

    # Create AuthContext
    cat > "$FINAL_DIR/frontend/src/contexts/AuthContext.jsx" << 'AUTHEOF'
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
AUTHEOF

    # Create ThemeContext
    cat > "$FINAL_DIR/frontend/src/contexts/ThemeContext.jsx" << 'THEMEEOF'
import React, { createContext, useContext, useState, useEffect } from 'react';

const ThemeContext = createContext(null);

export const useTheme = () => useContext(ThemeContext);

export const ThemeProvider = ({ children }) => {
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'light');

  useEffect(() => {
    // Apply theme to document
    document.documentElement.setAttribute('data-theme', theme);
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
THEMEEOF

    # Create DashboardLayout component
    cat > "$FINAL_DIR/frontend/src/layouts/DashboardLayout.jsx" << 'DASHEOF'
import React, { useState } from 'react';
import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useTheme } from '../contexts/ThemeContext';
import { Moon, Sun, LogOut, Menu, X, Home, Users, Activity, 
         Settings, Server, BarChart2, User, Map } from 'lucide-react';

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
            <X size={18} className="text-gray-500 dark:text-gray-400" />
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
                <Home size={18} className="mr-3" />
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
                <Users size={18} className="mr-3" />
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
                <Activity size={18} className="mr-3" />
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
                <Server size={18} className="mr-3" />
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
                <BarChart2 size={18} className="mr-3" />
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
                <Settings size={18} className="mr-3" />
                System Settings
              </NavLink>
            </li>
            <li>
              <NavLink
                to="/geolocation"
                className={({ isActive }) =>
                  `flex items-center px-4 py-2 text-sm font-medium rounded-md ${
                    isActive
                      ? 'bg-blue-50 text-blue-700 dark:bg-blue-900 dark:text-blue-200'
                      : 'text-gray-700 hover:bg-gray-100 dark:text-gray-200 dark:hover:bg-gray-700'
                  }`
                }
              >
                <Map size={18} className="mr-3" />
                Geolocation
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
                <Sun size={18} className="text-gray-500 dark:text-gray-400" />
              ) : (
                <Moon size={18} className="text-gray-500" />
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
              <User size={18} />
            </NavLink>
            
            <button 
              onClick={handleLogout}
              className="p-2 rounded-md text-gray-500 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-gray-700"
            >
              <LogOut size={18} />
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
                <Menu size={18} />
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
DASHEOF

    # Create AuthLayout component
    cat > "$FINAL_DIR/frontend/src/layouts/AuthLayout.jsx" << 'AUTHLEOF'
import React from 'react';
import { Outlet, Navigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

const AuthLayout = () => {
  const { isAuthenticated, loading } = useAuth();
  
  if (loading) {
    return <div className="loading">Loading...</div>;
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
AUTHLEOF

    # Create Login page
    cat > "$FINAL_DIR/frontend/src/pages/Login.jsx" << 'LOGINEOF'
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
LOGINEOF

    # Create Dashboard page
    cat > "$FINAL_DIR/frontend/src/pages/Dashboard.jsx" << 'DASHPEOF'
import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { toast } from 'react-hot-toast';
import { Server, Users, Activity, HardDrive, Database, Cpu } from 'lucide-react';

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
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
        </div>
      ) : (
        <>
          {/* System stats */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
              <div className="flex items-center">
                <div className="p-3 rounded-full bg-blue-100 dark:bg-blue-900 text-blue-500 dark:text-blue-300 mr-4">
                  <Cpu size={24} />
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
                  <Database size={24} />
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
                  <HardDrive size={24} />
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
                  <Users size={24} />
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
                  <Activity size={24} />
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
                  <Server size={24} />
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
DASHPEOF

    # Create UserManagement page (basic version)
    cat > "$FINAL_DIR/frontend/src/pages/UserManagement.jsx" << 'USERMGMTEOF'
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { toast } from 'react-hot-toast';
import { 
  Edit, Trash2, UserPlus, Check, X, Clock, Search,
  ChevronLeft, ChevronRight, Filter, RefreshCw 
} from 'lucide-react';

const UserManagement = () => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(10);
  const [filter, setFilter] = useState('all');
  
  // Form state for new/edited user
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    mobile: '',
    referred_by: '',
    expiry_days: 30,
    max_connections: 1,
    data_limit_gb: 0,
    status: 'active',
    notes: ''
  });
  
  // Fetch users data
  const fetchUsers = async () => {
    try {
      setLoading(true);
      const response = await axios.get('/api/users');
      setUsers(response.data.users || []);
    } catch (error) {
      console.error('Error fetching users:', error);
      toast.error('Failed to load users data');
    } finally {
      setLoading(false);
    }
  };
  
  useEffect(() => {
    fetchUsers();
  }, []);
  
  // Filter users
  const filteredUsers = users.filter(user => {
    const matchesSearch = user.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (user.email && user.email.toLowerCase().includes(searchQuery.toLowerCase()));
    
    if (filter === 'all') return matchesSearch;
    if (filter === 'active') return matchesSearch && user.status === 'active';
    if (filter === 'deactive') return matchesSearch && user.status === 'deactive';
    if (filter === 'expired') return matchesSearch && user.expiry?.remaining?.expired;
    
    return matchesSearch;
  });
  
  // Pagination
  const indexOfLastUser = currentPage * itemsPerPage;
  const indexOfFirstUser = indexOfLastUser - itemsPerPage;
  const currentUsers = filteredUsers.slice(indexOfFirstUser, indexOfLastUser);
  const totalPages = Math.ceil(filteredUsers.length / itemsPerPage);
  
  // Handle page change
  const handlePageChange = (pageNumber) => {
    if (pageNumber > 0 && pageNumber <= totalPages) {
      setCurrentPage(pageNumber);
    }
  };
  
  // Handle form input changes
  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };
  
  // Handle user add/edit form submission
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    try {
      if (showAddModal) {
        // Creating new user
        const response = await axios.post('/api/users', formData);
        if (response.data.success) {
          toast.success(`User ${formData.username} created successfully`);
          fetchUsers();
          setShowAddModal(false);
        }
      } else if (showEditModal && selectedUser) {
        // Editing existing user
        const response = await axios.put(`/api/users/${selectedUser.username}`, formData);
        if (response.data.success) {
          toast.success(`User ${selectedUser.username} updated successfully`);
          fetchUsers();
          setShowEditModal(false);
        }
      }
    } catch (error) {
      console.error('Error saving user:', error);
      toast.error(error.response?.data?.error || 'Failed to save user');
    }
  };
  
  // Open edit modal for user
  const handleEditUser = (user) => {
    setSelectedUser(user);
    setFormData({
      username: user.username,
      email: user.email || '',
      mobile: user.mobile || '',
      referred_by: user.referred_by || '',
      expiry_days: 30, // Will extend by this many days
      max_connections: user.max_connections || 1,
      data_limit_gb: user.data_limit?.bytes ? (user.data_limit.bytes / (1024 * 1024 * 1024)) : 0,
      status: user.status || 'active',
      notes: user.notes || ''
    });
    setShowEditModal(true);
  };
  
  // Handle user deletion
  const handleDeleteUser = async (username) => {
    if (!window.confirm(`Are you sure you want to delete user ${username}?`)) {
      return;
    }
    
    try {
      const response = await axios.delete(`/api/users/${username}`);
      if (response.data.success) {
        toast.success(`User ${username} deleted successfully`);
        fetchUsers();
      }
    } catch (error) {
      console.error('Error deleting user:', error);
      toast.error(error.response?.data?.error || 'Failed to delete user');
    }
  };
  
  // Reset form data for new user
  const openAddModal = () => {
    setFormData({
      username: '',
      email: '',
      mobile: '',
      referred_by: '',
      expiry_days: 30,
      max_connections: 1,
      data_limit_gb: 0,
      status: 'active',
      notes: ''
    });
    setShowAddModal(true);
  };
  
  return (
    <div>
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center mb-6">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-4 sm:mb-0">User Management</h1>
        
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative">
            <input
              type="text"
              placeholder="Search users..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10 pr-4 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <Search size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
          </div>
          
          <div className="relative">
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="pl-10 pr-4 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="all">All users</option>
              <option value="active">Active users</option>
              <option value="deactive">Deactivated users</option>
              <option value="expired">Expired users</option>
            </select>
            <Filter size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
          </div>
          
          <button
            onClick={() => fetchUsers()}
            className="p-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-600"
          >
            <RefreshCw size={18} />
          </button>
          
          <button
            onClick={openAddModal}
            className="px-4 py-2 rounded-md bg-blue-600 text-white flex items-center gap-2 hover:bg-blue-700"
          >
            <UserPlus size={18} />
            <span>Add User</span>
          </button>
        </div>
      </div>
      
      {/* Users table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead className="bg-gray-50 dark:bg-gray-700">
              <tr>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Username
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Status
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Expiry
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Usage
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Connections
                </th>
                <th scope="col" className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
              {loading ? (
                <tr>
                  <td colSpan="6" className="px-6 py-12 text-center text-gray-500 dark:text-gray-400">
                    <div className="flex justify-center">
                      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
                    </div>
                  </td>
                </tr>
              ) : currentUsers.length === 0 ? (
                <tr>
                  <td colSpan="6" className="px-6 py-12 text-center text-gray-500 dark:text-gray-400">
                    No users found
                  </td>
                </tr>
              ) : (
                currentUsers.map(user => (
                  <tr key={user.username} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm font-medium text-gray-900 dark:text-white">{user.username}</div>
                      <div className="text-xs text-gray-500 dark:text-gray-400">{user.email || 'No email'}</div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        user.status === 'active' ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300' :
                        user.status === 'deactive' ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300' :
                        'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'
                      }`}>
                                                {user.status === 'active' ? (
                          <Check size={14} className="mr-1" />
                        ) : (
                          <X size={14} className="mr-1" />
                        )}
                        {user.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {user.expiry?.date ? (
                        <div className="flex flex-col">
                          <span className={`text-sm ${
                            user.expiry.remaining.expired ? 'text-red-600 dark:text-red-400' : 'text-gray-900 dark:text-white'
                          }`}>
                            {new Date(user.expiry.date).toLocaleDateString()}
                          </span>
                          {user.expiry.remaining.expired ? (
                            <span className="text-xs text-red-600 dark:text-red-400 flex items-center">
                              <Clock size={12} className="mr-1" />
                              Expired
                            </span>
                          ) : (
                            <span className="text-xs text-gray-500 dark:text-gray-400 flex items-center">
                              <Clock size={12} className="mr-1" />
                              {user.expiry.remaining.days}d {user.expiry.remaining.hours}h left
                            </span>
                          )}
                        </div>
                      ) : (
                        <span className="text-gray-500 dark:text-gray-400">No expiry</span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {user.data_limit?.bytes > 0 ? (
                        <div className="flex flex-col">
                          <div className="flex justify-between text-xs text-gray-500 dark:text-gray-400 mb-1">
                            <span>{user.data_usage.formatted}</span>
                            <span>{user.data_limit.formatted}</span>
                          </div>
                          <div className="w-32 bg-gray-200 dark:bg-gray-700 rounded-full h-2.5">
                            <div
                              className={`h-2.5 rounded-full ${
                                user.usage_percentage >= 90 ? 'bg-red-600' :
                                user.usage_percentage >= 75 ? 'bg-yellow-400' :
                                'bg-green-500'
                              }`}
                              style={{ width: `${user.usage_percentage}%` }}
                            ></div>
                          </div>
                        </div>
                      ) : (
                        <span className="text-gray-500 dark:text-gray-400">Unlimited</span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex flex-col">
                        <span className="text-sm text-gray-900 dark:text-white">
                          {user.active_connections} / {user.max_connections}
                        </span>
                        <span className="text-xs text-gray-500 dark:text-gray-400">active / max</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right">
                      <button
                        onClick={() => handleEditUser(user)}
                        className="text-indigo-600 hover:text-indigo-900 dark:text-indigo-400 dark:hover:text-indigo-300 mr-4"
                      >
                        <Edit size={16} />
                      </button>
                      <button
                        onClick={() => handleDeleteUser(user.username)}
                        className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
                      >
                        <Trash2 size={16} />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        
        {/* Pagination */}
        {filteredUsers.length > 0 && (
          <div className="bg-white dark:bg-gray-800 px-4 py-3 flex items-center justify-between border-t border-gray-200 dark:border-gray-700 sm:px-6">
            <div className="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
              <div>
                <p className="text-sm text-gray-700 dark:text-gray-300">
                  Showing <span className="font-medium">{indexOfFirstUser + 1}</span> to{' '}
                  <span className="font-medium">
                    {indexOfLastUser > filteredUsers.length ? filteredUsers.length : indexOfLastUser}
                  </span>{' '}
                  of <span className="font-medium">{filteredUsers.length}</span> results
                </p>
              </div>
              <div>
                <nav className="relative z-0 inline-flex rounded-md shadow-sm -space-x-px" aria-label="Pagination">
                  <button
                    onClick={() => handlePageChange(currentPage - 1)}
                    disabled={currentPage === 1}
                    className={`relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-sm font-medium ${
                      currentPage === 1
                        ? 'text-gray-300 dark:text-gray-500 cursor-not-allowed'
                        : 'text-gray-500 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-600'
                    }`}
                  >
                    <ChevronLeft size={18} />
                  </button>
                  
                  {[...Array(totalPages)].map((_, idx) => (
                    <button
                      key={idx}
                      onClick={() => handlePageChange(idx + 1)}
                      className={`relative inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium ${
                        currentPage === idx + 1
                          ? 'z-10 bg-blue-50 dark:bg-blue-900 border-blue-500 dark:border-blue-500 text-blue-600 dark:text-blue-200'
                          : 'bg-white dark:bg-gray-700 text-gray-500 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-600'
                      }`}
                    >
                      {idx + 1}
                    </button>
                  ))}
                  
                  <button
                    onClick={() => handlePageChange(currentPage + 1)}
                    disabled={currentPage === totalPages}
                    className={`relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-sm font-medium ${
                      currentPage === totalPages
                        ? 'text-gray-300 dark:text-gray-500 cursor-not-allowed'
                        : 'text-gray-500 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-600'
                    }`}
                  >
                    <ChevronRight size={18} />
                  </button>
                </nav>
              </div>
            </div>
          </div>
        )}
      </div>
      
      {/* Add User Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            <div className="fixed inset-0 transition-opacity">
              <div className="absolute inset-0 bg-gray-500 dark:bg-gray-900 opacity-75"></div>
            </div>
            <span className="hidden sm:inline-block sm:align-middle sm:h-screen"></span>&#8203;
            <div className="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
              <div className="bg-white dark:bg-gray-800 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                <div className="sm:flex sm:items-start">
                  <div className="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left w-full">
                    <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-white">
                      Add New User
                    </h3>
                    <div className="mt-4">
                      <form onSubmit={handleSubmit} className="space-y-4">
                        <div>
                          <label htmlFor="username" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                            Username*
                          </label>
                          <input
                            type="text"
                            id="username"
                            name="username"
                            value={formData.username}
                            onChange={handleInputChange}
                            required
                            className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                          />
                        </div>
                        
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <label htmlFor="email" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                              Email
                            </label>
                            <input
                              type="email"
                              id="email"
                              name="email"
                              value={formData.email}
                              onChange={handleInputChange}
                              className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                            />
                          </div>
                          
                          <div>
                            <label htmlFor="mobile" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                              Mobile
                            </label>
                            <input
                              type="text"
                              id="mobile"
                              name="mobile"
                              value={formData.mobile}
                              onChange={handleInputChange}
                              className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                            />
                          </div>
                        </div>
                        
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <label htmlFor="expiry_days" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                              Expiry Days
                            </label>
                            <input
                              type="number"
                              id="expiry_days"
                              name="expiry_days"
                              value={formData.expiry_days}
                              onChange={handleInputChange}
                              min="0"
                              className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                            />
                          </div>
                          
                          <div>
                            <label htmlFor="max_connections" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                              Max Connections
                            </label>
                            <input
                              type="number"
                              id="max_connections"
                              name="max_connections"
                              value={formData.max_connections}
                              onChange={handleInputChange}
                              min="1"
                              className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                            />
                          </div>
                        </div>
                        
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <label htmlFor="data_limit_gb" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                              Data Limit (GB)
                            </label>
                            <input
                              type="number"
                              id="data_limit_gb"
                              name="data_limit_gb"
                              value={formData.data_limit_gb}
                              onChange={handleInputChange}
                              min="0"
                              step="0.1"
                              className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                            />
                          </div>
                          
                          <div>
                            <label htmlFor="status" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                              Status
                            </label>
                            <select
                              id="status"
                              name="status"
                              value={formData.status}
                              onChange={handleInputChange}
                              className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                            >
                              <option value="active">Active</option>
                              <option value="deactive">Deactive</option>
                            </select>
                          </div>
                        </div>
                        
                        <div>
                          <label htmlFor="notes" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                            Notes
                          </label>
                          <textarea
                            id="notes"
                            name="notes"
                            value={formData.notes}
                            onChange={handleInputChange}
                            rows="3"
                            className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                          ></textarea>
                        </div>
                      </form>
                    </div>
                  </div>
                </div>
              </div>
              <div className="bg-gray-50 dark:bg-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
                <button
                  type="button"
                  onClick={handleSubmit}
                  className="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-blue-600 text-base font-medium text-white hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:ml-3 sm:w-auto sm:text-sm"
                >
                  Add User
                </button>
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 dark:border-gray-600 shadow-sm px-4 py-2 bg-white dark:bg-gray-800 text-base font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
      
      {/* Edit User Modal */}
      {showEditModal && selectedUser && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            <div className="fixed inset-0 transition-opacity">
              <div className="absolute inset-0 bg-gray-500 dark:bg-gray-900 opacity-75"></div>
            </div>
            <span className="hidden sm:inline-block sm:align-middle sm:h-screen"></span>&#8203;
            <div className="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
              <div className="bg-white dark:bg-gray-800 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                <div className="sm:flex sm:items-start">
                  <div className="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left w-full">
                    <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-white">
                      Edit User: {selectedUser.username}
                    </h3>
                    <div className="mt-4">
                      <form onSubmit={handleSubmit} className="space-y-4">
                        {/* Similar form fields to Add User Modal */}
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <label htmlFor="email" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                              Email
                            </label>
                            <input
                              type="email"
                              id="email"
                              name="email"
                              value={formData.email}
                              onChange={handleInputChange}
                              className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                            />
                          </div>
                          
                          <div>
                            <label htmlFor="mobile" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                              Mobile
                            </label>
                            <input
                              type="text"
                              id="mobile"
                              name="mobile"
                              value={formData.mobile}
                              onChange={handleInputChange}
                              className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                            />
                          </div>
                        </div>
                        
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <label htmlFor="expiry_days" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                              Extend Expiry (Days)
                            </label>
                            <input
                              type="number"
                              id="expiry_days"
                              name="expiry_days"
                              value={formData.expiry_days}
                              onChange={handleInputChange}
                              min="0"
                              className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                            />
                          </div>
                          
                          <div>
                            <label htmlFor="max_connections" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                              Max Connections
                            </label>
                            <input
                              type="number"
                              id="max_connections"
                              name="max_connections"
                              value={formData.max_connections}
                              onChange={handleInputChange}
                              min="1"
                              className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                            />
                          </div>
                        </div>
                        
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <label htmlFor="data_limit_gb" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                              Data Limit (GB)
                            </label>
                            <input
                              type="number"
                              id="data_limit_gb"
                              name="data_limit_gb"
                              value={formData.data_limit_gb}
                              onChange={handleInputChange}
                              min="0"
                              step="0.1"
                              className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                            />
                          </div>
                          
                          <div>
                            <label htmlFor="status" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                              Status
                            </label>
                            <select
                              id="status"
                              name="status"
                              value={formData.status}
                              onChange={handleInputChange}
                              className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                            >
                              <option value="active">Active</option>
                              <option value="deactive">Deactive</option>
                            </select>
                          </div>
                        </div>
                        
                        <div>
                          <label htmlFor="notes" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                            Notes
                          </label>
                          <textarea
                            id="notes"
                            name="notes"
                            value={formData.notes}
                            onChange={handleInputChange}
                            rows="3"
                            className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                          ></textarea>
                        </div>
                      </form>
                    </div>
                  </div>
                </div>
              </div>
              <div className="bg-gray-50 dark:bg-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
                <button
                  type="button"
                  onClick={handleSubmit}
                  className="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-blue-600 text-base font-medium text-white hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:ml-3 sm:w-auto sm:text-sm"
                >
                  Save Changes
                </button>
                <button
                  type="button"
                  onClick={() => setShowEditModal(false)}
                  className="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 dark:border-gray-600 shadow-sm px-4 py-2 bg-white dark:bg-gray-800 text-base font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default UserManagement;
USERMGMTEOF

    # Create ActiveConnections page (basic version)
    cat > "$FINAL_DIR/frontend/src/pages/ActiveConnections.jsx" << 'ACTIVEEOF'
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { toast } from 'react-hot-toast';
import { 
  RefreshCw, Search, Filter, Clock, Wifi, Upload, Download, X
} from 'lucide-react';

const ActiveConnections = () => {
  const [connections, setConnections] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('all');
  const [protocols, setProtocols] = useState([]);
  
  // Fetch active connections
  const fetchConnections = async () => {
    try {
      setLoading(true);
      const response = await axios.get('/api/connections/active');
      
      if (response.data && response.data.connections) {
        setConnections(response.data.connections);
        
        // Extract unique protocols
        const uniqueProtocols = [...new Set(response.data.connections.map(conn => conn.protocol))];
        setProtocols(uniqueProtocols);
      }
    } catch (error) {
      console.error('Error fetching connections:', error);
      toast.error('Failed to load active connections');
    } finally {
      setLoading(false);
    }
  };
  
  useEffect(() => {
    fetchConnections();
    
    // Set up auto-refresh interval
    const intervalId = setInterval(fetchConnections, 30000); // Refresh every 30 seconds
    
    return () => clearInterval(intervalId);
  }, []);
  
  // Filter connections
  const filteredConnections = connections.filter(connection => {
    const matchesSearch = connection.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (connection.client_ip && connection.client_ip.includes(searchQuery));
    
    const matchesProtocol = protocolFilter === 'all' || connection.protocol === protocolFilter;
    
    return matchesSearch && matchesProtocol;
  });
  
  // Handle connection termination
  const handleTerminateConnection = async (connectionId) => {
    if (!window.confirm('Are you sure you want to terminate this connection?')) {
      return;
    }
    
    try {
      const response = await axios.post(`/api/connections/terminate/${connectionId}`);
      
      if (response.data && response.data.success) {
        toast.success('Connection terminated successfully');
        fetchConnections(); // Refresh the list
      }
    } catch (error) {
      console.error('Error terminating connection:', error);
      toast.error(error.response?.data?.error || 'Failed to terminate connection');
    }
  };
  
  return (
    <div>
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center mb-6">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-4 sm:mb-0">Active Connections</h1>
        
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative">
            <input
              type="text"
              placeholder="Search username or IP..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10 pr-4 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <Search size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
          </div>
          
          <div className="relative">
            <select
              value={protocolFilter}
              onChange={(e) => setProtocolFilter(e.target.value)}
              className="pl-10 pr-4 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="all">All protocols</option>
              {protocols.map(protocol => (
                <option key={protocol} value={protocol}>{protocol}</option>
              ))}
            </select>
            <Filter size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
          </div>
          
                   <button
            onClick={fetchConnections}
            className="p-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-600"
          >
            <RefreshCw size={18} />
          </button>
        </div>
      </div>
      
      {/* Connections table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead className="bg-gray-50 dark:bg-gray-700">
              <tr>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Username
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Protocol
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  IP Address
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Duration
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Traffic
                </th>
                <th scope="col" className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
              {loading ? (
                <tr>
                  <td colSpan="6" className="px-6 py-12 text-center text-gray-500 dark:text-gray-400">
                    <div className="flex justify-center">
                      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
                    </div>
                  </td>
                </tr>
              ) : filteredConnections.length === 0 ? (
                <tr>
                  <td colSpan="6" className="px-6 py-12 text-center text-gray-500 dark:text-gray-400">
                    No active connections found
                  </td>
                </tr>
              ) : (
                filteredConnections.map(connection => (
                  <tr key={connection.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm font-medium text-gray-900 dark:text-white">{connection.username}</div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300">
                        <Wifi size={14} className="mr-1" />
                        {connection.protocol}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {connection.client_ip || "Unknown"}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center text-sm text-gray-500 dark:text-gray-400">
                        <Clock size={14} className="mr-1" />
                        {connection.duration.formatted}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm text-gray-500 dark:text-gray-400">
                        <div className="flex items-center">
                          <Download size={14} className="text-green-500 mr-1" />
                          {connection.download.formatted}
                        </div>
                        <div className="flex items-center mt-1">
                          <Upload size={14} className="text-blue-500 mr-1" />
                          {connection.upload.formatted}
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right">
                      <button
                        onClick={() => handleTerminateConnection(connection.id)}
                        className="inline-flex items-center px-2.5 py-1.5 border border-transparent text-xs font-medium rounded text-red-700 bg-red-100 hover:bg-red-200 dark:text-red-200 dark:bg-red-900 dark:hover:bg-red-800"
                      >
                        <X size={14} className="mr-1" />
                        Terminate
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default ActiveConnections;
ACTIVEEOF

    # Create SystemSettings component (basic version)
    cat > "$FINAL_DIR/frontend/src/pages/SystemSettings.jsx" << 'SYSEOF'
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { toast } from 'react-hot-toast';
import { Save, RefreshCw, Database, Server, Shield, Cpu } from 'lucide-react';

const SystemSettings = () => {
  const [settings, setSettings] = useState({
    web_panel: {
      port: 8080,
      ssl_enabled: false,
      domain: '',
      session_timeout: 24
    },
    security: {
      auth_attempts: 5,
      lockout_time: 15,
      api_rate_limit: 100,
      admin_ips: []
    },
    backup: {
      auto_backup: true,
      backup_frequency: 'daily',
      backup_retention: 7,
      backup_path: '/opt/irssh-backups'
    },
    monitoring: {
      enabled: false,
      log_level: 'info',
      notification_email: '',
      telegram_enabled: false,
      telegram_bot_token: '',
      telegram_chat_id: ''
    }
  });
  
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [activeTab, setActiveTab] = useState('web_panel');
  
  // Fetch system settings
  const fetchSettings = async () => {
    try {
      setLoading(true);
      const response = await axios.get('/api/system/settings');
      
      if (response.data && response.data.settings) {
        setSettings(response.data.settings);
      }
    } catch (error) {
      console.error('Error fetching system settings:', error);
      toast.error('Failed to load system settings');
    } finally {
      setLoading(false);
    }
  };
  
  useEffect(() => {
    fetchSettings();
  }, []);
  
  // Handle input changes
  const handleChange = (section, field, value) => {
    setSettings(prev => ({
      ...prev,
      [section]: {
        ...prev[section],
        [field]: value
      }
    }));
  };
  
  // Handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    try {
      setSaving(true);
      const response = await axios.post('/api/system/settings', { settings });
      
      if (response.data && response.data.success) {
        toast.success('Settings saved successfully');
      }
    } catch (error) {
      console.error('Error saving settings:', error);
      toast.error(error.response?.data?.error || 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  };
  
  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      </div>
    );
  }
  
  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">System Settings</h1>
        
        <div className="flex gap-3">
          <button
            onClick={fetchSettings}
            className="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700"
          >
            <RefreshCw size={16} className="mr-2" />
            Refresh
          </button>
          
          <button
            onClick={handleSubmit}
            disabled={saving}
            className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Save size={16} className="mr-2" />
            {saving ? 'Saving...' : 'Save Settings'}
          </button>
        </div>
      </div>
      
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
        {/* Tabs */}
        <div className="border-b border-gray-200 dark:border-gray-700">
          <nav className="flex -mb-px">
            <button
              onClick={() => setActiveTab('web_panel')}
              className={`py-4 px-6 text-sm font-medium ${
                activeTab === 'web_panel'
                  ? 'border-b-2 border-blue-500 text-blue-600 dark:text-blue-400'
                  : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600'
              }`}
            >
              <Server size={16} className="inline mr-2" />
              Web Panel
            </button>
            
            <button
              onClick={() => setActiveTab('security')}
              className={`py-4 px-6 text-sm font-medium ${
                activeTab === 'security'
                  ? 'border-b-2 border-blue-500 text-blue-600 dark:text-blue-400'
                  : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600'
              }`}
            >
              <Shield size={16} className="inline mr-2" />
              Security
            </button>
            
            <button
              onClick={() => setActiveTab('backup')}
              className={`py-4 px-6 text-sm font-medium ${
                activeTab === 'backup'
                  ? 'border-b-2 border-blue-500 text-blue-600 dark:text-blue-400'
                  : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600'
              }`}
            >
              <Database size={16} className="inline mr-2" />
              Backup
            </button>
            
            <button
              onClick={() => setActiveTab('monitoring')}
              className={`py-4 px-6 text-sm font-medium ${
                activeTab === 'monitoring'
                  ? 'border-b-2 border-blue-500 text-blue-600 dark:text-blue-400'
                  : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600'
              }`}
            >
              <Cpu size={16} className="inline mr-2" />
              Monitoring
            </button>
          </nav>
        </div>
        
        {/* Tab content */}
        <div className="p-6">
          {activeTab === 'web_panel' && (
            <div className="space-y-6">
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">Web Panel Settings</h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label htmlFor="web_port" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Web Panel Port
                  </label>
                  <input
                    type="number"
                    id="web_port"
                    value={settings.web_panel.port}
                    onChange={(e) => handleChange('web_panel', 'port', parseInt(e.target.value))}
                    min="1"
                    max="65535"
                    className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Port for the web panel (default: 8080)
                  </p>
                </div>
                
                <div>
                  <label htmlFor="domain" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Domain (optional)
                  </label>
                  <input
                    type="text"
                    id="domain"
                    value={settings.web_panel.domain}
                    onChange={(e) => handleChange('web_panel', 'domain', e.target.value)}
                    placeholder="example.com"
                    className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Domain name for the web panel (leave blank for IP access)
                  </p>
                </div>
                
                <div>
                  <label htmlFor="session_timeout" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Session Timeout (hours)
                  </label>
                  <input
                    type="number"
                    id="session_timeout"
                    value={settings.web_panel.session_timeout}
                    onChange={(e) => handleChange('web_panel', 'session_timeout', parseInt(e.target.value))}
                    min="1"
                    max="720"
                    className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Duration before user is logged out (default: 24 hours)
                  </p>
                </div>
                
                <div className="flex items-center">
                  <input
                    type="checkbox"
                    id="ssl_enabled"
                    checked={settings.web_panel.ssl_enabled}
                    onChange={(e) => handleChange('web_panel', 'ssl_enabled', e.target.checked)}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  />
                  <label htmlFor="ssl_enabled" className="ml-2 block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Enable SSL/HTTPS
                  </label>
                </div>
              </div>
            </div>
          )}
          
          {activeTab === 'security' && (
            <div className="space-y-6">
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">Security Settings</h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label htmlFor="auth_attempts" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Max Authentication Attempts
                  </label>
                  <input
                    type="number"
                    id="auth_attempts"
                    value={settings.security.auth_attempts}
                    onChange={(e) => handleChange('security', 'auth_attempts', parseInt(e.target.value))}
                    min="1"
                    max="10"
                    className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Maximum login attempts before lockout
                  </p>
                </div>
                
                <div>
                  <label htmlFor="lockout_time" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Lockout Time (minutes)
                  </label>
                  <input
                    type="number"
                    id="lockout_time"
                    value={settings.security.lockout_time}
                    onChange={(e) => handleChange('security', 'lockout_time', parseInt(e.target.value))}
                    min="5"
                    max="60"
                    className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Duration of account lockout after failed attempts
                  </p>
                </div>
                
                <div>
                  <label htmlFor="api_rate_limit" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                    API Rate Limit
                  </label>
                  <input
                    type="number"
                    id="api_rate_limit"
                    value={settings.security.api_rate_limit}
                    onChange={(e) => handleChange('security', 'api_rate_limit', parseInt(e.target.value))}
                    min="10"
                    max="1000"
                    className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Maximum API requests per minute per IP
                  </p>
                </div>
                
                <div>
                  <label htmlFor="admin_ips" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Admin IP Whitelist (optional)
                  </label>
                  <input
                    type="text"
                    id="admin_ips"
                    value={settings.security.admin_ips.join(', ')}
                    onChange={(e) => handleChange('security', 'admin_ips', e.target.value.split(',').map(ip => ip.trim()).filter(ip => ip))}
                    placeholder="127.0.0.1, 192.168.1.100"
                    className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Comma-separated list of IPs allowed to access admin panel (empty = all IPs)
                  </p>
                </div>
              </div>
            </div>
          )}
          
          {activeTab === 'backup' && (
            <div className="space-y-6">
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">Backup Settings</h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="flex items-center">
                  <input
                    type="checkbox"
                    id="auto_backup"
                    checked={settings.backup.auto_backup}
                    onChange={(e) => handleChange('backup', 'auto_backup', e.target.checked)}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  />
                  <label htmlFor="auto_backup" className="ml-2 block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Enable Automatic Backups
                  </label>
                </div>
                
                <div>
                  <label htmlFor="backup_frequency" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Backup Frequency
                  </label>
                  <select
                    id="backup_frequency"
                    value={settings.backup.backup_frequency}
                    onChange={(e) => handleChange('backup', 'backup_frequency', e.target.value)}
                    className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  >
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="monthly">Monthly</option>
                  </select>
                </div>
                
                <div>
                  <label htmlFor="backup_retention" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Backup Retention (days)
                  </label>
                  <input
                    type="number"
                    id="backup_retention"
                    value={settings.backup.backup_retention}
                    onChange={(e) => handleChange('backup', 'backup_retention', parseInt(e.target.value))}
                    min="1"
                    max="90"
                    className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Number of days to keep backups before deletion
                  </p>
                </div>
                
                <div>
                  <label htmlFor="backup_path" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Backup Path
                  </label>
                  <input
                    type="text"
                    id="backup_path"
                    value={settings.backup.backup_path}
                    onChange={(e) => handleChange('backup', 'backup_path', e.target.value)}
                    className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Directory where backups will be stored
                  </p>
                </div>
              </div>
              
              <div className="mt-4">
                <button
                  type="button"
                  className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
                >
                  <Database size={16} className="mr-2" />
                  Create Backup Now
                </button>
              </div>
            </div>
          )}
          
          {activeTab === 'monitoring' && (
            <div className="space-y-6">
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">Monitoring Settings</h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="flex items-center">
                  <input
                    type="checkbox"
                    id="monitoring_enabled"
                    checked={settings.monitoring.enabled}
                    onChange={(e) => handleChange('monitoring', 'enabled', e.target.checked)}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  />
                  <label htmlFor="monitoring_enabled" className="ml-2 block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Enable System Monitoring
                  </label>
                </div>
                
                <div>
                  <label htmlFor="log_level" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Log Level
                  </label>
                  <select
                    id="log_level"
                    value={settings.monitoring.log_level}
                    onChange={(e) => handleChange('monitoring', 'log_level', e.target.value)}
                    className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  >
                    <option value="error">Error</option>
                    <option value="warn">Warning</option>
                    <option value="info">Info</option>
                    <option value="debug">Debug</option>
                  </select>
                </div>
                
                <div>
                  <label htmlFor="notification_email" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Notification Email (optional)
                  </label>
                  <input
                    type="email"
                    id="notification_email"
                    value={settings.monitoring.notification_email}
                    onChange={(e) => handleChange('monitoring', 'notification_email', e.target.value)}
                    placeholder="admin@example.com"
                    className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Email address to receive monitoring alerts
                  </p>
                </div>
                
                <div className="flex items-center">
                  <input
                    type="checkbox"
                    id="telegram_enabled"
                    checked={settings.monitoring.telegram_enabled}
                    onChange={(e) => handleChange('monitoring', 'telegram_enabled', e.target.checked)}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  />
                  <label htmlFor="telegram_enabled" className="ml-2 block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Enable Telegram Notifications
                  </label>
                </div>
                
                {settings.monitoring.telegram_enabled && (
                  <>
                    <div>
                      <label htmlFor="telegram_bot_token" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                        Telegram Bot Token
                      </label>
                      <input
                        type="text"
                        id="telegram_bot_token"
                        value={settings.monitoring.telegram_bot_token}
                                                onChange={(e) => handleChange('monitoring', 'telegram_bot_token', e.target.value)}
                        className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                      />
                    </div>
                    
                    <div>
                      <label htmlFor="telegram_chat_id" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                        Telegram Chat ID
                      </label>
                      <input
                        type="text"
                        id="telegram_chat_id"
                        value={settings.monitoring.telegram_chat_id}
                        onChange={(e) => handleChange('monitoring', 'telegram_chat_id', e.target.value)}
                        className="mt-1 block w-full border border-gray-300 dark:border-gray-600 rounded-md shadow-sm py-2 px-3 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                      />
                    </div>
                  </>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SystemSettings;
SYSEOF

    # Create vite.config.js
    cat > "$FINAL_DIR/frontend/vite.config.js" << 'VITEEOF'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': resolve(__dirname, './src')
    }
  },
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
VITEEOF

    # Create package.json for frontend
    cat > "$FINAL_DIR/frontend/package.json" << 'PKGEOF'
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
PKGEOF

    # Create tailwind.config.js
    cat > "$FINAL_DIR/frontend/tailwind.config.js" << 'TAILWINDEOF'
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
TAILWINDEOF

    # Create postcss.config.js
    cat > "$FINAL_DIR/frontend/postcss.config.js" << 'POSTCSSEOF'
export default {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
}
POSTCSSEOF

    # Create index.css for tailwind
    mkdir -p "$FINAL_DIR/frontend/src"
    cat > "$FINAL_DIR/frontend/src/index.css" << 'INDEXCSSEOF'
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
INDEXCSSEOF

    # Create main.jsx
    cat > "$FINAL_DIR/frontend/src/main.jsx" << 'MAINEOF'
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
MAINEOF

    # Create index.html
    cat > "$FINAL_DIR/frontend/index.html" << 'INDEXEOF'
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/vite.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>IRSSH Panel</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.jsx"></script>
  </body>
</html>
INDEXEOF

    # Create build script for frontend
    cat > "$FINAL_DIR/frontend/build.sh" << 'BUILDEOF'
#!/bin/bash
echo "Building IRSSH Panel frontend..."

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "Node.js not found. Please install Node.js first."
    exit 1
fi

# Install dependencies
echo "Installing dependencies..."
npm install

# Build the frontend
echo "Building frontend..."
npm run build

# Check if build was successful
if [ $? -eq 0 ]; then
    echo "Frontend built successfully!"
else
    echo "Failed to build frontend. Please check the errors above."
    exit 1
fi
BUILDEOF
    chmod +x "$FINAL_DIR/frontend/build.sh"

    # Create a script to install and configure the web UI
    cat > "$SCRIPTS_DIR/setup_web_ui.sh" << EOF
#!/bin/bash

# Web UI Setup Script
PANEL_DIR="${FINAL_DIR}"

echo "Setting up IRSSH Panel web UI..."

# Change to frontend directory
cd "\$PANEL_DIR/frontend"

# Install dependencies and build frontend
./build.sh

# Check if build was successful
if [ ! -d "\$PANEL_DIR/frontend/dist" ]; then
    echo "Frontend build failed. Please check the logs."
    exit 1
fi

# Configure nginx
echo "Configuring nginx to serve the web UI..."
cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen ${WEB_PORT};
    listen [::]:${WEB_PORT};
    
    server_name _;
    
    root \$PANEL_DIR/frontend/dist;
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
EOL

# Enable the site
ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default 2>/dev/null

# Restart nginx
systemctl restart nginx

echo "Web UI setup completed successfully!"
echo "You can access the web panel at: http://${SERVER_IPv4}:${WEB_PORT}"
EOF
    chmod +x "$SCRIPTS_DIR/setup_web_ui.sh"

    info "Web UI setup completed"
}

# Function to install protocols
install_protocols() {
    info "Installing selected protocols..."
    
    # Source the protocol modules
    for module in "${MODULES_DIR}"/*protocol-*.sh; do
        if [ -f "$module" ]; then
            source "$module"
        fi
    done
    
    # Install each selected protocol
    if [ "${INSTALL_SSH}" = true ]; then
        install_ssh
    fi
    
    if [ "${INSTALL_WIREGUARD}" = true ]; then
        install_wireguard
    fi
    
    if [ "${INSTALL_L2TP}" = true ]; then
        install_l2tp
    fi
    
    if [ "${INSTALL_IKEV2}" = true ]; then
        install_ikev2
    fi
    
    if [ "${INSTALL_CISCO}" = true ]; then
        install_cisco
    fi
    
    if [ "${INSTALL_SINGBOX}" = true ]; then
        install_singbox
    fi
    
    if [ "${INSTALL_SSLVPN}" = true ]; then
        install_sslvpn
    fi
    
    if [ "${INSTALL_NORDWHISPER}" = true ]; then
        install_nordwhisper
    fi
    
    info "Protocol installation completed"
}

# Function to setup monitoring for protocols
setup_protocol_monitoring() {
    info "Setting up protocol monitoring..."
    
    # Make sure monitoring scripts directory exists
    mkdir -p "${SCRIPTS_DIR}/monitoring"
    
    # Create systemd services for each protocol monitor
    if [ "${INSTALL_SSH}" = true ]; then
        cat > /etc/systemd/system/irssh-ssh-monitor.service << EOL
[Unit]
Description=IRSSH SSH Connection Monitor
After=network.target sshd.service irssh-user-manager.service
Wants=irssh-user-manager.service

[Service]
Type=simple
ExecStart=${SCRIPTS_DIR}/monitoring/${SSH_MONITOR} --daemon
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOL
    fi
    
    if [ "${INSTALL_WIREGUARD}" = true ]; then
        cat > /etc/systemd/system/irssh-wireguard-monitor.service << EOL
[Unit]
Description=IRSSH WireGuard Connection Monitor
After=network.target wg-quick@wg0.service irssh-user-manager.service
Wants=irssh-user-manager.service

[Service]
Type=simple
ExecStart=${SCRIPTS_DIR}/monitoring/${WIREGUARD_MONITOR} --daemon
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOL
    fi
    
    if [ "${INSTALL_L2TP}" = true ]; then
        cat > /etc/systemd/system/irssh-l2tp-monitor.service << EOL
[Unit]
Description=IRSSH L2TP Connection Monitor
After=network.target xl2tpd.service strongswan.service irssh-user-manager.service
Wants=irssh-user-manager.service

[Service]
Type=simple
ExecStart=${SCRIPTS_DIR}/monitoring/${L2TP_MONITOR} --daemon
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOL
    fi
    
    if [ "${INSTALL_IKEV2}" = true ]; then
        cat > /etc/systemd/system/irssh-ikev2-monitor.service << EOL
[Unit]
Description=IRSSH IKEv2 Connection Monitor
After=network.target strongswan.service irssh-user-manager.service
Wants=irssh-user-manager.service

[Service]
Type=simple
ExecStart=${SCRIPTS_DIR}/monitoring/${IKEV2_MONITOR} --daemon
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOL
    fi
    
    if [ "${INSTALL_CISCO}" = true ]; then
        cat > /etc/systemd/system/irssh-cisco-monitor.service << EOL
[Unit]
Description=IRSSH Cisco Connection Monitor
After=network.target ocserv.service irssh-user-manager.service
Wants=irssh-user-manager.service

[Service]
Type=simple
ExecStart=${SCRIPTS_DIR}/monitoring/${CISCO_MONITOR} --daemon
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOL
    fi
    
    if [ "${INSTALL_SINGBOX}" = true ]; then
        cat > /etc/systemd/system/irssh-singbox-monitor.service << EOL
[Unit]
Description=IRSSH Sing-Box Connection Monitor
After=network.target sing-box.service irssh-user-manager.service
Wants=irssh-user-manager.service

[Service]
Type=simple
ExecStart=${SCRIPTS_DIR}/monitoring/${SINGBOX_MONITOR} --daemon
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOL
    fi
    
    if [ "${INSTALL_SSLVPN}" = true ]; then
        cat > /etc/systemd/system/irssh-sslvpn-monitor.service << EOL
[Unit]
Description=IRSSH SSL-VPN Connection Monitor
After=network.target openvpn@server.service irssh-user-manager.service
Wants=irssh-user-manager.service

[Service]
Type=simple
ExecStart=${SCRIPTS_DIR}/monitoring/${SSLVPN_MONITOR} --daemon
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOL
    fi
    
    if [ "${INSTALL_NORDWHISPER}" = true ]; then
        cat > /etc/systemd/system/irssh-nordwhisper-monitor.service << EOL
[Unit]
Description=IRSSH NordWhisper Connection Monitor
After=network.target openvpn@nordwhisper.service irssh-user-manager.service
Wants=irssh-user-manager.service

[Service]
Type=simple
ExecStart=${SCRIPTS_DIR}/monitoring/${NORDWHISPER_MONITOR} --daemon
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOL
    fi
    
    # Reload systemd daemon
    systemctl daemon-reload
    
    info "Protocol monitoring setup completed"
}

# Function to start required services
start_services() {
    info "Starting required services..."
    
    # Start database service if not running
    if ! systemctl is-active --quiet postgresql; then
        systemctl start postgresql
    fi
    
    # Start nginx if not running
    if ! systemctl is-active --quiet nginx; then
        systemctl start nginx
    fi
    
    # Start redis if installed and not running
    if command -v redis-server &> /dev/null && ! systemctl is-active --quiet redis-server; then
        systemctl start redis-server
    fi
    
    # Start API service
    systemctl start irssh-api
    
    # Start user manager service
    systemctl start irssh-user-manager
    
    # Start protocol monitors
    if [ "${INSTALL_SSH}" = true ]; then
        systemctl start irssh-ssh-monitor
    fi
    
    if [ "${INSTALL_WIREGUARD}" = true ]; then
        systemctl start irssh-wireguard-monitor
    fi
    
    if [ "${INSTALL_L2TP}" = true ]; then
        systemctl start irssh-l2tp-monitor
    fi
    
    if [ "${INSTALL_IKEV2}" = true ]; then
        systemctl start irssh-ikev2-monitor
    fi
    
    if [ "${INSTALL_CISCO}" = true ]; then
        systemctl start irssh-cisco-monitor
    fi
    
    if [ "${INSTALL_SINGBOX}" = true ]; then
        systemctl start irssh-singbox-monitor
    fi
    
    if [ "${INSTALL_SSLVPN}" = true ]; then
        systemctl start irssh-sslvpn-monitor
    fi
    
    if [ "${INSTALL_NORDWHISPER}" = true ]; then
        systemctl start irssh-nordwhisper-monitor
    fi
    
    info "Services started successfully"
}

# Function to display installation summary
display_summary() {
    local ADMIN_USER=$1
    local WEB_PORT=$2
    local SERVER_IPv4=$3
    local SERVER_IPv6=$4
    
    echo ""
    echo "IRSSH Panel Installation Summary"
    echo "-------------------------------"
    echo "Panel Version: 4.2.0"
    echo "Installation Date: $(date +"%Y-%m-%d %H:%M:%S")"
    echo ""
    echo "Web Interface:"
    if [ ! -z "$SERVER_IPv4" ]; then
        echo "IPv4: http://${SERVER_IPv4}:${WEB_PORT}"
    fi
    if [ ! -z "$SERVER_IPv6" ]; then
        echo "IPv6: http://[${SERVER_IPv6}]:${WEB_PORT}"
    fi
    echo ""
    echo "Admin Credentials:"
    echo "Username: ${ADMIN_USER}"
    echo "Password: (As specified during installation)"
    echo ""
    echo "Database Information:"
    echo "DB Name: ${DB_NAME}"
    echo "DB User: ${DB_USER}"
    echo "DB Password: ${DB_USER_PASSWORD}"
    echo ""
    echo "Enabled Protocols:"
    if [ "${INSTALL_SSH}" = true ]; then
        echo "- SSH (Port: ${SSH_PORT})"
    fi
    if [ "${INSTALL_WIREGUARD}" = true ]; then
        echo "- WireGuard (Port: ${WIREGUARD_PORT})"
    fi
    if [ "${INSTALL_L2TP}" = true ]; then
        echo "- L2TP/IPsec (Port: ${L2TP_PORT})"
    fi
    if [ "${INSTALL_IKEV2}" = true ]; then
        echo "- IKEv2/IPsec (Port: ${IKEV2_PORT})"
    fi
    if [ "${INSTALL_CISCO}" = true ]; then
        echo "- Cisco AnyConnect (Port: ${CISCO_PORT})"
    fi
    if [ "${INSTALL_SINGBOX}" = true ]; then
        echo "- SingBox (Port: ${SINGBOX_PORT})"
    fi
    if [ "${INSTALL_SSLVPN}" = true ]; then
        echo "- SSL-VPN (OpenVPN) (Port: ${SSLVPN_PORT})"
    fi
    if [ "${INSTALL_NORDWHISPER}" = true ]; then
        echo "- NordWhisper (Port: ${NORDWHISPER_PORT})"
    fi
    echo ""
    echo "Additional Features:"
    echo "- Advanced User Management: ${INSTALL_USER_MANAGEMENT}"
    echo "- Monitoring: ${ENABLE_MONITORING}"
    echo "- Geolocation: Installed (Disabled by default)"
    echo ""
    echo "Management Tools:"
    echo "- Admin CLI Tool: irssh-admin"
    echo "- User Manager: http://${SERVER_IPv4}:${WEB_PORT}/users"
    echo "- Client Portal: http://${SERVER_IPv4}:${WEB_PORT}/portal (when activated)"
    echo ""
    echo "For more information, please check:"
    echo "- Logs: ${LOG_DIR}"
    echo "- Configuration: ${CONFIG_DIR}"
    echo "- Admin CLI: Run 'irssh-admin help' for available commands"
}

# Function to get user configuration
get_user_config() {
    info "Getting user configuration..."
    
    # Admin user
    read -p "Enter admin username: " ADMIN_USER
    while [ -z "$ADMIN_USER" ]; do
        read -p "Username cannot be empty. Enter admin username: " ADMIN_USER
    done
    
# Admin password
read -s -p "Enter admin password: " ADMIN_PASS
echo

if [ -z "$ADMIN_PASS" ]; then
    # Fixed: properly closed the while loop
    while [ -z "$ADMIN_PASS" ]; do
        read -s -p "Password cannot be empty. Enter admin password: " ADMIN_PASS
        echo
    done
fi
    
    # Database information
    DB_NAME="irssh_panel"
    DB_USER="$ADMIN_USER"
    DB_USER_PASSWORD="$ADMIN_PASS"
    
    # Web panel port
    while true; do
        read -p "Enter web panel port (4-5 digits) or press Enter for random port: " WEB_PORT
        if [ -z "$WEB_PORT" ]; then
            WEB_PORT=$(shuf -i 1234-65432 -n 1)
            info "Generated random port: $WEB_PORT"
            break
        elif [[ "$WEB_PORT" =~ ^[0-9]{4,5}$ ]] && [ "$WEB_PORT" -ge 1234 ] && [ "$WEB_PORT" -le 65432 ]; then
            break
        else
            error "Invalid port number. Must be between 1234 and 65432" "no-exit"
        fi
    done
    
    # Protocol selection
    echo "Select protocols to install:"
    read -p "Install SSH? (Y/n): " INSTALL_SSH
    INSTALL_SSH=${INSTALL_SSH:-y}
    INSTALL_SSH=$(echo $INSTALL_SSH | tr '[:upper:]' '[:lower:]')
    INSTALL_SSH=$([ "$INSTALL_SSH" = "y" ] && echo true || echo false)
    
    read -p "Install WireGuard? (Y/n): " INSTALL_WIREGUARD
    INSTALL_WIREGUARD=${INSTALL_WIREGUARD:-y}
    INSTALL_WIREGUARD=$(echo $INSTALL_WIREGUARD | tr '[:upper:]' '[:lower:]')
    INSTALL_WIREGUARD=$([ "$INSTALL_WIREGUARD" = "y" ] && echo true || echo false)
    
    read -p "Install L2TP/IPsec? (Y/n): " INSTALL_L2TP
    INSTALL_L2TP=${INSTALL_L2TP:-y}
    INSTALL_L2TP=$(echo $INSTALL_L2TP | tr '[:upper:]' '[:lower:]')
    INSTALL_L2TP=$([ "$INSTALL_L2TP" = "y" ] && echo true || echo false)
    
    read -p "Install IKEv2/IPsec? (Y/n): " INSTALL_IKEV2
    INSTALL_IKEV2=${INSTALL_IKEV2:-y}
    INSTALL_IKEV2=$(echo $INSTALL_IKEV2 | tr '[:upper:]' '[:lower:]')
    INSTALL_IKEV2=$([ "$INSTALL_IKEV2" = "y" ] && echo true || echo false)
    
    read -p "Install Cisco AnyConnect? (Y/n): " INSTALL_CISCO
    INSTALL_CISCO=${INSTALL_CISCO:-y}
    INSTALL_CISCO=$(echo $INSTALL_CISCO | tr '[:upper:]' '[:lower:]')
    INSTALL_CISCO=$([ "$INSTALL_CISCO" = "y" ] && echo true || echo false)
    
    read -p "Install SingBox? (Y/n): " INSTALL_SINGBOX
    INSTALL_SINGBOX=${INSTALL_SINGBOX:-y}
    INSTALL_SINGBOX=$(echo $INSTALL_SINGBOX | tr '[:upper:]' '[:lower:]')
    INSTALL_SINGBOX=$([ "$INSTALL_SINGBOX" = "y" ] && echo true || echo false)
    
    read -p "Install SSL-VPN (OpenVPN)? (Y/n): " INSTALL_SSLVPN
    INSTALL_SSLVPN=${INSTALL_SSLVPN:-y}
    INSTALL_SSLVPN=$(echo $INSTALL_SSLVPN | tr '[:upper:]' '[:lower:]')
    INSTALL_SSLVPN=$([ "$INSTALL_SSLVPN" = "y" ] && echo true || echo false)
    
    read -p "Install NordWhisper (Obfuscated OpenVPN)? (Y/n): " INSTALL_NORDWHISPER
    INSTALL_NORDWHISPER=${INSTALL_NORDWHISPER:-y}
    INSTALL_NORDWHISPER=$(echo $INSTALL_NORDWHISPER | tr '[:upper:]' '[:lower:]')
    INSTALL_NORDWHISPER=$([ "$INSTALL_NORDWHISPER" = "y" ] && echo true || echo false)
    
    # Additional features
    read -p "Enable monitoring? (y/N): " ENABLE_MONITORING
    ENABLE_MONITORING=${ENABLE_MONITORING:-n}
    ENABLE_MONITORING=$(echo $ENABLE_MONITORING | tr '[:upper:]' '[:lower:]')
    ENABLE_MONITORING=$([ "$ENABLE_MONITORING" = "y" ] && echo true || echo false)
    
    read -p "Install advanced user management module? (Y/n): " INSTALL_USER_MANAGEMENT
    INSTALL_USER_MANAGEMENT=${INSTALL_USER_MANAGEMENT:-y}
    INSTALL_USER_MANAGEMENT=$(echo $INSTALL_USER_MANAGEMENT | tr '[:upper:]' '[:lower:]')
    INSTALL_USER_MANAGEMENT=$([ "$INSTALL_USER_MANAGEMENT" = "y" ] && echo true || echo false)
    
    # Port configuration
    SSH_PORT=22
    WIREGUARD_PORT=51820
    L2TP_PORT=1701
    IKEV2_PORT=500
    CISCO_PORT=443
    SINGBOX_PORT=1080
    SSLVPN_PORT=1194
    NORDWHISPER_PORT=1195
    
    info "User configuration completed"
}

# Function to detect server IP addresses
get_server_ip() {
    info "Detecting server IP addresses..."
    
    # Try multiple methods to detect IPv4
    SERVER_IPv4=$(curl -s4 -m 5 ifconfig.me || curl -s4 -m 5 icanhazip.com || curl -s4 -m 5 ipinfo.io/ip)
    
    if [ -z "$SERVER_IPv4" ]; then
        SERVER_IPv4=$(ip -4 route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}')
    fi
    
    # Try multiple methods to detect IPv6
    SERVER_IPv6=$(curl -s6 -m 5 ifconfig.me || curl -s6 -m 5 icanhazip.com || curl -s6 -m 5 ipinfo.io/ip)
    
    if [ -z "$SERVER_IPv6" ]; then
        SERVER_IPv6=$(ip -6 addr show scope global 2>/dev/null | grep -oP '(?<=inet6\s)[\da-f:]+(?=/\d+\s)' | head -n 1)
    fi
    
    if [ -z "$SERVER_IPv4" ] && [ -z "$SERVER_IPv6" ]; then
        warn "Could not determine server IP address, some features may not work properly"
    else
        if [ ! -z "$SERVER_IPv4" ]; then
            info "Detected IPv4: $SERVER_IPv4"
        fi
        if [ ! -z "$SERVER_IPv6" ]; then
            info "Detected IPv6: $SERVER_IPv6"
        fi
    fi
}

# Function to install dependencies based on OS
install_dependencies() {
    info "Installing system dependencies..."
    
    # Detect OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        OS=$(uname -s)
    fi
    
    case $OS in
        ubuntu|debian)
            # Update package lists
            apt-get update || error "Failed to update package lists"
            
            # Install basic required packages
            apt-get install -y \
                curl wget git nano unzip zip tar lsof net-tools netcat \
                build-essential python3 python3-pip || error "Failed to install basic packages"
                
            # Install PostgreSQL and Nginx
            apt-get install -y \
                nginx \
                postgresql \
                                postgresql-contrib || error "Failed to install PostgreSQL and Nginx"
            
            # Install Node.js 20.x
            curl -fsSL https://deb.nodesource.com/setup_20.x | bash - || error "Failed to set up Node.js repository"
            apt-get install -y nodejs || error "Failed to install Node.js"
            
            # Install Redis for session management
            apt-get install -y redis-server || error "Failed to install Redis"
            ;;
        centos|rhel|fedora)
            # Update package lists
            yum update -y || error "Failed to update package lists"
            
            # Install EPEL repository
            yum install -y epel-release || error "Failed to install EPEL repository"
            
            # Install basic required packages
            yum install -y \
                curl wget git nano unzip zip tar lsof net-tools nc \
                gcc gcc-c++ make python3 python3-pip || error "Failed to install basic packages"
                
            # Install PostgreSQL and Nginx
            yum install -y \
                nginx \
                postgresql \
                postgresql-server \
                postgresql-contrib || error "Failed to install PostgreSQL and Nginx"
            
            # Initialize PostgreSQL database
            postgresql-setup --initdb || warn "PostgreSQL database already initialized"
            
            # Install Node.js 20.x
            curl -fsSL https://rpm.nodesource.com/setup_20.x | bash - || error "Failed to set up Node.js repository"
            yum install -y nodejs || error "Failed to install Node.js"
            
            # Install Redis for session management
            yum install -y redis || error "Failed to install Redis"
            ;;
        *)
            error "Unsupported operating system: $OS"
            ;;
    esac
    
    # Install development tools and global npm packages
    npm install -g npm@latest || warn "Failed to update npm to latest version"
    npm install -g pm2 || warn "Failed to install PM2"
    
    # Install Python dependencies for monitoring scripts
    pip3 install psycopg2-binary requests schedule || warn "Failed to install Python dependencies"
    
    info "Dependencies installation completed"
}

# Main function
main() {
    # Check if running as root
    check_root
    
    # Welcome message
    echo "----------------------------------------"
    echo "  IRSSH Panel Modular Installer v4.2.0  "
    echo "----------------------------------------"
    echo
    echo "This script will install IRSSH Panel with a modular structure."
    echo "All components will be installed in separate files for easier management."
    echo
    
    # Create necessary directories
    create_dirs
    
    # Get server IP
    get_server_ip
    
    # Get user configuration
    get_user_config
    
    # Download main installer script
    download_installer
    
    # Create module files
    create_modules
    
    # Install dependencies
    install_dependencies
    
    # Setup database
    source "${MODULES_DIR}/${DATABASE_SETUP}"
    setup_database
    
    # Setup web server
    source "${MODULES_DIR}/${WEB_SERVER_SETUP}"
    setup_web_server
    
    # Install protocols
    install_protocols
    
    # Setup monitoring
    if [ "$ENABLE_MONITORING" = true ]; then
        source "${MODULES_DIR}/${MONITORING_SETUP}"
        setup_monitoring
    fi
    
    # Setup protocol monitoring
    setup_protocol_monitoring
    
    # Setup user management
    if [ "$INSTALL_USER_MANAGEMENT" = true ]; then
        source "${MODULES_DIR}/${USER_MANAGEMENT}"
        create_user_management_service
    fi
    
    # Create admin CLI tool
    source "${MODULES_DIR}/${ADMIN_CLI}"
    create_admin_cli_tool
    
    # Setup geolocation (hidden by default)
    source "${MODULES_DIR}/${GEOLOCATION_SETUP}"
    setup_geolocation
    
    # Setup web UI
    setup_web_ui
    
    # Start required services
    start_services
    
    # Display installation summary
    display_summary "$ADMIN_USER" "$WEB_PORT" "$SERVER_IPv4" "$SERVER_IPv6"
    
    info "Installation completed successfully!"
}

# Function to clean up temporary files
cleanup() {
    info "Cleaning up temporary files..."
    if [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
}

# Run the main function
main "$@"
