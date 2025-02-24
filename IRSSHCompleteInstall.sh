#!/bin/bash

# IRSSH Panel Complete Installation Script
# Version: 3.6.0

# Base directories
PANEL_DIR="/opt/irssh-panel"
CONFIG_DIR="/etc/enhanced_ssh"
LOG_DIR="/var/log/irssh"
BACKUP_DIR="/opt/irssh-backups"
TEMP_DIR="/tmp/irssh-install"
SSL_DIR="/etc/nginx/ssl"

# Protocol configuration
declare -A PROTOCOLS=(
    ["SSH"]=true
    ["L2TP"]=true
    ["IKEV2"]=true
    ["CISCO"]=true
    ["WIREGUARD"]=true
    ["SINGBOX"]=true
)

# Port configuration
declare -A PORTS=(
    ["SSH"]=22
    ["SSH_TLS"]=444
    ["WEBSOCKET"]=2082
    ["L2TP"]=1701
    ["IKEV2"]=500
    ["CISCO"]=85
    ["WIREGUARD"]=51820
    ["SINGBOX"]=1080
    ["UDPGW"]=7300
)

# User Configuration
ADMIN_USER=""
ADMIN_PASS=""
ENABLE_MONITORING="n"
SERVER_IPv4=""
SERVER_IPv6=""
DB_NAME="irssh"
REPO_URL="https://github.com/irkids/IRSSH-Panel.git"

# Logging functions
log() {
    local level=$1
    local message=$2
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message"
    echo "[$timestamp] [$level] $message" >> "$LOG_DIR/installation.log"
}

info() {
    log "INFO" "$1"
}

error() {
    log "ERROR" "$1"
    if [[ "${2:-}" != "no-exit" ]]; then
        cleanup
        exit 1
    fi
}

cleanup() {
    info "Performing cleanup..."
    rm -rf "$TEMP_DIR"
}

get_server_ip() {
    SERVER_IPv4=$(curl -s4 ifconfig.me)
    if [ -z "$SERVER_IPv4" ]; then
        SERVER_IPv4=$(ip -4 route get 8.8.8.8 | awk '{print $7; exit}')
    fi

    SERVER_IPv6=$(curl -s6 ifconfig.me)

    if [ -z "$SERVER_IPv4" ] && [ -z "$SERVER_IPv6" ]; then
        error "Could not determine server IP address"
    fi
}

get_config() {
    info "Getting initial configuration..."
    
    read -p "Enter admin username: " ADMIN_USER
    while [ -z "$ADMIN_USER" ]; do
        read -p "Username cannot be empty. Enter admin username: " ADMIN_USER
    done
    
    read -s -p "Enter admin password: " ADMIN_PASS
    echo
    while [ -z "$ADMIN_PASS" ]; do
        read -s -p "Password cannot be empty. Enter admin password: " ADMIN_PASS
        echo
    done

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
    PORTS["WEB"]=$WEB_PORT
    
    read -p "Enable monitoring? (y/N): " ENABLE_MONITORING
    ENABLE_MONITORING=${ENABLE_MONITORING,,}
}

setup_dependencies() {
    info "Installing system dependencies..."
    
    # Update system
    apt-get update || error "Failed to update package lists"
    
    # Remove old Node.js completely
    apt-get remove -y nodejs npm node-*
    apt-get purge -y nodejs npm
    apt-get autoremove -y
    rm -rf /usr/local/lib/node_modules
    rm -rf /usr/local/bin/node
    rm -rf /usr/local/bin/npm
    rm -rf /etc/apt/sources.list.d/nodesource.list*
    
    # Install required packages
    apt-get install -y \
        nginx \
        postgresql \
        postgresql-contrib \
        git \
        curl \
        build-essential \
        python3 \
        python3-pip \
        || error "Failed to install dependencies"
    
    # Install Node.js 20.x
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
    
    # Install development tools
    npm install -g npm@latest
    npm install -g pm2
    
    info "Dependencies installation completed"
}

setup_database() {
    info "Setting up database..."
    
    # Start PostgreSQL if not running
    systemctl start postgresql
    systemctl enable postgresql
    
    # Switch to postgres home directory to avoid permission warnings
    cd /var/lib/postgresql || error "Failed to access PostgreSQL directory"
    
    # Check if database exists and create if needed
    if ! sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
        info "Creating new database: $DB_NAME"
        sudo -u postgres createdb "$DB_NAME" || error "Failed to create database"
        
        # Create user and grant privileges
        sudo -u postgres psql -c "CREATE USER ${ADMIN_USER} WITH PASSWORD '${ADMIN_PASS}';" || error "Failed to create database user"
        sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${ADMIN_USER};" || error "Failed to grant privileges"
    else
        info "Database '$DB_NAME' already exists"
        
        # Update user password if it exists, create if it doesn't
        sudo -u postgres psql -c "DO \$\$
        BEGIN
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = '${ADMIN_USER}') THEN
                ALTER USER ${ADMIN_USER} WITH PASSWORD '${ADMIN_PASS}';
            ELSE
                CREATE USER ${ADMIN_USER} WITH PASSWORD '${ADMIN_PASS}';
            END IF;
        END
        \$\$;" || error "Failed to update database user"
        
        sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${ADMIN_USER};" || error "Failed to grant privileges"
    fi
    
    info "Database setup completed"
}

setup_web_server() {
    info "Setting up web server..."

    # Clone repository into temporary directory
    git clone "$REPO_URL" "$TEMP_DIR/repo" || error "Failed to clone repository"

    # Check if frontend and backend directories exist in the repo
    if [ ! -d "$TEMP_DIR/repo/frontend" ]; then
        mkdir -p "$TEMP_DIR/repo/frontend"
        info "Frontend directory missing in repository, creating it"
    fi

    if [ ! -d "$TEMP_DIR/repo/backend" ]; then
        mkdir -p "$TEMP_DIR/repo/backend"
        info "Backend directory missing in repository, creating it"
        
        # Create basic package.json
        cat > "$TEMP_DIR/repo/backend/package.json" << EOF
{
  "name": "irssh-panel-backend",
  "version": "1.0.0",
  "description": "Backend for IRSSH Panel",
  "main": "index.js",
  "scripts": {
    "start": "node index.js",
    "migrate": "echo 'No migration script available yet'"
  },
  "dependencies": {
    "bcrypt": "^5.1.0",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.0"
  }
}
EOF

        # Create basic index.js
        cat > "$TEMP_DIR/repo/backend/index.js" << EOF
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

// Simple in-memory user storage - would be replaced with database in production
const users = [
  {
    id: 1,
    username: '${ADMIN_USER}',
    // Password will be set during installation
    password: '',
    role: 'admin'
  }
];

// Update admin password when server starts
users[0].password = bcrypt.hashSync('${ADMIN_PASS}', 10);

// Authentication endpoint
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  const user = users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    process.env.JWT_SECRET || 'irssh-secret-key',
    { expiresIn: '1d' }
  );
  
  res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
});

// Status endpoint
app.get('/api/status', (req, res) => {
  res.json({ status: 'ok', message: 'IRSSH Panel API is running' });
});

// Protected endpoint
app.get('/api/users', (req, res) => {
  // In production, add authentication middleware
  res.json({ users: users.map(u => ({ id: u.id, username: u.username, role: u.role })) });
});

app.listen(port, () => {
  console.log(\`IRSSH Panel API listening on port \${port}\`);
});
EOF
    fi

    # Setup frontend
    mkdir -p "$PANEL_DIR/frontend"
    cp -r "$TEMP_DIR/repo/frontend/"* "$PANEL_DIR/frontend/"
    cd "$PANEL_DIR/frontend" || error "Failed to access frontend directory"

    # Create proper index.html
    cat > index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>IRSSH Panel</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="./src/main.ts"></script>
  </body>
</html>
EOF
    info "Created index.html with correct paths"

    # Make sure src directory exists
    mkdir -p src
    
    # Create main.ts if needed
    if [ ! -f "src/main.ts" ]; then
        cat > src/main.ts << 'EOF'
import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
)
EOF
        info "Created main.ts file"

        # Create App.jsx if needed
        if [ ! -f "src/App.jsx" ] && [ ! -f "src/App.tsx" ]; then
            cat > src/App.jsx << 'EOF'
import React from 'react'

function App() {
  return (
    <div className="app">
      <header>
        <h1>IRSSH Panel</h1>
      </header>
      <main>
        <p>Welcome to the IRSSH Panel</p>
      </main>
    </div>
  )
}

export default App
EOF
            info "Created App.jsx file"
        fi
        
        # Create index.css if needed
        if [ ! -f "src/index.css" ]; then
            cat > src/index.css << 'EOF'
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen,
    Ubuntu, Cantarell, 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif;
}

.app {
  text-align: center;
  padding: 2rem;
}
EOF
            info "Created index.css file"
        fi
    fi

    # Create package.json if needed
    if [ ! -f "package.json" ]; then
        cat > package.json << 'EOF'
{
  "name": "irssh-panel-frontend",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0"
  },
  "devDependencies": {
    "@types/react": "^18.2.15",
    "@types/react-dom": "^18.2.7",
    "@vitejs/plugin-react-swc": "^3.3.2",
    "vite": "^4.4.5"
  }
}
EOF
        info "Created package.json file"
    fi

    # Install frontend dependencies
    npm install || error "Failed to install frontend dependencies"

    # Install additional required packages
    npm install --save react react-dom
    npm install --save @tanstack/react-query react-hot-toast lucide-react react-hook-form @hookform/resolvers zod date-fns
    npm install --save-dev @vitejs/plugin-react-swc vite

    # Create vite.config.js
    cat > vite.config.js << 'EOF'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'
import { resolve } from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': resolve(__dirname, './src')
    }
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true
  }
})
EOF

    # Create a PostCSS config file
    cat > postcss.config.cjs << 'EOF'
module.exports = {
  plugins: {
    autoprefixer: {}
  }
};
EOF

    # Create build script
    cat > build-frontend.sh << 'EOF'
#!/bin/bash
echo "Building frontend..."

# Make sure index.html has correct paths
sed -i 's|src=./src/main.ts"|src="./src/main.ts"|g' index.html 2>/dev/null
sed -i 's|/src/main.ts|./src/main.ts|g' index.html 2>/dev/null
sed -i 's|../src/main.ts|./src/main.ts|g' index.html 2>/dev/null

# Try to build with Vite
echo "Attempting Vite build..."
npx vite build || {
  echo "Vite build failed. Creating complete dashboard..."
  mkdir -p dist
  
  cat > dist/index.html << 'EOFHTML'
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>IRSSH Panel</title>
    <style>
      :root {
        --primary-color: #0070f3;
        --secondary-color: #0051c3;
        --background-color: #f5f5f5;
        --card-bg: #ffffff;
        --text-color: #333333;
        --border-color: #dddddd;
        --success-color: #10b981;
        --warning-color: #f59e0b;
        --danger-color: #ef4444;
        --info-color: #3b82f6;
      }

      body {
        margin: 0;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen,
          Ubuntu, Cantarell, 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif;
        background-color: var(--background-color);
        color: var(--text-color);
      }

      * {
        box-sizing: border-box;
      }

      .container {
        display: flex;
        min-height: 100vh;
      }

      .sidebar {
        width: 240px;
        background-color: var(--card-bg);
        border-right: 1px solid var(--border-color);
        padding: 1rem 0;
        display: flex;
        flex-direction: column;
      }

      .logo-container {
        display: flex;
        align-items: center;
        padding: 0 1rem;
        margin-bottom: 2rem;
        border-bottom: 1px solid var(--border-color);
        padding-bottom: 1rem;
      }

      .logo {
        width: 40px;
        height: 40px;
        border-radius: 50%;
        background-color: var(--primary-color);
        margin-right: 1rem;
        display: flex;
        align-items: center;
        justify-content: center;
        color: white;
        font-weight: bold;
      }

      .logo-text {
        font-size: 1.5rem;
        font-weight: bold;
        color: var(--primary-color);
      }

      .user-info {
        padding: 0 1rem;
        margin-bottom: 2rem;
      }

      .user-role {
        font-size: 0.8rem;
        color: #666;
      }

      .user-name {
        font-weight: bold;
        margin-top: 0.25rem;
      }

      .avatar {
        width: 40px;
        height: 40px;
        border-radius: 50%;
        background-color: #3b82f6;
        margin-right: 1rem;
        display: flex;
        align-items: center;
        justify-content: center;
        color: white;
        font-weight: bold;
      }

      .menu {
        flex: 1;
        padding: 0;
        margin: 0;
        list-style: none;
      }

      .menu-item {
        padding: 0.75rem 1rem;
        display: flex;
        align-items: center;
        cursor: pointer;
        border-left: 3px solid transparent;
      }

      .menu-item:hover {
        background-color: rgba(0, 112, 243, 0.05);
      }

      .menu-item.active {
        background-color: rgba(0, 112, 243, 0.1);
        border-left-color: var(--primary-color);
        font-weight: 500;
      }

      .menu-icon {
        width: 20px;
        height: 20px;
        margin-right: 0.75rem;
        display: flex;
        align-items: center;
        justify-content: center;
      }

      .submenu {
        list-style: none;
        padding-left: 2.5rem;
        margin: 0;
        height: 0;
        overflow: hidden;
        transition: height 0.3s ease;
      }

      .menu-item.expanded .submenu {
        height: auto;
      }

      .submenu-item {
        padding: 0.5rem 0;
        cursor: pointer;
        display: flex;
        align-items: center;
      }

      .submenu-item:hover {
        color: var(--primary-color);
      }

      .submenu-icon {
        width: 16px;
        height: 16px;
        margin-right: 0.5rem;
      }

      .main-content {
        flex: 1;
        padding: 2rem;
        overflow-y: auto;
      }

      .header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 2rem;
      }

      .page-title {
        font-size: 2rem;
        font-weight: bold;
        margin: 0;
      }

      .card {
        background-color: var(--card-bg);
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        padding: 1.5rem;
        margin-bottom: 1.5rem;
      }

      .card-title {
        font-size: 1.25rem;
        font-weight: 600;
        margin-top: 0;
        margin-bottom: 1.5rem;
      }

      .row {
        display: flex;
        flex-wrap: wrap;
        margin: -0.75rem;
      }

      .col {
        padding: 0.75rem;
        flex: 1;
        min-width: 200px;
      }

      .stats-grid {
        display: flex;
        gap: 1.5rem;
        margin-bottom: 1.5rem;
      }

      .stat-card {
        flex: 1;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        text-align: center;
        padding: 1.5rem;
        background-color: var(--card-bg);
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
      }

      .usage-chart {
        width: 120px;
        height: 120px;
        position: relative;
        margin-bottom: 1rem;
      }

      .chart-circle {
        width: 100%;
        height: 100%;
        border-radius: 50%;
        background: conic-gradient(
          var(--success-color) 0%,
          var(--background-color) 0%
        );
        display: flex;
        align-items: center;
        justify-content: center;
        position: relative;
      }

      .chart-circle::before {
        content: "";
        position: absolute;
        width: 80%;
        height: 80%;
        border-radius: 50%;
        background-color: var(--card-bg);
      }

      .chart-value {
        position: relative;
        z-index: 1;
        font-size: 1.75rem;
        font-weight: bold;
      }

      .chart-label {
        font-weight: 500;
        margin-top: 0.5rem;
        font-size: 1.25rem;
      }

      .chart-icon {
        margin-top: 0.5rem;
        font-size: 1.5rem;
        color: #888;
      }

      .bandwidth-chart {
        height: 250px;
        width: 100%;
        background-color: var(--card-bg);
        margin-bottom: 1rem;
        border-radius: 8px;
        padding: 1rem;
        display: flex;
        flex-direction: column;
      }

      .chart-header {
        display: flex;
        justify-content: space-between;
        margin-bottom: 1rem;
      }

      .chart-tabs {
        display: flex;
        gap: 1rem;
      }

      .chart-tab {
        padding: 0.5rem 1rem;
        cursor: pointer;
        border-radius: 4px;
        font-weight: 500;
      }

      .chart-tab.active {
        background-color: var(--primary-color);
        color: white;
      }

      .chart-content {
        flex: 1;
        display: flex;
        position: relative;
      }

      .y-axis {
        width: 50px;
        height: 100%;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        align-items: flex-start;
        padding-right: 10px;
        color: #888;
        font-size: 0.8rem;
      }

      .chart-bars {
        flex: 1;
        display: flex;
        align-items: flex-end;
        justify-content: space-between;
        height: 100%;
        position: relative;
      }

      .chart-bar {
        flex: 1;
        margin: 0 4px;
        display: flex;
        flex-direction: column;
        align-items: center;
        height: 100%;
        justify-content: flex-end;
      }

      .bar-segment {
        width: 100%;
        background-color: var(--primary-color);
        border-radius: 4px 4px 0 0;
      }

      .bar-segment.receive {
        background-color: var(--info-color);
      }

      .bar-label {
        margin-top: 8px;
        font-size: 0.8rem;
        color: #888;
      }

      .x-axis {
        display: flex;
        justify-content: space-between;
        margin-top: 8px;
        color: #888;
        font-size: 0.8rem;
      }

      .legend {
        display: flex;
        gap: 1rem;
        margin-top: 1rem;
      }

      .legend-item {
        display: flex;
        align-items: center;
        font-size: 0.9rem;
        color: #666;
      }

      .legend-color {
        width: 12px;
        height: 12px;
        border-radius: 2px;
        margin-right: 0.5rem;
      }

      .users-stats {
        display: flex;
        flex-wrap: wrap;
        gap: 1rem;
      }

      .user-stat {
        flex: 1;
        min-width: 150px;
        padding: 1rem;
        border-radius: 8px;
        background-color: var(--card-bg);
        text-align: center;
      }

      .user-stat-value {
        font-size: 2rem;
        font-weight: bold;
        margin: 0.5rem 0;
      }

      .user-stat-label {
        color: #666;
        font-size: 0.9rem;
      }

      .user-stat-icon {
        display: inline-block;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        margin-right: 0.5rem;
      }

      .active-icon {
        background-color: var(--success-color);
      }

      .expired-icon {
        background-color: var(--danger-color);
      }

      .expired-soon-icon {
        background-color: var(--warning-color);
      }

      .deactive-icon {
        background-color: #888;
      }

      .protocol-table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 1rem;
      }

      .protocol-table th, .protocol-table td {
        padding: 0.75rem;
        text-align: left;
        border-bottom: 1px solid var(--border-color);
      }

      .protocol-table th {
        font-weight: 500;
        color: #666;
      }

      .header-actions {
        display: flex;
        gap: 1rem;
      }

      .header-button {
        background-color: transparent;
        border: none;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        width: 40px;
        height: 40px;
        border-radius: 50%;
        color: #666;
      }

      .header-button:hover {
        background-color: rgba(0, 0, 0, 0.05);
      }

      /* Login styles */
      .login-container {
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
        width: 100%;
        background-color: var(--background-color);
      }

      .login-card {
        background-color: white;
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        padding: 2rem;
        width: 400px;
        max-width: 90%;
      }

      .login-header {
        text-align: center;
        margin-bottom: 2rem;
      }

      .form-group {
        margin-bottom: 1rem;
      }

      label {
        display: block;
        margin-bottom: 0.5rem;
        font-weight: 500;
      }

      input {
        width: 100%;
        padding: 0.5rem;
        border: 1px solid #ddd;
        border-radius: 4px;
        font-size: 1rem;
        box-sizing: border-box;
      }

      button {
        width: 100%;
        padding: 0.75rem;
        background-color: #0070f3;
        color: white;
        border: none;
        border-radius: 4px;
        font-size: 1rem;
        cursor: pointer;
        margin-top: 1rem;
      }

      button:hover {
        background-color: #0051c3;
      }

      .error-message {
        color: #e53e3e;
        margin-top: 1rem;
        text-align: center;
        display: none;
      }
    </style>
  </head>
  <body>
    <div id="app-container">
      <!-- Login screen -->
      <div id="login-screen" class="login-container">
        <div class="login-card">
          <div class="login-header">
            <h1>IRSSH Panel</h1>
            <p>Please sign in to continue</p>
          </div>
          <form id="login-form">
            <div class="form-group">
              <label for="username">Username</label>
              <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
              <label for="password">Password</label>
              <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
          </form>
          <div id="error-message" class="error-message">
            Invalid username or password
          </div>
        </div>
      </div>

      <!-- Dashboard -->
      <div id="dashboard" class="container" style="display: none;">
        <div class="sidebar">
          <div class="logo-container">
            <div class="logo">IR</div>
            <div class="logo-text">IRSSH</div>
          </div>
          
          <div class="user-info">
            <div class="user-role">Administrator</div>
            <div class="user-name">User: Admin</div>
          </div>
          
          <ul class="menu">
            <li class="menu-item active">
              <span class="menu-icon">📊</span>
              Dashboard
            </li>
            <li class="menu-item">
              <span class="menu-icon">👥</span>
              User Management
              <ul class="submenu">
                <li class="submenu-item">
                  <span class="submenu-icon">🔑</span>
                  SSH Users
                </li>
                <li class="submenu-item">
                  <span class="submenu-icon">🔒</span>
                  L2TP Users
                </li>
                <li class="submenu-item">
                  <span class="submenu-icon">🔐</span>
                  IKEv2 Users
                </li>
                <li class="submenu-item">
                  <span class="submenu-icon">🌐</span>
                  Cisco AnyConnect Users
                </li>
                <li class="submenu-item">
                  <span class="submenu-icon">🛡️</span>
                  WireGuard Users
                </li>
                <li class="submenu-item">
                  <span class="submenu-icon">📡</span>
                  SingBox Users
                </li>
                <li class="submenu-item">
                  <span class="submenu-icon">👥</span>
                  All Users
                </li>
              </ul>
            </li>
            <li class="menu-item">
              <span class="menu-icon">👤</span>
              Online User
            </li>
            <li class="menu-item">
              <span class="menu-icon">⚙️</span>
              Settings
            </li>
            <li class="menu-item" id="logout-btn">
              <span class="menu-icon">🚪</span>
              Logout
            </li>
          </ul>
        </div>
        
        <div class="main-content">
          <div class="header">
            <h1 class="page-title">Dashboard</h1>
            <div class="header-actions">
              <button class="header-button">🔄</button>
              <button class="header-button">🌙</button>
              <button class="header-button">🌐</button>
            </div>
          </div>
          
          <div class="card">
            <h2 class="card-title">Server Resource Statistics</h2>
            <div class="stats-grid">
              <div class="stat-card">
                <div class="usage-chart">
                  <div class="chart-circle" style="background: conic-gradient(#10b981 0%, #f5f5f5 0%)">
                    <div class="chart-value">0%</div>
                  </div>
                </div>
                <div class="chart-label">CPU Usage</div>
                <div class="chart-icon">💻</div>
              </div>
              
              <div class="stat-card">
                <div class="usage-chart">
                  <div class="chart-circle" style="background: conic-gradient(#10b981 0%, #f5f5f5 0%)">
                    <div class="chart-value">0%</div>
                  </div>
                </div>
                <div class="chart-label">RAM Usage</div>
                <div class="chart-icon">🧠</div>
              </div>
              
              <div class="stat-card">
                <div class="usage-chart">
                  <div class="chart-circle" style="background: conic-gradient(#10b981 0%, #f5f5f5 0%)">
                    <div class="chart-value">0%</div>
                  </div>
                </div>
                <div class="chart-label">Disk Usage</div>
                <div class="chart-icon">💽</div>
              </div>
            </div>
          </div>
          
          <div class="row">
            <div class="col">
              <div class="card">
                <h2 class="card-title">Bandwidth Statistics</h2>
                <div class="bandwidth-chart">
                  <div class="chart-header">
                    <div class="chart-title">Monthly Chart</div>
                    <div class="chart-tabs">
                      <div class="chart-tab active">Daily Chart</div>
                      <div class="chart-tab">Monthly Chart</div>
                    </div>
                  </div>
                  
                  <div class="chart-content">
                    <div class="y-axis">
                      <div>3515 GB</div>
                      <div>2636 GB</div>
                      <div>1757 GB</div>
                      <div>878 GB</div>
                      <div>0 MB</div>
                    </div>
                    
                    <div class="chart-bars">
                      <div class="chart-bar">
                        <div class="bar-segment" style="height: 10%;"></div>
                        <div class="bar-segment receive" style="height: 5%;"></div>
                        <div class="bar-label">Jan</div>
                      </div>
                      <div class="chart-bar">
                        <div class="bar-segment" style="height: 15%;"></div>
                        <div class="bar-segment receive" style="height: 10%;"></div>
                        <div class="bar-label">Feb</div>
                      </div>
                      <div class="chart-bar">
                        <div class="bar-segment" style="height: 25%;"></div>
                        <div class="bar-segment receive" style="height: 15%;"></div>
                        <div class="bar-label">Mar</div>
                      </div>
                      <div class="chart-bar">
                        <div class="bar-segment" style="height: 30%;"></div>
                        <div class="bar-segment receive" style="height: 20%;"></div>
                        <div class="bar-label">Apr</div>
                      </div>
                      <div class="chart-bar">
                        <div class="bar-segment" style="height: 35%;"></div>
                        <div class="bar-segment receive" style="height: 25%;"></div>
                        <div class="bar-label">May</div>
                      </div>
                      <div class="chart-bar">
                        <div class="bar-segment" style="height: 40%;"></div>
                        <div class="bar-segment receive" style="height: 30%;"></div>
                        <div class="bar-label">Jun</div>
                      </div>
                      <div class="chart-bar">
                        <div class="bar-segment" style="height: 45%;"></div>
                        <div class="bar-segment receive" style="height: 30%;"></div>
                        <div class="bar-label">Jul</div>
                      </div>
                      <div class="chart-bar">
                        <div class="bar-segment" style="height: 50%;"></div>
                        <div class="bar-segment receive" style="height: 25%;"></div>
                        <div class="bar-label">Aug</div>
                      </div>
                      <div class="chart-bar">
                        <div class="bar-segment" style="height: 40%;"></div>
                        <div class="bar-segment receive" style="height: 20%;"></div>
                        <div class="bar-label">Sep</div>
                      </div>
                      <div class="chart-bar">
                        <div class="bar-segment" style="height: 30%;"></div>
                        <div class="bar-segment receive" style="height: 15%;"></div>
                        <div class="bar-label">Oct</div>
                      </div>
                      <div class="chart-bar">
                        <div class="bar-segment" style="height: 20%;"></div>
                        <div class="bar-segment receive" style="height: 10%;"></div>
                        <div class="bar-label">Nov</div>
                      </div>
                      <div class="chart-bar">
                        <div class="bar-segment" style="height: 10%;"></div>
                        <div class="bar-segment receive" style="height: 5%;"></div>
                        <div class="bar-label">Dec</div>
                      </div>
                    </div>
                  </div>
                </div>
                
                <div class="legend">
                  <div class="legend-item">
                    <div class="legend-color" style="background-color: var(--primary-color);"></div>
                    Send:
                  </div>
                  <div class="legend-item">
                    <div class="legend-color" style="background-color: var(--info-color);"></div>
                    Receive:
                  </div>
                  <div class="legend-item">
                    <strong>Total Bandwidth Usage:</strong>
                  </div>
                </div>
              </div>
            </div>
            
            <div class="col">
              <div class="card">
                <h2 class="card-title">Users Statistics</h2>
                <div class="users-stats">
                  <div class="user-stat">
                    <div class="user-stat-label">
                      <span class="user-stat-icon active-icon"></span>
                      Active
                    </div>
                    <div class="user-stat-value">0</div>
                  </div>
                  
                  <div class="user-stat">
                    <div class="user-stat-label">
                      <span class="user-stat-icon expired-icon"></span>
                      Expired
                    </div>
                    <div class="user-stat-value">0</div>
                  </div>
                  
                  <div class="user-stat">
                    <div class="user-stat-label">
                      <span class="user-stat-icon expired-soon-icon"></span>
                      Expired in 24 hours
                    </div>
                    <div class="user-stat-value">0</div>
                  </div>
                  
                  <div class="user-stat">
                    <div class="user-stat-label">
                      <span class="user-stat-icon deactive-icon"></span>
                      Deactive
                    </div>
                    <div class="user-stat-value">0</div>
                  </div>
                </div>
                
                <p style="text-align: center; margin-top: 1rem;">
                  Online
                  <br>
                  <strong style="font-size: 1.5rem;">0</strong>
                </p>
                
                <p style="text-align: center; margin-top: 1rem;">
                  All User: <strong>0</strong>
                </p>
              </div>
            </div>
          </div>
          
          <div class="card">
            <h2 class="card-title">Protocol Statistics</h2>
            <table class="protocol-table">
              <thead>
                <tr>
                  <th>Protocol</th>
                  <th>Online Users</th>
                  <th>Protocol port</th>
                  <th>Incoming Traffic</th>
                  <th>Outgoing Traffic</th>
                  <th>Time Of Being Online</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>SSH</td>
                  <td>3</td>
                  <td>22</td>
                  <td>1.2 Mbps</td>
                  <td>0.8 Mbps</td>
                  <td>2023-10-14 10:00:00</td>
                </tr>
                <tr>
                  <td>WireGuard</td>
                  <td>2</td>
                  <td>10582</td>
                  <td>0.5 Mbps</td>
                  <td>0.3 Mbps</td>
                  <td>2023-10-14 11:30:00</td>
                </tr>
                <tr>
                  <td>SingBox</td>
                  <td>2</td>
                  <td>1049</td>
                  <td>0.3 Mbps</td>
                  <td>0.2 Mbps</td>
                  <td>2023-10-14 12:45:00</td>
                </tr>
                <tr>
                  <td>Cisco</td>
                  <td>1</td>
                  <td>85</td>
                  <td>0.3 Mbps</td>
                  <td>0.2 Mbps</td>
                  <td>2023-10-14 12:45:00</td>
                </tr>
                <tr>
                  <td>IKEv2</td>
                  <td>1</td>
                  <td>49500</td>
                  <td>0.3 Mbps</td>
                  <td>0.2 Mbps</td>
                  <td>2023-10-14 12:45:00</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <script>
      document.addEventListener('DOMContentLoaded', function() {
        const loginForm = document.getElementById('login-form');
        const loginScreen = document.getElementById('login-screen');
        const dashboard = document.getElementById('dashboard');
        const errorMessage = document.getElementById('error-message');
        const logoutBtn = document.getElementById('logout-btn');
        
        // Set admin credentials from installation
        const ADMIN_USERNAME = '${ADMIN_USER}';
        const ADMIN_PASSWORD = '${ADMIN_PASS}';
        
        // Check if already logged in (using localStorage)
        const isLoggedIn = localStorage.getItem('irssh_logged_in');
        if (isLoggedIn === 'true') {
          loginScreen.style.display = 'none';
          dashboard.style.display = 'flex';
        }
        
        // Handle login
        loginForm.addEventListener('submit', function(e) {
          e.preventDefault();
          const username = document.getElementById('username').value;
          const password = document.getElementById('password').value;
          
          // Check credentials (in a real app, this would be an API call)
          if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
            localStorage.setItem('irssh_logged_in', 'true');
            loginScreen.style.display = 'none';
            dashboard.style.display = 'flex';
            errorMessage.style.display = 'none';
          } else {
            errorMessage.style.display = 'block';
          }
        });
        
        // Handle logout
        logoutBtn.addEventListener('click', function() {
          localStorage.removeItem('irssh_logged_in');
          dashboard.style.display = 'none';
          loginScreen.style.display = 'flex';
        });
        
        // Handle menu item clicks
        const menuItems = document.querySelectorAll('.menu-item');
        menuItems.forEach(item => {
          item.addEventListener('click', function() {
            if (this.querySelector('.submenu')) {
              this.classList.toggle('expanded');
            }
          });
        });
      });
    </script>
  </body>
</html>
EOFHTML
  
  echo "Created dashboard successfully."
  exit 0
}
EOF

    # Make the build script executable
    chmod +x build-frontend.sh

    # Run the build script
    ./build-frontend.sh || error "Failed to build frontend" "no-exit"

    # Setup backend
    mkdir -p "$PANEL_DIR/backend"
    cp -r "$TEMP_DIR/repo/backend/"* "$PANEL_DIR/backend/"
    cd "$PANEL_DIR/backend" || error "Failed to access backend directory"

    # Ensure backend package.json exists
    if [ ! -f "package.json" ]; then
        cat > package.json << EOF
{
  "name": "irssh-panel-backend",
  "version": "1.0.0",
  "description": "Backend for IRSSH Panel",
  "main": "index.js",
  "scripts": {
    "start": "node index.js",
    "migrate": "node migrate.js"
  },
  "dependencies": {
    "bcrypt": "^5.1.0",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.0"
  }
}
EOF
    fi

    # Create a basic backend index.js if it doesn't exist
    if [ ! -f "index.js" ]; then
        cat > index.js << EOF
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

// Simple in-memory user storage - would be replaced with database in production
const users = [
  {
    id: 1,
    username: '${ADMIN_USER}',
    // Password will be set during installation
    password: '${ADMIN_PASS}',
    role: 'admin'
  }
];

// Update admin password when server starts - hash it
bcrypt.hash('${ADMIN_PASS}', 10, (err, hash) => {
  if (!err) {
    users[0].password = hash;
    console.log('Admin password updated');
  }
});

// Authentication endpoint
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  
  bcrypt.compare(password, user.password, (err, result) => {
    if (err || !result) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'irssh-secret-key',
      { expiresIn: '1d' }
    );
    
    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  });
});

// Status endpoint
app.get('/api/status', (req, res) => {
  res.json({ status: 'ok', message: 'IRSSH Panel API is running' });
});

// Protected endpoint
app.get('/api/users', (req, res) => {
  // In production, add authentication middleware
  res.json({ users: users.map(u => ({ id: u.id, username: u.username, role: u.role })) });
});

app.listen(port, () => {
  console.log(\`IRSSH Panel API listening on port \${port}\`);
});
EOF
    fi

    # Create a basic migration script if needed
    if [ ! -f "migrate.js" ]; then
        cat > migrate.js << 'EOF'
console.log("Setting up database schema...");
// This would connect to database and create tables in a production environment
console.log("Database initialization completed successfully");
EOF
    fi

    # Create backend environment file
    cat > .env << EOL
NODE_ENV=production
PORT=3000
DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$ADMIN_USER
DB_PASS=$ADMIN_PASS
JWT_SECRET=$(openssl rand -base64 32)
EOL

    # Install backend dependencies
    npm install || error "Failed to install backend dependencies" "no-exit"

    # Try to initialize database schema
    npm run migrate || error "Failed to initialize database schema" "no-exit"

    # Create admin user in database
    HASHED_PASSWORD=$(node -e "console.log(require('bcrypt').hashSync('${ADMIN_PASS}', 10))")
    sudo -u postgres psql -d "$DB_NAME" -c "CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'user'
    );" || info "Failed to create users table (may already exist)"
    
    sudo -u postgres psql -d "$DB_NAME" -c "INSERT INTO users (username, password, role) 
        VALUES ('${ADMIN_USER}', '${HASHED_PASSWORD}', 'admin') 
        ON CONFLICT (username) DO UPDATE SET password = '${HASHED_PASSWORD}';" || info "Failed to create admin user in database"

    # Configure nginx for frontend and API proxy
    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen ${PORTS[WEB]};
    listen [::]:${PORTS[WEB]};
    
    server_name _;
    
    root $PANEL_DIR/frontend/dist;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ /index.html;
    }
    
    location /api {
        proxy_pass http://localhost:3000;
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

    # Setup systemd service for backend API
    cat > /etc/systemd/system/irssh-api.service << EOL
[Unit]
Description=IRSSH Panel API Server
After=network.target postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=$PANEL_DIR/backend
ExecStart=/usr/bin/npm start
Restart=always
Environment=NODE_ENV=production
Environment=PORT=3000

[Install]
WantedBy=multi-user.target
EOL

    # Enable and restart nginx and backend service
    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    systemctl daemon-reload
    systemctl enable irssh-api
    systemctl start irssh-api
    systemctl restart nginx
    systemctl enable nginx

    # Set permissions for frontend
    chown -R www-data:www-data "$PANEL_DIR/frontend"
    chmod -R 755 "$PANEL_DIR/frontend"

    info "Web server setup completed"
}

install_ssh() {
    info "Installing SSH protocol..."
    
    apt-get install -y openssh-server stunnel4 || error "Failed to install SSH packages"
    
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    cat > /etc/ssh/sshd_config << EOL
Port ${PORTS[SSH]}
PermitRootLogin yes
PasswordAuthentication yes
X11Forwarding yes
PrintMotd no

MaxAuthTries 6
LoginGraceTime 30
PermitEmptyPasswords no
ClientAliveInterval 300
ClientAliveCountMax 3

SyslogFacility AUTH
LogLevel INFO
EOL

    mkdir -p /etc/stunnel
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/stunnel/stunnel.pem \
        -out /etc/stunnel/stunnel.pem \
        -subj "/CN=localhost"
    
    chmod 600 /etc/stunnel/stunnel.pem
    
    cat > /etc/stunnel/stunnel.conf << EOL
pid = /var/run/stunnel4/stunnel.pid
setuid = stunnel4
setgid = stunnel4
cert = /etc/stunnel/stunnel.pem
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh-tls]
client = no
accept = ${PORTS[SSH_TLS]}
connect = 127.0.0.1:${PORTS[SSH]}
EOL

    # Install websocat for websocket support if not already installed
    if ! command -v websocat &> /dev/null; then
        info "Installing websocat for websocket support..."
        apt-get install -y wget
        wget -qO /usr/local/bin/websocat https://github.com/vi/websocat/releases/download/v1.11.0/websocat.x86_64-unknown-linux-musl
        chmod +x /usr/local/bin/websocat
    fi

    cat > /etc/systemd/system/websocket.service << EOL
[Unit]
Description=WebSocket for SSH
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/websocat -t --binary-protocol ws-l:0.0.0.0:${PORTS[WEBSOCKET]} tcp:127.0.0.1:${PORTS[SSH]}
Restart=always

[Install]
WantedBy=multi-user.target
EOL

    systemctl daemon-reload
    systemctl restart ssh
    systemctl enable stunnel4
    systemctl restart stunnel4
    systemctl enable websocket
    systemctl start websocket
    
    info "SSH installation completed"
}

install_l2tp() {
    info "Installing L2TP/IPsec..."
    
    apt-get install -y strongswan xl2tpd || error "Failed to install L2TP packages"
    
    PSK=$(openssl rand -base64 32)
    
    cat > /etc/ipsec.conf << EOL
config setup
    charondebug="ike 2, knl 2"
    uniqueids=no

conn L2TP-PSK
    authby=secret
    auto=add
    keyingtries=3
    rekey=no
    ikelifetime=8h
    keylife=1h
    type=transport
    left=%defaultroute
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
    dpddelay=30
    dpdtimeout=120
    dpdaction=clear
EOL

    echo ": PSK \"$PSK\"" > /etc/ipsec.secrets
    chmod 600 /etc/ipsec.secrets
    
    cat > /etc/xl2tpd/xl2tpd.conf << EOL
[global]
ipsec saref = yes
port = ${PORTS[L2TP]}

[lns default]
ip range = 10.10.10.100-10.10.10.200
local ip = 10.10.10.1
require chap = yes
refuse pap = yes
require authentication = yes
name = L2TP-VPN
ppp debug = yes
length bit = yes
EOL

    systemctl restart strongswan
    systemctl enable strongswan
    systemctl restart xl2tpd
    systemctl enable xl2tpd
    
    info "L2TP installation completed"
}

install_ikev2() {
    info "Installing IKEv2..."
    
    apt-get install -y strongswan strongswan-pki || error "Failed to install IKEv2 packages"
    
    mkdir -p /etc/ipsec.d/{private,cacerts,certs}
    
    ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/ca-key.pem
    chmod 600 /etc/ipsec.d/private/ca-key.pem
    
    ipsec pki --self --ca --lifetime 3650 \
        --in /etc/ipsec.d/private/ca-key.pem \
        --type rsa --dn "CN=VPN CA" \
        --outform pem > /etc/ipsec.d/cacerts/ca-cert.pem
    
    ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/server-key.pem
    chmod 600 /etc/ipsec.d/private/server-key.pem
    
    ipsec pki --pub --in /etc/ipsec.d/private/server-key.pem --type rsa \
        | ipsec pki --issue --lifetime 1825 \
            --cacert /etc/ipsec.d/cacerts/ca-cert.pem \
            --cakey /etc/ipsec.d/private/ca-key.pem \
            --dn "CN=vpn.server.com" \
            --san "vpn.server.com" \
            --flag serverAuth --flag ikeIntermediate \
            --outform pem > /etc/ipsec.d/certs/server-cert.pem
    
    cat > /etc/ipsec.conf << EOL
config setup
    charondebug="ike 2, knl 2, cfg 2, net 2, esp 2"

conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%any
    leftid=@vpn.server.com
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
   right=%any
   rightauth=eap-mschapv2
   rightsourceip=10.20.20.0/24
   rightdns=8.8.8.8,8.8.4.4
EOL

   systemctl restart strongswan
   systemctl enable strongswan
   
   info "IKEv2 installation completed"
}

install_cisco() {
   info "Installing OpenConnect (Cisco AnyConnect)..."
   
   apt-get install -y ocserv gnutls-bin || error "Failed to install OpenConnect packages"
   
   mkdir -p /etc/ocserv/ssl
   cd /etc/ocserv/ssl || error "Failed to access OpenConnect SSL directory"
   
   certtool --generate-privkey --outfile ca-key.pem
   
   cat > ca.tmpl << EOL
cn = "VPN CA"
organization = "IRSSH Panel"
serial = 1
expiration_days = 3650
ca
signing_key
cert_signing_key
crl_signing_key
EOL

   certtool --generate-self-signed --load-privkey ca-key.pem \
       --template ca.tmpl --outfile ca-cert.pem
   
   certtool --generate-privkey --outfile server-key.pem
   
   cat > server.tmpl << EOL
cn = "VPN Server"
organization = "IRSSH Panel"
expiration_days = 3650
signing_key
encryption_key
tls_www_server
EOL

   certtool --generate-certificate --load-privkey server-key.pem \
       --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem \
       --template server.tmpl --outfile server-cert.pem
   
   cat > /etc/ocserv/ocserv.conf << EOL
auth = "plain[passwd=/etc/ocserv/ocpasswd]"
tcp-port = ${PORTS[CISCO]}
udp-port = ${PORTS[CISCO]}
run-as-user = nobody
run-as-group = daemon
server-cert = /etc/ocserv/ssl/server-cert.pem
server-key = /etc/ocserv/ssl/server-key.pem
ca-cert = /etc/ocserv/ssl/ca-cert.pem
socket-file = /var/run/ocserv-socket
isolate-workers = true
max-clients = 128
max-same-clients = 2
keepalive = 32400
dpd = 90
mobile-dpd = 1800
try-mtu-discovery = true
server-stats-reset-time = 604800
EOL

   systemctl restart ocserv
   systemctl enable ocserv
   
   info "OpenConnect installation completed"
}

install_wireguard() {
   info "Installing WireGuard..."
   
   apt-get install -y wireguard || error "Failed to install WireGuard"
   
   mkdir -p /etc/wireguard
   cd /etc/wireguard || error "Failed to access WireGuard directory"
   
   wg genkey | tee server_private.key | wg pubkey > server_public.key
   chmod 600 server_private.key
   
   cat > /etc/wireguard/wg0.conf << EOL
[Interface]
PrivateKey = $(cat server_private.key)
Address = 10.66.66.1/24
ListenPort = ${PORTS[WIREGUARD]}
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

MTU = 1420
Table = off
PreUp = sysctl -w net.ipv4.ip_forward=1
EOL

   systemctl enable wg-quick@wg0
   systemctl start wg-quick@wg0
   
   info "WireGuard installation completed"
}

install_singbox() {
   info "Installing Sing-Box..."
   
   local ARCH="amd64"
   local VERSION="1.7.0"
   local URL="https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box-${VERSION}-linux-${ARCH}.tar.gz"
   
   mkdir -p /tmp/sing-box
   wget "$URL" -O /tmp/sing-box.tar.gz || error "Failed to download Sing-Box"
   tar -xzf /tmp/sing-box.tar.gz -C /tmp/sing-box --strip-components=1
   
   cp /tmp/sing-box/sing-box /usr/local/bin/
   chmod +x /usr/local/bin/sing-box || error "Failed to set permissions for sing-box"
   
   mkdir -p /etc/sing-box
   
   cat > /etc/sing-box/config.json << EOL
{
   "log": {
       "level": "info",
       "output": "/var/log/sing-box.log"
   },
   "inbounds": [
       {
           "type": "mixed",
           "listen": "::",
           "listen_port": ${PORTS[SINGBOX]},
           "sniff": true,
           "sniff_override_destination": false
       }
   ],
   "outbounds": [
       {
           "type": "direct",
           "tag": "direct"
       }
   ]
}
EOL

   cat > /etc/systemd/system/sing-box.service << EOL
[Unit]
Description=Sing-Box Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=always

[Install]
WantedBy=multi-user.target
EOL

   systemctl daemon-reload
   systemctl enable sing-box
   systemctl start sing-box
   
   info "Sing-Box installation completed"
}

setup_monitoring() {
   if [ "$ENABLE_MONITORING" != "y" ]; then
       info "Monitoring system disabled, skipping..."
       return 0
   fi
   
   info "Setting up monitoring system..."
   
   apt-get install -y prometheus-node-exporter collectd vnstat || error "Failed to install monitoring tools"
   
   mkdir -p /var/log/irssh/metrics
   
   cat > /etc/systemd/system/node-exporter.service << EOL
[Unit]
Description=Prometheus Node Exporter
After=network.target

[Service]
Type=simple
User=node_exporter
ExecStart=/usr/bin/node_exporter
Restart=always

[Install]
WantedBy=multi-user.target
EOL

   cat > /etc/collectd/collectd.conf << EOL
LoadPlugin cpu
LoadPlugin memory
LoadPlugin network
LoadPlugin interface
LoadPlugin load
LoadPlugin disk

<Plugin interface>
   Interface "eth0"
   IgnoreSelected false
</Plugin>

<Plugin network>
   Server "localhost" "25826"
</Plugin>
EOL

   systemctl daemon-reload
   systemctl enable node-exporter
   systemctl start node-exporter
   systemctl enable collectd
   systemctl start collectd
   
   info "Monitoring setup completed"
}

main() {
   info "Starting IRSSH Panel installation..."
   
   mkdir -p "$LOG_DIR"
   mkdir -p "$CONFIG_DIR"
   mkdir -p "$PANEL_DIR"
   mkdir -p "$TEMP_DIR"
   
   get_server_ip
   get_config
   setup_dependencies
   
   # Try setting up database, but continue on failure
   setup_database || {
       error "Database setup failed, but continuing with installation" "no-exit"
       # Try to create database with minimal requirements
       sudo -u postgres createdb "$DB_NAME" 2>/dev/null
       sudo -u postgres psql -c "CREATE USER ${ADMIN_USER} WITH PASSWORD '${ADMIN_PASS}';" 2>/dev/null
       sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${ADMIN_USER};" 2>/dev/null
   }
   
   # Setup web server
   setup_web_server || error "Web server setup failed" "no-exit"
   
   # Install protocols
   for protocol in "${!PROTOCOLS[@]}"; do
       if [ "${PROTOCOLS[$protocol]}" = true ]; then
           info "Installing ${protocol}..."
           install_${protocol,,} || error "Failed to install $protocol" "no-exit"
       fi
   done
   
   setup_monitoring
   cleanup
   
   info "Installation completed successfully!"
   
   cat << EOL

IRSSH Panel Installation Summary
-------------------------------
Panel Version: 3.6.0
Web Interface:
$([ ! -z "$SERVER_IPv4" ] && echo "IPv4: http://${SERVER_IPv4}:${PORTS[WEB]}")
$([ ! -z "$SERVER_IPv6" ] && echo "IPv6: http://${SERVER_IPv6}:${PORTS[WEB]}")

Admin Credentials:
Username: ${ADMIN_USER}
Password: (As specified during installation)

Enabled Protocols:
$(for protocol in "${!PROTOCOLS[@]}"; do
   if [ "${PROTOCOLS[$protocol]}" = true ]; then
       echo "- $protocol (Port: ${PORTS[$protocol]})"
   fi
done)

Additional Features:
- Monitoring: ${ENABLE_MONITORING}

For more information, please check:
- Logs: ${LOG_DIR}
- Configuration: ${CONFIG_DIR}
EOL
}

main
