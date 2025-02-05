#!/bin/bash

# IRSSH Panel Complete Installation Script
# Version: 3.5.0

# Directories
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
MODULES_DIR="$PANEL_DIR/modules"
PROTOCOLS_DIR="$MODULES_DIR/protocols"
LOG_DIR="/var/log/irssh"
BACKUP_DIR="/opt/irssh-backups"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Utility functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    [[ "${2:-}" != "no-exit" ]] && cleanup && exit 1
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Generate secure keys and passwords
DB_NAME="irssh_panel"
DB_USER="irssh_admin"
DB_PASS=$(openssl rand -base64 32)
ADMIN_PASS=$(openssl rand -base64 16)
JWT_SECRET=$(openssl rand -base64 32)

# Installation modes
INSTALL_SSH=true
INSTALL_DROPBEAR=true
INSTALL_L2TP=true
INSTALL_IKEV2=true
INSTALL_CISCO=true
INSTALL_WIREGUARD=true
INSTALL_SINGBOX=true

# Protocol ports
SSH_PORT=22
DROPBEAR_PORT=22722
WEBSOCKET_PORT=2082
SSH_TLS_PORT=443
L2TP_PORT=1701
IKEV2_PORT=500
CISCO_PORT=443
WIREGUARD_PORT=51820
SINGBOX_PORT=1080
BADVPN_PORT=7300
WEB_PORT=443

# TypeScript Setup Function
setup_typescript() {
    log "Configuring TypeScript environment..."
    cd "$FRONTEND_DIR" || error "Failed to access frontend directory"
    
    # Create tsconfig.json
    cat > tsconfig.json << 'EOL'
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "baseUrl": "./src",
    "paths": {
      "@/*": ["*"],
      "@components/*": ["components/*"],
      "@stores/*": ["stores/*"],
      "@context/*": ["context/*"],
      "@utils/*": ["utils/*"],
      "@hooks/*": ["hooks/*"],
      "@types/*": ["types/*"]
    }
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
}
EOL

    # Create tsconfig.node.json
    cat > tsconfig.node.json << 'EOL'
{
  "compilerOptions": {
    "composite": true,
    "skipLibCheck": true,
    "module": "ESNext",
    "moduleResolution": "bundler",
    "allowSyntheticDefaultImports": true
  },
  "include": ["vite.config.ts"]
}
EOL
}

# Store Management Setup
setup_stores() {
    log "Setting up state management with Zustand..."
    mkdir -p "$FRONTEND_DIR/src/stores"
    
    # Create roleStore.ts
    cat > "$FRONTEND_DIR/src/stores/roleStore.ts" << 'EOL'
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export interface User {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  createdAt: Date;
  lastLogin?: Date;
  status: UserStatus;
  protocol: Protocol;
}

export enum UserRole {
  ADMIN = 'admin',
  USER = 'user',
  RESELLER = 'reseller'
}

export enum UserStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  EXPIRED = 'expired',
  SUSPENDED = 'suspended'
}

export enum Protocol {
  SSH = 'ssh',
  L2TP = 'l2tp',
  IKEV2 = 'ikev2',
  CISCO = 'cisco',
  WIREGUARD = 'wireguard',
  SINGBOX = 'singbox'
}

interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  setUser: (user: User | null) => void;
  setToken: (token: string | null) => void;
  logout: () => void;
}

const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      token: null,
      isAuthenticated: false,
      setUser: (user) => set({ user, isAuthenticated: !!user }),
      setToken: (token) => set({ token }),
      logout: () => set({ user: null, token: null, isAuthenticated: false }),
    }),
    {
      name: 'auth-storage',
    }
  )
);

export default useAuthStore;
EOL

    # Create themeStore.ts
    cat > "$FRONTEND_DIR/src/stores/themeStore.ts" << 'EOL'
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface ThemeState {
  isDark: boolean;
  toggleTheme: () => void;
}

const useThemeStore = create<ThemeState>()(
  persist(
    (set) => ({
      isDark: false,
      toggleTheme: () => set((state) => ({ isDark: !state.isDark })),
    }),
    {
      name: 'theme-storage',
    }
  )
);

export default useThemeStore;
EOL
}

[Previous Code From IRSSHComplete4.sh Goes Here - Including All Protocol Installation Functions]

# Updated Frontend Setup
setup_frontend() {
    log "Setting up frontend application..."
    cd "$FRONTEND_DIR" || error "Failed to access frontend directory"

    # Update package.json with TypeScript support
    cat > package.json << 'EOL'
{
  "name": "irssh-panel-frontend",
  "version": "3.5.0",
  "private": true,
  "dependencies": {
    "@headlessui/react": "^1.7.17",
    "@heroicons/react": "^2.0.18",
    "axios": "^1.6.2",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.21.0",
    "recharts": "^2.10.3",
    "zustand": "^4.4.7",
    "clsx": "^2.0.0",
    "@types/node": "^20.10.4",
    "@types/react": "^18.2.45",
    "@types/react-dom": "^18.2.17",
    "typescript": "^5.3.3"
  },
  "devDependencies": {
    "@typescript-eslint/eslint-plugin": "^6.14.0",
    "@typescript-eslint/parser": "^6.14.0",
    "@vitejs/plugin-react-swc": "^3.5.0",
    "autoprefixer": "^10.4.16",
    "eslint": "^8.55.0",
    "eslint-plugin-react-hooks": "^4.6.0",
    "eslint-plugin-react-refresh": "^0.4.5",
    "postcss": "^8.4.32",
    "tailwindcss": "^3.3.6",
    "vite": "^5.0.7"
  },
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "lint": "eslint src --ext ts,tsx --report-unused-disable-directives --max-warnings 0",
    "preview": "vite preview"
  }
}
EOL

    # Install dependencies
    npm install --legacy-peer-deps || error "Frontend dependency installation failed"

    # Create Vite config
    cat > vite.config.ts << 'EOL'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
})
EOL

    # Build frontend
    npm run build || error "Frontend build failed"
}

# Updated Backend Setup
setup_backend() {
    log "Setting up backend server..."
    cd "$BACKEND_DIR" || error "Failed to access backend directory"

    # Create package.json for backend
    cat > package.json << 'EOL'
{
  "name": "irssh-panel-backend",
  "version": "3.5.0",
  "private": true,
  "scripts": {
    "start": "node src/index.js",
    "start:dev": "nodemon src/index.js",
    "test": "jest",
    "lint": "eslint ."
  },
  "dependencies": {
    "express": "^4.18.2",
    "mongoose": "^8.0.3",
    "jsonwebtoken": "^9.0.2",
    "bcryptjs": "^2.4.3",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "helmet": "^7.1.0",
    "winston": "^3.11.0",
    "express-validator": "^7.0.1",
    "express-rate-limit": "^7.1.5",
    "compression": "^1.7.4"
  },
  "devDependencies": {
    "nodemon": "^3.0.2",
    "jest": "^29.7.0",
    "supertest": "^6.3.3",
    "eslint": "^8.55.0"
  }
}
EOL

    # Install backend dependencies
    npm install || error "Backend dependency installation failed"

    # Setup CORS configuration
    mkdir -p src/middleware
    cat > src/middleware/cors.js << 'EOL'
const cors = require('cors');

const corsOptions = {
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    methods: ['GET', 'POST', 'PUT', DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 86400
};

module.exports = cors(corsOptions);
EOL

    # Create main server file
    cat > src/index.js << 'EOL'
const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const cors = require('./middleware/cors');

const app = express();

// Security middleware
app.use(helmet());
app.use(cors);
app.use(compression());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});
app.use(limiter);

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/users', require('./routes/users'));
app.use('/api/protocols', require('./routes/protocols'));

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
EOL
}

[Rest of the IRSSHComplete4.sh Code Including All Other Functions]

# Main Installation Flow
main() {
    log "Starting IRSSH Panel installation v3.5.0"
    
    check_requirements
    create_backup
    setup_directories
    install_dependencies
    install_protocols
    setup_typescript
    setup_stores
    setup_frontend
    setup_backend
    setup_database
    setup_nginx
    setup_ssl
    setup_firewall
    setup_security
    setup_cron
    verify_installation
    
    save_installation_info
    log "Installation completed successfully!"
}

# Start installation
main
