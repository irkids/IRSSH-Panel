#!/bin/bash

# Advanced Integrated User Management Module for IRSSH-Panel
# Version: 3.0
# This script adds advanced user management capabilities to IRSSH-Panel with optimized resource usage

# Define colors for better output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log function
log() {
    local level=$1
    local message=$2
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    case $level in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} $timestamp - $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $timestamp - $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $timestamp - $message"
            ;;
        "DEBUG")
            if [[ "${DEBUG_MODE}" == "true" ]]; then
                echo -e "${BLUE}[DEBUG]${NC} $timestamp - $message"
            fi
            ;;
        *)
            echo "$timestamp - $message"
            ;;
    esac
    
    # Also log to file if LOG_DIR exists
    if [[ -d "${LOG_DIR}" ]]; then
        echo "[$timestamp] [$level] $message" >> "${LOG_DIR}/user_management.log"
    fi
}

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
   log "ERROR" "This script must be run as root"
   exit 1
fi

# Configuration variables
DEBUG_MODE="false"
PANEL_DIR="/opt/irssh-panel"
CONFIG_DIR="/etc/enhanced_ssh"
LOG_DIR="/var/log/irssh"
BACKUP_DIR="/opt/irssh-backups"
BASE_DIR="${PANEL_DIR}"
BACKEND_DIR="${BASE_DIR}/backend"
SERVICES_DIR="${BASE_DIR}/services"
SCRIPTS_DIR="${BASE_DIR}/scripts"
MODULES_DIR="${BASE_DIR}/modules"
FRONTEND_DIR="${BASE_DIR}/frontend"
MONITOR_DIR="${BASE_DIR}/monitoring"

# Database configuration
DB_NAME="irssh_panel"
DB_USER="irssh_admin"
DB_USER_PASSWORD=""
DB_PORT=5432
DB_HOST="localhost"
DB_SSL_MODE="disable"
DB_MAX_OPEN_CONNS=20
DB_MAX_IDLE_CONNS=5
DB_CONN_MAX_LIFETIME=30

# Determine CPU and Memory resources for optimal configuration
CPU_CORES=$(grep -c ^processor /proc/cpuinfo)
TOTAL_MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_MEM_MB=$((TOTAL_MEM_KB / 1024))

# Resource optimization based on server specs
if [[ $CPU_CORES -le 1 ]]; then
    log "WARN" "Running with limited CPU resources (1 core)"
    DB_MAX_OPEN_CONNS=10
    DB_MAX_IDLE_CONNS=3
    # Set PostgreSQL to use minimal resources
    PGSQL_SHARED_BUFFERS="256MB"
    PGSQL_EFFECTIVE_CACHE_SIZE="512MB"
    PGSQL_WORK_MEM="16MB"
    PGSQL_MAINTENANCE_WORK_MEM="64MB"
    PGSQL_MAX_CONNECTIONS=50
elif [[ $CPU_CORES -ge 4 ]]; then
    log "INFO" "Running with good CPU resources ($CPU_CORES cores)"
    DB_MAX_OPEN_CONNS=50
    DB_MAX_IDLE_CONNS=10
    # Set PostgreSQL to use more resources
    PGSQL_SHARED_BUFFERS="1GB"
    PGSQL_EFFECTIVE_CACHE_SIZE="3GB"
    PGSQL_WORK_MEM="64MB"
    PGSQL_MAINTENANCE_WORK_MEM="256MB"
    PGSQL_MAX_CONNECTIONS=200
else
    log "INFO" "Running with moderate CPU resources ($CPU_CORES cores)"
    DB_MAX_OPEN_CONNS=25
    DB_MAX_IDLE_CONNS=5
    # Set PostgreSQL to use moderate resources
    PGSQL_SHARED_BUFFERS="512MB"
    PGSQL_EFFECTIVE_CACHE_SIZE="1GB"
    PGSQL_WORK_MEM="32MB"
    PGSQL_MAINTENANCE_WORK_MEM="128MB"
    PGSQL_MAX_CONNECTIONS=100
fi

if [[ $TOTAL_MEM_MB -lt 2048 ]]; then
    log "WARN" "Running with limited memory resources (${TOTAL_MEM_MB}MB)"
    # Adjust PostgreSQL for low memory
    PGSQL_SHARED_BUFFERS="128MB"
    PGSQL_EFFECTIVE_CACHE_SIZE="256MB"
    PGSQL_WORK_MEM="4MB"
    PGSQL_MAINTENANCE_WORK_MEM="32MB"
    PGSQL_MAX_CONNECTIONS=30
fi

# Welcome message
clear
cat << "EOF"
╔════════════════════════════════════════════════════════════════════╗
║             Advanced User Management Module Installation            ║
║                          Version 3.0                                ║
╚════════════════════════════════════════════════════════════════════╝
EOF
echo ""
log "INFO" "Starting installation of Advanced User Management Module..."

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to generate a secure password
generate_password() {
    local length=${1:-24}
    local charset="A-Za-z0-9"
    
    # Use OpenSSL if available, fallback to /dev/urandom
    if command_exists openssl; then
        openssl rand -base64 32 | tr -dc "$charset" | head -c "$length"
    else
        < /dev/urandom tr -dc "$charset" | head -c "$length"
    fi
}

# Create directories with proper permissions
create_directories() {
    log "INFO" "Creating required directories..."
    
    # Main directories
    mkdir -p ${LOG_DIR}/user-manager
    mkdir -p ${SCRIPTS_DIR}/monitoring
    mkdir -p ${CONFIG_DIR}/db
    mkdir -p ${SERVICES_DIR}/user-manager
    mkdir -p ${SERVICES_DIR}/user-manager/client-portal
    mkdir -p ${MONITOR_DIR}/user-usage

    # Set correct permissions
    chmod 750 ${LOG_DIR}/user-manager
    chmod 750 ${CONFIG_DIR}/db
    chmod 750 ${SERVICES_DIR}/user-manager
    
    log "INFO" "Directories created successfully."
}

# Check system for required software
check_requirements() {
    log "INFO" "Checking system requirements..."
    
    local missing_packages=()
    
    # Check for PostgreSQL
    if ! command_exists psql; then
        missing_packages+=("postgresql postgresql-contrib")
    fi
    
    # Check for Node.js
    if ! command_exists node || ! command_exists npm; then
        missing_packages+=("nodejs npm")
    fi
    
    # Check for Redis
    if ! command_exists redis-server; then
        missing_packages+=("redis-server")
    fi
    
    # Check for Python3
    if ! command_exists python3; then
        missing_packages+=("python3 python3-pip")
    fi
    
    # Install any missing packages
    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        log "WARN" "Some required packages are missing. Installing: ${missing_packages[*]}"
        apt-get update
        apt-get install -y ${missing_packages[@]}
    fi
    
    # Check Node.js version
    if command_exists node; then
        local node_version=$(node -v | cut -d 'v' -f 2 | cut -d '.' -f 1)
        if [[ $node_version -lt 16 ]]; then
            log "WARN" "Node.js version is too old ($(node -v)). Updating to the latest LTS version."
            # Install newer Node.js
            curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
            apt-get install -y nodejs
        fi
    fi
    
    log "INFO" "System requirements check completed."
}

# Check if PostgreSQL installation
check_postgres() {
    log "INFO" "Checking PostgreSQL installation..."
    
    if ! command_exists psql; then
        log "WARN" "PostgreSQL is not installed. Installing..."
        
        # Update package lists
        apt-get update
        
        # Install PostgreSQL
        apt-get install -y postgresql postgresql-contrib
        
        # Enable and start service
        systemctl enable postgresql
        systemctl start postgresql
        
        # Verify installation
        if ! systemctl is-active --quiet postgresql; then
            log "ERROR" "PostgreSQL installation failed or service didn't start."
            exit 1
        fi
        
        log "INFO" "PostgreSQL installation completed."
    else
        log "INFO" "PostgreSQL is already installed."
    fi
    
    # Check PostgreSQL version
    local pg_version=$(psql --version | awk '{print $3}' | cut -d '.' -f 1)
    log "INFO" "PostgreSQL version: $pg_version"
    
    # Optimize PostgreSQL configuration based on system resources
    optimize_postgresql
}

# Optimize PostgreSQL based on system resources
optimize_postgresql() {
    log "INFO" "Optimizing PostgreSQL configuration..."
    
    # Find PostgreSQL config directory and main config file
    local pg_version=$(psql --version | awk '{print $3}' | cut -d '.' -f 1)
    local pg_config_dir=$(find /etc/postgresql -name "postgresql.conf" | head -n 1 | xargs dirname)
    
    if [[ -z "$pg_config_dir" ]]; then
        log "WARN" "Could not find PostgreSQL config directory. Skipping optimization."
        return
    fi
    
    log "DEBUG" "PostgreSQL config directory: $pg_config_dir"
    
    # Backup the original configuration
    cp "$pg_config_dir/postgresql.conf" "$pg_config_dir/postgresql.conf.backup"
    
    # Apply optimizations
    cat > "$pg_config_dir/conf.d/irssh-optimizations.conf" << EOF
# IRSSH Panel PostgreSQL Optimizations
# Automatically generated - Do not edit manually

# Connection Settings
max_connections = ${PGSQL_MAX_CONNECTIONS}
superuser_reserved_connections = 3

# Memory Settings
shared_buffers = ${PGSQL_SHARED_BUFFERS}
effective_cache_size = ${PGSQL_EFFECTIVE_CACHE_SIZE}
work_mem = ${PGSQL_WORK_MEM}
maintenance_work_mem = ${PGSQL_MAINTENANCE_WORK_MEM}

# Write Ahead Log
wal_buffers = 16MB
synchronous_commit = off

# Query Planner
random_page_cost = 2.0
effective_io_concurrency = 200

# Checkpointing
checkpoint_completion_target = 0.9
min_wal_size = 80MB
max_wal_size = 1GB

# Logging and Statistics
log_min_duration_statement = 2000
track_io_timing = on
EOF

    # Restart PostgreSQL to apply changes
    systemctl restart postgresql
    
    log "INFO" "PostgreSQL optimization completed."
}

# Install required dependencies
install_dependencies() {
    log "INFO" "Installing required dependencies..."
    
    # Update package lists
    apt-get update
    
    # Install packages
    apt-get install -y jq curl wget git nano unzip zip tar \
    nodejs npm redis-server postgresql-client libpq-dev python3-pip \
    lsof net-tools netcat tmux
    
    # Install Node.js dependencies
    npm install -g pm2
    
    # Install Python deps for scripts
    pip3 install psycopg2-binary python-telegram-bot schedule requests
    
    log "INFO" "Dependencies installation completed."
}

# Initialize PostgreSQL database
setup_database() {
    log "INFO" "Setting up PostgreSQL database..."
    
    # Generate database password if not set
    if [[ -z "$DB_USER_PASSWORD" ]]; then
        DB_USER_PASSWORD=$(generate_password 24)
        log "INFO" "Generated database password"
    fi
    
    # Create user and database as postgres user
    su - postgres -c "psql -c \"CREATE USER $DB_USER WITH PASSWORD '$DB_USER_PASSWORD';\""
    su - postgres -c "psql -c \"CREATE DATABASE $DB_NAME OWNER $DB_USER;\""
    
    # Save database credentials to config
    cat > $CONFIG_DIR/db/database.conf << EOF
DB_HOST=$DB_HOST
DB_PORT=$DB_PORT
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_USER_PASSWORD
DB_SSL_MODE=$DB_SSL_MODE
EOF
    
    # Create database schema
    cat > $SCRIPTS_DIR/setup_db.sql << 'EOF'
-- User profiles table
CREATE TABLE IF NOT EXISTS user_profiles (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100),
    mobile VARCHAR(20),
    referred_by VARCHAR(50),
    notes TEXT,
    telegram_id VARCHAR(100),
    max_connections INTEGER DEFAULT 1,
    expiry_date TIMESTAMP,
    data_limit BIGINT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_notification TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'deactive', 'suspended')),
    usage_alerts BOOLEAN DEFAULT true
);

-- User connections table
CREATE TABLE IF NOT EXISTS user_connections (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    protocol VARCHAR(20) NOT NULL,
    connect_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    disconnect_time TIMESTAMP,
    client_ip VARCHAR(50),
    upload_bytes BIGINT DEFAULT 0,
    download_bytes BIGINT DEFAULT 0,
    session_id VARCHAR(100) UNIQUE,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'closed', 'terminated')),
    disconnect_reason VARCHAR(50),
    FOREIGN KEY (username) REFERENCES user_profiles(username) ON DELETE CASCADE
);

-- User audit log table (for tracking changes to user accounts)
CREATE TABLE IF NOT EXISTS user_audit_logs (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    details JSONB,
    performed_by VARCHAR(50),
    action_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES user_profiles(username) ON DELETE CASCADE
);

-- Protocol definitions with configuration
CREATE TABLE IF NOT EXISTS protocols (
    id SERIAL PRIMARY KEY,
    name VARCHAR(20) UNIQUE NOT NULL,
    display_name VARCHAR(50) NOT NULL,
    port INTEGER,
    enabled BOOLEAN DEFAULT TRUE,
    config JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- System settings
CREATE TABLE IF NOT EXISTS system_settings (
    id SERIAL PRIMARY KEY,
    setting_key VARCHAR(50) UNIQUE NOT NULL,
    setting_value TEXT,
    setting_type VARCHAR(20) DEFAULT 'string',
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Daily traffic stats for performance reports
CREATE TABLE IF NOT EXISTS daily_traffic_stats (
    id SERIAL PRIMARY KEY,
    date DATE NOT NULL,
    protocol VARCHAR(20),
    upload_bytes BIGINT DEFAULT 0,
    download_bytes BIGINT DEFAULT 0,
    active_users INTEGER DEFAULT 0,
    peak_connections INTEGER DEFAULT 0,
    UNIQUE(date, protocol)
);

-- User notifications
CREATE TABLE IF NOT EXISTS user_notifications (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    notification_type VARCHAR(20) NOT NULL,
    message TEXT NOT NULL,
    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    read BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (username) REFERENCES user_profiles(username) ON DELETE CASCADE
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_connections_username ON user_connections(username);
CREATE INDEX IF NOT EXISTS idx_connections_status ON user_connections(status);
CREATE INDEX IF NOT EXISTS idx_connections_connect_time ON user_connections(connect_time);
CREATE INDEX IF NOT EXISTS idx_connections_session_id ON user_connections(session_id);
CREATE INDEX IF NOT EXISTS idx_traffic_stats_date ON daily_traffic_stats(date);
CREATE INDEX IF NOT EXISTS idx_user_profiles_expiry ON user_profiles(expiry_date);
CREATE INDEX IF NOT EXISTS idx_user_profiles_status ON user_profiles(status);
CREATE INDEX IF NOT EXISTS idx_audit_logs_username ON user_audit_logs(username);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON user_audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_notifications_username ON user_notifications(username);

-- Insert default protocols
INSERT INTO protocols (name, display_name, port) VALUES
    ('ssh', 'SSH', 22),
    ('wireguard', 'WireGuard', 51820),
    ('l2tp', 'L2TP/IPsec', 1701),
    ('ikev2', 'IKEv2', 500),
    ('cisco', 'Cisco IPsec', 85),
    ('singbox', 'Sing-Box', 1080)
ON CONFLICT (name) DO UPDATE
SET display_name = EXCLUDED.display_name,
    port = EXCLUDED.port;

-- Insert default settings
INSERT INTO system_settings (setting_key, setting_value, setting_type, description) VALUES
    ('check_interval', '5', 'integer', 'Minutes between user connection checks'),
    ('notification_hours', '24', 'integer', 'Hours before expiry to send notifications'),
    ('client_portal_ipv6_only', 'true', 'boolean', 'Restrict client portal to IPv6 addresses only'),
    ('backup_enabled', 'true', 'boolean', 'Enable automatic database backups'),
    ('backup_interval', '24', 'integer', 'Hours between database backups'),
    ('max_backup_count', '14', 'integer', 'Maximum number of backups to keep'),
    ('auto_cleanup_connections', 'true', 'boolean', 'Auto-cleanup stale connections'),
    ('auto_cleanup_interval', '60', 'integer', 'Minutes between stale connection cleanup'),
    ('version', '3.0', 'string', 'Version of user management module')
ON CONFLICT (setting_key) DO UPDATE
SET setting_value = EXCLUDED.setting_value,
    setting_type = EXCLUDED.setting_type,
    description = EXCLUDED.description;

-- Create database functions
CREATE OR REPLACE FUNCTION update_user_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION update_protocol_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create triggers for updated_at fields
CREATE TRIGGER update_user_profiles_updated_at
BEFORE UPDATE ON user_profiles
FOR EACH ROW EXECUTE FUNCTION update_user_updated_at();

CREATE TRIGGER update_protocols_updated_at
BEFORE UPDATE ON protocols
FOR EACH ROW EXECUTE FUNCTION update_protocol_updated_at();

-- Function to log user changes
CREATE OR REPLACE FUNCTION log_user_changes()
RETURNS TRIGGER AS $$
DECLARE
    changes jsonb := '{}'::jsonb;
    change_detected boolean := false;
BEGIN
    -- Only run on update
    IF (TG_OP = 'UPDATE') THEN
        -- Check for changes to each relevant field
        IF NEW.email IS DISTINCT FROM OLD.email THEN
            changes := jsonb_set(changes, '{email}', jsonb_build_object('old', OLD.email, 'new', NEW.email));
            change_detected := true;
        END IF;
        
        IF NEW.max_connections IS DISTINCT FROM OLD.max_connections THEN
            changes := jsonb_set(changes, '{max_connections}', jsonb_build_object('old', OLD.max_connections, 'new', NEW.max_connections));
            change_detected := true;
        END IF;
        
        IF NEW.expiry_date IS DISTINCT FROM OLD.expiry_date THEN
            changes := jsonb_set(changes, '{expiry_date}', jsonb_build_object(
                'old', to_char(OLD.expiry_date, 'YYYY-MM-DD HH24:MI:SS'),
                'new', to_char(NEW.expiry_date, 'YYYY-MM-DD HH24:MI:SS')
            ));
            change_detected := true;
        END IF;
        
        IF NEW.data_limit IS DISTINCT FROM OLD.data_limit THEN
            changes := jsonb_set(changes, '{data_limit}', jsonb_build_object('old', OLD.data_limit, 'new', NEW.data_limit));
            change_detected := true;
        END IF;
        
        IF NEW.status IS DISTINCT FROM OLD.status THEN
            changes := jsonb_set(changes, '{status}', jsonb_build_object('old', OLD.status, 'new', NEW.status));
            change_detected := true;
        END IF;
        
        -- Insert a log record if any changes were detected
        IF change_detected THEN
            INSERT INTO user_audit_logs (username, action, details, performed_by)
            VALUES (NEW.username, 'UPDATE', changes, current_user);
        END IF;
    
    -- Log creation
    ELSIF (TG_OP = 'INSERT') THEN
        INSERT INTO user_audit_logs (username, action, details, performed_by)
        VALUES (NEW.username, 'CREATE', jsonb_build_object(
            'email', NEW.email,
            'max_connections', NEW.max_connections,
            'expiry_date', to_char(NEW.expiry_date, 'YYYY-MM-DD HH24:MI:SS'),
            'data_limit', NEW.data_limit
        ), current_user);
    
    -- Log deletion
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO user_audit_logs (username, action, details, performed_by)
        VALUES (OLD.username, 'DELETE', jsonb_build_object(
            'deleted_at', to_char(now(), 'YYYY-MM-DD HH24:MI:SS')
        ), current_user);
    END IF;
    
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for logging user changes
CREATE TRIGGER log_user_profile_changes
AFTER INSERT OR UPDATE OR DELETE ON user_profiles
FOR EACH ROW EXECUTE FUNCTION log_user_changes();

-- Create function to aggregate daily traffic stats
CREATE OR REPLACE FUNCTION aggregate_daily_traffic()
RETURNS void AS $$
DECLARE
    current_date date := current_date;
    yesterday date := current_date - interval '1 day';
BEGIN
    -- Get yesterday's date if run early in the morning
    IF EXTRACT(HOUR FROM NOW()) < 1 THEN
        yesterday := current_date - interval '2 days';
        current_date := current_date - interval '1 day';
    END IF;

    -- Aggregate by protocol for yesterday
    INSERT INTO daily_traffic_stats (date, protocol, upload_bytes, download_bytes, active_users, peak_connections)
    SELECT 
        yesterday as date,
        protocol,
        SUM(upload_bytes) as upload_bytes,
        SUM(download_bytes) as download_bytes,
        COUNT(DISTINCT username) as active_users,
        COUNT(*) as connections
    FROM 
        user_connections
    WHERE 
        connect_time >= yesterday AND connect_time < current_date
    GROUP BY 
        protocol
    ON CONFLICT (date, protocol) 
    DO UPDATE SET
        upload_bytes = EXCLUDED.upload_bytes,
        download_bytes = EXCLUDED.download_bytes,
        active_users = EXCLUDED.active_users,
        peak_connections = EXCLUDED.peak_connections;
END;
$$ LANGUAGE plpgsql;
EOF
    
    # Execute SQL script
    PGPASSWORD=$DB_USER_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -f $SCRIPTS_DIR/setup_db.sql
    
    # Create a database backup script
    cat > $SCRIPTS_DIR/backup_database.sh << EOF
#!/bin/bash
# Database backup script

BACKUP_DIR="${BACKUP_DIR}/db"
DB_NAME="${DB_NAME}"
DB_USER="${DB_USER}"
DB_PASSWORD="${DB_USER_PASSWORD}"
DB_HOST="${DB_HOST}"
TIMESTAMP=\$(date +"%Y%m%d_%H%M%S")
MAX_BACKUPS=\$(psql -h \$DB_HOST -U \$DB_USER -d \$DB_NAME -t -c "SELECT setting_value::integer FROM system_settings WHERE setting_key='max_backup_count';" 2>/dev/null || echo 14)

# Create backup directory if it doesn't exist
mkdir -p \$BACKUP_DIR

# Perform backup
PGPASSWORD=\$DB_PASSWORD pg_dump -h \$DB_HOST -U \$DB_USER -d \$DB_NAME -F c -f "\$BACKUP_DIR/\$DB_NAME-\$TIMESTAMP.backup"

# Compress the backup
gzip "\$BACKUP_DIR/\$DB_NAME-\$TIMESTAMP.backup"

# Delete old backups
cd \$BACKUP_DIR
ls -tp | grep -v '/$' | tail -n +\$((MAX_BACKUPS+1)) | xargs -I {} rm -- {}

# Log success
echo "[\$(date +'%Y-%m-%d %H:%M:%S')] Backup completed: \$BACKUP_DIR/\$DB_NAME-\$TIMESTAMP.backup.gz"
EOF
    
    chmod +x $SCRIPTS_DIR/backup_database.sh
    
    # Setup cron job for database backup
    if ! crontab -l | grep -q "backup_database.sh"; then
        (crontab -l 2>/dev/null; echo "0 2 * * * $SCRIPTS_DIR/backup_database.sh") | crontab -
    fi
    
    log "INFO" "Database setup completed."
}

# Create Node.js service for user management
create_user_manager_service() {
    log "INFO" "Creating user management service..."
    
    # Create package.json
    cat > $SERVICES_DIR/user-manager/package.json << 'EOF'
{
  "name": "irssh-user-manager",
  "version": "3.0.0",
  "description": "User management service for IRSSH-Panel",
  "main": "index.js",
  "scripts": {
    "start": "node index.js",
    "dev": "nodemon index.js"
  },
  "dependencies": {
    "axios": "^1.6.0",
    "bcrypt": "^5.1.0",
    "compression": "^1.7.4",
    "connect-redis": "^7.1.0",
    "cors": "^2.8.5",
    "cron": "^3.1.0",
    "dotenv": "^16.3.1",
    "express": "^4.18.2",
    "express-rate-limit": "^7.1.0",
    "express-session": "^1.17.3",
    "helmet": "^7.1.0",
    "jsonwebtoken": "^9.0.2",
    "moment": "^2.29.4",
    "pg": "^8.11.3",
    "pino": "^8.15.0",
    "pino-pretty": "^10.2.0",
    "redis": "^4.6.10",
    "telegraf": "^4.15.0",
    "validator": "^13.11.0",
    "winston": "^3.11.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}
EOF

    # Create main service file
    cat > $SERVICES_DIR/user-manager/index.js << 'EOF'
// main.js - IRSSH User Manager Service
const express = require('express');
const { Pool } = require('pg');
const { CronJob } = require('cron');
const axios = require('axios');
const moment = require('moment');
const { createClient } = require('redis');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const jwt = require('jsonwebtoken');
const { Telegraf } = require('telegraf');
const winston = require('winston');
const validator = require('validator');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const dotenv = require('dotenv');

// Load environment variables
dotenv.config({ path: path.join(__dirname, '../../config/db/database.conf') });
dotenv.config({ path: path.join(__dirname, '../../.env') });

// Application Configuration
const config = {
    port: process.env.USER_MANAGER_PORT || 3001,
    checkInterval: process.env.CHECK_INTERVAL || '*/5 * * * *', // Every 5 minutes
    autoCleanupInterval: process.env.AUTO_CLEANUP_INTERVAL || '*/30 * * * *', // Every 30 minutes
    telegramBotToken: process.env.TELEGRAM_BOT_TOKEN || '',
    telegramAdminChat: process.env.TELEGRAM_ADMIN_CHAT || '',
    jwtSecret: process.env.JWT_SECRET || 'irssh-user-management-secret-key',
    database: {
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT) || 5432,
        database: process.env.DB_NAME || 'irssh_panel',
        user: process.env.DB_USER || 'irssh_admin',
        password: process.env.DB_PASSWORD || '',
        ssl: process.env.DB_SSL_MODE === 'require' ? { rejectUnauthorized: false } : false,
        max: parseInt(process.env.DB_MAX_CONNS) || 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 5000
    },
    redis: {
        url: process.env.REDIS_URL || 'redis://localhost:6379'
    },
    clientPortalIpv6Only: process.env.CLIENT_PORTAL_IPV6_ONLY === 'true',
    sessionSecret: process.env.SESSION_SECRET || 'irssh-session-secret',
    logLevel: process.env.LOG_LEVEL || 'info',
    environment: process.env.NODE_ENV || 'production'
};

// Configure logger
const logger = winston.createLogger({
    level: config.logLevel,
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) => {
            return `${timestamp} [${level.toUpperCase()}]: ${message}`;
        })
    ),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        }),
        new winston.transports.File({ 
            filename: 'user-manager-error.log', 
            dirname: path.join(__dirname, '../../logs'),
            level: 'error'
        }),
        new winston.transports.File({ 
            filename: 'user-manager.log', 
            dirname: path.join(__dirname, '../../logs')
        })
    ]
});

// Initialize PostgreSQL connection
const db = new Pool(config.database);

db.on('error', (err) => {
    logger.error(`PostgreSQL Error: ${err.message}`);
});

// Test database connection
db.query('SELECT NOW()', (err, res) => {
    if (err) {
        logger.error(`Database connection error: ${err.message}`);
        process.exit(1);
    } else {
        logger.info(`Connected to PostgreSQL database: ${config.database.database}`);
    }
});

// Initialize Redis
const redisClient = createClient({
    url: config.redis.url
});

redisClient.on('error', (err) => logger.error(`Redis Client Error: ${err}`));

// Initialize Telegram bot if token is provided
let bot = null;
if (config.telegramBotToken) {
    bot = new Telegraf(config.telegramBotToken);
    bot.launch().then(() => {
        logger.info('Telegram bot started');
        // Notify admin if configured
        if (config.telegramAdminChat) {
            bot.telegram.sendMessage(
                config.telegramAdminChat,
                `🚀 IRSSH User Manager service started\n\nEnvironment: ${config.environment}\nTime: ${moment().format('YYYY-MM-DD HH:mm:ss')}`
            ).catch(err => {
                logger.error(`Failed to send admin startup notification: ${err.message}`);
            });
        }
    }).catch(err => {
        logger.error(`Failed to start Telegram bot: ${err.message}`);
    });
    
    // Set up bot commands
    bot.command('status', async (ctx) => {
        try {
            // Verify the user is an admin
            if (ctx.chat.id.toString() !== config.telegramAdminChat && !await isUserAdmin(ctx.from.id)) {
                return ctx.reply('❌ Unauthorized: This command is available to admins only.');
            }
            
            // Get system status
            const activeConnections = await getActiveConnectionsCount();
            const userCount = await getUserCount();
            const expiringSoon = await getExpiringUsersCount(24);
            const uptime = process.uptime();
            const uptimeFormatted = formatUptime(uptime);
            
            ctx.reply(
                `📊 *IRSSH User Manager Status*\n\n` +
                `⏱ Uptime: ${uptimeFormatted}\n` +
                `👥 Total Users: ${userCount}\n` +
                `🔌 Active Connections: ${activeConnections}\n` +
                `⏳ Expiring in 24h: ${expiringSoon}\n` +
                `🖥 Server Time: ${moment().format('YYYY-MM-DD HH:mm:ss')}`,
                { parse_mode: 'Markdown' }
            );
        } catch (error) {
            logger.error(`Error in /status command: ${error.message}`);
            ctx.reply('❌ Error getting system status');
        }
    });
    
    bot.command('user', async (ctx) => {
        try {
            // Check if admin or querying own account
            const args = ctx.message.text.split(' ');
            if (args.length < 2) {
                return ctx.reply('❌ Usage: /user username');
            }
            
            const username = args[1];
            const isAdmin = ctx.chat.id.toString() === config.telegramAdminChat || await isUserAdmin(ctx.from.id);
            const isOwnAccount = await isUserOwnTelegram(username, ctx.from.id);
            
            if (!isAdmin && !isOwnAccount) {
                return ctx.reply('❌ Unauthorized: You can only query your own account.');
            }
            
            // Get user data
            const user = await getUserByUsername(username);
            if (!user) {
                return ctx.reply(`❌ User '${username}' not found.`);
            }
            
            const expiry = user.expiry_date ? moment(user.expiry_date) : null;
            const timeLeft = expiry ? moment.duration(expiry.diff(moment())) : null;
            const connections = await getUserActiveConnections(username);
            
            let expiryText = 'No expiration date';
            if (expiry) {
                if (expiry < moment()) {
                    expiryText = `Expired on ${expiry.format('YYYY-MM-DD')}`;
                } else {
                    expiryText = `${timeLeft.humanize()} left (${expiry.format('YYYY-MM-DD')})`;
                }
            }
            
            ctx.reply(
                `👤 *User: ${username}*\n\n` +
                `📅 Expiry: ${expiryText}\n` +
                `🔌 Active Connections: ${connections.length}/${user.max_connections}\n` +
                `💾 Data Limit: ${formatBytes(user.data_limit)}\n` +
                `📊 Status: ${user.status}\n` +
                (connections.length > 0 ? '\n*Active Connections:*\n' + 
                    connections.map(c => `- ${c.protocol}: Connected from ${c.client_ip} (${moment.duration(moment().diff(moment(c.connect_time))).humanize()})`).join('\n')
                    : ''),
                { parse_mode: 'Markdown' }
            );
        } catch (error) {
            logger.error(`Error in /user command: ${error.message}`);
            ctx.reply('❌ Error getting user information');
        }
    });
}

// Connect to Redis before proceeding
(async () => {
    try {
        await redisClient.connect();
        logger.info('Connected to Redis');
        
        // Start the Express application after connecting to Redis
        startExpressApp();
    } catch (err) {
        logger.error(`Failed to connect to Redis: ${err.message}`);
        process.exit(1);
    }
})();

// Helper Functions
async function getUserCount() {
    const result = await db.query('SELECT COUNT(*) FROM user_profiles');
    return parseInt(result.rows[0].count);
}

async function getActiveConnectionsCount() {
    const result = await db.query("SELECT COUNT(*) FROM user_connections WHERE status = 'active'");
    return parseInt(result.rows[0].count);
}

async function getExpiringUsersCount(hours) {
    const result = await db.query(
        'SELECT COUNT(*) FROM user_profiles WHERE expiry_date BETWEEN NOW() AND NOW() + INTERVAL $1 HOUR',
        [hours]
    );
    return parseInt(result.rows[0].count);
}

async function getUserByUsername(username) {
    const result = await db.query('SELECT * FROM user_profiles WHERE username = $1', [username]);
    return result.rows.length > 0 ? result.rows[0] : null;
}

async function getUserActiveConnections(username) {
    const result = await db.query(
        "SELECT * FROM user_connections WHERE username = $1 AND status = 'active'",
        [username]
    );
    return result.rows;
}

async function isUserAdmin(telegramId) {
    // Check if the Telegram ID belongs to an admin user
    const result = await db.query(
        "SELECT COUNT(*) FROM user_profiles WHERE telegram_id = $1 AND telegram_id IN (SELECT setting_value FROM system_settings WHERE setting_key = 'admin_telegram_ids')",
        [telegramId.toString()]
    );
    return parseInt(result.rows[0].count) > 0;
}

async function isUserOwnTelegram(username, telegramId) {
    const result = await db.query(
        'SELECT COUNT(*) FROM user_profiles WHERE username = $1 AND telegram_id = $2',
        [username, telegramId.toString()]
    );
    return parseInt(result.rows[0].count) > 0;
}

function formatUptime(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    if (days > 0) {
        return `${days}d ${hours}h ${minutes}m`;
    } else if (hours > 0) {
        return `${hours}h ${minutes}m`;
    } else {
        return `${minutes}m`;
    }
}

function formatBytes(bytes, decimals = 2) {
    if (!bytes || bytes === 0 || bytes === '0') return 'Unlimited';
    
    bytes = parseInt(bytes);
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

function getCurrentTimestamp() {
    return moment().format('YYYY-MM-DD HH:mm:ss');
}

// Express application setup
function startExpressApp() {
    const app = express();
    
    // Basic middleware
    app.use(express.json());
    app.use(compression());
    app.use(cors({
        origin: process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',') : '*',
        methods: ['GET', 'POST', 'PUT', 'DELETE'],
        allowedHeaders: ['Content-Type', 'Authorization'],
        credentials: true
    }));
    
    app.use(helmet({
        contentSecurityPolicy: false
    }));
    
    // API rate limiting
    const apiLimiter = rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // Limit each IP to 100 requests per windowMs
        standardHeaders: true,
        legacyHeaders: false,
        message: 'Too many requests from this IP, please try again later.'
    });
    
    // Apply rate limiting to API routes
    app.use('/api/', apiLimiter);
    
    // Authentication middleware
    const authMiddleware = (req, res, next) => {
        try {
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ error: 'Authentication required' });
            }
            
            const token = authHeader.split(' ')[1];
            const decoded = jwt.verify(token, config.jwtSecret);
            
            req.user = decoded;
            next();
        } catch (error) {
            return res.status(401).json({ error: 'Invalid or expired token' });
        }
    };
    
    // Admin middleware for restricted routes
    const adminMiddleware = (req, res, next) => {
        if (!req.user || req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        next();
    };
    
    // Session middleware for client portal
    const sessionMiddleware = session({
        store: new RedisStore({ client: redisClient }),
        secret: config.sessionSecret,
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: config.environment === 'production',
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        }
    });
    
    // Client portal IPv6 middleware
    const ipv6OnlyMiddleware = (req, res, next) => {
        if (config.clientPortalIpv6Only) {
            const clientIp = req.ip || req.connection.remoteAddress;
            
            // Check if the IP is IPv6 (contains colon)
            if (!clientIp || !clientIp.includes(':')) {
                return res.status(403).send('Access restricted to IPv6 addresses only');
            }
        }
        next();
    };
    
    // Login route for client portal
    app.post('/portal/api/login', async (req, res) => {
        try {
            const { username, password } = req.body;
            
            if (!username || !password) {
                return res.status(400).json({ error: 'Username and password are required' });
            }
            
            // Check if user exists
            const userResult = await db.query(
                'SELECT * FROM user_profiles WHERE username = $1',
                [username]
            );
            
            if (userResult.rows.length === 0) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            
            const user = userResult.rows[0];
            
            // For this simple client portal, we're authenticating based on username existence
            // In a real implementation, you would verify the password against a hash
            
            // Generate a temporary token for the client portal session
            const token = jwt.sign(
                { id: user.id, username: user.username },
                config.jwtSecret,
                { expiresIn: '24h' }
            );
            
            res.json({ success: true, token });
        } catch (error) {
            logger.error(`Login error: ${error.message}`);
            res.status(500).json({ error: 'Authentication failed' });
        }
    });
    
    // Get account info for client portal
    app.get('/portal/api/account', async (req, res) => {
        try {
            // Parse token from Authorization header
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ error: 'Authentication required' });
            }
            
            const token = authHeader.split(' ')[1];
            let decoded;
            
            try {
                decoded = jwt.verify(token, config.jwtSecret);
            } catch (error) {
                return res.status(401).json({ error: 'Invalid or expired token' });
            }
            
            const username = decoded.username;
            
            // Get user data
            const userResult = await db.query(
                'SELECT * FROM user_profiles WHERE username = $1',
                [username]
            );
            
            if (userResult.rows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
            
            const user = userResult.rows[0];
            
            // Get active connections count
            const connectionsResult = await db.query(
                "SELECT COUNT(*) FROM user_connections WHERE username = $1 AND status = 'active'",
                [username]
            );
            
            const activeConnections = parseInt(connectionsResult.rows[0].count);
            
            // Get total data usage
            const usageResult = await db.query(
                'SELECT COALESCE(SUM(upload_bytes + download_bytes), 0) as total_usage FROM user_connections WHERE username = $1',
                [username]
            );
            
            const totalUsage = parseInt(usageResult.rows[0].total_usage);
            const dataLimit = parseInt(user.data_limit);
            
            // Calculate time remaining until expiry
            let timeRemaining = { days: 0, hours: 0, minutes: 0 };
            if (user.expiry_date) {
                const now = moment();
                const expiry = moment(user.expiry_date);
                
                if (expiry.isAfter(now)) {
                    const duration = moment.duration(expiry.diff(now));
                    timeRemaining = {
                        days: Math.floor(duration.asDays()),
                        hours: duration.hours(),
                        minutes: duration.minutes()
                    };
                }
            }
            
            // Prepare response
            res.json({
                account: {
                    username: user.username,
                    email: user.email,
                    mobile: user.mobile,
                    max_connections: user.max_connections,
                    active_connections: activeConnections,
                    expiry_date: user.expiry_date,
                    time_remaining: timeRemaining,
                    data_usage: {
                        used: {
                            bytes: totalUsage,
                            formatted: formatBytes(totalUsage)
                        },
                        limit: {
                            bytes: dataLimit,
                            formatted: formatBytes(dataLimit)
                        },
                        percentage: dataLimit > 0 ? Math.min(100, Math.round((totalUsage / dataLimit) * 100)) : 0
                    }
                }
            });
        } catch (error) {
            logger.error(`Account info error: ${error.message}`);
            res.status(500).json({ error: 'Failed to retrieve account information' });
        }
    });
    
    // Get connection history for client portal
    app.get('/portal/api/connections/history', async (req, res) => {
        try {
            // Parse token from Authorization header
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ error: 'Authentication required' });
            }
            
            const token = authHeader.split(' ')[1];
            let decoded;
            
            try {
                decoded = jwt.verify(token, config.jwtSecret);
            } catch (error) {
                return res.status(401).json({ error: 'Invalid or expired token' });
            }
            
            const username = decoded.username;
            
            // Get recent connections
            const connectionsResult = await db.query(
                `SELECT 
                    id, protocol, connect_time, disconnect_time, client_ip, 
                    upload_bytes, download_bytes, status, session_id,
                    CASE
                        WHEN disconnect_time IS NOT NULL THEN 
                            EXTRACT(EPOCH FROM (disconnect_time - connect_time)) / 60
                        WHEN status = 'active' THEN
                            EXTRACT(EPOCH FROM (NOW() - connect_time)) / 60
                        ELSE 0
                    END as duration_minutes
                FROM user_connections
                WHERE username = $1
                ORDER BY connect_time DESC
                LIMIT 100`,
                [username]
            );
            
            // Get protocol summary
            const protocolSummaryResult = await db.query(
                `SELECT 
                    protocol, 
                    COUNT(*) as connections,
                    COALESCE(SUM(upload_bytes), 0) as upload_bytes,
                    COALESCE(SUM(download_bytes), 0) as download_bytes,
                    COALESCE(SUM(
                        CASE
                            WHEN disconnect_time IS NOT NULL THEN 
                                EXTRACT(EPOCH FROM (disconnect_time - connect_time)) / 60
                            WHEN status = 'active' THEN
                                EXTRACT(EPOCH FROM (NOW() - connect_time)) / 60
                            ELSE 0
                        END
                    ), 0) as duration_minutes
                FROM user_connections
                WHERE username = $1
                GROUP BY protocol`,
                [username]
            );
            
            // Get last 30 days chart data
            const chartDataResult = await db.query(
                `SELECT 
                    DATE(connect_time) as date,
                    COALESCE(SUM(upload_bytes), 0) as upload_bytes,
                    COALESCE(SUM(download_bytes), 0) as download_bytes
                FROM user_connections
                WHERE username = $1
                    AND connect_time >= NOW() - INTERVAL '30 days'
                GROUP BY DATE(connect_time)
                ORDER BY date ASC`,
                [username]
            );
            
            // Format connections
            const connections = connectionsResult.rows.map(conn => {
                const upload = parseInt(conn.upload_bytes) || 0;
                const download = parseInt(conn.download_bytes) || 0;
                const duration = parseFloat(conn.duration_minutes) || 0;
                
                return {
                    id: conn.id,
                    protocol: conn.protocol,
                    connect_time: conn.connect_time,
                    disconnect_time: conn.disconnect_time,
                    status: conn.status,
                    session_id: conn.session_id,
                    client_ip: conn.client_ip,
                    duration: {
                        minutes: Math.round(duration),
                        formatted: formatDuration(duration)
                    },
                    upload: {
                        bytes: upload,
                        formatted: formatBytes(upload)
                    },
                    download: {
                        bytes: download,
                        formatted: formatBytes(download)
                    },
                    total_traffic: {
                        bytes: upload + download,
                        formatted: formatBytes(upload + download)
                    }
                };
            });
            
            // Format protocol summary
            const byProtocol = {};
            protocolSummaryResult.rows.forEach(row => {
                const upload = parseInt(row.upload_bytes) || 0;
                const download = parseInt(row.download_bytes) || 0;
                const duration = parseFloat(row.duration_minutes) || 0;
                
                byProtocol[row.protocol] = {
                    connections: parseInt(row.connections),
                    duration: {
                        minutes: Math.round(duration),
                        formatted: formatDuration(duration)
                    },
                    upload: {
                        bytes: upload,
                        formatted: formatBytes(upload)
                    },
                    download: {
                        bytes: download,
                        formatted: formatBytes(download)
                    },
                    total_traffic: {
                        bytes: upload + download,
                        formatted: formatBytes(upload + download)
                    }
                };
            });
            
            // Calculate total summary
            const totalUpload = protocolSummaryResult.rows.reduce((sum, row) => sum + parseInt(row.upload_bytes || 0), 0);
            const totalDownload = protocolSummaryResult.rows.reduce((sum, row) => sum + parseInt(row.download_bytes || 0), 0);
            const totalDuration = protocolSummaryResult.rows.reduce((sum, row) => sum + parseFloat(row.duration_minutes || 0), 0);
            
            // Format chart data
            const chartData = chartDataResult.rows.map(row => {
                const uploadMB = Math.round((parseInt(row.upload_bytes) || 0) / (1024 * 1024) * 100) / 100;
                const downloadMB = Math.round((parseInt(row.download_bytes) || 0) / (1024 * 1024) * 100) / 100;
                
                return {
                    date: row.date,
                    upload_mb: uploadMB,
                    download_mb: downloadMB,
                    total_mb: uploadMB + downloadMB
                };
            });
            
            res.json({
                connections,
                summary: {
                    total_connections: connections.length,
                    by_protocol: byProtocol,
                    total_upload: {
                        bytes: totalUpload,
                        formatted: formatBytes(totalUpload)
                    },
                    total_download: {
                        bytes: totalDownload,
                        formatted: formatBytes(totalDownload)
                    },
                    total_traffic: {
                        bytes: totalUpload + totalDownload,
                        formatted: formatBytes(totalUpload + totalDownload)
                    },
                    total_duration: {
                        minutes: Math.round(totalDuration),
                        formatted: formatDuration(totalDuration)
                    }
                },
                chart_data: chartData
            });
        } catch (error) {
            logger.error(`Connection history error: ${error.message}`);
            res.status(500).json({ error: 'Failed to retrieve connection history' });
        }
    });
    
    // Get daily usage statistics for client portal
    app.get('/portal/api/connections/daily', async (req, res) => {
        try {
            // Parse token from Authorization header
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ error: 'Authentication required' });
            }
            
            const token = authHeader.split(' ')[1];
            let decoded;
            
            try {
                decoded = jwt.verify(token, config.jwtSecret);
            } catch (error) {
                return res.status(401).json({ error: 'Invalid or expired token' });
            }
            
            const username = decoded.username;
            
            // Get daily stats for the last 30 days
            const statsResult = await db.query(
                `SELECT 
                    DATE(connect_time) as date,
                    COALESCE(SUM(upload_bytes + download_bytes), 0) as total_bytes,
                    COALESCE(SUM(
                        CASE
                            WHEN disconnect_time IS NOT NULL THEN 
                                EXTRACT(EPOCH FROM (disconnect_time - connect_time)) / 60
                            WHEN status = 'active' THEN
                                EXTRACT(EPOCH FROM (NOW() - connect_time)) / 60
                            ELSE 0
                        END
                    ), 0) as duration_minutes
                FROM user_connections
                WHERE username = $1
                    AND connect_time >= NOW() - INTERVAL '30 days'
                GROUP BY DATE(connect_time)
                ORDER BY date ASC`,
                [username]
            );
            
            // Format daily stats
            const dailyStats = statsResult.rows.map(row => {
                const totalTraffic = parseInt(row.total_bytes) || 0;
                const duration = parseFloat(row.duration_minutes) || 0;
                
                return {
                    date: row.date,
                    total_traffic: {
                        bytes: totalTraffic,
                        formatted: formatBytes(totalTraffic)
                    },
                    duration: {
                        minutes: Math.round(duration),
                        formatted: formatDuration(duration)
                    }
                };
            });
            
            res.json({
                daily_stats: dailyStats
            });
        } catch (error) {
            logger.error(`Daily usage error: ${error.message}`);
            res.status(500).json({ error: 'Failed to retrieve daily usage statistics' });
        }
    });
    
    // Connection tracking API endpoints
    app.post('/api/connections/start', async (req, res) => {
        const { username, protocol, client_ip, session_id } = req.body;
        
        if (!username || !protocol) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        
        try {
            // Check if user exists
            const userResult = await db.query(
                'SELECT * FROM user_profiles WHERE username = $1',
                [username]
            );
            
            if (userResult.rows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
            
            const user = userResult.rows[0];
            
            // Check if user is active
            if (user.status !== 'active') {
                return res.status(403).json({ error: 'Account is not active' });
            }
            
            // Check if user has expired
            if (user.expiry_date && moment(user.expiry_date).isBefore(moment())) {
                return res.status(403).json({ error: 'Account has expired' });
            }
            
            // Check if user has reached the connection limit
            const activeConnectionsResult = await db.query(
                "SELECT COUNT(*) as count FROM user_connections WHERE username = $1 AND status = 'active'",
                [username]
            );
            
            const activeConnections = parseInt(activeConnectionsResult.rows[0].count);
            const maxConnections = parseInt(user.max_connections);
            
            if (activeConnections >= maxConnections) {
                return res.status(403).json({ 
                    error: 'Maximum connection limit reached',
                    active: activeConnections,
                    max: maxConnections
                });
            }
            
            // Check if user has exceeded data limit
            if (user.data_limit > 0) {
                const usageResult = await db.query(
                    'SELECT COALESCE(SUM(upload_bytes + download_bytes), 0) as total_usage FROM user_connections WHERE username = $1',
                    [username]
                );
                
                const totalUsage = parseInt(usageResult.rows[0].total_usage);
                
                if (totalUsage > user.data_limit) {
                    return res.status(403).json({ 
                        error: 'Data limit exceeded',
                        usage: totalUsage,
                        limit: user.data_limit
                    });
                }
            }
            
            // Insert new connection
            const result = await db.query(`
                INSERT INTO user_connections (username, protocol, client_ip, session_id, connect_time, status)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING id
            `, [username, protocol, client_ip, session_id, getCurrentTimestamp(), 'active']);
            
            // Log connection start in audit trail
            await db.query(`
                INSERT INTO user_audit_logs (username, action, details, performed_by)
                VALUES ($1, $2, $3, $4)
            `, [
                username, 
                'CONNECTION_START', 
                JSON.stringify({
                    protocol, 
                    client_ip, 
                    session_id,
                    connection_id: result.rows[0].id
                }),
                'system'
            ]);
            
            // Notify via Telegram if user has Telegram ID
            if (bot && user.telegram_id && user.usage_alerts) {
                try {
                    await bot.telegram.sendMessage(
                        user.telegram_id,
                        `🔌 *New Connection*\n\nA new ${protocol} connection for your account *${username}* has been established from ${client_ip}.\n\nTime: ${moment().format('YYYY-MM-DD HH:mm:ss')}`,
                        { parse_mode: 'Markdown' }
                    );
                } catch (telegramError) {
                    logger.error(`Failed to send Telegram notification: ${telegramError.message}`);
                }
            }
            
            res.json({ 
                success: true, 
                connection_id: result.rows[0].id,
                message: `Connection started for ${username} using ${protocol}`
            });
        } catch (error) {
            logger.error(`Error recording connection start: ${error.message}`);
            res.status(500).json({ error: 'Database error' });
        }
    });

    app.post('/api/connections/end', async (req, res) => {
        const { username, session_id, upload_bytes, download_bytes } = req.body;
        
        if (!username || !session_id) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        
        try {
            // Update connection status
            const result = await db.query(`
                UPDATE user_connections
                SET status = 'closed', 
                    disconnect_time = $1,
                    upload_bytes = COALESCE(upload_bytes, 0) + COALESCE($2, 0),
                    download_bytes = COALESCE(download_bytes, 0) + COALESCE($3, 0),
                    disconnect_reason = 'normal'
                WHERE username = $4 AND session_id = $5 AND status = 'active'
                RETURNING id
            `, [
                getCurrentTimestamp(), 
                upload_bytes || 0, 
                download_bytes || 0,
                username,
                session_id
            ]);
            
            if (result.rows.length === 0) {
                return res.status(404).json({ error: 'No active connection found with given session ID' });
            }
            
            // Log connection end in audit trail
            await db.query(`
                INSERT INTO user_audit_logs (username, action, details, performed_by)
                VALUES ($1, $2, $3, $4)
            `, [
                username, 
                'CONNECTION_END', 
                JSON.stringify({
                    session_id,
                    connection_id: result.rows[0].id,
                    upload_bytes: upload_bytes || 0,
                    download_bytes: download_bytes || 0
                }),
                'system'
            ]);
            
            res.json({ 
                success: true, 
                message: `Connection ended for ${username}`
            });
        } catch (error) {
            logger.error(`Error recording connection end: ${error.message}`);
            res.status(500).json({ error: 'Database error' });
        }
    });

    app.post('/api/connections/update_traffic', async (req, res) => {
        const { username, session_id, upload_bytes, download_bytes } = req.body;
        
        if (!username || !session_id) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        
        try {
            // Update traffic data
            const result = await db.query(`
                UPDATE user_connections
                SET upload_bytes = COALESCE(upload_bytes, 0) + COALESCE($1, 0),
                    download_bytes = COALESCE(download_bytes, 0) + COALESCE($2, 0)
                WHERE username = $3 AND session_id = $4 AND status = 'active'
                RETURNING id
            `, [
                upload_bytes || 0, 
                download_bytes || 0,
                username,
                session_id
            ]);
            
            if (result.rows.length === 0) {
                return res.status(404).json({ error: 'No active connection found with given session ID' });
            }
            
            // Check if user has exceeded data limit
            const userResult = await db.query(
                'SELECT data_limit FROM user_profiles WHERE username = $1 AND data_limit > 0',
                [username]
            );
            
            if (userResult.rows.length > 0) {
                const dataLimit = parseInt(userResult.rows[0].data_limit);
                
                // Get total usage
                const usageResult = await db.query(`
                    SELECT SUM(upload_bytes + download_bytes) as total_usage
                    FROM user_connections
                    WHERE username = $1
                `, [username]);
                
                const totalUsage = parseInt(usageResult.rows[0].total_usage || 0);
                
                // If data limit exceeded, terminate all active connections
                if (totalUsage > dataLimit) {
                    logger.info(`User ${username} has exceeded data limit (${totalUsage} > ${dataLimit})`);
                    
                    // Get all active connections for this user
                    const connectionsResult = await db.query(`
                        SELECT id, protocol, session_id
                        FROM user_connections
                        WHERE username = $1 AND status = 'active'
                    `, [username]);
                    
                    // Terminate each connection
                    for (const conn of connectionsResult.rows) {
                        await db.query(`
                            UPDATE user_connections
                            SET status = 'terminated', disconnect_time = $1, disconnect_reason = 'data_limit_exceeded'
                            WHERE id = $2
                        `, [getCurrentTimestamp(), conn.id]);
                        
                        await terminateConnection(username, conn.protocol, conn.session_id);
                    }
                    
                    // Log the data limit event
                    await db.query(`
                        INSERT INTO user_audit_logs (username, action, details, performed_by)
                        VALUES ($1, $2, $3, $4)
                    `, [
                        username, 
                        'DATA_LIMIT_EXCEEDED', 
                        JSON.stringify({
                            usage: totalUsage,
                            limit: dataLimit,
                            connections_terminated: connectionsResult.rows.length
                        }),
                        'system'
                    ]);
                    
                    // Notify user via Telegram
                    const user = await getUserByUsername(username);
                    if (bot && user && user.telegram_id && user.usage_alerts) {
                        try {
                            await bot.telegram.sendMessage(
                                user.telegram_id,
                                `⚠️ *Data Limit Exceeded* ⚠️\n\nYour account *${username}* has reached its data transfer limit of ${formatBytes(dataLimit)}.\n\nAll active connections have been terminated. Please contact support to increase your data limit.`,
                                { parse_mode: 'Markdown' }
                            );
                        } catch (telegramError) {
                            logger.error(`Failed to send Telegram notification: ${telegramError.message}`);
                        }
                    }
                    
                    return res.json({ 
                        success: true,
                        data_limit_exceeded: true,
                        message: `Data limit exceeded for ${username}. All connections terminated.`
                    });
                }
            }
            
            res.json({ success: true });
        } catch (error) {
            logger.error(`Error updating traffic: ${error.message}`);
            res.status(500).json({ error: 'Database error' });
        }
    });

    // Function to terminate a connection based on protocol
    async function terminateConnection(username, protocol, sessionId) {
        logger.info(`Terminating ${protocol} connection for ${username}, session ${sessionId}`);
        
        try {
            // Implement protocol-specific termination logic
            switch (protocol.toLowerCase()) {
                case 'ssh':
                    // Execute a script that kills the user's SSH session
                    try {
                        await execAsync(`pkill -f "sshd:.*${username}@"`);
                    } catch (error) {
                        // pkill returns non-zero if no processes were killed, which is not an actual error
                        logger.debug(`SSH termination command result: ${error.message}`);
                    }
                    break;
                    
                case 'wireguard':
                    // Find the WireGuard interface and public key associated with this session
                    // This is just an example, you'd need to adapt to your actual wireguard setup
                    try {
                        // Example approach: Get peer info from session ID (which might contain the peer public key)
                        const peerKey = sessionId.split('_').pop(); // Assuming session ID format includes the peer key
                        if (peerKey && peerKey.length > 10) {
                            // Find the interface where this peer is connected
                            const { stdout } = await execAsync(`wg show all | grep -B 2 ${peerKey} | grep interface | awk '{print $2}'`);
                            const interface = stdout.trim();
                            
                            if (interface) {
                                // Remove the peer temporarily
                                await execAsync(`wg set ${interface} peer ${peerKey} remove`);
                                
                                // Optionally, you could re-add the peer with a different configuration
                                // that doesn't allow connections by modifying its allowed IPs
                                // await execAsync(`wg set ${interface} peer ${peerKey} allowed-ips none`);
                            }
                        }
                    } catch (error) {
                        logger.error(`WireGuard termination error: ${error.message}`);
                    }
                    break;
                    
                case 'l2tp':
                    // Terminate L2TP session - implementation depends on your L2TP setup
                    try {
                        // Example: Find and kill the pppd process associated with the username
                        await execAsync(`pkill -f "pppd.*${username}"`);
                    } catch (error) {
                        logger.debug(`L2TP termination command result: ${error.message}`);
                    }
                    break;
                    
                case 'ikev2':
                    // Terminate IKEv2 session - implementation depends on your IKEv2 setup
                    try {
                        // Example using strongswan:
                        // Find the connection ID and terminate it
                        const { stdout } = await execAsync(`swanctl --list-sas | grep -B 3 ${username} | grep unique-id | awk '{print $3}'`);
                        const uniqueId = stdout.trim();
                        
                        if (uniqueId) {
                            await execAsync(`swanctl --terminate --ike ${uniqueId}`);
                        }
                    } catch (error) {
                        logger.debug(`IKEv2 termination command result: ${error.message}`);
                    }
                    break;
                    
                case 'cisco':
                    // Terminate Cisco IPsec/OpenConnect session
                    try {
                        // Example using ocserv:
                        // Get the OpenConnect client ID and disconnect it
                        const { stdout } = await execAsync(`occtl -j show users | jq '.[] | select(.username=="${username}") | .id'`);
                        const clientId = stdout.trim().replace(/"/g, '');
                        
                        if (clientId) {
                            await execAsync(`occtl disconnect id ${clientId}`);
                        }
                    } catch (error) {
                        logger.debug(`Cisco/OpenConnect termination command result: ${error.message}`);
                    }
                    break;
                    
                case 'singbox':
                    // Terminate Sing-Box session - implementation depends on your Sing-Box setup
                    // This would typically involve API calls or configuration changes
                    logger.warn(`Sing-Box termination not fully implemented yet for user ${username}`);
                    break;
                    
                default:
                    logger.warn(`Protocol ${protocol} termination not implemented yet`);
            }
            
            // Publish termination event to Redis for other services to respond
            await redisClient.publish('connection:terminate', JSON.stringify({
                username,
                protocol,
                sessionId,
                timestamp: getCurrentTimestamp()
            }));
            
            return true;
        } catch (error) {
            logger.error(`Error terminating connection: ${error.message}`);
            return false;
        }
    }

    // User management API
    app.get('/api/users', authMiddleware, async (req, res) => {
        try {
            const result = await db.query(`
                SELECT 
                    username, 
                    email, 
                    mobile, 
                    referred_by,
                    expiry_date,
                    max_connections,
                    data_limit,
                    telegram_id,
                    notes,
                    status,
                    created_at,
                    (
                        SELECT COUNT(*) 
                        FROM user_connections 
                        WHERE username = user_profiles.username AND status = 'active'
                    ) as active_connections,
                    (
                        SELECT COALESCE(SUM(upload_bytes + download_bytes), 0)
                        FROM user_connections 
                        WHERE username = user_profiles.username
                    ) as total_usage
                FROM user_profiles
                ORDER BY 
                    CASE 
                        WHEN status = 'active' AND (expiry_date IS NULL OR expiry_date > NOW()) THEN 1
                        WHEN status = 'active' AND expiry_date <= NOW() THEN 2
                        ELSE 3
                    END,
                    username
            `);
            
            // Format the response data
            const formattedUsers = result.rows.map(user => {
                const dataLimit = parseInt(user.data_limit) || 0;
                const totalUsage = parseInt(user.total_usage) || 0;
                
                return {
                    username: user.username,
                    email: user.email,
                    mobile: user.mobile,
                    referred_by: user.referred_by,
                    max_connections: parseInt(user.max_connections) || 1,
                    active_connections: parseInt(user.active_connections) || 0,
                    telegram_id: user.telegram_id,
                    notes: user.notes,
                    status: user.status,
                    created_at: user.created_at,
                    expiry: {
                        date: user.expiry_date,
                        remaining: calculateTimeRemaining(user.expiry_date)
                    },
                    data_usage: {
                        bytes: totalUsage,
                        formatted: formatBytes(totalUsage)
                    },
                    data_limit: {
                        bytes: dataLimit,
                        formatted: formatBytes(dataLimit)
                    },
                    usage_percentage: dataLimit > 0 ? Math.min(100, Math.round((totalUsage / dataLimit) * 100)) : 0
                };
            });
            
            res.json({ users: formattedUsers });
        } catch (error) {
            logger.error(`Error fetching users: ${error.message}`);
            res.status(500).json({ error: 'Database error' });
        }
    });

    app.post('/api/users', authMiddleware, adminMiddleware, async (req, res) => {
        const { 
            username, 
            email, 
            mobile, 
            referred_by, 
            max_connections,
            expiry_days,
            data_limit_gb,
            telegram_id,
            notes,
            status
        } = req.body;
        
        if (!username) {
            return res.status(400).json({ error: 'Username is required' });
        }
        
        if (!validator.isAlphanumeric(username) && !username.includes('_') && !username.includes('-')) {
            return res.status(400).json({ error: 'Username must contain only alphanumeric characters, underscores, or hyphens' });
        }
        
        try {
            // Check if user already exists
            const existingUser = await db.query(
                'SELECT username FROM user_profiles WHERE username = $1',
                [username]
            );
            
            if (existingUser.rows.length > 0) {
                return res.status(400).json({ error: 'Username already exists' });
            }
            
            // Calculate expiry date if provided
            let expiryDate = null;
            if (expiry_days) {
                expiryDate = moment().add(parseInt(expiry_days), 'days').format('YYYY-MM-DD HH:mm:ss');
            }
            
            // Calculate data limit in bytes
            const dataLimit = data_limit_gb ? Math.floor(parseFloat(data_limit_gb) * 1024 * 1024 * 1024) : 0;
            
            // Insert new user
            await db.query(`
                INSERT INTO user_profiles (
                    username, 
                    email, 
                    mobile, 
                    referred_by, 
                    max_connections,
                    expiry_date,
                    data_limit,
                    telegram_id,
                    notes,
                    status
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            `, [
                username,
                email || null,
                mobile || null,
                referred_by || null,
                max_connections || 1,
                expiryDate,
                dataLimit,
                telegram_id || null,
                notes || null,
                status || 'active'
            ]);
            
            // Log user creation
            await db.query(`
                INSERT INTO user_audit_logs (username, action, details, performed_by)
                VALUES ($1, $2, $3, $4)
            `, [
                username, 
                'USER_CREATED',
                JSON.stringify({
                    creator: req.user.username,
                    expiry_days: expiry_days,
                    data_limit_gb: data_limit_gb
                }),
                req.user.username
            ]);
            
            res.status(201).json({ 
                success: true, 
                message: `User ${username} created successfully`,
                user: {
                    username,
                    email: email || null,
                    mobile: mobile || null,
                    referred_by: referred_by || null,
                    max_connections: max_connections || 1,
                    expiry_date: expiryDate,
                    data_limit: {
                        bytes: dataLimit,
                        formatted: formatBytes(dataLimit)
                    },
                    telegram_id: telegram_id || null,
                    notes: notes || null,
                    status: status || 'active'
                }
            });
        } catch (error) {
            logger.error(`Error creating user: ${error.message}`);
            res.status(500).json({ error: 'Database error' });
        }
    });

    // Helper function to calculate time remaining until expiry
    function calculateTimeRemaining(expiryDate) {
        if (!expiryDate) return { expired: false, days: 0, hours: 0, minutes: 0 };
        
        const now = moment();
        const expiry = moment(expiryDate);
        const diff = expiry.diff(now);
        
        if (diff <= 0) return { expired: true, days: 0, hours: 0, minutes: 0 };
        
        const duration = moment.duration(diff);
        return { 
            expired: false,
            days: Math.floor(duration.asDays()),
            hours: duration.hours(),
            minutes: duration.minutes()
        };
    }

    // Helper function to format duration in minutes
    function formatDuration(minutes) {
        if (minutes < 1) return 'Less than a minute';
        
        const hours = Math.floor(minutes / 60);
        const remainingMinutes = Math.round(minutes % 60);
        
        if (hours < 1) {
            return `${remainingMinutes} minute${remainingMinutes !== 1 ? 's' : ''}`;
        }
        
        const days = Math.floor(hours / 24);
        const remainingHours = hours % 24;
        
        if (days < 1) {
            return `${hours} hour${hours !== 1 ? 's' : ''} ${remainingMinutes} minute${remainingMinutes !== 1 ? 's' : ''}`;
        }
        
        return `${days} day${days !== 1 ? 's' : ''} ${remainingHours} hour${remainingHours !== 1 ? 's' : ''}`;
    }

    // Serve client portal static files
    const clientPortalPath = path.join(__dirname, 'client-portal');
    if (fs.existsSync(clientPortalPath)) {
        app.use('/portal', ipv6OnlyMiddleware, express.static(clientPortalPath));
    }

    // Start scheduled jobs
    setupScheduledJobs();

    // Start the server
    const PORT = process.env.PORT || 3001;
    app.listen(PORT, () => {
        logger.info(`User Manager API server running on port ${PORT}`);
    });
}

// Setup scheduled jobs
function setupScheduledJobs() {
    // Check connection limits and enforce them
    new CronJob(config.checkInterval, async () => {
        try {
            await enforceConnectionLimits();
            await checkExpiringAccounts();
        } catch (error) {
            logger.error(`Error in scheduled connection check: ${error.message}`);
        }
    }, null, true);
    
    // Auto cleanup stale connections
    new CronJob(config.autoCleanupInterval, async () => {
        try {
            await cleanupStaleConnections();
        } catch (error) {
            logger.error(`Error in stale connection cleanup: ${error.message}`);
        }
    }, null, true);
    
    // Aggregate daily statistics at midnight
    new CronJob('0 0 * * *', async () => {
        try {
            await aggregateDailyStats();
        } catch (error) {
            logger.error(`Error aggregating daily stats: ${error.message}`);
        }
    }, null, true);
}

// Function to check and enforce connection limits
async function enforceConnectionLimits() {
    logger.info('Running connection limit enforcement check');
    
    try {
        // Get all users with active connections
        const activeConnectionsResult = await db.query(`
            SELECT username, COUNT(*) as active_connections 
            FROM user_connections 
            WHERE status = 'active' 
            GROUP BY username
        `);
        
        for (const userRow of activeConnectionsResult.rows) {
            const username = userRow.username;
            const activeConnections = parseInt(userRow.active_connections);
            
            // Get user's connection limit
            const userProfileResult = await db.query(
                'SELECT max_connections FROM user_profiles WHERE username = $1',
                [username]
            );
            
            if (userProfileResult.rows.length === 0) {
                logger.warn(`No profile found for user ${username}`);
                continue;
            }
            
            const maxConnections = parseInt(userProfileResult.rows[0].max_connections);
            
            // Check if user has exceeded their connection limit
            if (activeConnections > maxConnections) {
                logger.info(`User ${username} has ${activeConnections} connections but is limited to ${maxConnections}`);
                
                // Get connections ordered by connect time (oldest first)
                const connectionsResult = await db.query(`
                    SELECT id, connect_time, protocol, client_ip, session_id
                    FROM user_connections
                    WHERE username = $1 AND status = 'active'
                    ORDER BY connect_time ASC
                `, [username]);
                
                // Keep the newest connections up to max_connections limit
                const connectionsToTerminate = connectionsResult.rows.slice(0, activeConnections - maxConnections);
                
                for (const conn of connectionsToTerminate) {
                    logger.info(`Terminating excess connection ${conn.id} for user ${username}`);
                    
                    // Update connection status
                    await db.query(`
                        UPDATE user_connections 
                        SET status = 'terminated', disconnect_time = $1, disconnect_reason = 'connection_limit_exceeded'
                        WHERE id = $2
                    `, [getCurrentTimestamp(), conn.id]);
                    
                    // Implement actual connection termination based on protocol
                    await terminateConnection(username, conn.protocol, conn.session_id);
                }
                
                // Log the event
                await db.query(`
                    INSERT INTO user_audit_logs (username, action, details, performed_by)
                    VALUES ($1, $2, $3, $4)
                `, [
                    username, 
                    'CONNECTION_LIMIT_EXCEEDED', 
                    JSON.stringify({
                        active_connections: activeConnections,
                        max_connections: maxConnections,
                        connections_terminated: connectionsToTerminate.length
                    }),
                    'system'
                ]);
                
                // Notify user via Telegram
                const user = await getUserByUsername(username);
                if (bot && user.telegram_id && user.usage_alerts) {
                    try {
                        await bot.telegram.sendMessage(
                            user.telegram_id,
                            `⚠️ *Connection Limit Warning* ⚠️\n\nYour account *${username}* has exceeded the maximum allowed connections (${maxConnections}).\n\n${connectionsToTerminate.length} oldest connection(s) have been terminated.`,
                            { parse_mode: 'Markdown' }
                        );
                    } catch (telegramError) {
                        logger.error(`Failed to send Telegram notification: ${telegramError.message}`);
                    }
                }
            }
        }
    } catch (error) {
        logger.error(`Error in enforceConnectionLimits: ${error.message}`);
    }
}

// Function to check for expiring accounts and send notifications
async function checkExpiringAccounts() {
    logger.info('Checking for accounts expiring soon');
    
    try {
        // Get notification hours from settings
        const settingsResult = await db.query(
            "SELECT setting_value FROM system_settings WHERE setting_key = 'notification_hours'"
        );
        
        const notificationHours = parseInt(settingsResult.rows[0]?.setting_value || '24');
        const expiryDate = moment().add(notificationHours, 'hours').format('YYYY-MM-DD HH:mm:ss');
        
        // Find users expiring within the notification period
        const expiringUsersResult = await db.query(`
            SELECT username, email, mobile, telegram_id, expiry_date, last_notification
            FROM user_profiles
            WHERE expiry_date <= $1 AND expiry_date > NOW() AND status = 'active'
        `, [expiryDate]);
        
        logger.info(`Found ${expiringUsersResult.rows.length} accounts expiring soon`);
        
        for (const user of expiringUsersResult.rows) {
            // Skip if notification was sent in the last 12 hours
            if (user.last_notification && moment(user.last_notification).isAfter(moment().subtract(12, 'hours'))) {
                logger.info(`Skipping notification for ${user.username} - already notified recently`);
                continue;
            }
            
            const expiryTime = moment(user.expiry_date);
            const hoursRemaining = expiryTime.diff(moment(), 'hours');
            
            logger.info(`Account ${user.username} expires in ${hoursRemaining} hours`);
            
            // Send notification via Telegram if we have bot and user's Telegram ID
            if (bot && user.telegram_id) {
                try {
                    await bot.telegram.sendMessage(user.telegram_id, 
                        `⚠️ *Account Expiry Notice* ⚠️\n\nYour account *${user.username}* will expire in *${hoursRemaining} hours*.\n\nPlease contact support to renew your subscription.`,
                        { parse_mode: 'Markdown' }
                    );
                    
                    // Update last notification timestamp
                    await db.query(`
                        UPDATE user_profiles
                        SET last_notification = $1
                        WHERE username = $2
                    `, [getCurrentTimestamp(), user.username]);
                    
                    logger.info(`Sent expiry notification to ${user.username} via Telegram`);
                } catch (error) {
                    logger.error(`Failed to send Telegram notification to ${user.username}: ${error.message}`);
                }
            } else {
                logger.info(`Cannot send notification to ${user.username} - missing Telegram info`);
            }
        }
    } catch (error) {
        logger.error(`Error in checkExpiringAccounts: ${error.message}`);
    }
}

// Function to cleanup stale connections
async function cleanupStaleConnections() {
    logger.info('Running stale connection cleanup');
    
    try {
        // Find connections that appear to be stale (active but no recent traffic updates)
        // This threshold should be configurable in the system settings
        const staleThresholdHours = 6; // Default to 6 hours
        const staleTimestamp = moment().subtract(staleThresholdHours, 'hours').format('YYYY-MM-DD HH:mm:ss');
        
        // Get stale connections
        const staleConnectionsResult = await db.query(`
            SELECT 
                id, username, protocol, session_id, connect_time, client_ip
            FROM user_connections
            WHERE status = 'active' AND connect_time < $1
        `, [staleTimestamp]);
        
        const staleConnections = staleConnectionsResult.rows;
        logger.info(`Found ${staleConnections.length} potentially stale connections`);
        
        for (const conn of staleConnections) {
            // Check if the connection is truly stale by attempting to check its status
            // This depends on the protocol and implementation details
            const isActive = await isConnectionActive(conn.protocol, conn.username, conn.session_id);
            
            if (!isActive) {
                logger.info(`Cleaning up stale connection ${conn.id} for user ${conn.username} (${conn.protocol})`);
                
                // Update connection status
                await db.query(`
                    UPDATE user_connections
                    SET status = 'closed', 
                        disconnect_time = $1,
                        disconnect_reason = 'stale_connection'
                    WHERE id = $2
                `, [getCurrentTimestamp(), conn.id]);
                
                // Log the cleanup
                await db.query(`
                    INSERT INTO user_audit_logs (username, action, details, performed_by)
                    VALUES ($1, $2, $3, $4)
                `, [
                    conn.username, 
                    'STALE_CONNECTION_CLEANUP',
                    JSON.stringify({
                        connection_id: conn.id,
                        protocol: conn.protocol,
                        connect_time: conn.connect_time,
                        duration: moment.duration(moment().diff(moment(conn.connect_time))).asHours().toFixed(2) + ' hours'
                    }),
                    'system'
                ]);
            }
        }
    } catch (error) {
        logger.error(`Error in cleanupStaleConnections: ${error.message}`);
    }
}

// Helper function to check if a connection is still active
async function isConnectionActive(protocol, username, sessionId) {
    try {
        switch (protocol.toLowerCase()) {
            case 'ssh':
                // Check if SSH session is still active
                const { stdout: sshOutput } = await execAsync(`ps aux | grep sshd | grep "${username}@" | grep -v grep`);
                return sshOutput.trim() !== '';
                
            case 'wireguard':
                // Check if WireGuard peer is still connected
                // This depends on how you've structured your session IDs
                const peerKey = sessionId.split('_').pop();
                if (peerKey && peerKey.length > 10) {
                    const { stdout: wgOutput } = await execAsync(`wg show all | grep -A 1 "${peerKey}" | grep "latest handshake"`);
                    
                    if (wgOutput.trim() === '') return false;
                    
                    // Check if the latest handshake was within the last hour
                    const handshakeMatch = wgOutput.match(/(\d+) seconds? ago/);
                    if (handshakeMatch) {
                        const seconds = parseInt(handshakeMatch[1]);
                        return seconds < 3600; // Less than 1 hour
                    }
                }
                return false;
                
            // Add cases for other protocols
            default:
                // If we don't have a specific check for this protocol, assume it's active
                return true;
        }
    } catch (error) {
        logger.debug(`Error checking connection status: ${error.message}`);
        // If there's an error checking the status, assume it's not active
        return false;
    }
}

// Function to aggregate daily statistics
async function aggregateDailyStats() {
    logger.info('Aggregating daily connection statistics');
    
    try {
        // Call the database function we created in the schema
        await db.query('SELECT aggregate_daily_traffic()');
        logger.info('Daily traffic statistics aggregated successfully');
    } catch (error) {
        logger.error(`Error aggregating daily stats: ${error.message}`);
    }
}

// Create client portal frontend
function create_client_portal() {
    const portalDir = path.join(__dirname, 'client-portal');
    const indexPath = path.join(portalDir, 'index.html');
    
    // Ensure directory exists
    if (!fs.existsSync(portalDir)) {
        fs.mkdirSync(portalDir, { recursive: true });
    }
    
    // Create HTML file for client portal
    fs.writeFileSync(indexPath, `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IRSSH Client Portal</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.css">
    <style>
        body {
            background-color: #f8f9fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .card {
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
            border: none;
        }
        .stat-card {
            text-align: center;
            padding: 15px;
            border-radius: 8px;
        }
        .stat-card h3 {
            font-size: 2rem;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .stat-card p {
            color: #6c757d;
            margin-bottom: 0;
        }
        .login-container {
            max-width: 400px;
            margin: 100px auto;
        }
        .navbar-brand {
            font-weight: bold;
            font-size: 1.5rem;
        }
        .connection-row {
            border-left: 5px solid #198754;
            margin-bottom: 10px;
            padding: 10px;
            border-radius: 5px;
            background-color: #f8f9fa;
        }
        .connection-row.inactive {
            border-left-color: #dc3545;
        }
        .loading {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100px;
        }
        .spinner-border {
            width: 3rem;
            height: 3rem;
        }
        #app {
            display: none;
        }
        .protocol-badge {
            font-size: 0.8rem;
            padding: 5px 10px;
            border-radius: 20px;
        }
        .chart-container {
            position: relative;
            height: 300px;
            width: 100%;
        }
        .dark-mode {
            background-color: #212529;
            color: #f8f9fa;
        }
        .dark-mode .card {
            background-color: #343a40;
            color: #f8f9fa;
        }
        .dark-mode .table {
            color: #f8f9fa;
        }
        .dark-mode .bg-light {
            background-color: #343a40 !important;
        }
        .dark-mode .text-dark {
            color: #f8f9fa !important;
        }
    </style>
</head>
<body>
    <div id="login" class="login-container">
        <div class="card">
            <div class="card-body">
                <h2 class="text-center mb-4">IRSSH Client Portal</h2>
                <form id="loginForm">
                    <div class="mb-3">
                        <label for="username" class="form-label">Username</label>
                        <input type="text" class="form-control" id="username" required>
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">Password</label>
                        <input type="password" class="form-control" id="password" required>
                    </div>
                    <div id="loginError" class="alert alert-danger d-none"></div>
                    <button type="submit" class="btn btn-primary w-100">Login</button>
                </form>
            </div>
        </div>
    </div>

    <div id="app">
        <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
            <div class="container">
                <a class="navbar-brand" href="#">IRSSH Client Portal</a>
                <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                    <span class="navbar-toggler-icon"></span>
                </button>
                <div class="collapse navbar-collapse" id="navbarNav">
                    <ul class="navbar-nav ms-auto">
                        <li class="nav-item">
                            <a class="nav-link active" href="#" id="dashboardLink">Dashboard</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#" id="connectionsLink">Connection History</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#" id="usageLink">Usage Statistics</a>
                        </li>
                        <li class="nav-item">
                            <button class="nav-link btn" id="themeToggle">🌓</button>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#" id="logoutBtn">Logout</a>
                        </li>
                    </ul>
                </div>
            </div>
        </nav>

        <div class="container mt-4">
            <div id="dashboard">
                <div class="row">
                    <div class="col-md-12">
                        <div class="card">
                            <div class="card-body">
                                <h5 class="card-title">Account Overview</h5>
                                <div class="row mt-3">
                                    <div class="col-md-6">
                                        <table class="table">
                                            <tr>
                                                <th>Username:</th>
                                                <td id="accountUsername"></td>
                                            </tr>
                                            <tr>
                                                <th>Expiry Date:</th>
                                                <td id="accountExpiry"></td>
                                            </tr>
                                            <tr>
                                                <th>Time Remaining:</th>
                                                <td id="accountTimeRemaining"></td>
                                            </tr>
                                            <tr>
                                                <th>Max Connections:</th>
                                                <td id="accountMaxConnections"></td>
                                            </tr>
                                        </table>
                                    </div>
                                    <div class="col-md-6">
                                        <h6>Data Usage</h6>
                                        <div class="progress mb-2" style="height: 25px;">
                                            <div id="dataUsageProgress" class="progress-bar" role="progressbar" style="width: 0%;" 
                                                aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">0%</div>
                                        </div>
                                        <div class="d-flex justify-content-between">
                                            <span id="dataUsed">0 GB</span>
                                            <span id="dataLimit">0 GB</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="row mt-4">
                    <div class="col-md-4">
                        <div class="card stat-card bg-light">
                            <p>Total Traffic (30 days)</p>
                            <h3 id="totalTraffic">-</h3>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card stat-card bg-light">
                            <p>Active Connections</p>
                            <h3 id="activeConnections">-</h3>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card stat-card bg-light">
                            <p>Total Connection Time</p>
                            <h3 id="totalConnectionTime">-</h3>
                        </div>
                    </div>
                </div>

                <div class="row mt-4">
                    <div class="col-md-12">
                        <div class="card">
                            <div class="card-body">
                                <h5 class="card-title">Daily Usage</h5>
                                <div class="chart-container">
                                    <canvas id="trafficChart"></canvas>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div id="connections" style="display: none;">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Connection History</h5>
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>Protocol</th>
                                        <th>Connect Time</th>
                                        <th>Duration</th>
                                        <th>Upload</th>
                                        <th>Download</th>
                                        <th>Total</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody id="connectionsTable">
                                    <!-- Connection data will be inserted here -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <div id="usage" style="display: none;">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Protocol Usage Summary</h5>
                        <div id="protocolSummary" class="mt-3">
                            <!-- Protocol summary will be inserted here -->
                        </div>
                    </div>
                </div>

                <div class="card mt-4">
                    <div class="card-body">
                        <h5 class="card-title">Daily Usage Statistics</h5>
                        <div class="chart-container">
                            <canvas id="dailyUsageChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>

            <div id="loading" class="loading">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/moment@2.29.4/moment.min.js"></script>
    <script>
        // API utilities
        const API = {
            token: null,
            
            async request(endpoint, method = 'GET', data = null) {
                const headers = {
                    'Content-Type': 'application/json'
                };
                
                if (this.token) {
                    headers['Authorization'] = \`Bearer \${this.token}\`;
                }
                
                const options = {
                    method,
                    headers
                };
                
                if (data) {
                    options.body = JSON.stringify(data);
                }
                
                try {
                    const response = await fetch(endpoint, options);
                    const result = await response.json();
                    
                    if (!response.ok) {
                        throw new Error(result.error || 'API request failed');
                    }
                    
                    return result;
                } catch (error) {
                    console.error('API Error:', error);
                    throw error;
                }
            },
            
            login(username, password) {
                return this.request('/portal/api/login', 'POST', { username, password });
            },
            
            getAccount() {
                return this.request('/portal/api/account');
            },
            
            getConnectionHistory() {
                return this.request('/portal/api/connections/history');
            },
            
            getDailyUsage() {
                return this.request('/portal/api/connections/daily');
            }
        };
        
        // DOM elements
        const elements = {
            login: document.getElementById('login'),
            loginForm: document.getElementById('loginForm'),
            loginError: document.getElementById('loginError'),
            app: document.getElementById('app'),
            loading: document.getElementById('loading'),
            dashboard: document.getElementById('dashboard'),
            connections: document.getElementById('connections'),
            usage: document.getElementById('usage'),
            
            // Navigation
            dashboardLink: document.getElementById('dashboardLink'),
            connectionsLink: document.getElementById('connectionsLink'),
            usageLink: document.getElementById('usageLink'),
            logoutBtn: document.getElementById('logoutBtn'),
            themeToggle: document.getElementById('themeToggle'),
            
            // Account info
            accountUsername: document.getElementById('accountUsername'),
            accountExpiry: document.getElementById('accountExpiry'),
            accountTimeRemaining: document.getElementById('accountTimeRemaining'),
            accountMaxConnections: document.getElementById('accountMaxConnections'),
            dataUsageProgress: document.getElementById('dataUsageProgress'),
            dataUsed: document.getElementById('dataUsed'),
            dataLimit: document.getElementById('dataLimit'),
            
            // Stats
            totalTraffic: document.getElementById('totalTraffic'),
            activeConnections: document.getElementById('activeConnections'),
            totalConnectionTime: document.getElementById('totalConnectionTime'),
            
            // Tables
            connectionsTable: document.getElementById('connectionsTable'),
            protocolSummary: document.getElementById('protocolSummary'),
        };
        
        // Charts
        let trafficChart = null;
        let dailyUsageChart = null;
        
        // Show/hide sections
        function showSection(section) {
            elements.dashboard.style.display = 'none';
            elements.connections.style.display = 'none';
            elements.usage.style.display = 'none';
            elements.loading.style.display = 'none';
            
            // Reset active nav links
            elements.dashboardLink.classList.remove('active');
            elements.connectionsLink.classList.remove('active');
            elements.usageLink.classList.remove('active');
            
            if (section === 'dashboard') {
                elements.dashboard.style.display = 'block';
                elements.dashboardLink.classList.add('active');
            } else if (section === 'connections') {
                elements.connections.style.display = 'block';
                elements.connectionsLink.classList.add('active');
            } else if (section === 'usage') {
                elements.usage.style.display = 'block';
                elements.usageLink.classList.add('active');
            } else if (section === 'loading') {
                elements.loading.style.display = 'flex';
            }
        }
        
        // Initialize app
        async function initApp() {
            // Check for saved token
            const savedToken = localStorage.getItem('portal_token');
            if (savedToken) {
                API.token = savedToken;
                elements.login.style.display = 'none';
                elements.app.style.display = 'block';
                showSection('loading');
                
                try {
                    await loadDashboard();
                    showSection('dashboard');
                } catch (error) {
                    // Token invalid or expired
                    logout();
                }
            }
            
            // Login form handler
            elements.loginForm.addEventListener('submit', async function(e) {
                e.preventDefault();
                
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                
                try {
                    elements.loginError.classList.add('d-none');
                    showSection('loading');
                    const result = await API.login(username, password);
                    
                    API.token = result.token;
                    localStorage.setItem('portal_token', result.token);
                    
                    elements.login.style.display = 'none';
                    elements.app.style.display = 'block';
                    
                    await loadDashboard();
                    showSection('dashboard');
                } catch (error) {
                    elements.loginError.textContent = error.message || 'Login failed. Please check your credentials.';
                    elements.loginError.classList.remove('d-none');
                    elements.login.style.display = 'block';
                }
            });
            
            // Navigation handlers
            elements.dashboardLink.addEventListener('click', async function(e) {
                e.preventDefault();
                showSection('loading');
                await loadDashboard();
                showSection('dashboard');
            });
            
            elements.connectionsLink.addEventListener('click', async function(e) {
                e.preventDefault();
                showSection('loading');
                await loadConnections();
                showSection('connections');
            });
            
            elements.usageLink.addEventListener('click', async function(e) {
                e.preventDefault();
                showSection('loading');
                await loadUsage();
                showSection('usage');
            });
            
            elements.logoutBtn.addEventListener('click', function(e) {
                e.preventDefault();
                logout();
            });
            
            // Theme toggle
            elements.themeToggle.addEventListener('click', function() {
                document.body.classList.toggle('dark-mode');
                localStorage.setItem('dark-mode', document.body.classList.contains('dark-mode'));
            });
            
            // Check for saved theme preference
            if (localStorage.getItem('dark-mode') === 'true') {
                document.body.classList.add('dark-mode');
            }
        }
        
        // Load dashboard data
        async function loadDashboard() {
            try {
                const accountData = await API.getAccount();
                const connectionsData = await API.getConnectionHistory();
                
                // Update account info
                elements.accountUsername.textContent = accountData.account.username;
                elements.accountExpiry.textContent = accountData.account.expiry_date ? 
                    new Date(accountData.account.expiry_date).toLocaleString() : 'No expiry date';
                elements.accountTimeRemaining.textContent = \`\${accountData.account.time_remaining.days} days, \${accountData.account.time_remaining.hours} hours\`;
                elements.accountMaxConnections.textContent = accountData.account.max_connections;
                
                // Update data usage
                if (accountData.account.data_usage.limit.bytes > 0) {
                    elements.dataUsageProgress.style.width = \`\${accountData.account.data_usage.percentage}%\`;
                    elements.dataUsageProgress.textContent = \`\${accountData.account.data_usage.percentage}%\`;
                    
                    if (accountData.account.data_usage.percentage > 90) {
                        elements.dataUsageProgress.classList.add('bg-danger');
                    } else if (accountData.account.data_usage.percentage > 75) {
                        elements.dataUsageProgress.classList.add('bg-warning');
                    } else {
                        elements.dataUsageProgress.classList.add('bg-success');
                    }
                } else {
                    elements.dataUsageProgress.style.width = '100%';
                    elements.dataUsageProgress.textContent = 'Unlimited';
                    elements.dataUsageProgress.classList.add('bg-info');
                }
                
                elements.dataUsed.textContent = accountData.account.data_usage.used.formatted;
                elements.dataLimit.textContent = accountData.account.data_usage.limit.bytes > 0 ? 
                    accountData.account.data_usage.limit.formatted : 'Unlimited';
                
                // Update stats
                elements.totalTraffic.textContent = connectionsData.summary.total_traffic.formatted;
                
                const activeConnections = connectionsData.connections.filter(conn => conn.status === 'active').length;
                elements.activeConnections.textContent = activeConnections;
                
                elements.totalConnectionTime.textContent = connectionsData.summary.total_duration.formatted;
                
                // Create traffic chart
                if (trafficChart) {
                    trafficChart.destroy();
                }
                
                const ctx = document.getElementById('trafficChart').getContext('2d');
                trafficChart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: connectionsData.chart_data.map(d => moment(d.date).format('MMM DD')),
                        datasets: [
                            {
                                label: 'Upload (MB)',
                                data: connectionsData.chart_data.map(d => d.upload_mb),
                                backgroundColor: 'rgba(54, 162, 235, 0.5)',
                                borderColor: 'rgba(54, 162, 235, 1)',
                                borderWidth: 1
                            },
                            {
                                label: 'Download (MB)',
                                data: connectionsData.chart_data.map(d => d.download_mb),
                                backgroundColor: 'rgba(75, 192, 192, 0.5)',
                                borderColor: 'rgba(75, 192, 192, 1)',
                                borderWidth: 1
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: {
                                beginAtZero: true,
                                title: {
                                    display: true,
                                    text: 'Megabytes'
                                }
                            }
                        }
                    }
                });
                
            } catch (error) {
                console.error('Error loading dashboard:', error);
                alert('Error loading data. Please try again.');
            }
        }
        
        // Load connections data
        async function loadConnections() {
            try {
                const connectionsData = await API.getConnectionHistory();
                
                // Clear table
                elements.connectionsTable.innerHTML = '';
                
                // Add connection rows
                for (const conn of connectionsData.connections) {
                    const row = document.createElement('tr');
                    
                    const statusClass = conn.status === 'active' ? 'success' : 
                        (conn.status === 'terminated' ? 'danger' : 'secondary');
                    
                    row.innerHTML = \`
                        <td><span class="badge bg-\${getProtocolColor(conn.protocol)} protocol-badge">\${conn.protocol}</span></td>
                        <td>\${new Date(conn.connect_time).toLocaleString()}</td>
                        <td>\${conn.duration.formatted}</td>
                        <td>\${conn.upload.formatted}</td>
                        <td>\${conn.download.formatted}</td>
                        <td>\${conn.total_traffic.formatted}</td>
                        <td><span class="badge bg-\${statusClass}">\${conn.status}</span></td>
                    \`;
                    
                    elements.connectionsTable.appendChild(row);
                }
                
            } catch (error) {
                console.error('Error loading connections:', error);
                alert('Error loading connection data. Please try again.');
            }
        }
        
        // Load usage statistics
        async function loadUsage() {
            try {
                const connectionsData = await API.getConnectionHistory();
                const dailyData = await API.getDailyUsage();
                
                // Protocol summary
                elements.protocolSummary.innerHTML = '';
                
                const protocols = Object.keys(connectionsData.summary.by_protocol);
                
                if (protocols.length > 0) {
                    const summaryTable = document.createElement('div');
                    summaryTable.className = 'table-responsive';
                    summaryTable.innerHTML = \`
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Protocol</th>
                                    <th>Connections</th>
                                    <th>Total Duration</th>
                                    <th>Upload</th>
                                    <th>Download</th>
                                    <th>Total Traffic</th>
                                </tr>
                            </thead>
                            <tbody>
                                \${protocols.map(protocol => {
                                    const data = connectionsData.summary.by_protocol[protocol];
                                    return \`
                                        <tr>
                                            <td><span class="badge bg-\${getProtocolColor(protocol)} protocol-badge">\${protocol}</span></td>
                                            <td>\${data.connections}</td>
                                            <td>\${data.duration.formatted}</td>
                                            <td>\${data.upload.formatted}</td>
                                            <td>\${data.download.formatted}</td>
                                            <td>\${data.total_traffic.formatted}</td>
                                        </tr>
                                    \`;
                                }).join('')}
                            </tbody>
                        </table>
                    \`;
                    
                    elements.protocolSummary.appendChild(summaryTable);
                } else {
                    elements.protocolSummary.innerHTML = '<p class="text-center">No protocol data available</p>';
                }
                
                // Daily usage chart
                if (dailyUsageChart) {
                    dailyUsageChart.destroy();
                }
                
                const ctx = document.getElementById('dailyUsageChart').getContext('2d');
                dailyUsageChart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: dailyData.daily_stats.map(d => moment(d.date).format('MMM DD')),
                        datasets: [
                            {
                                label: 'Total Traffic (MB)',
                                data: dailyData.daily_stats.map(d => Math.round(d.total_traffic.bytes / (1024 * 1024) * 100) / 100),
                                borderColor: 'rgba(153, 102, 255, 1)',
                                backgroundColor: 'rgba(153, 102, 255, 0.2)',
                                borderWidth: 2,
                                fill: true,
                                tension: 0.4
                            },
                            {
                                label: 'Duration (Hours)',
                                data: dailyData.daily_stats.map(d => Math.round(d.duration.minutes / 60 * 10) / 10),
                                borderColor: 'rgba(255, 159, 64, 1)',
                                backgroundColor: 'rgba(255, 159, 64, 0.2)',
                                borderWidth: 2,
                                fill: true,
                                tension: 0.4,
                                yAxisID: 'y1'
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: {
                                beginAtZero: true,
                                title: {
                                    display: true,
                                    text: 'Traffic (MB)'
                                }
                            },
                            y1: {
                                beginAtZero: true,
                                position: 'right',
                                title: {
                                    display: true,
                                    text: 'Duration (Hours)'
                                },
                                grid: {
                                    drawOnChartArea: false
                                }
                            }
                        }
                    }
                });
                
            } catch (error) {
                console.error('Error loading usage statistics:', error);
                alert('Error loading usage data. Please try again.');
            }
        }
        
        // Helper function for protocol colors
        function getProtocolColor(protocol) {
            const colors = {
                'ssh': 'primary',
                'wireguard': 'success',
                'l2tp': 'info',
                'ikev2': 'warning',
                'cisco': 'danger',
                'singbox': 'dark'
            };
            
            return colors[protocol.toLowerCase()] || 'secondary';
        }
        
        // Logout function
        function logout() {
            localStorage.removeItem('portal_token');
            API.token = null;
            elements.app.style.display = 'none';
            elements.login.style.display = 'block';
            elements.loginForm.reset();
        }
        
        // Initialize the application
        document.addEventListener('DOMContentLoaded', initApp);
    </script>
</body>
</html>`);
    
    logger.info("Client portal frontend created successfully.");
}

module.exports = app;
}

# Create monitoring scripts for protocols
function create_monitoring_scripts() {
    log "INFO" "Creating protocol monitoring scripts..."
    
    # Create SSH connection monitor
    cat > $SCRIPTS_DIR/monitoring/ssh_monitor.py << 'EOF'
#!/usr/bin/env python3

"""
SSH Connection Monitor for IRSSH-Panel
This script monitors SSH connections and reports to the connection tracker
"""

import os
import sys
import time
import json
import logging
import subprocess
import argparse
import requests
import hashlib
import psycopg2
import configparser
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/opt/irssh-panel/logs/ssh_monitor.log')
    ]
)
logger = logging.getLogger('ssh-monitor')

# Configuration
CONFIG_FILE = '/opt/irssh-panel/config/db/database.conf'

# API endpoints
API_URL = 'http://localhost:3001/api/connections'

def load_config():
    """Load database configuration from file"""
    if not os.path.exists(CONFIG_FILE):
        logger.error(f"Config file not found: {CONFIG_FILE}")
        sys.exit(1)
        
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    
    try:
        db_config = {
            'host': config.get('DEFAULT', 'DB_HOST', fallback='localhost'),
            'port': config.get('DEFAULT', 'DB_PORT', fallback='5432'),
            'dbname': config.get('DEFAULT', 'DB_NAME'),
            'user': config.get('DEFAULT', 'DB_USER'),
            'password': config.get('DEFAULT', 'DB_PASSWORD')
        }
        return db_config
    except configparser.NoSectionError:
        # Try reading as KEY=VALUE format
        db_config = {}
        with open(CONFIG_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"\'')
                    
                    if key == 'DB_HOST':
                        db_config['host'] = value
                    elif key == 'DB_PORT':
                        db_config['port'] = value
                    elif key == 'DB_NAME':
                        db_config['dbname'] = value
                    elif key == 'DB_USER':
                        db_config['user'] = value
                    elif key == 'DB_PASSWORD':
                        db_config['password'] = value
                        
        if not all(k in db_config for k in ['dbname', 'user', 'password']):
            logger.error("Missing required database configuration")
            sys.exit(1)
            
        return db_config

def get_db_connection():
    """Get a connection to the PostgreSQL database"""
    db_config = load_config()
    try:
        conn = psycopg2.connect(**db_config)
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        return None

def get_active_ssh_connections():
    """Get currently active SSH sessions with username"""
    try:
        # Get all active SSH connections
        output = subprocess.check_output(
            "netstat -tnpa | grep 'ESTABLISHED.*sshd' | awk '{print $5 \" \" $7}'", 
            shell=True, text=True
        )
        
        connections = []
        for line in output.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                ip_address = parts[0].split(':')[0]  # Remove port
                process_info = ' '.join(parts[1:])
                
                # Extract username from process info
                # Format is usually: sshd: username@pts/0
                if 'sshd:' in process_info:
                    username_part = process_info.split('sshd:')[1].strip()
                    if '@' in username_part:
                        username = username_part.split('@')[0].strip()
                        
                        # Skip system users
                        if username not in ['root', 'nobody', 'sshd']:
                            connections.append({
                                'username': username,
                                'ip_address': ip_address,
                                'session_id': f"{username}_{ip_address}_{hash_session_id(username, ip_address)}"
                            })
        
        return connections
    except Exception as e:
        logger.error(f"Error getting SSH connections: {e}")
        return []

def hash_session_id(username, ip_address):
    """Create a unique hash for the session ID"""
    session_string = f"{username}_{ip_address}_{int(time.time())}"
    return hashlib.md5(session_string.encode()).hexdigest()[:16]

def check_user_exists(username):
    """Check if user exists in the database"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT username FROM user_profiles WHERE username = %s", (username,))
            return cur.fetchone() is not None
    except Exception as e:
        logger.error(f"Error checking user existence: {e}")
        return False
    finally:
        conn.close()

def get_active_sessions_from_db():
    """Get active sessions from the database"""
    conn = get_db_connection()
    if not conn:
        return {}
    
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT username, session_id FROM user_connections "
                "WHERE protocol = 'ssh' AND status = 'active'"
            )
            return {row[1]: row[0] for row in cur.fetchall()}
    except Exception as e:
        logger.error(f"Error getting active sessions from DB: {e}")
        return {}
    finally:
        conn.close()

def report_connection_start(username, ip_address, session_id):
    """Report new connection to the API"""
    try:
        response = requests.post(
            f"{API_URL}/start",
            json={
                "username": username,
                "protocol": "ssh",
                "client_ip": ip_address,
                "session_id": session_id
            },
            timeout=5
        )
        
        if response.status_code == 200:
            logger.info(f"Reported new SSH connection: {username} from {ip_address}")
            return True
        else:
            logger.error(f"Failed to report connection: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error reporting connection start: {e}")
        return False

def report_connection_end(username, session_id):
    """Report connection end to the API"""
    try:
        response = requests.post(
            f"{API_URL}/end",
            json={
                "username": username,
                "session_id": session_id
            },
            timeout=5
        )
        
        if response.status_code == 200:
            logger.info(f"Reported SSH disconnect: {username} (Session: {session_id})")
            return True
        else:
            logger.warning(f"Failed to report disconnect: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error reporting connection end: {e}")
        return False

def monitor_ssh_connections():
    """Main monitoring loop"""
    logger.info("Starting SSH connection monitor")
    
    # Track previous connections
    previous_connections = set()
    
    # Run continuously
    while True:
        try:
            # Get current SSH connections
            current_connections = get_active_ssh_connections()
            current_session_ids = {conn['session_id'] for conn in current_connections}
            
            # Get active sessions from database
            db_sessions = get_active_sessions_from_db()
            
            # Check for new connections
            for conn in current_connections:
                if conn['session_id'] not in previous_connections:
                    # Verify user exists in our system
                    if check_user_exists(conn['username']):
                        report_connection_start(
                            conn['username'], 
                            conn['ip_address'], 
                            conn['session_id']
                        )
            
            # Check for ended connections
            for session_id, username in db_sessions.items():
                if session_id not in current_session_ids:
                    report_connection_end(username, session_id)
            
            # Update previous connections for next iteration
            previous_connections = current_session_ids
            
            # Sleep before next check
            time.sleep(60)  # Check every minute
            
        except KeyboardInterrupt:
            logger.info("Stopping SSH connection monitor")
            break
        except Exception as e:
            logger.error(f"Error in monitoring loop: {e}")
            time.sleep(30)  # Sleep and retry

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SSH Connection Monitor for IRSSH-Panel')
    parser.add_argument('--daemon', action='store_true', help='Run as a daemon process')
    args = parser.parse_args()
    
    if args.daemon:
        # Fork process to run as daemon
        pid = os.fork()
        if pid > 0:
            # Exit parent process
            sys.exit(0)
            
        # Detach from terminal
        os.setsid()
        os.umask(0)
        
        # Fork again
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
        
        # Close file descriptors
        for fd in range(0, 3):
            try:
                os.close(fd)
            except OSError:
                pass
                
        # Redirect stdout/stderr
        sys.stdout = open('/opt/irssh-panel/logs/ssh_monitor_stdout.log', 'w')
        sys.stderr = open('/opt/irssh-panel/logs/ssh_monitor_stderr.log', 'w')
        
        logger.info("Running as daemon process")
    
    monitor_ssh_connections()
EOF
    
    # Make SSH monitor executable
    chmod +x $SCRIPTS_DIR/monitoring/ssh_monitor.py
    
    # Create WireGuard monitor script
    cat > $SCRIPTS_DIR/monitoring/wireguard_monitor.py << 'EOF'
#!/usr/bin/env python3

"""
WireGuard Connection Monitor for IRSSH-Panel
This script monitors WireGuard connections and reports to the connection tracker
"""

import os
import sys
import time
import json
import logging
import subprocess
import argparse
import requests
import hashlib
import psycopg2
import configparser
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/opt/irssh-panel/logs/wireguard_monitor.log')
    ]
)
logger = logging.getLogger('wireguard-monitor')

# Configuration
CONFIG_FILE = '/opt/irssh-panel/config/db/database.conf'
WG_CONFIG_DIR = '/etc/wireguard'

# API endpoints
API_URL = 'http://localhost:3001/api/connections'

def load_config():
    """Load database configuration from file"""
    if not os.path.exists(CONFIG_FILE):
        logger.error(f"Config file not found: {CONFIG_FILE}")
        sys.exit(1)
        
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    
    try:
        db_config = {
            'host': config.get('DEFAULT', 'DB_HOST', fallback='localhost'),
            'port': config.get('DEFAULT', 'DB_PORT', fallback='5432'),
            'dbname': config.get('DEFAULT', 'DB_NAME'),
            'user': config.get('DEFAULT', 'DB_USER'),
            'password': config.get('DEFAULT', 'DB_PASSWORD')
        }
        return db_config
    except configparser.NoSectionError:
        # Try reading as KEY=VALUE format
        db_config = {}
        with open(CONFIG_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"\'')
                    
                    if key == 'DB_HOST':
                        db_config['host'] = value
                    elif key == 'DB_PORT':
                        db_config['port'] = value
                    elif key == 'DB_NAME':
                        db_config['dbname'] = value
                    elif key == 'DB_USER':
                        db_config['user'] = value
                    elif key == 'DB_PASSWORD':
                        db_config['password'] = value
                        
        if not all(k in db_config for k in ['dbname', 'user', 'password']):
            logger.error("Missing required database configuration")
            sys.exit(1)
            
        return db_config

def get_db_connection():
    """Get a connection to the PostgreSQL database"""
    db_config = load_config()
    try:
        conn = psycopg2.connect(**db_config)
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        return None

def get_username_for_pubkey(pubkey):
    """Map public key to username based on WireGuard config"""
    if not os.path.exists(WG_CONFIG_DIR):
        logger.error(f"WireGuard config directory not found: {WG_CONFIG_DIR}")
        return None
        
    for config_file in os.listdir(WG_CONFIG_DIR):
        if not config_file.endswith('.conf'):
            continue
            
        config_path = os.path.join(WG_CONFIG_DIR, config_file)
        with open(config_path, 'r') as f:
            config_content = f.read()
            
        if pubkey in config_content:
            # Try to extract username from config comment
            lines = config_content.splitlines()
            for i, line in enumerate(lines):
                if pubkey in line and i > 0:
                    # Check previous lines for a user comment
                    for j in range(i-1, max(0, i-3), -1):
                        if '# User:' in lines[j]:
                            return lines[j].split('# User:')[1].strip()
            
            # Fallback: try to get from database
            conn = get_db_connection()
            if conn:
                try:
                    with conn.cursor() as cur:
                        cur.execute(
                            "SELECT username FROM wireguard_peers WHERE public_key = %s",
                            (pubkey,)
                        )
                        result = cur.fetchone()
                        if result:
                            return result[0]
                except Exception as e:
                    logger.error(f"Database error: {e}")
                finally:
                    conn.close()
    
    return None

def get_active_wireguard_connections():
    """Get active WireGuard connections"""
    active_connections = []
    
    try:
        # Get all WireGuard interfaces
        interfaces_output = subprocess.check_output(
            "wg show interfaces", 
            shell=True, text=True
        ).strip()
        
        if not interfaces_output:
            return []
            
        interfaces = interfaces_output.split()
        
        for interface in interfaces:
            # Get peer information for this interface
            wg_output = subprocess.check_output(
                f"wg show {interface} dump", 
                shell=True, text=True
            )
            
            # Skip header line
            for line in wg_output.splitlines()[1:]:
                parts = line.strip().split()
                if len(parts) < 6:
                    continue
                    
                pubkey = parts[0]
                endpoint = parts[2]
                latest_handshake = int(parts[3])
                rx_bytes = int(parts[4])
                tx_bytes = int(parts[5])
                
                # Consider connection active if handshake was within last 3 minutes
                current_time = int(time.time())
                if current_time - latest_handshake < 180:
                    username = get_username_for_pubkey(pubkey)
                    
                    if username:
                        active_connections.append({
                            'username': username,
                            'pubkey': pubkey,
                            'endpoint': endpoint,
                            'rx_bytes': rx_bytes,
                            'tx_bytes': tx_bytes,
                            'interface': interface,
                            'session_id': f"wg_{username}_{pubkey[:8]}"
                        })
        
        return active_connections
    except Exception as e:
        logger.error(f"Error getting WireGuard connections: {e}")
        return []

def get_active_sessions_from_db():
    """Get active WireGuard sessions from the database"""
    conn = get_db_connection()
    if not conn:
        return {}
    
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT username, session_id FROM user_connections "
                "WHERE protocol = 'wireguard' AND status = 'active'"
            )
            return {row[1]: row[0] for row in cur.fetchall()}
    except Exception as e:
        logger.error(f"Error getting active sessions from DB: {e}")
        return {}
    finally:
        conn.close()

def report_connection_start(username, endpoint, session_id):
    """Report new connection to the API"""
    try:
        response = requests.post(
            f"{API_URL}/start",
            json={
                "username": username,
                "protocol": "wireguard",
                "client_ip": endpoint.split(':')[0] if ':' in endpoint else endpoint,
                "session_id": session_id
            },
            timeout=5
        )
        
        if response.status_code == 200:
            logger.info(f"Reported new WireGuard connection: {username} from {endpoint}")
            return True
        else:
            logger.error(f"Failed to report connection: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error reporting connection start: {e}")
        return False

def report_connection_end(username, session_id):
    """Report connection end to the API"""
    try:
        response = requests.post(
            f"{API_URL}/end",
            json={
                "username": username,
                "session_id": session_id
            },
            timeout=5
        )
        
        if response.status_code == 200:
            logger.info(f"Reported WireGuard disconnect: {username} (Session: {session_id})")
            return True
        else:
            logger.warning(f"Failed to report disconnect: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error reporting connection end: {e}")
        return False

def update_traffic_stats(username, session_id, rx_bytes, tx_bytes):
    """Update traffic statistics for an active connection"""
    try:
        response = requests.post(
            f"{API_URL}/update_traffic",
            json={
                "username": username,
                "session_id": session_id,
                "upload_bytes": tx_bytes,
                "download_bytes": rx_bytes
            },
            timeout=5
        )
        
        if response.status_code != 200:
            logger.warning(f"Failed to update traffic stats: {response.status_code} - {response.text}")
    except Exception as e:
        logger.error(f"Error updating traffic stats: {e}")

def monitor_wireguard_connections():
    """Main monitoring loop"""
    logger.info("Starting WireGuard connection monitor")
    
    # Track previous connections and their traffic stats
    previous_connections = {}
    
    # Run continuously
    while True:
        try:
            # Get current WireGuard connections
            current_connections = get_active_wireguard_connections()
            current_connections_map = {conn['session_id']: conn for conn in current_connections}
            
            # Get active sessions from database
            db_sessions = get_active_sessions_from_db()
            
            # Check for new connections and update traffic stats
            for conn in current_connections:
                session_id = conn['session_id']
                
                # New connection
                if session_id not in previous_connections:
                    report_connection_start(
                        conn['username'],
                        conn['endpoint'],
                        session_id
                    )
                else:
                    # Update traffic stats - calculate delta
                    prev_rx = previous_connections[session_id]['rx_bytes']
                    prev_tx = previous_connections[session_id]['tx_bytes']
                    
                    # Calculate traffic increments
                    rx_delta = conn['rx_bytes'] - prev_rx
                    tx_delta = conn['tx_bytes'] - prev_tx
                    
                    # Only report if there's actual traffic (avoid unnecessary API calls)
                    if rx_delta > 0 or tx_delta > 0:
                        update_traffic_stats(
                            conn['username'],
                            session_id,
                            rx_delta,
                            tx_delta
                        )
            
            # Check for ended connections
            for session_id, username in db_sessions.items():
                if session_id not in current_connections_map:
                    report_connection_end(username, session_id)
            
            # Update previous connections for next iteration
            previous_connections = current_connections_map
            
            # Sleep before next check
            time.sleep(60)  # Check every minute
        
        except KeyboardInterrupt:
            logger.info("Stopping WireGuard connection monitor")
            break
        except Exception as e:
            logger.error(f"Error in monitoring loop: {e}")
            time.sleep(30)  # Sleep and retry

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='WireGuard Connection Monitor for IRSSH-Panel')
    parser.add_argument('--daemon', action='store_true', help='Run as a daemon process')
    args = parser.parse_args()
    
    if args.daemon:
        # Fork process to run as daemon
        pid = os.fork()
        if pid > 0:
            # Exit parent process
            sys.exit(0)
            
        # Detach from terminal
        os.setsid()
        os.umask(0)
        
        # Fork again
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
        
        # Close file descriptors
        for fd in range(0, 3):
            try:
                os.close(fd)
            except OSError:
                pass
                
        # Redirect stdout/stderr
        sys.stdout = open('/opt/irssh-panel/logs/wireguard_monitor_stdout.log', 'w')
        sys.stderr = open('/opt/irssh-panel/logs/wireguard_monitor_stderr.log', 'w')
        
        logger.info("Running as daemon process")
    
    monitor_wireguard_connections()
EOF
    
    # Make WireGuard monitor executable
    chmod +x $SCRIPTS_DIR/monitoring/wireguard_monitor.py
    
    log "INFO" "Protocol monitoring scripts created."
}

# Create systemd service files for user manager and monitors
function create_systemd_services() {
    log "INFO" "Creating systemd service files..."
    
    # Create user-manager service
    cat > /etc/systemd/system/irssh-user-manager.service << EOF
[Unit]
Description=IRSSH Panel User Management Service
After=network.target postgresql.service redis-server.service
Wants=postgresql.service redis-server.service

[Service]
Type=simple
User=root
WorkingDirectory=$SERVICES_DIR/user-manager
ExecStart=/usr/bin/node index.js
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
Environment=NODE_ENV=production
EnvironmentFile=-$CONFIG_DIR/db/database.conf

[Install]
WantedBy=multi-user.target
EOF
    
    # Create SSH monitor service
    cat > /etc/systemd/system/irssh-ssh-monitor.service << EOF
[Unit]
Description=IRSSH SSH Connection Monitor
After=network.target sshd.service irssh-user-manager.service
Wants=irssh-user-manager.service

[Service]
Type=simple
User=root
ExecStart=$SCRIPTS_DIR/monitoring/ssh_monitor.py --daemon
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # Create WireGuard monitor service if WireGuard is installed
    if command -v wg &> /dev/null; then
        cat > /etc/systemd/system/irssh-wireguard-monitor.service << EOF
[Unit]
Description=IRSSH WireGuard Connection Monitor
After=network.target wg-quick@wg0.service irssh-user-manager.service
Wants=irssh-user-manager.service

[Service]
Type=simple
User=root
ExecStart=$SCRIPTS_DIR/monitoring/wireguard_monitor.py --daemon
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    fi
    
    # Create auto-repair service
    cat > /etc/systemd/system/irssh-auto-repair.service << EOF
[Unit]
Description=IRSSH Panel Auto-Repair Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=$SCRIPTS_DIR/auto_repair.sh
Restart=always
RestartSec=300
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Create auto-repair script
    cat > $SCRIPTS_DIR/auto_repair.sh << 'EOF'
#!/bin/bash

# IRSSH Panel Auto-Repair Script
# This script periodically checks the health of the system and attempts to repair any issues

LOG_DIR="/var/log/irssh"
SERVICES=("postgresql" "redis-server" "irssh-user-manager" "irssh-ssh-monitor" "nginx")
REPAIR_LOG="$LOG_DIR/auto_repair.log"

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

log() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1" >> "$REPAIR_LOG"
}

check_and_repair_service() {
    local service=$1
    log "Checking service: $service"
    
    if ! systemctl is-active --quiet "$service"; then
        log "Service $service is not running. Attempting to start..."
        systemctl start "$service"
        
        sleep 5
        
        if systemctl is-active --quiet "$service"; then
            log "Successfully started $service"
        else
            log "Failed to start $service. Checking for common issues..."
            
            case "$service" in
                postgresql)
                    # Check for PostgreSQL common issues
                    if [ -d "/var/lib/postgresql" ]; then
                        log "Checking PostgreSQL data directory permissions..."
                        chown -R postgres:postgres /var/lib/postgresql
                    fi
                    ;;
                redis-server)
                    # Check Redis common issues
                    log "Checking Redis socket file..."
                    rm -f /var/run/redis/redis-server.sock
                    ;;
                irssh-user-manager)
                    # Check if Node.js is installed
                    if ! command -v node &> /dev/null; then
                        log "Node.js not found. Attempting to reinstall..."
                        apt-get install -y nodejs npm
                    fi
                    
                    # Check if service directory exists
                    if [ ! -d "/opt/irssh-panel/services/user-manager" ]; then
                        log "User-manager service directory not found!"
                    else
                        # Try reinstalling dependencies
                        log "Reinstalling Node.js dependencies..."
                        cd /opt/irssh-panel/services/user-manager
                        npm install
                    fi
                    ;;
            esac
            
            # Try starting the service again
            systemctl start "$service"
            
            if systemctl is-active --quiet "$service"; then
                log "Successfully started $service after repairs"
            else
                log "Failed to start $service after repairs. Manual intervention required."
            fi
        fi
    else
        log "Service $service is running normally"
    fi
}

check_disk_space() {
    log "Checking disk space..."
    
    # Check root filesystem usage
    local disk_usage=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    
    if [ "$disk_usage" -gt 90 ]; then
        log "WARNING: Disk space is critically low: ${disk_usage}%"
        
        # Try to cleanup some space
        log "Cleaning up old logs and temporary files..."
        find /var/log -type f -name "*.gz" -delete
        find /var/log -type f -name "*.1" -delete
        find /var/log -type f -name "*.old" -delete
        find /tmp -type f -mtime +7 -delete
        
        # Clean package cache
        apt-get clean
        
        # Check disk usage again
        disk_usage=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
        log "Disk usage after cleanup: ${disk_usage}%"
    else
        log "Disk space is adequate: ${disk_usage}%"
    fi
}

check_database_health() {
    log "Checking PostgreSQL database health..."
    
    if systemctl is-active --quiet postgresql; then
        # Check if our database exists and is accessible
        if su - postgres -c "psql -l" | grep -q "irssh_panel"; then
            log "Database exists and is accessible"
            
            # Check for dead connections
            local dead_connections=$(su - postgres -c "psql -d irssh_panel -c \"SELECT count(*) FROM pg_stat_activity WHERE state = 'idle in transaction' AND (now() - state_change) > '10 minutes'::interval;\"" | sed -n 3p | tr -d ' ')
            
            if [ "$dead_connections" -gt 5 ]; then
                log "Found $dead_connections idle transactions. Terminating..."
                su - postgres -c "psql -d irssh_panel -c \"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE state = 'idle in transaction' AND (now() - state_change) > '10 minutes'::interval;\""
            fi
        else
            log "Warning: Database not found or not accessible"
        fi
    else
        log "PostgreSQL is not running, skipping database checks"
    fi
}

# Main function
main() {
    log "Starting auto-repair check..."
    
    # Check all critical services
    for service in "${SERVICES[@]}"; do
        check_and_repair_service "$service"
    done
    
    # Check disk space
    check_disk_space
    
    # Check database health
    check_database_health
    
    log "Auto-repair check completed"
}

# Run the main function
main
EOF

    # Make auto-repair script executable
    chmod +x $SCRIPTS_DIR/auto_repair.sh
    
    # Reload systemd to recognize new services
    systemctl daemon-reload
    
    log "INFO" "Systemd service files created."
}

# Create admin user management script
function create_admin_script() {
    log "INFO" "Creating admin user management script..."
    
    cat > $SCRIPTS_DIR/admin_user_management.sh << 'EOF'
#!/bin/bash

# IRSSH-Panel Advanced User Management Admin Script
# This script provides CLI utilities for managing users

# Colors and formatting
BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Load database configuration
if [ -f "/opt/irssh-panel/config/db/database.conf" ]; then
    source /opt/irssh-panel/config/db/database.conf
else
    echo -e "${RED}Error: Database configuration not found${NC}"
    exit 1
fi

# Check if psql is available
if ! command -v psql &> /dev/null; then
    echo -e "${RED}Error: PostgreSQL client (psql) not installed${NC}"
    exit 1
fi

# Check system performance and recommendations
system_health_check() {
    clear
    echo -e "${BOLD}${BLUE}System Health Check${NC}"
    echo "======================="
    echo ""
    
    # Check CPU load
    load=$(cat /proc/loadavg | awk '{print $1}')
    cores=$(grep -c ^processor /proc/cpuinfo)
    load_per_core=$(echo "$load/$cores" | bc -l)
    
    echo -e "CPU Cores: ${cores}"
    echo -e "Current Load: ${load} ($(printf "%.2f" $(echo "$load_per_core*100" | bc -l))% per core)"
    
    if (( $(echo "$load_per_core > 0.7" | bc -l) )); then
        echo -e "${RED}[WARNING] CPU load is high${NC}"
    elif (( $(echo "$load_per_core > 0.5" | bc -l) )); then
        echo -e "${YELLOW}[WARNING] CPU load is moderate${NC}"
    else
        echo -e "${GREEN}[OK] CPU load is normal${NC}"
    fi
    
    # Check memory usage
    mem_total=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    mem_available=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
    mem_used=$(($mem_total - $mem_available))
    mem_percent=$(( ($mem_used * 100) / $mem_total ))
    
    echo -e "\nMemory Total: $(($mem_total / 1024)) MB"
    echo -e "Memory Used: $(($mem_used / 1024)) MB (${mem_percent}%)"
    
    if [ $mem_percent -gt 90 ]; then
        echo -e "${RED}[WARNING] Memory usage is very high${NC}"
    elif [ $mem_percent -gt 75 ]; then
        echo -e "${YELLOW}[WARNING] Memory usage is high${NC}"
    else
        echo -e "${GREEN}[OK] Memory usage is normal${NC}"
    fi
    
    # Check disk usage
    disk_usage=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    
    echo -e "\nDisk Usage: ${disk_usage}%"
    
    if [ $disk_usage -gt 90 ]; then
        echo -e "${RED}[WARNING] Disk usage is very high${NC}"
    elif [ $disk_usage -gt 75 ]; then
        echo -e "${YELLOW}[WARNING] Disk usage is high${NC}"
    else
        echo -e "${GREEN}[OK] Disk usage is normal${NC}"
    fi
    
    # Check database connections
    db_connections=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT count(*) FROM pg_stat_activity;")
    db_connections=$(echo $db_connections | tr -d ' ')
    
    echo -e "\nActive Database Connections: ${db_connections}"
    
    if [ $db_connections -gt 20 ]; then
        echo -e "${YELLOW}[WARNING] Many database connections${NC}"
    else
        echo -e "${GREEN}[OK] Database connection count is normal${NC}"
    fi
    
    # Check service status
    echo -e "\nService Status:"
    
    services=("postgresql" "redis-server" "irssh-user-manager" "irssh-ssh-monitor")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet $service; then
            echo -e "${GREEN}[ACTIVE]${NC} $service"
        else
            echo -e "${RED}[INACTIVE]${NC} $service"
        fi
    done
    
    echo ""
    echo -n "Press Enter to continue..."
    read
}

# Main menu
show_main_menu() {
    clear
    echo -e "${BOLD}${BLUE}IRSSH-Panel Advanced User Management${NC}"
    echo "========================================"
    echo ""
    echo "1. List Users"
    echo "2. Add User"
    echo "3. Bulk Add Users"
    echo "4. Modify User"
    echo "5. Delete User"
    echo "6. View User Details"
    echo "7. View Active Connections"
    echo "8. Connection History"
    echo "9. Users About to Expire"
    echo "10. Send Notification"
    echo "11. Restart Services"
    echo "12. System Health Check"
    echo "13. Database Backup"
    echo "14. Exit"
    echo ""
    echo -n "Enter your choice [1-14]: "
    read choice
    
    case $choice in
        1) list_users ;;
        2) add_user ;;
        3) bulk_add_users ;;
        4) modify_user ;;
        5) delete_user ;;
        6) view_user_details ;;
        7) view_active_connections ;;
        8) connection_history ;;
        9) users_to_expire ;;
        10) send_notification ;;
        11) restart_services ;;
        12) system_health_check ;;
        13) backup_database ;;
        14) exit 0 ;;
        *) 
            echo -e "${RED}Invalid choice. Press Enter to continue...${NC}"
            read
            show_main_menu
            ;;
    esac
}

# Run PostgreSQL query
run_query() {
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -t -c "$1"
}

# Format bytes to human-readable
format_bytes() {
    local bytes=$1
    local decimals=${2:-2}
    
    if ((bytes < 1024)); then
        echo "${bytes} B"
    elif ((bytes < 1048576)); then
        echo "$(bc <<< "scale=$decimals; $bytes/1024") KB"
    elif ((bytes < 1073741824)); then
        echo "$(bc <<< "scale=$decimals; $bytes/1048576") MB"
    else
        echo "$(bc <<< "scale=$decimals; $bytes/1073741824") GB"
    fi
}

# Format duration in minutes
format_duration() {
    local minutes=$1
    
    if (( minutes < 60 )); then
        echo "${minutes}m"
    elif (( minutes < 1440 )); then
        local hours=$(( minutes / 60 ))
        local remaining_minutes=$(( minutes % 60 ))
        echo "${hours}h ${remaining_minutes}m"
    else
        local days=$(( minutes / 1440 ))
        local remaining_hours=$(( (minutes % 1440) / 60 ))
        echo "${days}d ${remaining_hours}h"
    fi
}

# List all users
list_users() {
    clear
    echo -e "${BOLD}User List${NC}"
    echo "=========="
    echo ""
    
    local result=$(run_query "
        SELECT 
            username, 
            expiry_date, 
            max_connections, 
            CASE 
                WHEN data_limit = 0 THEN 'Unlimited' 
                ELSE pg_size_pretty(data_limit) 
            END as data_limit,
            status,
            CASE 
                WHEN expiry_date IS NULL THEN 'No expiry'
                WHEN expiry_date < NOW() THEN 'Expired' 
                ELSE CONCAT(
                    EXTRACT(DAY FROM expiry_date - NOW())::INTEGER, 'd ', 
                    EXTRACT(HOUR FROM expiry_date - NOW())::INTEGER, 'h'
                )
            END as time_left,
            (
                SELECT COUNT(*) 
                FROM user_connections 
                WHERE username = user_profiles.username AND status = 'active'
            ) as active_connections
        FROM user_profiles
        ORDER BY 
            CASE 
                WHEN status = 'active' AND (expiry_date IS NULL OR expiry_date > NOW()) THEN 1
                WHEN status = 'active' AND expiry_date <= NOW() THEN 2
                ELSE 3
            END,
            username
    ")
    
    # Print column headers
    printf "%-20s | %-15s | %-20s | %-15s | %-15s | %-10s | %-8s\n" "Username" "Status" "Expiry Date" "Time Left" "Data Limit" "Max Conn" "Active"
    echo "------------------------------------------------------------------------------------------------------"
    
    # Parse and print results
    echo "$result" | while read -r line; do
        if [[ -z "$line" ]]; then continue; fi
        
        # Extract fields
        local username=$(echo "$line" | awk -F'|' '{print $1}' | sed 's/^ *//g' | sed 's/ *$//g')
        local expiry_date=$(echo "$line" | awk -F'|' '{print $2}' | sed 's/^ *//g' | sed 's/ *$//g')
        local max_conn=$(echo "$line" | awk -F'|' '{print $3}' | sed 's/^ *//g' | sed 's/ *$//g')
        local data_limit=$(echo "$line" | awk -F'|' '{print $4}' | sed 's/^ *//g' | sed 's/ *$//g')
        local status=$(echo "$line" | awk -F'|' '{print $5}' | sed 's/^ *//g' | sed 's/ *$//g')
        local time_left=$(echo "$line" | awk -F'|' '{print $6}' | sed 's/^ *//g' | sed 's/ *$//g')
        local active=$(echo "$line" | awk -F'|' '{print $7}' | sed 's/^ *//g' | sed 's/ *$//g')
        
        # Colorize status
        local status_colored="$status"
        if [[ "$status" == "active" ]]; then
            status_colored="${GREEN}active${NC}"
        elif [[ "$status" == "deactive" ]]; then
            status_colored="${RED}deactive${NC}"
        elif [[ "$status" == "suspended" ]]; then
            status_colored="${YELLOW}suspended${NC}"
        fi
        
        # Colorize expired users
        if [[ "$time_left" == "Expired" ]]; then
            printf "%-20s | %-15b | %-20s | ${RED}%-15s${NC} | %-15s | %-10s | %-8s\n" "$username" "$status_colored" "$expiry_date" "$time_left" "$data_limit" "$max_conn" "$active"
        elif [[ "$time_left" == "No expiry" ]]; then
            printf "%-20s | %-15b | %-20s | ${GREEN}%-15s${NC} | %-15s | %-10s | %-8s\n" "$username" "$status_colored" "$expiry_date" "$time_left" "$data_limit" "$max_conn" "$active"
        else
            printf "%-20s | %-15b | %-20s | %-15s | %-15s | %-10s | %-8s\n" "$username" "$status_colored" "$expiry_date" "$time_left" "$data_limit" "$max_conn" "$active"
        fi
    done
    
    echo ""
    echo -n "Press Enter to continue..."
    read
    show_main_menu
}

# Backup database
backup_database() {
    clear
    echo -e "${BOLD}Database Backup${NC}"
    echo "================"
    echo ""
    
    # Check for backup directory
    BACKUP_DIR="/opt/irssh-backups/db"
    if [ ! -d "$BACKUP_DIR" ]; then
        mkdir -p "$BACKUP_DIR"
    fi
    
    # Generate filename with timestamp
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    BACKUP_FILE="$BACKUP_DIR/${DB_NAME}-${TIMESTAMP}.backup"
    
    echo -e "Creating backup in: ${BACKUP_FILE}"
    echo -e "Please wait..."
    
    # Perform backup
    PGPASSWORD="$DB_PASSWORD" pg_dump -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -F c -f "$BACKUP_FILE"
    
    if [ $? -eq 0 ]; then
        # Compress the backup
        gzip "$BACKUP_FILE"
        echo -e "${GREEN}Backup completed successfully!${NC}"
        echo -e "Backup saved to: ${BACKUP_FILE}.gz"
        
        # Show existing backups
        echo ""
        echo -e "Existing backups:"
        ls -lh "$BACKUP_DIR" | grep -v "total" | sort -r
        
        # Cleanup old backups (keep last 30)
        echo ""
        BACKUP_COUNT=$(ls -1 "$BACKUP_DIR" | wc -l)
        if [ $BACKUP_COUNT -gt 30 ]; then
            echo -e "Cleaning up old backups (keeping last 30)..."
            ls -t "$BACKUP_DIR" | tail -n +31 | xargs -I {} rm -f "$BACKUP_DIR/{}"
        fi
    else
        echo -e "${RED}Backup failed!${NC}"
    fi
    
    echo ""
    echo -n "Press Enter to continue..."
    read
    show_main_menu
}

# Start the main menu
show_main_menu
EOF
    
    chmod +x $SCRIPTS_DIR/admin_user_management.sh
    
    # Create symlink for easy access
    ln -sf $SCRIPTS_DIR/admin_user_management.sh /usr/local/bin/irssh-users
    
    log "INFO" "Admin user management script created."
}

# Modify install script to include user management module
function modify_install_script() {
    log "INFO" "Updating main install script to include user management module..."
    
    # Create patch script for the main installer
    cat > $SCRIPTS_DIR/patch_installer.sh << 'EOF'
#!/bin/bash

# This script patches the main IRSSH-Panel install script to include user management features

INSTALL_SCRIPT="/opt/irssh-panel/scripts/install.sh"

if [ ! -f "$INSTALL_SCRIPT" ]; then
    echo "Error: Main install script not found!"
    exit 1
fi

# Create backup of original script
cp "$INSTALL_SCRIPT" "${INSTALL_SCRIPT}.backup"

# Add user management module to the installation
sed -i '/# Main installation function/i \
# Install user management module\
function install_user_management() {\
    info "Installing advanced user management module..."\
    \
    # Run the user management installer script\
    bash $SCRIPT_DIR/modules/user-management/setup.sh\
    \
    info "User management module installation completed"\
}\
' "$INSTALL_SCRIPT"

# Add user management to main() function
sed -i '/cleanup/i \
   # Install user management if requested\
   if [ "$INSTALL_USER_MANAGEMENT" = "y" ]; then\
       install_user_management\
   fi\
' "$INSTALL_SCRIPT"

# Add user management option to configuration
sed -i '/read -p "Enable monitoring? (y\/N): " ENABLE_MONITORING/a \
    read -p "Install advanced user management module? (y\/N): " INSTALL_USER_MANAGEMENT\
    INSTALL_USER_MANAGEMENT=${INSTALL_USER_MANAGEMENT,,}\
' "$INSTALL_SCRIPT"

echo "Main install script patched successfully!"
EOF

    chmod +x $SCRIPTS_DIR/patch_installer.sh
    
    # Create symbolica link to the user management module for the main installer
    mkdir -p $PANEL_DIR/scripts/modules/user-management
    ln -sf $SCRIPTS_DIR/setup.sh $PANEL_DIR/scripts/modules/user-management/setup.sh
    
    log "INFO" "Main install script updated."
}

# Create Dashboard Widgets for User Management
function create_dashboard_widgets() {
    log "INFO" "Creating dashboard widgets for user management..."
    
    # Create React component for user management dashboard
    mkdir -p $FRONTEND_DIR/src/components/users
    
    # Create UserManagement.jsx component
    cat > $FRONTEND_DIR/src/components/users/UserManagement.jsx << 'EOF'
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { toast } from 'react-hot-toast';

const UserManagement = () => {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [newUser, setNewUser] = useState({
        username: '',
        max_connections: 1,
        expiry_days: 30,
        data_limit_gb: 0
    });
    const [showAddForm, setShowAddForm] = useState(false);
    const [activeUsers, setActiveUsers] = useState(0);
    const [expiredUsers, setExpiredUsers] = useState(0);
    const [expiringUsers, setExpiringUsers] = useState(0);

    // Fetch users data
    useEffect(() => {
        fetchUsers();
    }, []);

    const fetchUsers = async () => {
        try {
            setLoading(true);
            const response = await axios.get('/api/users');
            setUsers(response.data.users);
            
            // Count statistics
            const active = response.data.users.filter(user => 
                user.status === 'active' && 
                (!user.expiry.date || new Date(user.expiry.date) > new Date())
            ).length;
            
            const expired = response.data.users.filter(user => 
                user.expiry.date && new Date(user.expiry.date) < new Date()
            ).length;
            
            const expiring = response.data.users.filter(user => {
                if (!user.expiry.date) return false;
                const expiryDate = new Date(user.expiry.date);
                const tomorrow = new Date();
                tomorrow.setDate(tomorrow.getDate() + 1);
                return expiryDate > new Date() && expiryDate < tomorrow;
            }).length;
            
            setActiveUsers(active);
            setExpiredUsers(expired);
            setExpiringUsers(expiring);
            
            setLoading(false);
        } catch (error) {
            console.error('Error fetching users:', error);
            toast.error('Failed to load users');
            setLoading(false);
        }
    };

    const handleInputChange = (e) => {
        const { name, value } = e.target;
        setNewUser(prev => ({ ...prev, [name]: value }));
    };

    const handleAddUser = async (e) => {
        e.preventDefault();
        try {
            await axios.post('/api/users', newUser);
            toast.success(`User ${newUser.username} created successfully`);
            setNewUser({
                username: '',
                max_connections: 1,
                expiry_days: 30,
                data_limit_gb: 0
            });
            setShowAddForm(false);
            fetchUsers();
        } catch (error) {
            console.error('Error creating user:', error);
            toast.error(error.response?.data?.error || 'Failed to create user');
        }
    };

    const handleDeleteUser = async (username) => {
        if (window.confirm(`Are you sure you want to delete user ${username}?`)) {
            try {
                await axios.delete(`/api/users/${username}`);
                toast.success(`User ${username} deleted successfully`);
                fetchUsers();
            } catch (error) {
                console.error('Error deleting user:', error);
                toast.error('Failed to delete user');
            }
        }
    };

    const handleExtendUser = async (username, days) => {
        try {
            await axios.put(`/api/users/${username}`, { extend_days: days });
            toast.success(`Extended ${username}'s expiry by ${days} days`);
            fetchUsers();
        } catch (error) {
            console.error('Error extending user:', error);
            toast.error('Failed to extend user');
        }
    };

    return (
        <div className="user-management-container">
            <div className="user-stats">
                <div className="stat-card">
                    <h3>{activeUsers}</h3>
                    <p>Active Users</p>
                </div>
                <div className="stat-card">
                    <h3>{expiredUsers}</h3>
                    <p>Expired Users</p>
                </div>
                <div className="stat-card">
                    <h3>{expiringUsers}</h3>
                    <p>Expiring in 24h</p>
                </div>
                <div className="stat-card">
                    <h3>{users.length}</h3>
                    <p>Total Users</p>
                </div>
            </div>

            <div className="user-actions">
                <button 
                    className="btn btn-primary" 
                    onClick={() => setShowAddForm(!showAddForm)}
                >
                    {showAddForm ? 'Cancel' : 'Add New User'}
                </button>
                <button 
                    className="btn btn-secondary" 
                    onClick={fetchUsers}
                >
                    Refresh
                </button>
            </div>

            {showAddForm && (
                <div className="add-user-form">
                    <h3>Add New User</h3>
                    <form onSubmit={handleAddUser}>
                        <div className="form-group">
                            <label>Username:</label>
                            <input 
                                type="text" 
                                name="username" 
                                value={newUser.username} 
                                onChange={handleInputChange} 
                                required 
                            />
                        </div>
                        <div className="form-group">
                            <label>Max Connections:</label>
                            <input 
                                type="number" 
                                name="max_connections" 
                                value={newUser.max_connections} 
                                onChange={handleInputChange} 
                                min="1" 
                                required 
                            />
                        </div>
                        <div className="form-group">
                            <label>Expiry Days:</label>
                            <input 
                                type="number" 
                                name="expiry_days" 
                                value={newUser.expiry_days} 
                                onChange={handleInputChange} 
                                min="1" 
                                required 
                            />
                        </div>
                        <div className="form-group">
                            <label>Data Limit (GB, 0 for unlimited):</label>
                            <input 
                                type="number" 
                                name="data_limit_gb" 
                                value={newUser.data_limit_gb} 
                                onChange={handleInputChange} 
                                min="0" 
                                step="0.1" 
                                required 
                            />
                        </div>
                        <div className="form-actions">
                            <button type="submit" className="btn btn-success">Create User</button>
                            <button type="button" className="btn btn-danger" onClick={() => setShowAddForm(false)}>Cancel</button>
                        </div>
                    </form>
                </div>
            )}

            <div className="users-table">
                <h3>User List</h3>
                {loading ? (
                    <p>Loading users...</p>
                ) : (
                    <table>
                        <thead>
                            <tr>
                                <th>Username</th>
                                <th>Status</th>
                                <th>Expiry</th>
                                <th>Data Usage</th>
                                <th>Connections</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {users.map(user => (
                                <tr key={user.username}>
                                    <td>{user.username}</td>
                                    <td>
                                        <span className={`status-badge ${user.status}`}>
                                            {user.status}
                                        </span>
                                    </td>
                                    <td>
                                        {user.expiry.date ? (
                                            <>
                                                {new Date(user.expiry.date).toLocaleDateString()}<br/>
                                                <small>
                                                    {user.expiry.remaining.expired ? 
                                                        <span className="expired">Expired</span> : 
                                                        `${user.expiry.remaining.days}d ${user.expiry.remaining.hours}h left`
                                                    }
                                                </small>
                                            </>
                                        ) : (
                                            <span>No expiry</span>
                                        )}
                                    </td>
                                    <td>
                                        {user.data_usage.formatted} / {user.data_limit.formatted}
                                        <div className="progress-bar">
                                            <div 
                                                className="progress" 
                                                style={{width: `${user.usage_percentage}%`}}
                                            ></div>
                                        </div>
                                    </td>
                                    <td>
                                        {user.active_connections} / {user.max_connections}
                                    </td>
                                    <td>
                                        <div className="action-buttons">
                                            <button 
                                                className="btn btn-sm btn-info"
                                                onClick={() => window.location.href = `/users/${user.username}`}
                                            >
                                                View
                                            </button>
                                            <button 
                                                className="btn btn-sm btn-success"
                                                onClick={() => handleExtendUser(user.username, 30)}
                                            >
                                                +30d
                                            </button>
                                            <button 
                                                className="btn btn-sm btn-danger"
                                                onClick={() => handleDeleteUser(user.username)}
                                            >
                                                Delete
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
        </div>
    );
};

export default UserManagement;
EOF

    # Create UserDetail.jsx component
    cat > $FRONTEND_DIR/src/components/users/UserDetail.jsx << 'EOF'
import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'react-hot-toast';
import { Chart, registerables } from 'chart.js';
Chart.register(...registerables);

const UserDetail = () => {
    const { username } = useParams();
    const [user, setUser] = useState(null);
    const [connections, setConnections] = useState([]);
    const [loading, setLoading] = useState(true);
    const [summary, setSummary] = useState({});
    const [editMode, setEditMode] = useState(false);
    const [userData, setUserData] = useState({
        max_connections: 1,
        extend_days: 30,
        data_limit_gb: 0,
        status: 'active'
    });
    const [trafficChart, setTrafficChart] = useState(null);

    useEffect(() => {
        fetchUserDetails();
    }, [username]);

    useEffect(() => {
        if (connections.length > 0 && !trafficChart) {
            createTrafficChart();
        }
    }, [connections]);

    const fetchUserDetails = async () => {
        try {
            setLoading(true);
            const response = await axios.get(`/api/users/${username}`);
            setUser(response.data.user);
            setConnections(response.data.connections);
            setSummary(response.data.summary);
            
            // Initialize form data with current user values
            setUserData({
                max_connections: response.data.user.max_connections,
                extend_days: 30, // Default value
                data_limit_gb: response.data.user.data_limit.bytes / (1024 * 1024 * 1024),
                status: response.data.user.status
            });
            
            setLoading(false);
        } catch (error) {
            console.error('Error fetching user details:', error);
            toast.error('Failed to load user details');
            setLoading(false);
        }
    };

    const handleInputChange = (e) => {
        const { name, value } = e.target;
        setUserData(prev => ({ ...prev, [name]: value }));
    };

    const handleUpdateUser = async (e) => {
        e.preventDefault();
        try {
            await axios.put(`/api/users/${username}`, userData);
            toast.success(`User ${username} updated successfully`);
            setEditMode(false);
            fetchUserDetails();
        } catch (error) {
            console.error('Error updating user:', error);
            toast.error(error.response?.data?.error || 'Failed to update user');
        }
    };

    const terminateConnection = async (sessionId) => {
        if (!window.confirm('Are you sure you want to terminate this connection?')) {
            return;
        }
        
        try {
            await axios.post(`/api/connections/${sessionId}/terminate`);
            toast.success('Connection terminated successfully');
            fetchUserDetails();
        } catch (error) {
            console.error('Error terminating connection:', error);
            toast.error('Failed to terminate connection');
        }
    };

    const createTrafficChart = () => {
        const ctx = document.getElementById('trafficChart');
        if (!ctx) return;
        
        // Group connections by date
        const dailyData = connections.reduce((acc, conn) => {
            const date = new Date(conn.connect_time).toLocaleDateString();
            
            if (!acc[date]) {
                acc[date] = {
                    upload: 0,
                    download: 0
                };
            }
            
            acc[date].upload += conn.upload.bytes;
            acc[date].download += conn.download.bytes;
            
            return acc;
        }, {});
        
        const labels = Object.keys(dailyData).sort((a, b) => new Date(a) - new Date(b));
        const uploadData = labels.map(date => dailyData[date].upload / (1024 * 1024)); // MB
        const downloadData = labels.map(date => dailyData[date].download / (1024 * 1024)); // MB
        
        if (trafficChart) {
            trafficChart.destroy();
        }
        
        const newChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels,
                datasets: [
                    {
                        label: 'Upload (MB)',
                        data: uploadData,
                        backgroundColor: 'rgba(54, 162, 235, 0.5)',
                        borderColor: 'rgba(54, 162, 235, 1)',
                        borderWidth: 1
                    },
                    {
                        label: 'Download (MB)',
                        data: downloadData,
                        backgroundColor: 'rgba(75, 192, 192, 0.5)',
                        borderColor: 'rgba(75, 192, 192, 1)',
                        borderWidth: 1
                    }
                ]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Traffic (MB)'
                        }
                    }
                }
            }
        });
        
        setTrafficChart(newChart);
    };

    if (loading) {
        return <div className="loading">Loading user details...</div>;
    }

    if (!user) {
        return <div className="error">User not found</div>;
    }

    return (
        <div className="user-detail-container">
            <div className="user-header">
                <h2>User: {username}</h2>
                <div className="user-actions">
                    <button 
                        className="btn btn-primary" 
                        onClick={() => setEditMode(!editMode)}
                    >
                        {editMode ? 'Cancel' : 'Edit User'}
                    </button>
                    <button 
                        className="btn btn-secondary" 
                        onClick={fetchUserDetails}
                    >
                        Refresh
                    </button>
                </div>
            </div>

            <div className="user-info-container">
                <div className="user-info-card">
                    <h3>Account Information</h3>
                    {editMode ? (
                        <form onSubmit={handleUpdateUser}>
                            <div className="form-group">
                                <label>Max Connections:</label>
                                <input 
                                    type="number" 
                                    name="max_connections" 
                                    value={userData.max_connections} 
                                    onChange={handleInputChange} 
                                    min="1" 
                                    required 
                                />
                            </div>
                            <div className="form-group">
                                <label>Extend Expiry (Days):</label>
                                <input 
                                    type="number" 
                                    name="extend_days" 
                                    value={userData.extend_days} 
                                    onChange={handleInputChange} 
                                    min="0" 
                                />
                            </div>
                            <div className="form-group">
                                <label>Data Limit (GB, 0 for unlimited):</label>
                                <input 
                                    type="number" 
                                    name="data_limit_gb" 
                                    value={userData.data_limit_gb} 
                                    onChange={handleInputChange} 
                                    min="0" 
                                    step="0.1" 
                                />
                            </div>
                            <div className="form-group">
                                <label>Status:</label>
                                <select 
                                    name="status" 
                                    value={userData.status} 
                                    onChange={handleInputChange}
                                >
                                    <option value="active">Active</option>
                                    <option value="deactive">Deactive</option>
                                    <option value="suspended">Suspended</option>
                                </select>
                            </div>
                            <div className="form-actions">
                                <button type="submit" className="btn btn-success">Save Changes</button>
                                <button 
                                    type="button" 
                                    className="btn btn-danger" 
                                    onClick={() => setEditMode(false)}
                                >
                                    Cancel
                                </button>
                            </div>
                        </form>
                    ) : (
                        <div className="user-info">
                            <p>
                                <strong>Status:</strong> 
                                <span className={`status-badge ${user.status}`}>
                                    {user.status}
                                </span>
                            </p>
                            <p>
                                <strong>Created:</strong> {new Date(user.created_at).toLocaleString()}
                            </p>
                            <p>
                                <strong>Expiry:</strong> {user.expiry.date ? 
                                    new Date(user.expiry.date).toLocaleString() : 'No expiry'}
                            </p>
                            <p>
                                <strong>Time Remaining:</strong> {user.expiry.remaining.expired ? 
                                    <span className="expired">Expired</span> : 
                                    `${user.expiry.remaining.days}d ${user.expiry.remaining.hours}h ${user.expiry.remaining.minutes}m`
                                }
                            </p>
                            <p>
                                <strong>Max Connections:</strong> {user.max_connections}
                            </p>
                            <p>
                                <strong>Data Limit:</strong> {user.data_limit.formatted}
                            </p>
                            <p>
                                <strong>Data Used:</strong> {user.data_usage.formatted} 
                                ({user.usage_percentage}%)
                            </p>
                            {user.email && <p><strong>Email:</strong> {user.email}</p>}
                            {user.mobile && <p><strong>Mobile:</strong> {user.mobile}</p>}
                            {user.telegram_id && <p><strong>Telegram ID:</strong> {user.telegram_id}</p>}
                            {user.notes && <p><strong>Notes:</strong> {user.notes}</p>}
                        </div>
                    )}
                </div>

                <div className="user-stats-card">
                    <h3>Usage Statistics</h3>
                    <div className="user-stats">
                        <div className="stat-item">
                            <span className="stat-value">{user.active_connections}</span>
                            <span className="stat-label">Active Connections</span>
                        </div>
                        <div className="stat-item">
                            <span className="stat-value">{connections.length}</span>
                            <span className="stat-label">Total Connections</span>
                        </div>
                        <div className="stat-item">
                            <span className="stat-value">{Object.keys(summary).length}</span>
                            <span className="stat-label">Protocols Used</span>
                        </div>
                    </div>
                    
                    <div className="data-usage-progress">
                        <div className="progress-label">
                            <span>Data Usage</span>
                            <span>{user.data_usage.formatted} / {user.data_limit.formatted}</span>
                        </div>
                        <div className="progress-bar">
                            <div 
                                className={`progress ${user.usage_percentage > 90 ? 'danger' : user.usage_percentage > 75 ? 'warning' : 'normal'}`} 
                                style={{width: `${user.usage_percentage}%`}}
                            ></div>
                        </div>
                    </div>
                    
                    <div className="chart-container">
                        <h4>Traffic History</h4>
                        <canvas id="trafficChart"></canvas>
                    </div>
                </div>
            </div>

            <div className="connections-container">
                <h3>Active Connections</h3>
                {connections.filter(conn => conn.status === 'active').length > 0 ? (
                    <table className="connections-table">
                        <thead>
                            <tr>
                                <th>Protocol</th>
                                <th>Connected Since</th>
                                <th>Duration</th>
                                <th>IP Address</th>
                                <th>Traffic</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {connections
                                .filter(conn => conn.status === 'active')
                                .map(conn => (
                                    <tr key={conn.id}>
                                        <td>
                                            <span className={`protocol-badge ${conn.protocol}`}>
                                                {conn.protocol}
                                            </span>
                                        </td>
                                        <td>{new Date(conn.connect_time).toLocaleString()}</td>
                                        <td>{conn.duration.formatted}</td>
                                        <td>{conn.client_ip}</td>
                                        <td>
                                            <div className="traffic-info">
                                                <span>↑ {conn.upload.formatted}</span>
                                                <span>↓ {conn.download.formatted}</span>
                                            </div>
                                        </td>
                                        <td>
                                            <button 
                                                className="btn btn-sm btn-danger"
                                                onClick={() => terminateConnection(conn.session_id)}
                                            >
                                                Terminate
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                        </tbody>
                    </table>
                ) : (
                    <p>No active connections</p>
                )}

                <h3>Connection History</h3>
                {connections.filter(conn => conn.status !== 'active').length > 0 ? (
                    <table className="connections-table">
                        <thead>
                            <tr>
                                <th>Protocol</th>
                                <th>Connect Time</th>
                                <th>Disconnect Time</th>
                                <th>Duration</th>
                                <th>Traffic</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {connections
                                .filter(conn => conn.status !== 'active')
                                .map(conn => (
                                    <tr key={conn.id}>
                                        <td>
                                            <span className={`protocol-badge ${conn.protocol}`}>
                                                {conn.protocol}
                                            </span>
                                        </td>
                                        <td>{new Date(conn.connect_time).toLocaleString()}</td>
                                        <td>{conn.disconnect_time ? 
                                            new Date(conn.disconnect_time).toLocaleString() : 'Still connected'}</td>
                                        <td>{conn.duration.formatted}</td>
                                        <td>
                                            <div className="traffic-info">
                                                <span>↑ {conn.upload.formatted}</span>
                                                <span>↓ {conn.download.formatted}</span>
                                            </div>
                                        </td>
                                        <td>
                                            <span className={`status-badge ${conn.status}`}>
                                                {conn.status}
                                            </span>
                                        </td>
                                    </tr>
                                ))}
                        </tbody>
                    </table>
                ) : (
                    <p>No connection history</p>
                )}
            </div>
        </div>
    );
};

export default UserDetail;
EOF

    # Create ActiveConnections.jsx component
    cat > $FRONTEND_DIR/src/components/users/ActiveConnections.jsx << 'EOF'
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { toast } from 'react-hot-toast';

const ActiveConnections = () => {
    const [connections, setConnections] = useState([]);
    const [loading, setLoading] = useState(true);
    const [stats, setStats] = useState({
        totalActive: 0,
        byProtocol: {}
    });

    useEffect(() => {
        fetchConnections();
        // Set up auto-refresh interval
        const interval = setInterval(fetchConnections, 30000); // Refresh every 30 seconds
        
        return () => clearInterval(interval);
    }, []);

    const fetchConnections = async () => {
        try {
            setLoading(true);
            const response = await axios.get('/api/connections/active');
            setConnections(response.data.connections);
            
            // Calculate stats
            const totalActive = response.data.connections.length;
            const byProtocol = response.data.connections.reduce((acc, conn) => {
                if (!acc[conn.protocol]) {
                    acc[conn.protocol] = 0;
                }
                acc[conn.protocol]++;
                return acc;
            }, {});
            
            setStats({
                totalActive,
                byProtocol
            });
            
            setLoading(false);
        } catch (error) {
            console.error('Error fetching connections:', error);
            toast.error('Failed to load active connections');
            setLoading(false);
        }
    };

    const terminateConnection = async (sessionId, username) => {
        if (!window.confirm(`Are you sure you want to terminate this connection for ${username}?`)) {
            return;
        }
        
        try {
            await axios.post(`/api/connections/${sessionId}/terminate`);
            toast.success('Connection terminated successfully');
            fetchConnections();
        } catch (error) {
            console.error('Error terminating connection:', error);
            toast.error('Failed to terminate connection');
        }
    };

    const formatTimestamp = (timestamp) => {
        return new Date(timestamp).toLocaleString();
    };

    const getProtocolColor = (protocol) => {
        const colors = {
            'ssh': 'primary',
            'wireguard': 'success',
            'l2tp': 'info',
            'ikev2': 'warning',
            'cisco': 'danger',
            'singbox': 'dark'
        };
        
        return colors[protocol.toLowerCase()] || 'secondary';
    };

    return (
        <div className="active-connections-container">
            <div className="header-actions">
                <h2>Active Connections</h2>
                <div className="actions">
                    <button 
                        className="btn btn-primary" 
                        onClick={fetchConnections}
                        disabled={loading}
                    >
                        {loading ? 'Refreshing...' : 'Refresh'}
                    </button>
                </div>
            </div>
            
            <div className="stats-panel">
                <div className="stat-card">
                    <h3>{stats.totalActive}</h3>
                    <p>Total Active Connections</p>
                </div>
                
                {Object.entries(stats.byProtocol).map(([protocol, count]) => (
                    <div className="stat-card" key={protocol}>
                        <h3>{count}</h3>
                        <p>
                            <span className={`badge bg-${getProtocolColor(protocol)}`}>
                                {protocol}
                            </span>
                        </p>
                    </div>
                ))}
            </div>
            
            {loading && connections.length === 0 ? (
                <div className="loading">Loading connections...</div>
            ) : connections.length > 0 ? (
                <div className="table-responsive">
                    <table className="table table-striped">
                        <thead>
                            <tr>
                                <th>User</th>
                                <th>Protocol</th>
                                <th>Connected Since</th>
                                <th>Duration</th>
                                <th>IP Address</th>
                                <th>Traffic</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {connections.map(conn => (
                                <tr key={conn.id}>
                                    <td>
                                        <a href={`/users/${conn.username}`}>
                                            {conn.username}
                                        </a>
                                    </td>
                                    <td>
                                        <span className={`badge bg-${getProtocolColor(conn.protocol)}`}>
                                            {conn.protocol}
                                        </span>
                                    </td>
                                    <td>{formatTimestamp(conn.connect_time)}</td>
                                    <td>{conn.duration.formatted}</td>
                                    <td>{conn.client_ip}</td>
                                    <td>
                                        <div className="traffic-info">
                                            <div>↑ {conn.upload.formatted}</div>
                                            <div>↓ {conn.download.formatted}</div>
                                        </div>
                                    </td>
                                    <td>
                                        <button 
                                            className="btn btn-sm btn-danger"
                                            onClick={() => terminateConnection(conn.session_id, conn.username)}
                                        >
                                            Terminate
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            ) : (
                <div className="no-data">No active connections found</div>
            )}
        </div>
    );
};

export default ActiveConnections;
EOF

    # Add CSS styles for user management
    cat > $FRONTEND_DIR/src/styles/user-management.css << 'EOF'
/* User Management Styles */
.user-management-container {
    padding: 1rem;
}

.user-stats {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 1.5rem;
}

.stat-card {
    background-color: white;
    border-radius: 8px;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    text-align: center;
}

.stat-card h3 {
    font-size: 2rem;
    margin-bottom: 0.5rem;
    font-weight: bold;
    color: #3b82f6;
}

.user-actions {
    display: flex;
    justify-content: space-between;
    margin-bottom: 1.5rem;
}

.add-user-form {
    background-color: white;
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.add-user-form h3 {
    margin-bottom: 1rem;
    color: #1f2937;
}

.form-group {
    margin-bottom: 1rem;
}

.form-group label {
    display: block;
    margin-bottom: 0.5rem;
    font-weight: 500;
}

.form-group input,
.form-group select {
    width: 100%;
    padding: 0.5rem;
    border: 1px solid #d1d5db;
    border-radius: 4px;
}

.form-actions {
    display: flex;
    gap: 1rem;
    margin-top: 1rem;
}

.users-table {
    background-color: white;
    border-radius: 8px;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.users-table h3 {
    margin-bottom: 1rem;
    color: #1f2937;
}

.users-table table {
    width: 100%;
    border-collapse: collapse;
}

.users-table th,
.users-table td {
    padding: 0.75rem;
    text-align: left;
    border-bottom: 1px solid #e5e7eb;
}

.users-table th {
    font-weight: 600;
    color: #4b5563;
}

.status-badge {
    display: inline-block;
    padding: 0.25rem 0.5rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 500;
}

.status-badge.active {
    background-color: #10b981;
    color: white;
}

.status-badge.deactive {
    background-color: #ef4444;
    color: white;
}

.status-badge.suspended {
    background-color: #f59e0b;
    color: white;
}

.expired {
    color: #ef4444;
    font-weight: 500;
}

.progress-bar {
    width: 100%;
    height: 8px;
    background-color: #e5e7eb;
    border-radius: 9999px;
    overflow: hidden;
    margin-top: 0.25rem;
}

.progress {
    height: 100%;
    background-color: #3b82f6;
    border-radius: 9999px;
}

.progress.danger {
    background-color: #ef4444;
}

.progress.warning {
    background-color: #f59e0b;
}

/* Action buttons */
.action-buttons {
    display: flex;
    gap: 0.5rem;
}

/* User detail page */
.user-detail-container {
    padding: 1rem;
}

.user-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
}

.user-header h2 {
    margin: 0;
    color: #1f2937;
}

.user-info-container {
    display: grid;
    grid-template-columns: 1fr 2fr;
    gap: 1.5rem;
    margin-bottom: 1.5rem;
}

@media (max-width: 768px) {
    .user-info-container {
        grid-template-columns: 1fr;
    }
}

.user-info-card,
.user-stats-card {
    background-color: white;
    border-radius: 8px;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.user-info-card h3,
.user-stats-card h3 {
    margin-top: 0;
    margin-bottom: 1rem;
    color: #1f2937;
}

.user-info p {
    margin-bottom: 0.75rem;
}

.user-info strong {
    display: inline-block;
    width: 150px;
    font-weight: 600;
}

.user-stats {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 1rem;
    margin-bottom: 1.5rem;
}

.stat-item {
    text-align: center;
}

.stat-value {
    display: block;
    font-size: 1.5rem;
    font-weight: bold;
    color: #3b82f6;
}

.stat-label {
    font-size: 0.875rem;
    color: #6b7280;
}

.data-usage-progress {
    margin-bottom: 1.5rem;
}

.progress-label {
    display: flex;
    justify-content: space-between;
    margin-bottom: 0.5rem;
}

.chart-container {
    height: 300px;
}

.chart-container h4 {
    margin-bottom: 1rem;
}

.connections-container {
    background-color: white;
    border-radius: 8px;
    padding: 1.5rem;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.connections-container h3 {
    margin-top: 0;
    margin-bottom: 1rem;
    color: #1f2937;
}

.connections-table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 1.5rem;
}

.connections-table th,
.connections-table td {
    padding: 0.75rem;
    text-align: left;
    border-bottom: 1px solid #e5e7eb;
}

.connections-table th {
    font-weight: 600;
    color: #4b5563;
}

.protocol-badge {
    display: inline-block;
    padding: 0.25rem 0.5rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 500;
    color: white;
}

.protocol-badge.ssh {
    background-color: #3b82f6;
}

.protocol-badge.wireguard {
    background-color: #10b981;
}

.protocol-badge.l2tp {
    background-color: #6366f1;
}

.protocol-badge.ikev2 {
    background-color: #f59e0b;
}

.protocol-badge.cisco {
    background-color: #ef4444;
}

.protocol-badge.singbox {
    background-color: #6b7280;
}

.traffic-info {
    display: flex;
    flex-direction: column;
}

.loading {
    display: flex;
    justify-content: center;
    align-items: center;
    height: 200px;
    font-size: 1rem;
    color: #6b7280;
}

.no-data {
    padding: 2rem;
    text-align: center;
    font-size: 1rem;
    color: #6b7280;
}

/* Active connections page */
.active-connections-container {
    padding: 1rem;
}

.header-actions {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
}

.header-actions h2 {
    margin: 0;
    color: #1f2937;
}

.stats-panel {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
    gap: 1rem;
    margin-bottom: 1.5rem;
}
EOF

    # Create routes for user management
    log "INFO" "Dashboard widgets for user management created."
}

# Install integrated user management module
function install_user_management() {
    # Check system requirements
    check_requirements
    
    # Create directories
    create_directories
    
    # Setup PostgreSQL and optimize for current server
    check_postgres
    
    # Install dependencies
    install_dependencies
    
    # Initialize database
    setup_database
    
    # Create User Manager service
    create_user_manager_service
    
    # Create client portal
    create_client_portal
    
    # Setup monitoring scripts
    create_monitoring_scripts
    
    # Create systemd services
    create_systemd_services
    
    # Create admin CLI script
    create_admin_script
    
    # Create dashboard widgets for React frontend
    create_dashboard_widgets
    
    # Modify main install script to include this module
    modify_install_script
    
    # Enable and start services
    systemctl daemon-reload
    systemctl enable irssh-user-manager
    systemctl enable irssh-ssh-monitor
    systemctl enable irssh-auto-repair
    
    # Start services
    systemctl start irssh-user-manager
    systemctl start irssh-ssh-monitor
    systemctl start irssh-auto-repair
    
    # Enable WireGuard monitor if WireGuard is installed
    if command -v wg &> /dev/null; then
        systemctl enable irssh-wireguard-monitor
        systemctl start irssh-wireguard-monitor
        log "INFO" "WireGuard monitoring enabled."
    fi
    
    # Create symlinks for management scripts
    ln -sf $SCRIPTS_DIR/admin_user_management.sh /usr/local/bin/irssh-users
    
    # Final success message
    clear
    cat << EOF
╔═══════════════════════════════════════════════════════════════════╗
║             Advanced User Management Installation Success          ║
╚═══════════════════════════════════════════════════════════════════╝

پنل مدیریت کاربران پیشرفته با موفقیت نصب شد!

دستورات مدیریتی:
  - irssh-users        : ابزار مدیریت کاربران از طریق خط فرمان

وضعیت سرویس‌ها:
  - User Manager      : $(systemctl is-active irssh-user-manager)
  - SSH Monitor       : $(systemctl is-active irssh-ssh-monitor)
  - WireGuard Monitor : $(if command -v wg &> /dev/null; then echo "$(systemctl is-active irssh-wireguard-monitor)"; else echo "نصب نشده"; fi)
  - Auto-Repair       : $(systemctl is-active irssh-auto-repair)

اطلاعات پایگاه داده:
  - نام پایگاه داده     : $DB_NAME
  - کاربر پایگاه داده     : $DB_USER
  - رمز عبور پایگاه داده : $DB_USER_PASSWORD (این رمز را ذخیره کنید!)

مراحل بعدی:
  1. برای مدیریت کاربران دستور 'irssh-users' را اجرا کنید
  2. برای مشاهده و کار با پنل وب، به آدرس http://SERVER_IP:${PORTS["WEB"]} مراجعه کنید
  3. می‌توانید کاربران را اضافه کرده و اتصالات را تست کنید

برای اطلاعات بیشتر، لاگ‌ها را در مسیر $LOG_DIR بررسی کنید.

EOF
}

# Function to run a quick health check
function run_health_check() {
    log "INFO" "Running system health check..."
    
    # Check services
    local services=("postgresql" "redis-server" "irssh-user-manager" "irssh-ssh-monitor")
    local failed_services=()
    
    for service in "${services[@]}"; do
        if ! systemctl is-active --quiet "$service"; then
            failed_services+=("$service")
        fi
    }
    
    if [ ${#failed_services[@]} -gt 0 ]; then
        log "WARN" "Some services are not running: ${failed_services[*]}"
        
        # Try to restart failed services
        for service in "${failed_services[@]}"; do
            log "INFO" "Attempting to restart $service..."
            systemctl restart "$service"
            
            if systemctl is-active --quiet "$service"; then
                log "INFO" "Successfully restarted $service"
            else
                log "ERROR" "Failed to restart $service"
            fi
        done
    else
        log "INFO" "All critical services are running."
    fi
    
    # Check database connection
    log "INFO" "Testing database connection..."
    
    if PGPASSWORD="$DB_USER_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1" &>/dev/null; then
        log "INFO" "Database connection successful."
    else
        log "ERROR" "Could not connect to database. Please check credentials and ensure PostgreSQL is running."
    fi
    
    # Check disk space
    log "INFO" "Checking disk space..."
    
    local disk_usage=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ "$disk_usage" -gt 90 ]; then
        log "WARN" "Disk space is critically low: ${disk_usage}%"
    elif [ "$disk_usage" -gt 75 ]; then
        log "WARN" "Disk space is getting low: ${disk_usage}%"
    else
        log "INFO" "Disk space is adequate: ${disk_usage}%"
    fi
    
    # Check memory usage
    log "INFO" "Checking memory usage..."
    
    local mem_total=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local mem_available=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
    local mem_used=$((mem_total - mem_available))
    local mem_percent=$((mem_used * 100 / mem_total))
    
    if [ "$mem_percent" -gt 90 ]; then
        log "WARN" "Memory usage is critically high: ${mem_percent}%"
    elif [ "$mem_percent" -gt 75 ]; then
        log "WARN" "Memory usage is high: ${mem_percent}%"
    else
        log "INFO" "Memory usage is normal: ${mem_percent}%"
    fi
    
    log "INFO" "Health check completed."
}

# Main function to execute the installation
function main() {
    # Display welcome message
    clear
    cat << "EOF"
╔════════════════════════════════════════════════════════════════════╗
║             Advanced User Management Module Installation            ║
║                          Version 3.0                                ║
╚════════════════════════════════════════════════════════════════════╝
EOF
    echo ""
    log "INFO" "Starting installation of Advanced User Management Module..."
    
    # Install user management module
    install_user_management
    
    # Run health check
    run_health_check
    
    log "INFO" "Installation completed successfully!"
    
    return 0
}
