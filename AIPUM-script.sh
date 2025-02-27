#!/bin/bash

# Advanced User Management Module for IRSSH-Panel
# Version: 2.0
# This script adds advanced user management capabilities to IRSSH-Panel using PostgreSQL

# Define colors for better output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
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
        *)
            echo "$timestamp - $message"
            ;;
    esac
}

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
   log "ERROR" "This script must be run as root"
   exit 1
fi

# Welcome message
clear
echo "============================================================"
echo "           Advanced User Management Module Installation      "
echo "============================================================"
echo ""
log "INFO" "Starting installation of Advanced User Management Module..."

# Configuration variables
DB_NAME="irssh_panel"
DB_USER="irssh_admin"
DB_USER_PASSWORD=$(< /dev/urandom tr -dc 'a-zA-Z0-9' | head -c20)
DB_PORT=5432
BASE_DIR="/opt/irssh-panel"
BACKEND_DIR="$BASE_DIR/backend"
SERVICES_DIR="$BASE_DIR/services"
SCRIPTS_DIR="$BASE_DIR/scripts"
CONFIG_DIR="$BASE_DIR/config"
FRONTEND_DIR="$BASE_DIR/frontend"
LOG_DIR="$BASE_DIR/logs"

# Check for PostgreSQL installation
check_postgres() {
    log "INFO" "Checking PostgreSQL installation..."
    if ! command -v psql &> /dev/null; then
        log "WARN" "PostgreSQL is not installed. Installing..."
        
        # Update package lists
        apt-get update
        
        # Install PostgreSQL
        apt-get install -y postgresql postgresql-contrib
        
        # Enable and start service
        systemctl enable postgresql
        systemctl start postgresql
        
        log "INFO" "PostgreSQL installation completed."
    else
        log "INFO" "PostgreSQL is already installed."
    fi
}

# Install required dependencies
install_dependencies() {
    log "INFO" "Installing required dependencies..."
    
    # Update package lists
    apt-get update
    
    # Install packages
    apt-get install -y jq curl nodejs npm redis-server postgresql-client libpq-dev python3-pip
    
    # Install Node.js dependencies
    npm install -g pm2
    
    # Install Python deps for scripts
    pip3 install psycopg2-binary python-telegram-bot schedule
    
    log "INFO" "Dependencies installation completed."
}

# Create directories
create_directories() {
    log "INFO" "Creating required directories..."
    
    mkdir -p $SERVICES_DIR/user-manager
    mkdir -p $SCRIPTS_DIR/monitoring
    mkdir -p $CONFIG_DIR/db
    mkdir -p $LOG_DIR
    mkdir -p $SERVICES_DIR/user-manager/client-portal
    
    log "INFO" "Directories created."
}

# Initialize PostgreSQL database
setup_database() {
    log "INFO" "Setting up PostgreSQL database..."
    
    # Create user and database as postgres user
    su - postgres -c "psql -c \"CREATE USER $DB_USER WITH PASSWORD '$DB_USER_PASSWORD';\""
    su - postgres -c "psql -c \"CREATE DATABASE $DB_NAME OWNER $DB_USER;\""
    
    # Save database credentials to config
    cat > $CONFIG_DIR/db/database.conf << EOF
DB_HOST=localhost
DB_PORT=$DB_PORT
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_USER_PASSWORD
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
    last_notification TIMESTAMP
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
    status VARCHAR(20) DEFAULT 'active',
    FOREIGN KEY (username) REFERENCES user_profiles(username) ON DELETE CASCADE
);

-- Protocol definitions
CREATE TABLE IF NOT EXISTS protocols (
    id SERIAL PRIMARY KEY,
    name VARCHAR(20) UNIQUE NOT NULL,
    display_name VARCHAR(50) NOT NULL,
    enabled BOOLEAN DEFAULT TRUE
);

-- System settings
CREATE TABLE IF NOT EXISTS system_settings (
    id SERIAL PRIMARY KEY,
    setting_key VARCHAR(50) UNIQUE NOT NULL,
    setting_value TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_connections_username ON user_connections(username);
CREATE INDEX IF NOT EXISTS idx_connections_status ON user_connections(status);
CREATE INDEX IF NOT EXISTS idx_connections_connect_time ON user_connections(connect_time);
CREATE INDEX IF NOT EXISTS idx_connections_session_id ON user_connections(session_id);

-- Insert default protocols
INSERT INTO protocols (name, display_name) VALUES
    ('ssh', 'SSH'),
    ('wireguard', 'WireGuard'),
    ('l2tp', 'L2TP/IPsec'),
    ('ikev2', 'IKEv2'),
    ('cisco', 'Cisco IPsec'),
    ('singbox', 'Sing-Box')
ON CONFLICT (name) DO NOTHING;

-- Insert default settings
INSERT INTO system_settings (setting_key, setting_value) VALUES
    ('check_interval', '5'),
    ('notification_hours', '24'),
    ('client_portal_ipv6_only', 'true'),
    ('version', '2.0')
ON CONFLICT (setting_key) DO NOTHING;
EOF
    
    # Execute SQL script
    PGPASSWORD=$DB_USER_PASSWORD psql -h localhost -U $DB_USER -d $DB_NAME -f $SCRIPTS_DIR/setup_db.sql
    
    log "INFO" "Database setup completed."
}

# Create Node.js service for user management
create_user_manager_service() {
    log "INFO" "Creating user management service..."
    
    # Create package.json
    cat > $SERVICES_DIR/user-manager/package.json << 'EOF'
{
  "name": "irssh-user-manager",
  "version": "2.0.0",
  "description": "User management service for IRSSH-Panel",
  "main": "index.js",
  "scripts": {
    "start": "node index.js"
  },
  "dependencies": {
    "axios": "^1.6.0",
    "cron": "^3.1.0",
    "express": "^4.18.2",
    "pg": "^8.11.3",
    "redis": "^4.6.10",
    "moment": "^2.29.4",
    "telegraf": "^4.15.0",
    "cors": "^2.8.5",
    "helmet": "^7.1.0",
    "winston": "^3.11.0",
    "dotenv": "^16.3.1"
  }
}
EOF
// main.js - IRSSH User Manager Service
const express = require('express');
const { Pool } = require('pg');
const { CronJob } = require('cron');
const axios = require('axios');
const moment = require('moment');
const { createClient } = require('redis');
const { Telegraf } = require('telegraf');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const winston = require('winston');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config({ path: path.join(__dirname, '../../config/db/database.conf') });
dotenv.config({ path: path.join(__dirname, '../../.env') });

// Configuration
const config = {
    port: process.env.USER_MANAGER_PORT || 3001,
    checkInterval: process.env.CHECK_INTERVAL || '*/5 * * * *', // Every 5 minutes
    telegramBotToken: process.env.TELEGRAM_BOT_TOKEN || '',
    telegramChannelId: process.env.TELEGRAM_CHANNEL_ID || '',
    database: {
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT) || 5432,
        database: process.env.DB_NAME || 'irssh_panel',
        user: process.env.DB_USER || 'irssh_admin',
        password: process.env.DB_PASSWORD || ''
    },
    clientPortalIpv6Only: process.env.CLIENT_PORTAL_IPV6_ONLY === 'true'
};

// Configure logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) => {
            return `${timestamp} [${level.toUpperCase()}]: ${message}`;
        })
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'user-manager.log', dirname: path.join(__dirname, '../../logs') })
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
    url: process.env.REDIS_URL || 'redis://localhost:6379'
});

(async () => {
    redisClient.on('error', (err) => logger.error(`Redis Client Error: ${err}`));
    await redisClient.connect();
    logger.info('Connected to Redis');
})();

// Initialize Telegram bot if token is provided
let bot = null;
if (config.telegramBotToken) {
    bot = new Telegraf(config.telegramBotToken);
    bot.launch().then(() => {
        logger.info('Telegram bot started');
    }).catch(err => {
        logger.error(`Failed to start Telegram bot: ${err}`);
    });
}

// Initialize Express app
const app = express();
app.use(express.json());
app.use(cors());
app.use(helmet({
    contentSecurityPolicy: false
}));

// Helper functions
function getCurrentTimestamp() {
    return moment().format('YYYY-MM-DD HH:mm:ss');
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
                        SET status = 'terminated', disconnect_time = $1
                        WHERE id = $2
                    `, [getCurrentTimestamp(), conn.id]);
                    
                    // Implement actual connection termination based on protocol
                    await terminateConnection(username, conn.protocol, conn.session_id);
                }
            }
        }
    } catch (error) {
        logger.error(`Error in enforceConnectionLimits: ${error.message}`);
    }
}

// Function to terminate a connection based on protocol
async function terminateConnection(username, protocol, sessionId) {
    // Implement protocol-specific termination logic
    logger.info(`Terminating ${protocol} connection for ${username}, session ${sessionId}`);
    
    try {
        // Example implementation - customize for each protocol
        switch (protocol.toLowerCase()) {
            case 'ssh':
                // Example: Execute a script that kills the user's SSH session
                const { exec } = require('child_process');
                exec(`pkill -f "sshd:.*${username}@"`);
                break;
            case 'wireguard':
                // Example: Use wg command to remove a peer
                // This is highly dependent on your WireGuard setup
                break;
            case 'l2tp':
                // Example: Terminate L2TP session
                break;
            case 'ikev2':
                // Example: Terminate IKEv2 session
                break;
            case 'cisco':
                // Example: Terminate Cisco IPsec session
                break;
            case 'singbox':
                // Example: Terminate Sing-Box session
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
            WHERE expiry_date <= $1 AND expiry_date > NOW()
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

// Schedule regular tasks
new CronJob(config.checkInterval, async () => {
    try {
        await enforceConnectionLimits();
        await checkExpiringAccounts();
    } catch (error) {
        logger.error('Error in scheduled tasks:', error);
    }
}, null, true);

// API endpoints for connection tracking
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
        
        // Check if user has expired
        if (userResult.rows[0].expiry_date && moment(userResult.rows[0].expiry_date).isBefore(moment())) {
            return res.status(403).json({ error: 'Account has expired' });
        }
        
        // Check if user has reached the connection limit
        const activeConnectionsResult = await db.query(
            'SELECT COUNT(*) as count FROM user_connections WHERE username = $1 AND status = $2',
            [username, 'active']
        );
        
        const activeConnections = parseInt(activeConnectionsResult.rows[0].count);
        const maxConnections = parseInt(userResult.rows[0].max_connections);
        
        if (activeConnections >= maxConnections) {
            return res.status(403).json({ 
                error: 'Maximum connection limit reached',
                active: activeConnections,
                max: maxConnections
            });
        }
        
        // Insert new connection
        const result = await db.query(`
            INSERT INTO user_connections (username, protocol, client_ip, session_id, connect_time, status)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
        `, [username, protocol, client_ip, session_id, getCurrentTimestamp(), 'active']);
        
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
                download_bytes = COALESCE(download_bytes, 0) + COALESCE($3, 0)
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
                        SET status = 'terminated', disconnect_time = $1
                        WHERE id = $2
                    `, [getCurrentTimestamp(), conn.id]);
                    
                    await terminateConnection(username, conn.protocol, conn.session_id);
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

// User profile management
app.post('/api/users/bulk_create', async (req, res) => {
    const { base_username, start_number, count, max_connections, expiry_days, data_limit_gb, email_domain, mobile, referred_by, notes } = req.body;
    
    if (!base_username || !count) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Validate inputs
    const numCount = parseInt(count);
    const startNum = parseInt(start_number || 1);
    
    if (isNaN(numCount) || numCount <= 0 || numCount > 1000) {
        return res.status(400).json({ error: 'Invalid count (must be between 1 and 1000)' });
    }
    
    try {
        // Begin transaction
        await db.query('BEGIN');
        
        // Calculate expiry date if provided
        let expiryDate = null;
        if (expiry_days) {
            expiryDate = moment().add(parseInt(expiry_days), 'days').format('YYYY-MM-DD HH:mm:ss');
        }
        
        // Calculate data limit in bytes
        const dataLimit = data_limit_gb ? Math.floor(parseFloat(data_limit_gb) * 1024 * 1024 * 1024) : 0;
        
        let successCount = 0;
        let errors = [];
        
        // Create users in batch
        for (let i = 0; i < numCount; i++) {
            const username = `${base_username}${startNum + i}`;
            let email = null;
            
            if (email_domain) {
                email = `${username}@${email_domain}`;
            }
            
            try {
                // Check if user exists
                const existingUser = await db.query(
                    'SELECT username FROM user_profiles WHERE username = $1',
                    [username]
                );
                
                if (existingUser.rows.length > 0) {
                    errors.push({ username, error: 'Username already exists' });
                    continue;
                }
                
                // Insert new user
                await db.query(`
                    INSERT INTO user_profiles (
                        username, email, mobile, referred_by, notes, 
                        max_connections, expiry_date, data_limit
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                `, [
                    username,
                    email,
                    mobile,
                    referred_by,
                    notes,
                    max_connections || 1,
                    expiryDate,
                    dataLimit
                ]);
                
                successCount++;
            } catch (error) {
                errors.push({ username, error: error.message });
            }
        }
        
        // Commit or rollback transaction
        if (errors.length === 0 || successCount > 0) {
            await db.query('COMMIT');
            
            res.status(201).json({ 
                success: true, 
                created: successCount,
                errors: errors.length > 0 ? errors : undefined,
                message: `Created ${successCount} users successfully`
            });
        } else {
            await db.query('ROLLBACK');
            
            res.status(400).json({ 
                success: false, 
                errors,
                message: 'Failed to create users'
            });
        }
    } catch (error) {
        await db.query('ROLLBACK');
        logger.error(`Error in bulk user creation: ${error.message}`);
        res.status(500).json({ error: 'Database error' });

// User management APIs
app.get('/api/users', async (req, res) => {
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
                created_at,
                (
                    SELECT COUNT(*) 
                    FROM user_connections 
                    WHERE username = user_profiles.username AND status = 'active'
                ) as active_connections,
                (
                    SELECT SUM(upload_bytes + download_bytes) 
                    FROM user_connections 
                    WHERE username = user_profiles.username
                ) as total_usage
            FROM user_profiles
            ORDER BY username
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
                    formatted: dataLimit > 0 ? formatBytes(dataLimit) : 'Unlimited'
                }
            };
        });
        
        res.json({ users: formattedUsers });
    } catch (error) {
        logger.error(`Error fetching users: ${error.message}`);
        res.status(500).json({ error: 'Database error' });
    }
});

app.get('/api/users/:username', async (req, res) => {
    const { username } = req.params;
    
    try {
        // Get user profile
        const userResult = await db.query(`
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
                created_at,
                (
                    SELECT COUNT(*) 
                    FROM user_connections 
                    WHERE username = user_profiles.username AND status = 'active'
                ) as active_connections,
                (
                    SELECT SUM(upload_bytes + download_bytes) 
                    FROM user_connections 
                    WHERE username = user_profiles.username
                ) as total_usage
            FROM user_profiles
            WHERE username = $1
        `, [username]);
        
        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const user = userResult.rows[0];
        const dataLimit = parseInt(user.data_limit) || 0;
        const totalUsage = parseInt(user.total_usage) || 0;
        
        // Get user connections
        const connectionsResult = await db.query(`
            SELECT 
                id,
                protocol,
                connect_time,
                disconnect_time,
                upload_bytes,
                download_bytes,
                client_ip,
                session_id,
                status,
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
            LIMIT 50
        `, [username]);
        
        // Format connections
        const formattedConnections = connectionsResult.rows.map(conn => {
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
        
        // Calculate protocol summaries
        const protocolSummary = {};
        
        // Group connections by protocol
        connectionsResult.rows.forEach(conn => {
            const protocol = conn.protocol;
            const upload = parseInt(conn.upload_bytes) || 0;
            const download = parseInt(conn.download_bytes) || 0;
            const duration = parseFloat(conn.duration_minutes) || 0;
            
            if (!protocolSummary[protocol]) {
                protocolSummary[protocol] = {
                    count: 0,
                    duration: {
                        minutes: 0,
                        formatted: ''
                    },
                    upload: {
                        bytes: 0,
                        formatted: ''
                    },
                    download: {
                        bytes: 0,
                        formatted: ''
                    },
                    total_traffic: {
                        bytes: 0,
                        formatted: ''
                    }
                };
            }
            
            protocolSummary[protocol].count++;
            protocolSummary[protocol].duration.minutes += duration;
            protocolSummary[protocol].upload.bytes += upload;
            protocolSummary[protocol].download.bytes += download;
            protocolSummary[protocol].total_traffic.bytes += upload + download;
        });
        
        // Format protocol summaries
        Object.keys(protocolSummary).forEach(protocol => {
            const summary = protocolSummary[protocol];
            summary.duration.formatted = formatDuration(summary.duration.minutes);
            summary.upload.formatted = formatBytes(summary.upload.bytes);
            summary.download.formatted = formatBytes(summary.download.bytes);
            summary.total_traffic.formatted = formatBytes(summary.total_traffic.bytes);
        });
        
        // Format user data for response
        const formattedUser = {
            username: user.username,
            email: user.email,
            mobile: user.mobile,
            referred_by: user.referred_by,
            max_connections: parseInt(user.max_connections) || 1,
            active_connections: parseInt(user.active_connections) || 0,
            telegram_id: user.telegram_id,
            notes: user.notes,
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
                formatted: dataLimit > 0 ? formatBytes(dataLimit) : 'Unlimited'
            }
        };
        
        res.json({
            user: formattedUser,
            connections: formattedConnections,
            summary: protocolSummary
        });
    } catch (error) {
        logger.error(`Error fetching user details: ${error.message}`);
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/users', async (req, res) => {
    const { 
        username, 
        email, 
        mobile, 
        referred_by, 
        max_connections,
        expiry_days,
        data_limit_gb,
        telegram_id,
        notes
    } = req.body;
    
    if (!username) {
        return res.status(400).json({ error: 'Username is required' });
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
                notes
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        `, [
            username,
            email || null,
            mobile || null,
            referred_by || null,
            max_connections || 1,
            expiryDate,
            dataLimit,
            telegram_id || null,
            notes || null
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
                    formatted: dataLimit > 0 ? formatBytes(dataLimit) : 'Unlimited'
                },
                telegram_id: telegram_id || null,
                notes: notes || null
            }
        });
    } catch (error) {
        logger.error(`Error creating user: ${error.message}`);
        res.status(500).json({ error: 'Database error' });
    }
});

app.put('/api/users/:username', async (req, res) => {
    const { username } = req.params;
    const { 
        email, 
        mobile, 
        referred_by, 
        max_connections,
        extend_days,
        data_limit_gb,
        telegram_id,
        notes
    } = req.body;
    
    try {
        // Check if user exists
        const userExists = await db.query(
            'SELECT * FROM user_profiles WHERE username = $1',
            [username]
        );
        
        if (userExists.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const user = userExists.rows[0];
        
        // Build update query dynamically
        const updates = [];
        const params = [];
        let paramIndex = 1;
        
        if (email !== undefined) {
            updates.push(`email = $${paramIndex++}`);
            params.push(email || null);
        }
        
        if (mobile !== undefined) {
            updates.push(`mobile = $${paramIndex++}`);
            params.push(mobile || null);
        }
        
        if (referred_by !== undefined) {
            updates.push(`referred_by = $${paramIndex++}`);
            params.push(referred_by || null);
        }
        
        if (max_connections !== undefined) {
            updates.push(`max_connections = $${paramIndex++}`);
            params.push(parseInt(max_connections) || 1);
        }
        
        // Handle expiry date extension
        if (extend_days && parseInt(extend_days) > 0) {
            const days = parseInt(extend_days);
            let newExpiryDate;
            
            if (user.expiry_date) {
                // Extend from current expiry
                newExpiryDate = moment(user.expiry_date).add(days, 'days').format('YYYY-MM-DD HH:mm:ss');
            } else {
                // Set from now
                newExpiryDate = moment().add(days, 'days').format('YYYY-MM-DD HH:mm:ss');
            }
            
            updates.push(`expiry_date = $${paramIndex++}`);
            params.push(newExpiryDate);
        }
        
        // Handle data limit
        if (data_limit_gb !== undefined) {
            const dataLimit = parseFloat(data_limit_gb) > 0 ? 
                Math.floor(parseFloat(data_limit_gb) * 1024 * 1024 * 1024) : 0;
            
            updates.push(`data_limit = $${paramIndex++}`);
            params.push(dataLimit);
        }
        
        if (telegram_id !== undefined) {
            updates.push(`telegram_id = $${paramIndex++}`);
            params.push(telegram_id || null);
        }
        
        if (notes !== undefined) {
            updates.push(`notes = $${paramIndex++}`);
            params.push(notes || null);
        }
        
        if (updates.length === 0) {
            return res.status(400).json({ error: 'No fields to update' });
        }
        
        // Add username as the last parameter
        params.push(username);
        
        // Execute the update query
        await db.query(`
            UPDATE user_profiles
            SET ${updates.join(', ')}
            WHERE username = $${paramIndex}
        `, params);
        
        // Get updated user data
        const updatedUserResult = await db.query(`
            SELECT * FROM user_profiles
            WHERE username = $1
        `, [username]);
        
        const updatedUser = updatedUserResult.rows[0];
        const dataLimit = parseInt(updatedUser.data_limit) || 0;
        
        res.json({
            success: true,
            message: `User ${username} updated successfully`,
            user: {
                username: updatedUser.username,
                email: updatedUser.email,
                mobile: updatedUser.mobile,
                referred_by: updatedUser.referred_by,
                max_connections: parseInt(updatedUser.max_connections) || 1,
                expiry_date: updatedUser.expiry_date,
                data_limit: {
                    bytes: dataLimit,
                    formatted: dataLimit > 0 ? formatBytes(dataLimit) : 'Unlimited'
                },
                telegram_id: updatedUser.telegram_id,
                notes: updatedUser.notes,
                created_at: updatedUser.created_at
            }
        });
    } catch (error) {
        logger.error(`Error updating user: ${error.message}`);
        res.status(500).json({ error: 'Database error' });
    }
});

app.delete('/api/users/:username', async (req, res) => {
    const { username } = req.params;
    
    try {
        // Check if user exists
        const userExists = await db.query(
            'SELECT username FROM user_profiles WHERE username = $1',
            [username]
        );
        
        if (userExists.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Begin transaction
        await db.query('BEGIN');
        
        // Get active connections to terminate them
        const activeConnections = await db.query(
            'SELECT id, protocol, session_id FROM user_connections WHERE username = $1 AND status = $1',
            [username, 'active']
        );
        
        // Terminate active connections
        for (const conn of activeConnections.rows) {
            await terminateConnection(username, conn.protocol, conn.session_id);
        }
        
        // Delete user connections (would happen automatically with CASCADE, but being explicit)
        await db.query('DELETE FROM user_connections WHERE username = $1', [username]);
        
        // Delete user profile
        await db.query('DELETE FROM user_profiles WHERE username = $1', [username]);
        
        // Commit transaction
        await db.query('COMMIT');
        
        res.json({
            success: true,
            message: `User ${username} deleted successfully`
        });
    } catch (error) {
        await db.query('ROLLBACK');
        logger.error(`Error deleting user: ${error.message}`);
        res.status(500).json({ error: 'Database error' });
    }
});

app.get('/api/connections/active', async (req, res) => {
    try {
        const result = await db.query(`
            SELECT 
                id,
                username, 
                protocol, 
                connect_time, 
                client_ip,
                session_id,
                EXTRACT(EPOCH FROM (NOW() - connect_time)) / 60 as duration_minutes,
                upload_bytes,
                download_bytes
            FROM user_connections 
            WHERE status = 'active'
            ORDER BY connect_time DESC
        `);
        
        // Format connection data
        const formattedConnections = result.rows.map(conn => {
            const upload = parseInt(conn.upload_bytes) || 0;
            const download = parseInt(conn.download_bytes) || 0;
            const duration = parseFloat(conn.duration_minutes) || 0;
            
            return {
                id: conn.id,
                username: conn.username,
                protocol: conn.protocol,
                connect_time: conn.connect_time,
                client_ip: conn.client_ip,
                session_id: conn.session_id,
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
        
        res.json({ connections: formattedConnections });
    } catch (error) {
        logger.error(`Error fetching active connections: ${error.message}`);
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/connections/:session_id/terminate', async (req, res) => {
    const { session_id } = req.params;
    
    try {
        // Get connection details
        const connectionResult = await db.query(`
            SELECT id, username, protocol, status
            FROM user_connections
            WHERE session_id = $1 AND status = 'active'
        `, [session_id]);
        
        if (connectionResult.rows.length === 0) {
            return res.status(404).json({ error: 'Active connection not found' });
        }
        
        const connection = connectionResult.rows[0];
        
        // Update connection status
        await db.query(`
            UPDATE user_connections
            SET status = 'terminated', disconnect_time = NOW()
            WHERE id = $1
        `, [connection.id]);
        
        // Terminate the actual connection
        await terminateConnection(connection.username, connection.protocol, session_id);
        
        res.json({
            success: true,
            message: `Connection terminated successfully`
        });
    } catch (error) {
        logger.error(`Error terminating connection: ${error.message}`);
        res.status(500).json({ error: 'Database error' });
    }
});

app.get('/api/users/expiring/soon', async (req, res) => {
    const days = parseInt(req.query.days) || 1;
    
    try {
        const expiryDate = moment().add(days, 'days').format('YYYY-MM-DD HH:mm:ss');
        
        const result = await db.query(`
            SELECT 
                username, 
                email, 
                mobile, 
                telegram_id,
                expiry_date,
                EXTRACT(EPOCH FROM (expiry_date - NOW())) / 3600 as hours_remaining
            FROM user_profiles 
            WHERE expiry_date <= $1 AND expiry_date > NOW()
            ORDER BY expiry_date
        `, [expiryDate]);
        
        // Format expiring users data
        const formattedUsers = result.rows.map(user => {
            const hoursRemaining = parseFloat(user.hours_remaining) || 0;
            
            return {
                username: user.username,
                email: user.email,
                mobile: user.mobile,
                telegram_id: user.telegram_id,
                expiry: {
                    date: user.expiry_date,
                    hours_remaining: Math.round(hoursRemaining),
                    formatted: formatTimeRemaining(hoursRemaining)
                }
            };
        });
        
        res.json({ users: formattedUsers });
    } catch (error) {
        logger.error(`Error fetching expiring users: ${error.message}`);
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/users/:username/notify/expiry', async (req, res) => {
    const { username } = req.params;
    
    try {
        // Check if user exists and has Telegram ID
        const userResult = await db.query(`
            SELECT username, telegram_id, expiry_date
            FROM user_profiles
            WHERE username = $1
        `, [username]);
        
        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const user = userResult.rows[0];
        
        if (!user.telegram_id) {
            return res.status(400).json({ error: 'User does not have a Telegram ID' });
        }
        
        if (!user.expiry_date) {
            return res.status(400).json({ error: 'User does not have an expiry date' });
        }
        
        if (!bot) {
            return res.status(500).json({ error: 'Telegram bot is not configured' });
        }
        
        // Calculate hours remaining
        const expiryTime = moment(user.expiry_date);
        const hoursRemaining = expiryTime.diff(moment(), 'hours');
        
        // Send notification
        await bot.telegram.sendMessage(user.telegram_id, 
            `⚠️ *Account Expiry Notice* ⚠️\n\nYour account *${username}* will expire in *${hoursRemaining} hours*.\n\nPlease contact support to renew your subscription.`,
            { parse_mode: 'Markdown' }
        );
        
        // Update last notification timestamp
        await db.query(`
            UPDATE user_profiles
            SET last_notification = NOW()
            WHERE username = $1
        `, [username]);
        
        res.json({
            success: true,
            message: `Notification sent to ${username} via Telegram`
        });
    } catch (error) {
        logger.error(`Error sending notification: ${error.message}`);
        res.status(500).json({ error: 'Failed to send notification' });
    }
});

// Helper functions for formatting
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

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

function calculateTimeRemaining(expiryDate) {
    if (!expiryDate) return null;
    
    const now = moment();
    const expiry = moment(expiryDate);
    const diff = expiry.diff(now);
    
    if (diff <= 0) return { days: 0, hours: 0, minutes: 0 };
    
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    
    return { days, hours, minutes };
}

function formatTimeRemaining(hours) {
    if (hours <= 0) return 'Expired';
    
    const days = Math.floor(hours / 24);
    const remainingHours = Math.round(hours % 24);
    
    if (days < 1) {
        return `${remainingHours} hour${remainingHours !== 1 ? 's' : ''}`;
    }
    
    return `${days} day${days !== 1 ? 's' : ''}, ${remainingHours} hour${remainingHours !== 1 ? 's' : ''}`;
}

// Client Portal API
const ipv6OnlyMiddleware = (req, res, next) => {
    if (config.clientPortalIpv6Only) {
        const clientIp = req.ip || req.connection.remoteAddress;
        
        // Check if the IP is IPv6
        if (!clientIp.includes(':')) {
            return res.status(403).send('Access restricted to IPv6 addresses only');
        }
    }
    next();
};

// Serve client portal static files
const clientPortalPath = path.join(__dirname, 'client-portal');
if (fs.existsSync(clientPortalPath)) {
    app.use('/portal', ipv6OnlyMiddleware, express.static(clientPortalPath));
}

// Start the server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    logger.info(`User Manager API server running on port ${PORT}`);
});

module.exports = app;

# Create Client Portal HTML
function create_client_portal() {
    log "INFO" "Creating client portal frontend..."
    
    # Create HTML file for client portal
    cat > $SERVICES_DIR/user-manager/client-portal/index.html << 'EOF'
<!DOCTYPE html>
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
                    headers['Authorization'] = `Bearer ${this.token}`;
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
                elements.accountTimeRemaining.textContent = `${accountData.account.time_remaining.days} days, ${accountData.account.time_remaining.hours} hours`;
                elements.accountMaxConnections.textContent = accountData.account.max_connections;
                
                // Update data usage
                if (accountData.account.data_usage.limit.bytes > 0) {
                    elements.dataUsageProgress.style.width = `${accountData.account.data_usage.percentage}%`;
                    elements.dataUsageProgress.textContent = `${accountData.account.data_usage.percentage}%`;
                    
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
                    
                    row.innerHTML = `
                        <td><span class="badge bg-${getProtocolColor(conn.protocol)} protocol-badge">${conn.protocol}</span></td>
                        <td>${new Date(conn.connect_time).toLocaleString()}</td>
                        <td>${conn.duration.formatted}</td>
                        <td>${conn.upload.formatted}</td>
                        <td>${conn.download.formatted}</td>
                        <td>${conn.total_traffic.formatted}</td>
                        <td><span class="badge bg-${statusClass}">${conn.status}</span></td>
                    `;
                    
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
                    summaryTable.innerHTML = `
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
                                ${protocols.map(protocol => {
                                    const data = connectionsData.summary.by_protocol[protocol];
                                    return `
                                        <tr>
                                            <td><span class="badge bg-${getProtocolColor(protocol)} protocol-badge">${protocol}</span></td>
                                            <td>${data.connections}</td>
                                            <td>${data.duration.formatted}</td>
                                            <td>${data.upload.formatted}</td>
                                            <td>${data.download.formatted}</td>
                                            <td>${data.total_traffic.formatted}</td>
                                        </tr>
                                    `;
                                }).join('')}
                            </tbody>
                        </table>
                    `;
                    
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
</html>
EOF
    
    log "INFO" "Client portal frontend created."
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
                    if key.strip() == 'DB_HOST':
                        db_config['host'] = value.strip()
                    elif key.strip() == 'DB_PORT':
                        db_config['port'] = value.strip()
                    elif key.strip() == 'DB_NAME':
                        db_config['dbname'] = value.strip()
                    elif key.strip() == 'DB_USER':
                        db_config['user'] = value.strip()
                    elif key.strip() == 'DB_PASSWORD':
                        db_config['password'] = value.strip()
        
        if not all(k in db_config for k in ['dbname', 'user', 'password']):
            logger.error("Missing required database configuration")
            sys.exit(1)
            
        return db_config

def get_db_connection():
    """Create a database connection"""
    db_config = load_config()
    conn = psycopg2.connect(**db_config)
    conn.autocommit = True
    return conn

def get_active_ssh_connections():
    """Get all active SSH connections with username"""
    try:
        # Run netstat to get established SSH connections
        output = subprocess.check_output(
            "netstat -tnpa | grep 'ESTABLISHED.*sshd' | awk '{print $5 \" \" $7}'",
            shell=True, universal_newlines=True
        )
        
        connections = []
        for line in output.strip().split('\n'):
            if not line:
                continue
                
            parts = line.split()
            if len(parts) >= 2:
                ip_address = parts[0].split(':')[0]  # Remove port number
                process_info = parts[1]
                
                # Extract username from process info (format: sshd: username@pts/0)
                username = None
                if '@' in process_info:
                    username = process_info.split(':')[1].strip().split('@')[0]
                
                if username and username != 'root':
                    connections.append({
                        'username': username,
                        'ip_address': ip_address
                    })
        
        return connections
    except subprocess.CalledProcessError as e:
        logger.error(f"Error getting SSH connections: {e}")
        return []

def generate_session_id(username, ip_address):
    """Generate a unique session ID for this connection"""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    data = f"{username}_{ip_address}_{timestamp}"
    return hashlib.md5(data.encode()).hexdigest()

def report_connection_start(username, ip_address):
    """Report a new SSH connection to the API"""
    try:
        session_id = generate_session_id(username, ip_address)
        
        response = requests.post(f"{API_URL}/start", json={
            'username': username,
            'protocol': 'ssh',
            'client_ip': ip_address,
            'session_id': session_id
        })
        
        if response.status_code == 200:
            logger.info(f"Reported new SSH connection: {username} from {ip_address} (Session: {session_id})")
            return session_id
        else:
            logger.error(f"Failed to report connection: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        logger.error(f"Error reporting connection: {e}")
        return None

def report_connection_end(username, session_id):
    """Report an SSH connection end to the API"""
    try:
        response = requests.post(f"{API_URL}/end", json={
            'username': username,
            'session_id': session_id
        })
        
        if response.status_code == 200:
            logger.info(f"Reported SSH disconnect: {username} (Session: {session_id})")
            return True
        else:
            logger.error(f"Failed to report disconnect: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error reporting disconnect: {e}")
        return False

def main():
    """Main monitoring loop"""
    logger.info("Starting SSH connection monitor")
    
    # Check if we can connect to the database
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT NOW()")
        cursor.close()
        conn.close()
        logger.info("Successfully connected to database")
    except Exception as e:
        logger.error(f"Failed to connect to database: {e}")
        sys.exit(1)
    
    # Track active sessions
    active_sessions = {}  # Format: {username_ip: session_id}
    
    # Main monitoring loop
    while True:
        try:
            # Get current connections
            current_connections = get_active_ssh_connections()
            current_connections_map = {f"{c['username']}_{c['ip_address']}": c for c in current_connections}
            
            # Check for new connections
            for key, conn_info in current_connections_map.items():
                if key not in active_sessions:
                    username = conn_info['username']
                    ip_address = conn_info['ip_address']
                    
                    # Check if user exists in database
                    db_conn = get_db_connection()
                    cursor = db_conn.cursor()
                    cursor.execute("SELECT username FROM user_profiles WHERE username = %s", (username,))
                    user_exists = cursor.fetchone() is not None
                    cursor.close()
                    db_conn.close()
                    
                    if user_exists:
                        session_id = report_connection_start(username, ip_address)
                        if session_id:
                            active_sessions[key] = {
                                'session_id': session_id,
                                'username': username,
                                'start_time': datetime.now()
                            }
                    else:
                        logger.warning(f"Ignoring connection for unknown user: {username}")
            
            # Check for ended connections
            ended_sessions = []
            for key, session in active_sessions.items():
                if key not in current_connections_map:
                    report_connection_end(session['username'], session['session_id'])
                    ended_sessions.append(key)
            
            # Remove ended sessions from tracking
            for key in ended_sessions:
                del active_sessions[key]
                
            # Sleep before next check
            time.sleep(60)  # Check every minute
            
        except KeyboardInterrupt:
            logger.info("Monitor stopped by user")
            break
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
            time.sleep(60)  # Wait a bit before retrying

if __name__ == "__main__":
    main()
EOF

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
    """Get currently active SSH connections with username"""
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

# Create WireGuard monitor script
function create_wireguard_monitor() {
    log "INFO" "Creating WireGuard monitoring script..."
    
    cat > $SCRIPTS_DIR/monitoring/wireguard_monitor.py << 'EOF'

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
    
    chmod +x $SCRIPTS_DIR/monitoring/wireguard_monitor.py
    log "INFO" "WireGuard monitoring script created."
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
    
    # Reload systemd
    systemctl daemon-reload
    
    log "INFO" "Systemd service files created."
}

# Create Nginx configuration for client portal
function create_nginx_config() {
    log "INFO" "Creating Nginx configuration for client portal..."
    
    if command -v nginx &> /dev/null; then
        cat > /etc/nginx/sites-available/irssh-client-portal << 'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name portal.irssh.local;  # Change this to your desired domain

    location / {
        proxy_pass http://localhost:3001/portal/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
EOF
        
        # Enable site if sites-enabled directory exists
        if [ -d "/etc/nginx/sites-enabled" ]; then
            ln -sf /etc/nginx/sites-available/irssh-client-portal /etc/nginx/sites-enabled/
            
            # Test and reload Nginx
            nginx -t && systemctl reload nginx
        fi
        
        log "INFO" "Nginx configuration created."
    else
        log "WARN" "Nginx not found. Skipping Nginx configuration."
    fi
}

# Create client portal setup script
function create_client_portal_setup() {
    log "INFO" "Creating client portal setup script..."
    
    cat > $SCRIPTS_DIR/setup_client_portal.sh << 'EOF'
#!/bin/bash

# Client Portal Setup Script for IRSSH-Panel
# This script configures the IPv6-only client portal

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root${NC}"
   exit 1
fi

echo -e "${GREEN}IRSSH-Panel Client Portal Setup${NC}"
echo "========================================"
echo ""

# Check if IPv6 is enabled
if ! ip -6 addr | grep -q "inet6"; then
    echo -e "${YELLOW}Warning: IPv6 might not be properly configured on this server${NC}"
    echo "The client portal can be restricted to IPv6 only access."
    echo ""
fi

# Get server IPv6 address
SERVER_IPV6=$(ip -6 addr | grep "scope global" | awk '{print $2}' | cut -d'/' -f1 | head -n 1)

# Prompt for portal domain or use IPv6 directly
read -p "Enter domain for client portal (leave blank to use IPv6 directly): " PORTAL_DOMAIN

# Prompt for IPv6 only mode
read -p "Restrict client portal to IPv6 only? (y/n) [y]: " IPV6_ONLY
IPV6_ONLY=${IPV6_ONLY:-y}

if [ -z "$PORTAL_DOMAIN" ]; then
    if [ -n "$SERVER_IPV6" ]; then
        PORTAL_URL="http://[$SERVER_IPV6]:3001/portal/"
        echo -e "${YELLOW}Client portal will be accessible at: ${PORTAL_URL}${NC}"
    else
        PORTAL_URL="http://localhost:3001/portal/"
        echo -e "${YELLOW}No global IPv6 address found. Client portal will be accessible at: ${PORTAL_URL}${NC}"
    fi
else
    PORTAL_URL="http://$PORTAL_DOMAIN/portal/"
    echo -e "${YELLOW}Client portal will be accessible at: ${PORTAL_URL}${NC}"
    
    if [ -n "$SERVER_IPV6" ]; then
        echo -e "${YELLOW}Make sure to point your domain to the server IPv6 address: ${SERVER_IPV6}${NC}"
    fi
fi

# Configure Nginx for the client portal
if command -v nginx >/dev/null 2>&1; then
    echo "Setting up Nginx as reverse proxy for the client portal..."
    
    # Create Nginx configuration
    cat > /etc/nginx/sites-available/irssh-client-portal << EOF
server {
    listen 80;
    listen [::]:80;
    
    $([ -n "$PORTAL_DOMAIN" ] && echo "server_name $PORTAL_DOMAIN;")
    
    location /portal/ {
        proxy_pass http://localhost:3001/portal/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF
    
    # Enable the site
    ln -sf /etc/nginx/sites-available/irssh-client-portal /etc/nginx/sites-enabled/
    
    # Test and reload Nginx
    nginx -t && systemctl reload nginx
    
    echo -e "${GREEN}Nginx configured successfully!${NC}"
else
    echo -e "${YELLOW}Warning: Nginx not found. Skipping reverse proxy setup.${NC}"
    echo "The client portal will be accessible directly via the connection tracker service."
fi

# Update connection tracker configuration
echo "Updating connection tracker service configuration..."

# Set IPv6 only mode in system settings
if [[ "$IPV6_ONLY" =~ ^[Yy]$ ]]; then
    IPV6_SETTING="true"
else
    IPV6_SETTING="false"
fi

# Update in database
PGPASSWORD=$(grep DB_PASSWORD /opt/irssh-panel/config/db/database.conf | cut -d'=' -f2)
DB_NAME=$(grep DB_NAME /opt/irssh-panel/config/db/database.conf | cut -d'=' -f2)
DB_USER=$(grep DB_USER /opt/irssh-panel/config/db/database.conf | cut -d'=' -f2)

psql -U "$DB_USER" -d "$DB_NAME" -c "UPDATE system_settings SET setting_value = '$IPV6_SETTING' WHERE setting_key = 'client_portal_ipv6_only'"

# Restart connection tracker service
systemctl restart irssh-user-manager

echo -e "${GREEN}Client portal setup completed successfully!${NC}"
echo ""
echo "Users can now access their account details at:"
echo -e "${GREEN}${PORTAL_URL}${NC}"
echo ""
echo -e "${YELLOW}Note: Users must use their IRSSH account credentials to log in.${NC}"

exit 0
EOF
    
    chmod +x $SCRIPTS_DIR/setup_client_portal.sh
    log "INFO" "Client portal setup script created."
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
    echo "12. Exit"
    echo ""
    echo -n "Enter your choice [1-12]: "
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
        12) exit 0 ;;
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
            CASE WHEN expiry_date < NOW() THEN 1
                 WHEN expiry_date IS NULL THEN 3
                 ELSE 2
            END,
            username
    ")
    
    # Print column headers
    printf "%-20s | %-20s | %-15s | %-15s | %-10s | %-8s\n" "Username" "Expiry Date" "Time Left" "Data Limit" "Max Conn" "Active"
    echo "-----------------------------------------------------------------------------------------------"
    
    # Parse and print results
    echo "$result" | while read -r line; do
        if [[ -z "$line" ]]; then continue; fi
        
        # Extract fields
        local username=$(echo "$line" | awk -F'|' '{print $1}' | sed 's/^ *//g' | sed 's/ *$//g')
        local expiry_date=$(echo "$line" | awk -F'|' '{print $2}' | sed 's/^ *//g' | sed 's/ *$//g')
        local time_left=$(echo "$line" | awk -F'|' '{print $5}' | sed 's/^ *//g' | sed 's/ *$//g')
        local data_limit=$(echo "$line" | awk -F'|' '{print $4}' | sed 's/^ *//g' | sed 's/ *$//g')
        local max_conn=$(echo "$line" | awk -F'|' '{print $3}' | sed 's/^ *//g' | sed 's/ *$//g')
        local active=$(echo "$line" | awk -F'|' '{print $6}' | sed 's/^ *//g' | sed 's/ *$//g')
        
        # Colorize expired users
        if [[ "$time_left" == "Expired" ]]; then
            printf "${RED}%-20s | %-20s | %-15s${NC} | %-15s | %-10s | %-8s\n" "$username" "$expiry_date" "$time_left" "$data_limit" "$max_conn" "$active"
        elif [[ "$time_left" == "No expiry" ]]; then
            printf "${GREEN}%-20s | %-20s | %-15s${NC} | %-15s | %-10s | %-8s\n" "$username" "$expiry_date" "$time_left" "$data_limit" "$max_conn" "$active"
        else
            printf "%-20s | %-20s | %-15s | %-15s | %-10s | %-8s\n" "$username" "$expiry_date" "$time_left" "$data_limit" "$max_conn" "$active"
        fi
    done
    
    echo ""
    echo -n "Press Enter to continue..."
    read
    show_main_menu
}

# Add a new user
add_user() {
    clear
    echo -e "${BOLD}Add New User${NC}"
    echo "============"
    echo ""
    
    read -p "Username: " username
    
    if [ -z "$username" ]; then
        echo -e "${RED}Error: Username cannot be empty${NC}"
        echo -n "Press Enter to continue..."
        read
        add_user
        return
    fi
    
    # Check if user already exists
    local user_exists=$(run_query "SELECT COUNT(*) FROM user_profiles WHERE username='$username'")
    user_exists=$(echo "$user_exists" | tr -d '[:space:]')
    
    if [ "$user_exists" -gt 0 ]; then
        echo -e "${RED}Error: User '$username' already exists${NC}"
        echo -n "Press Enter to continue..."
        read
        add_user
        return
    fi
    
    read -p "Email (optional): " email
    read -p "Mobile (optional): " mobile
    read -p "Referred by (optional): " referred_by
    read -p "Max simultaneous connections [1]: " max_connections
    read -p "Expiry days from now [30]: " expiry_days
    read -p "Data limit in GB (0 for unlimited) [0]: " data_limit_gb
    read -p "Telegram ID (optional): " telegram_id
    read -p "Notes (optional): " notes
    
    # Set defaults
    max_connections=${max_connections:-1}
    expiry_days=${expiry_days:-30}
    data_limit_gb=${data_limit_gb:-0}
    
    # Calculate expiry date
    local expiry_date=$(date -d "+$expiry_days days" "+%Y-%m-%d %H:%M:%S")
    
    # Calculate data limit in bytes
    local data_limit=$(echo "$data_limit_gb * 1024 * 1024 * 1024" | bc | cut -d'.' -f1)
    
    # Insert user
    run_query "
        INSERT INTO user_profiles (
            username, email, mobile, referred_by, max_connections, 
            expiry_date, data_limit, telegram_id, notes
        ) VALUES (
            '$username', '${email:-NULL}', '${mobile:-NULL}', '${referred_by:-NULL}', 
            $max_connections, '$expiry_date', $data_limit, '${telegram_id:-NULL}', 
            '${notes:-NULL}'
        )
    "
    
    echo -e "${GREEN}User '$username' added successfully!${NC}"
    echo -n "Press Enter to continue..."
    read
    show_main_menu
}

# Bulk add users
bulk_add_users() {
    clear
    echo -e "${BOLD}Bulk Add Users${NC}"
    echo "=============="
    echo ""
    
    read -p "Base username: " base_username
    read -p "Start number [1]: " start_number
    read -p "Number of users to create: " user_count
    read -p "Max simultaneous connections [1]: " max_connections
    read -p "Expiry days from now [30]: " expiry_days
    read -p "Data limit in GB (0 for unlimited) [0]: " data_limit_gb
    read -p "Common email domain (optional, e.g. example.com): " email_domain
    read -p "Referred by (optional): " referred_by
    read -p "Notes (optional): " notes
    
    # Set defaults
    start_number=${start_number:-1}
    max_connections=${max_connections:-1}
    expiry_days=${expiry_days:-30}
    data_limit_gb=${data_limit_gb:-0}
    
    if [ -z "$base_username" ] || [ -z "$user_count" ]; then
        echo -e "${RED}Error: Base username and user count are required${NC}"
        echo -n "Press Enter to continue..."
        read
        bulk_add_users
        return
    fi
    
    # Calculate expiry date
    local expiry_date=$(date -d "+$expiry_days days" "+%Y-%m-%d %H:%M:%S")
    
    # Calculate data limit in bytes
    local data_limit=$(echo "$data_limit_gb * 1024 * 1024 * 1024" | bc | cut -d'.' -f1)
    
    # Begin transaction
    run_query "BEGIN TRANSACTION"
    
    echo "Creating users..."
    local success_count=0
    local error_count=0
    
    for (( i=0; i<user_count; i++ )); do
        local current_number=$((start_number + i))
        local username="${base_username}${current_number}"
        
        # Generate email if domain provided
        local email="NULL"
        if [ -n "$email_domain" ]; then
            email="${username}@${email_domain}"
        fi
        
        # Check if user already exists
        local user_exists=$(run_query "SELECT COUNT(*) FROM user_profiles WHERE username='$username'")
        user_exists=$(echo "$user_exists" | tr -d '[:space:]')
        
        if [ "$user_exists" -eq 0 ]; then
            run_query "
                INSERT INTO user_profiles (
                    username, email, referred_by, max_connections, 
                    expiry_date, data_limit, notes
                ) VALUES (
                    '$username', '$email', '${referred_by:-NULL}', 
                    $max_connections, '$expiry_date', $data_limit, 
                    '${notes:-NULL}'
                )
            "
            success_count=$((success_count + 1))
            echo -e "${GREEN}Created user: $username${NC}"
        else
            echo -e "${YELLOW}Skipped existing user: $username${NC}"
            error_count=$((error_count + 1))
        fi
    done
    
    # Commit transaction
    run_query "COMMIT"
    
    echo -e "${GREEN}Bulk user creation completed. Created $success_count users. Skipped $error_count users.${NC}"
    echo -n "Press Enter to continue..."
    read
    show_main_menu
}

# Modify user
modify_user() {
    clear
    echo -e "${BOLD}Modify User${NC}"
    echo "==========="
    echo ""
    
    read -p "Enter username to modify: " username
    
    if [ -z "$username" ]; then
        echo -e "${RED}Error: Username cannot be empty${NC}"
        echo -n "Press Enter to continue..."
        read
        modify_user
        return
    fi
    
    # Check if user exists
    local user_exists=$(run_query "SELECT COUNT(*) FROM user_profiles WHERE username='$username'")
    user_exists=$(echo "$user_exists" | tr -d '[:space:]')
    
    if [ "$user_exists" -eq 0 ]; then
        echo -e "${RED}Error: User '$username' does not exist${NC}"
        echo -n "Press Enter to continue..."
        read
        modify_user
        return
    fi
    
    # Get current user data
    local user_data=$(run_query "SELECT * FROM user_profiles WHERE username='$username'")
    
    echo -e "${BOLD}Current user data:${NC}"
    echo "$user_data" | sed 's/|/\n/g'
    echo ""
    
    echo "Leave blank to keep current value"
    read -p "Email: " email
    read -p "Mobile: " mobile
    read -p "Referred by: " referred_by
    read -p "Max simultaneous connections: " max_connections
    read -p "Extend expiry by days (0 to keep current): " extend_days
    read -p "Data limit in GB (0 for unlimited): " data_limit_gb
    read -p "Telegram ID: " telegram_id
    read -p "Notes: " notes
    
    # Prepare update query
    local query="UPDATE user_profiles SET "
    local updates=()
    
    if [ -n "$email" ]; then
        updates+=("email='$email'")
    fi
    
    if [ -n "$mobile" ]; then
        updates+=("mobile='$mobile'")
    fi
    
    if [ -n "$referred_by" ]; then
        updates+=("referred_by='$referred_by'")
    fi
    
    if [ -n "$max_connections" ]; then
        updates+=("max_connections=$max_connections")
    fi
    
    if [ -n "$extend_days" ] && [ "$extend_days" -gt 0 ]; then
        # Get current expiry date
        local current_expiry=$(run_query "SELECT expiry_date FROM user_profiles WHERE username='$username'")
        current_expiry=$(echo "$current_expiry" | tr -d '[:space:]')
        
        if [ -n "$current_expiry" ] && [ "$current_expiry" != "NULL" ]; then
            # Calculate new expiry date
            local new_expiry=$(date -d "$current_expiry +$extend_days days" "+%Y-%m-%d %H:%M:%S")
            updates+=("expiry_date='$new_expiry'")
        else
            # If no current expiry, set from now
            local new_expiry=$(date -d "+$extend_days days" "+%Y-%m-%d %H:%M:%S")
            updates+=("expiry_date='$new_expiry'")
        fi
    fi
    
    if [ -n "$data_limit_gb" ]; then
        local data_limit=$(echo "$data_limit_gb * 1024 * 1024 * 1024" | bc | cut -d'.' -f1)
        updates+=("data_limit=$data_limit")
    fi
    
    if [ -n "$telegram_id" ]; then
        updates+=("telegram_id='$telegram_id'")
    fi
    
    if [ -n "$notes" ]; then
        updates+=("notes='$notes'")
    fi
    
    # Execute update if there are changes
    if [ ${#updates[@]} -gt 0 ]; then
        local update_str=$(IFS=, ; echo "${updates[*]}")
        query+="$update_str WHERE username='$username'"
        
        run_query "$query"
        echo -e "${GREEN}User '$username' updated successfully!${NC}"
    else
        echo -e "${YELLOW}No changes made.${NC}"
    fi
    
    echo -n "Press Enter to continue..."
    read
    show_main_menu
}

# Delete user
delete_user() {
    clear
    echo -e "${BOLD}Delete User${NC}"
    echo "==========="
    echo ""
    
    read -p "Enter username to delete: " username
    
    if [ -z "$username" ]; then
        echo -e "${RED}Error: Username cannot be empty${NC}"
        echo -n "Press Enter to continue..."
        read
        delete_user
        return
    fi
    
    # Check if user exists
    local user_exists=$(run_query "SELECT COUNT(*) FROM user_profiles WHERE username='$username'")
    user_exists=$(echo "$user_exists" | tr -d '[:space:]')
    
    if [ "$user_exists" -eq 0 ]; then
        echo -e "${RED}Error: User '$username' does not exist${NC}"
        echo -n "Press Enter to continue..."
        read
        delete_user
        return
    fi
    
    read -p "Are you sure you want to delete user '$username'? This will also delete all connection history. (y/N): " confirm
    
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo -e "${YELLOW}User deletion cancelled.${NC}"
        echo -n "Press Enter to continue..."
        read
        show_main_menu
        return
    fi
    
    # Begin transaction
    run_query "BEGIN TRANSACTION"
    
    # Delete user connections
    run_query "DELETE FROM user_connections WHERE username='$username'"
    
    # Delete user profile
    run_query "DELETE FROM user_profiles WHERE username='$username'"
    
    # Commit transaction
    run_query "COMMIT"
    
    echo -e "${GREEN}User '$username' deleted successfully!${NC}"
    echo -n "Press Enter to continue..."
    read
    show_main_menu
}

# View user details
view_user_details() {
    clear
    echo -e "${BOLD}User Details${NC}"
    echo "============"
    echo ""
    
    read -p "Enter username: " username
    
    if [ -z "$username" ]; then
        echo -e "${RED}Error: Username cannot be empty${NC}"
        echo -n "Press Enter to continue..."
        read
        view_user_details
        return
    fi
    
    # Check if user exists
    local user_exists=$(run_query "SELECT COUNT(*) FROM user_profiles WHERE username='$username'")
    user_exists=$(echo "$user_exists" | tr -d '[:space:]')
    
    if [ "$user_exists" -eq 0 ]; then
        echo -e "${RED}Error: User '$username' does not exist${NC}"
        echo -n "Press Enter to continue..."
        read
        view_user_details
        return
    fi
    
    # Get user profile data
    echo -e "${BOLD}User Profile:${NC}"
    run_query "SELECT * FROM user_profiles WHERE username='$username'"
    echo ""
    
    # Calculate data usage
    local total_usage=$(run_query "
        SELECT COALESCE(SUM(upload_bytes + download_bytes), 0)
        FROM user_connections
        WHERE username='$username'
    ")
    total_usage=$(echo "$total_usage" | tr -d '[:space:]')
    
    local data_limit=$(run_query "
        SELECT data_limit FROM user_profiles WHERE username='$username'
    ")
    data_limit=$(echo "$data_limit" | tr -d '[:space:]')
    
    # Format data usage
    local total_usage_gb=$(echo "scale=2; $total_usage / (1024*1024*1024)" | bc)
    
    if [ "$data_limit" -eq 0 ]; then
        local data_limit_str="Unlimited"
        local usage_percent=0
    else
        local data_limit_gb=$(echo "scale=2; $data_limit / (1024*1024*1024)" | bc)
        local data_limit_str="${data_limit_gb} GB"
        local usage_percent=$(echo "scale=2; ($total_usage / $data_limit) * 100" | bc)
    fi
    
    echo -e "${BOLD}Data Usage:${NC} ${total_usage_gb} GB of ${data_limit_str} (${usage_percent}%)"
    echo ""
    
    # Get active connections
    echo -e "${BOLD}Active Connections:${NC}"
    local active_count=$(run_query "
        SELECT COUNT(*) FROM user_connections
        WHERE username='$username' AND status='active'
    ")
    active_count=$(echo "$active_count" | tr -d '[:space:]')
    
    if [ "$active_count" -eq 0 ]; then
        echo "No active connections."
    else
        echo "Protocol | Connect Time | Client IP | Duration"
        echo "-------------------------------------------"
        
        run_query "
            SELECT 
                protocol, 
                connect_time, 
                client_ip,
                EXTRACT(EPOCH FROM (NOW() - connect_time)) / 60 as duration_minutes
            FROM user_connections
            WHERE username='$username' AND status='active'
            ORDER BY connect_time DESC
        " | while read -r line; do
            if [[ -z "$line" ]]; then continue; fi
            
            local protocol=$(echo "$line" | awk -F'|' '{print $1}' | sed 's/^ *//g' | sed 's/ *$//g')
            local connect_time=$(echo "$line" | awk -F'|' '{print $2}' | sed 's/^ *//g' | sed 's/ *$//g')
            local client_ip=$(echo "$line" | awk -F'|' '{print $3}' | sed 's/^ *//g' | sed 's/ *$//g')
            local duration=$(echo "$line" | awk -F'|' '{print $4}' | sed 's/^ *//g' | sed 's/ *$//g')
            
            # Format duration
            local formatted_duration=$(format_duration "${duration%.*}")
            
            printf "%-10s | %-19s | %-15s | %s\n" "$protocol" "$connect_time" "$client_ip" "$formatted_duration"
        done
    fi
    
    # Get recent connection history
    echo ""
    echo -e "${BOLD}Recent Connection History (Last 10):${NC}"
    local connection_count=$(run_query "
        SELECT COUNT(*) FROM user_connections WHERE username='$username'
    ")
    connection_count=$(echo "$connection_count" | tr -d '[:space:]')
    
    if [ "$connection_count" -eq 0 ]; then
        echo "No connection history."
    else
        echo "Protocol | Connect Time | Disconnect Time | Duration | Upload | Download"
        echo "----------------------------------------------------------------------"
        
        run_query "
            SELECT 
                protocol, 
                connect_time, 
                disconnect_time, 
                CASE 
                    WHEN disconnect_time IS NOT NULL THEN 
                        EXTRACT(EPOCH FROM (disconnect_time - connect_time)) / 60 
                    WHEN status = 'active' THEN
                        EXTRACT(EPOCH FROM (NOW() - connect_time)) / 60
                    ELSE 0 
                END as duration_minutes,
                upload_bytes, 
                download_bytes
            FROM user_connections 
            WHERE username='$username' 
            ORDER BY connect_time DESC
            LIMIT 10
        " | while read -r line; do
            if [[ -z "$line" ]]; then continue; fi
            
            local protocol=$(echo "$line" | awk -F'|' '{print $1}' | sed 's/^ *//g' | sed 's/ *$//g')
            local connect_time=$(echo "$line" | awk -F'|' '{print $2}' | sed 's/^ *//g' | sed 's/ *$//g')
            local disconnect_time=$(echo "$line" | awk -F'|' '{print $3}' | sed 's/^ *//g' | sed 's/ *$//g')
            local duration=$(echo "$line" | awk -F'|' '{print $4}' | sed 's/^ *//g' | sed 's/ *$//g')
            local upload=$(echo "$line" | awk -F'|' '{print $5}' | sed 's/^ *//g' | sed 's/ *$//g')
            local download=$(echo "$line" | awk -F'|' '{print $6}' | sed 's/^ *//g' | sed 's/ *$//g')
            
            # Format values
            local formatted_duration=$(format_duration "${duration%.*}")
            local formatted_upload=$(format_bytes "$upload")
            local formatted_download=$(format_bytes "$download")
            
            if [ -z "$disconnect_time" ] || [ "$disconnect_time" = "NULL" ]; then
                disconnect_time="Still connected"
            fi
            
            printf "%-10s | %-19s | %-19s | %-10s | %-8s | %s\n" "$protocol" "$connect_time" "$disconnect_time" "$formatted_duration" "$formatted_upload" "$formatted_download"
        done
    fi
    
    echo ""
    echo -n "Press Enter to continue..."
    read
    show_main_menu
}

# View active connections
view_active_connections() {
    clear
    echo -e "${BOLD}Active Connections${NC}"
    echo "=================="
    echo ""
    
    # Count active connections
    local active_count=$(run_query "
        SELECT COUNT(*) FROM user_connections WHERE status='active'
    ")
    active_count=$(echo "$active_count" | tr -d '[:space:]')
    
    if [ "$active_count" -eq 0 ]; then
        echo "No active connections."
    else
        echo "Username | Protocol | Connect Time | Duration | Client IP"
        echo "------------------------------------------------------"
        
        run_query "
            SELECT 
                username, 
                protocol, 
                connect_time, 
                EXTRACT(EPOCH FROM (NOW() - connect_time)) / 60 as duration_minutes,
                client_ip
            FROM user_connections 
            WHERE status='active' 
            ORDER BY connect_time DESC
        " | while read -r line; do
            if [[ -z "$line" ]]; then continue; fi
            
            local username=$(echo "$line" | awk -F'|' '{print $1}' | sed 's/^ *//g' | sed 's/ *$//g')
            local protocol=$(echo "$line" | awk -F'|' '{print $2}' | sed 's/^ *//g' | sed 's/ *$//g')
            local connect_time=$(echo "$line" | awk -F'|' '{print $3}' | sed 's/^ *//g' | sed 's/ *$//g')
            local duration=$(echo "$line" | awk -F'|' '{print $4}' | sed 's/^ *//g' | sed 's/ *$//g')
            local client_ip=$(echo "$line" | awk -F'|' '{print $5}' | sed 's/^ *//g' | sed 's/ *$//g')
            
            # Format duration
            local formatted_duration=$(format_duration "${duration%.*}")
            
            printf "%-10s | %-10s | %-19s | %-10s | %s\n" "$username" "$protocol" "$connect_time" "$formatted_duration" "$client_ip"
        done
    fi
    
    echo ""
    echo -n "Press Enter to continue..."
    read
    show_main_menu
}

# Connection history
connection_history() {
    clear
    echo -e "${BOLD}Connection History${NC}"
    echo "=================="
    echo ""
    
    read -p "Enter username (leave blank for all users): " username
    read -p "Number of days to look back [7]: " days
    
    days=${days:-7}
    local date_limit=$(date -d "-$days days" "+%Y-%m-%d")
    
    # Prepare query
    local query
    if [ -n "$username" ]; then
        query="
            SELECT 
                username, 
                protocol, 
                connect_time, 
                disconnect_time, 
                CASE 
                    WHEN disconnect_time IS NOT NULL THEN 
                        EXTRACT(EPOCH FROM (disconnect_time - connect_time)) / 60 
                    WHEN status = 'active' THEN
                        EXTRACT(EPOCH FROM (NOW() - connect_time)) / 60
                    ELSE 0 
                END as duration_minutes,
                upload_bytes, 
                download_bytes, 
                client_ip, 
                status
            FROM user_connections 
            WHERE username='$username' AND connect_time >= '$date_limit'
            ORDER BY connect_time DESC
            LIMIT 100
        "
    else
        query="
            SELECT 
                username, 
                protocol, 
                connect_time, 
                disconnect_time, 
                CASE 
                    WHEN disconnect_time IS NOT NULL THEN 
                        EXTRACT(EPOCH FROM (disconnect_time - connect_time)) / 60 
                    WHEN status = 'active' THEN
                        EXTRACT(EPOCH FROM (NOW() - connect_time)) / 60
                    ELSE 0 
                END as duration_minutes,
                upload_bytes, 
                download_bytes, 
                client_ip, 
                status
            FROM user_connections 
            WHERE connect_time >= '$date_limit'
            ORDER BY connect_time DESC
            LIMIT 100
        "
    fi
    
    # Execute query
    local connection_count=$(run_query "SELECT COUNT(*) FROM ($query) as count_query")
    connection_count=$(echo "$connection_count" | tr -d '[:space:]')
    
    if [ "$connection_count" -eq 0 ]; then
        echo "No connection history found for the specified criteria."
    else
        if [ -n "$username" ]; then
            echo -e "Showing last $connection_count connections for user ${BOLD}$username${NC} in the past $days days"
        else
            echo -e "Showing last $connection_count connections for ${BOLD}all users${NC} in the past $days days"
        fi
        
        echo ""
        echo "Username | Protocol | Connect Time | Status | Duration | Upload | Download | IP"
        echo "-------------------------------------------------------------------------"
        
        run_query "$query" | while read -r line; do
            if [[ -z "$line" ]]; then continue; fi
            
            local username=$(echo "$line" | awk -F'|' '{print $1}' | sed 's/^ *//g' | sed 's/ *$//g')
            local protocol=$(echo "$line" | awk -F'|' '{print $2}' | sed 's/^ *//g' | sed 's/ *$//g')
            local connect_time=$(echo "$line" | awk -F'|' '{print $3}' | sed 's/^ *//g' | sed 's/ *$//g')
            local status=$(echo "$line" | awk -F'|' '{print $9}' | sed 's/^ *//g' | sed 's/ *$//g')
            local duration=$(echo "$line" | awk -F'|' '{print $5}' | sed 's/^ *//g' | sed 's/ *$//g')
            local upload=$(echo "$line" | awk -F'|' '{print $6}' | sed 's/^ *//g' | sed 's/ *$//g')
            local download=$(echo "$line" | awk -F'|' '{print $7}' | sed 's/^ *//g' | sed 's/ *$//g')
            local client_ip=$(echo "$line" | awk -F'|' '{print $8}' | sed 's/^ *//g' | sed 's/ *$//g')
            
            # Format values
            local formatted_duration=$(format_duration "${duration%.*}")
            local formatted_upload=$(format_bytes "$upload")
            local formatted_download=$(format_bytes "$download")
            
            # Color status
            local status_colored
            if [ "$status" = "active" ]; then
                status_colored="${GREEN}active${NC}"
            elif [ "$status" = "terminated" ]; then
                status_colored="${RED}terminated${NC}"
            else
                status_colored="${BLUE}closed${NC}"
            fi
            
            printf "%-10s | %-10s | %-19s | %-15s | %-10s | %-8s | %-8s | %s\n" "$username" "$protocol" "$connect_time" "$status_colored" "$formatted_duration" "$formatted_upload" "$formatted_download" "$client_ip"
        done
    fi
    
    echo ""
    echo -n "Press Enter to continue..."
    read
    show_main_menu
}

# Users about to expire
users_to_expire() {
    clear
    echo -e "${BOLD}Users About to Expire${NC}"
    echo "===================="
    echo ""
    
    read -p "Days to look ahead [7]: " days
    
    days=${days:-7}
    local expiry_date=$(date -d "+$days days" "+%Y-%m-%d")
    
    # Execute query
    local query="
        SELECT 
            username, 
            expiry_date, 
            mobile, 
            email, 
            telegram_id,
            EXTRACT(EPOCH FROM (expiry_date - NOW())) / 3600 as hours_remaining
        FROM user_profiles 
        WHERE expiry_date <= '$expiry_date' AND expiry_date > NOW()
        ORDER BY expiry_date
    "
    
    local user_count=$(run_query "SELECT COUNT(*) FROM ($query) as count_query")
    user_count=$(echo "$user_count" | tr -d '[:space:]')
    
    if [ "$user_count" -eq 0 ]; then
        echo "No users are set to expire in the next $days days."
    else
        echo -e "Found ${BOLD}$user_count${NC} users expiring in the next $days days"
        echo ""
        echo "Username | Expiry Date | Hours Left | Telegram ID | Email | Mobile"
        echo "----------------------------------------------------------------"
        
        run_query "$query" | while read -r line; do
            if [[ -z "$line" ]]; then continue; fi
            
            local username=$(echo "$line" | awk -F'|' '{print $1}' | sed 's/^ *//g' | sed 's/ *$//g')
            local expiry_date=$(echo "$line" | awk -F'|' '{print $2}' | sed 's/^ *//g' | sed 's/ *$//g')
            local mobile=$(echo "$line" | awk -F'|' '{print $3}' | sed 's/^ *//g' | sed 's/ *$//g')
            local email=$(echo "$line" | awk -F'|' '{print $4}' | sed 's/^ *//g' | sed 's/ *$//g')
            local telegram_id=$(echo "$line" | awk -F'|' '{print $5}' | sed 's/^ *//g' | sed 's/ *$//g')
            local hours=$(echo "$line" | awk -F'|' '{print $6}' | sed 's/^ *//g' | sed 's/ *$//g')
            
            local hours_rounded=$(echo "${hours%.*}")
            
            # Color based on urgency
            local hours_colored
            if [ "$hours_rounded" -lt 12 ]; then
                hours_colored="${RED}${hours_rounded}h${NC}"
            elif [ "$hours_rounded" -lt 24 ]; then
                hours_colored="${YELLOW}${hours_rounded}h${NC}"
            else
                hours_colored="${hours_rounded}h"
            fi
            
            # Format empty fields
            [ "$telegram_id" = "NULL" ] && telegram_id="-"
            [ "$email" = "NULL" ] && email="-"
            [ "$mobile" = "NULL" ] && mobile="-"
            
            printf "%-10s | %-19s | %-11s | %-12s | %-20s | %s\n" "$username" "$expiry_date" "$hours_colored" "$telegram_id" "$email" "$mobile"
        done
        
        # Option to send notifications
        echo ""
        read -p "Do you want to send Telegram notifications to these users? (y/N): " send_notifications
        
        if [ "$send_notifications" = "y" ] || [ "$send_notifications" = "Y" ]; then
            echo "Sending notifications..."
            
            run_query "$query" | while read -r line; do
                if [[ -z "$line" ]]; then continue; fi
                
                local username=$(echo "$line" | awk -F'|' '{print $1}' | sed 's/^ *//g' | sed 's/ *$//g')
                local telegram_id=$(echo "$line" | awk -F'|' '{print $5}' | sed 's/^ *//g' | sed 's/ *$//g')
                local hours=$(echo "$line" | awk -F'|' '{print $6}' | sed 's/^ *//g' | sed 's/ *$//g')
                
                if [ -n "$telegram_id" ] && [ "$telegram_id" != "NULL" ]; then
                    # Send notification with curl
                    curl -s "http://localhost:3001/api/users/$username/notify/expiry" -X POST -H "Content-Type: application/json" -d "{}" > /dev/null
                    
                    echo -e "Notification sent to user ${BOLD}${username}${NC} (${hours%.*} hours remaining)"
                else
                    echo -e "${YELLOW}Skipping user ${username} - no Telegram ID${NC}"
                fi
            done
        fi
    fi
    
    echo ""
    echo -n "Press Enter to continue..."
    read
    show_main_menu
}

# Send notification
send_notification() {
    clear
    echo -e "${BOLD}Send Telegram Notification${NC}"
    echo "========================="
    echo ""
    
    read -p "Enter username to notify: " username
    
    if [ -z "$username" ]; then
        echo -e "${RED}Error: Username cannot be empty${NC}"
        echo -n "Press Enter to continue..."
        read
        send_notification
        return
    fi
    
    # Check if user exists and has Telegram ID
    local user_data=$(run_query "
        SELECT username, telegram_id
        FROM user_profiles
        WHERE username='$username'
    ")
    
    if [ -z "$user_data" ]; then
        echo -e "${RED}Error: User '$username' does not exist${NC}"
        echo -n "Press Enter to continue..."
        read
        send_notification
        return
    fi
    
    local telegram_id=$(echo "$user_data" | awk -F'|' '{print $2}' | sed 's/^ *//g' | sed 's/ *$//g')
    
    if [ -z "$telegram_id" ] || [ "$telegram_id" = "NULL" ]; then
        echo -e "${RED}Error: User '$username' does not have a Telegram ID${NC}"
        echo -n "Press Enter to continue..."
        read
        send_notification
        return
    fi
    
    read -p "Enter notification message: " message
    
    if [ -z "$message" ]; then
        echo -e "${RED}Error: Message cannot be empty${NC}"
        echo -n "Press Enter to continue..."
        read
        send_notification
        return
    fi
    
    # Send custom notification
    local response=$(curl -s "http://localhost:3001/api/users/$username/notify/custom" -X POST \
        -H "Content-Type: application/json" \
        -d "{\"message\": \"$message\"}")
    
    echo -e "${GREEN}Notification sent to $username successfully!${NC}"
    echo -n "Press Enter to continue..."
    read
    show_main_menu
}

# Restart services
restart_services() {
    clear
    echo -e "${BOLD}Restart Services${NC}"
    echo "================="
    echo ""
    
    echo "Select service to restart:"
    echo "1. User Manager (Main Service)"
    echo "2. SSH Monitor"
    echo "3. WireGuard Monitor"
    echo "4. All Services"
    echo "5. Back to Main Menu"
    echo ""
    echo -n "Enter your choice [1-5]: "
    read choice
    
    case $choice in
        1)
            systemctl restart irssh-user-manager
            echo -e "${GREEN}User Manager service restarted.${NC}"
            ;;
        2)
            systemctl restart irssh-ssh-monitor
            echo -e "${GREEN}SSH Monitor service restarted.${NC}"
            ;;
        3)
            if systemctl list-unit-files | grep -q irssh-wireguard-monitor; then
                systemctl restart irssh-wireguard-monitor
                echo -e "${GREEN}WireGuard Monitor service restarted.${NC}"
            else
                echo -e "${RED}WireGuard Monitor service not installed.${NC}"
            fi
            ;;
        4)
            systemctl restart irssh-user-manager
            systemctl restart irssh-ssh-monitor
            if systemctl list-unit-files | grep -q irssh-wireguard-monitor; then
                systemctl restart irssh-wireguard-monitor
            fi
            echo -e "${GREEN}All services restarted.${NC}"
            ;;
        5)
            show_main_menu
            return
            ;;
        *)
            echo -e "${RED}Invalid choice.${NC}"
            ;;
    esac
    
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

# Main installation function
function install_user_management() {
    # Check and install dependencies
    check_postgres
    install_dependencies
    create_directories
    
    # Setup database
    setup_database
    
    # Create service and monitoring scripts
    create_user_manager_service
    create_client_portal
    create_monitoring_scripts
    create_systemd_services
    create_nginx_config
    create_client_portal_setup
    create_admin_script
    
    # Enable and start services
    systemctl daemon-reload
    systemctl enable irssh-user-manager
    systemctl enable irssh-ssh-monitor
    
    # Start services
    systemctl start irssh-user-manager
    systemctl start irssh-ssh-monitor
    
    # Enable WireGuard monitor if WireGuard is installed
    if command -v wg &> /dev/null; then
        systemctl enable irssh-wireguard-monitor
        systemctl start irssh-wireguard-monitor
    fi
    
    # Create symlinks for management scripts
    ln -sf $SCRIPTS_DIR/admin_user_management.sh /usr/local/bin/irssh-users
    ln -sf $SCRIPTS_DIR/setup_client_portal.sh /usr/local/bin/irssh-portal-setup
    
    # Final success message
    clear
    cat << EOF
╔═══════════════════════════════════════════════════════════════════╗
║             Advanced User Management Installation Success          ║
╚═══════════════════════════════════════════════════════════════════╝

The Advanced User Management module has been successfully installed!

Management Commands:
  - irssh-users        : User management CLI tool
  - irssh-portal-setup : Configure client portal

Services Status:
  - User Manager      : $(systemctl is-active irssh-user-manager)
  - SSH Monitor       : $(systemctl is-active irssh-ssh-monitor)
  - WireGuard Monitor : $(if command -v wg &> /dev/null; then echo "$(systemctl is-active irssh-wireguard-monitor)"; else echo "not installed"; fi)

Database Information:
  - Database Name     : $DB_NAME
  - Database User     : $DB_USER
  - Database Password : $DB_USER_PASSWORD (SAVE THIS!)

Next Steps:
  1. Run 'irssh-users' to manage users
  2. Run 'irssh-portal-setup' to configure the client portal
  3. Add users and test connections

For more information, check the logs in $LOG_DIR directory.

EOF
}

# Start installation
install_user_management
