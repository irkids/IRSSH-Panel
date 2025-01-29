#!/bin/bash

# Setup PostgreSQL database
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

    # Create database and user with error handling
    {
        sudo -u postgres psql -c "DROP DATABASE IF EXISTS $DB_NAME;"
        sudo -u postgres psql -c "DROP USER IF EXISTS $DB_USER;"
        sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
        sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"
    } || error "Failed to setup database"

    # Apply initial SQL schema
    cat > /tmp/init.sql << EOL
-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    protocol VARCHAR(50) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true
);

-- Create traffic table
CREATE TABLE traffic (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    upload BIGINT DEFAULT 0,
    download BIGINT DEFAULT 0,
    date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create sessions table
CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    ip_address VARCHAR(45),
    start_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true
);

-- Create bandwidth_logs table
CREATE TABLE bandwidth_logs (
    id SERIAL PRIMARY KEY,
    date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    protocol VARCHAR(50),
    bytes_in BIGINT DEFAULT 0,
    bytes_out BIGINT DEFAULT 0
);

-- Create system_logs table
CREATE TABLE system_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    type VARCHAR(50),
    message TEXT,
    level VARCHAR(20)
);

-- Create settings table
CREATE TABLE settings (
    key VARCHAR(255) PRIMARY KEY,
    value TEXT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_traffic_user_id ON traffic(user_id);
CREATE INDEX idx_traffic_date ON traffic(date);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_active ON sessions(is_active);
CREATE INDEX idx_bandwidth_logs_date ON bandwidth_logs(date);
CREATE INDEX idx_system_logs_timestamp ON system_logs(timestamp);
CREATE INDEX idx_system_logs_type ON system_logs(type);

-- Insert default settings
INSERT INTO settings (key, value) VALUES
    ('backup_enabled', 'true'),
    ('backup_interval', '24'),
    ('max_users', '1000'),
    ('max_connections_per_user', '2'),
    ('bandwidth_limit_enabled', 'false'),
    ('bandwidth_limit_value', '1024'),
    ('notification_email', ''),
    ('telegram_bot_token', ''),
    ('telegram_chat_id', '')
ON CONFLICT (key) DO NOTHING;
EOL

    # Apply schema
    PGPASSWORD="$DB_PASS" psql -h localhost -U "$DB_USER" -d "$DB_NAME" -f /tmp/init.sql || error "Failed to initialize database schema"
    rm -f /tmp/init.sql

    # Save database configuration
    cat > "$CONFIG_DIR/database.env" << EOL
DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASS=$DB_PASS
EOL
    chmod 600 "$CONFIG_DIR/database.env"

    # Configure PostgreSQL
    cat > /etc/postgresql/*/main/conf.d/irssh-optimizations.conf << EOL
# Memory Configuration
shared_buffers = '256MB'
work_mem = '16MB'
maintenance_work_mem = '128MB'
effective_cache_size = '512MB'

# Checkpointing Configuration
checkpoint_completion_target = 0.9
checkpoint_timeout = '15min'
max_wal_size = '1GB'
min_wal_size = '80MB'

# Query Planning Configuration
random_page_cost = 1.1
effective_io_concurrency = 200

# Connection Settings
max_connections = 100
superuser_reserved_connections = 3

# Logging Configuration
log_destination = 'stderr'
logging_collector = on
log_directory = '/var/log/postgresql'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_truncate_on_rotation = on
log_rotation_age = 1d
log_rotation_size = 0
log_min_duration_statement = 1000
log_checkpoints = on
log_connections = on
log_disconnections = on
log_lock_waits = on
log_temp_files = 0
log_autovacuum_min_duration = 0

# Autovacuum Configuration
autovacuum = on
autovacuum_max_workers = 3
autovacuum_naptime = '1min'
autovacuum_vacuum_threshold = 50
autovacuum_analyze_threshold = 50
autovacuum_vacuum_scale_factor = 0.02
autovacuum_analyze_scale_factor = 0.01
EOL

    # Restart PostgreSQL to apply configuration
    systemctl restart postgresql

    log "Database setup completed successfully"
}

# Backup database function
backup_database() {
    local backup_dir="$BACKUP_DIR/database"
    mkdir -p "$backup_dir"

    local backup_file="$backup_dir/backup-$(date +%Y%m%d-%H%M%S).sql"
    PGPASSWORD="$DB_PASS" pg_dump -h localhost -U "$DB_USER" -d "$DB_NAME" > "$backup_file" || \
        error "Failed to create database backup"

    # Compress backup
    gzip "$backup_file"

    # Remove old backups (keep last 7 days)
    find "$backup_dir" -name "backup-*.sql.gz" -mtime +7 -delete

    log "Database backup created: $backup_file.gz"
}

# Restore database function
restore_database() {
    local backup_file="$1"
    if [[ ! -f "$backup_file" ]]; then
        error "Backup file not found: $backup_file"
    }

    # If file is compressed, decompress it
    if [[ "$backup_file" == *.gz ]]; then
        gunzip -c "$backup_file" | PGPASSWORD="$DB_PASS" psql -h localhost -U "$DB_USER" -d "$DB_NAME" || \
            error "Failed to restore database from backup"
    else
        PGPASSWORD="$DB_PASS" psql -h localhost -U "$DB_USER" -d "$DB_NAME" -f "$backup_file" || \
            error "Failed to restore database from backup"
    fi

    log "Database restored successfully from: $backup_file"
}
