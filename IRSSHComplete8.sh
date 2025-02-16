#!/bin/bash

# Improved IRSSH Panel Installation Script Sections
# Version: 3.5.1

# Central configuration paths
CONFIG_BASE="/etc/enhanced_ssh"
CONFIG_FILE="$CONFIG_BASE/config.yaml"
PANEL_DIR="/opt/irssh-panel"
LOG_DIR="/var/log/irssh"

# Logging function with levels
log() {
    local level=$1
    local message=$2
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    echo -e "[$timestamp] [$level] $message"
    echo "[$timestamp] [$level] $message" >> "$LOG_DIR/installation.log"
}

# Load or generate configuration
setup_configuration() {
    log "INFO" "Setting up configuration..."
    
    # Generate secure credentials
    DB_NAME=${DB_NAME:-"ssh_manager"}
    DB_USER=${DB_USER:-"irssh_admin"}
    DB_PASS=${DB_PASS:-$(openssl rand -base64 32)}
    JWT_SECRET=$(openssl rand -base64 32)
    
    # Create configuration directory
    mkdir -p "$CONFIG_BASE"
    
    # Create or update config.yaml
    cat > "$CONFIG_FILE" << EOL
# IRSSH Panel Configuration
# Generated: $(date +'%Y-%m-%d %H:%M:%S')

# Database Configuration
db_host: localhost
db_port: 5432
db_name: $DB_NAME
db_user: $DB_USER
db_password: $DB_PASS

# Web Panel Configuration
web_port: $WEB_PORT
jwt_secret: $JWT_SECRET

# Protocol Ports
ssh_port: $SSH_PORT
dropbear_port: $DROPBEAR_PORT
websocket_port: $WEBSOCKET_PORT
l2tp_port: $L2TP_PORT
ikev2_port: $IKEV2_PORT
cisco_port: $CISCO_PORT
wireguard_port: $WIREGUARD_PORT
singbox_port: $SINGBOX_PORT
EOL

    # Set secure permissions
    chmod 600 "$CONFIG_FILE"
    
    # Export configuration as environment variables
    export SSH_DB_HOST=$(grep '^db_host:' "$CONFIG_FILE" | awk '{print $2}')
    export SSH_DB_PORT=$(grep '^db_port:' "$CONFIG_FILE" | awk '{print $2}')
    export SSH_DB_NAME="$DB_NAME"
    export SSH_DB_USER="$DB_USER"
    export SSH_DB_PASSWORD="$DB_PASS"
    
    log "INFO" "Configuration setup completed"
}

# Improved database setup with consistent authentication
setup_database() {
    log "INFO" "Setting up PostgreSQL database..."

    # Ensure PostgreSQL is running
    systemctl start postgresql
    systemctl enable postgresql

    # Wait for PostgreSQL to be ready
    local max_attempts=30
    local attempt=1
    while ! pg_isready; do
        if [ $attempt -ge $max_attempts ]; then
            log "ERROR" "PostgreSQL failed to start after $max_attempts attempts"
            return 1
        fi
        log "INFO" "Waiting for PostgreSQL... (attempt $attempt/$max_attempts)"
        sleep 1
        ((attempt++))
    done

    # Update PostgreSQL authentication configuration
    PG_HBA="/etc/postgresql/14/main/pg_hba.conf"
    
    # Backup original configuration
    cp "$PG_HBA" "${PG_HBA}.backup"
    
    # Update authentication methods for both IPv4 and IPv6
    sed -i \
        -e 's/local\s\+all\s\+all\s\+peer/local   all             all                                     md5/' \
        -e 's/host\s\+all\s\+all\s\+127.0.0.1\/32\s\+scram-sha-256/host    all             all             127.0.0.1\/32            md5/' \
        -e 's/host\s\+all\s\+all\s\+::1\/128\s\+scram-sha-256/host    all             all             ::1\/128                 md5/' \
        "$PG_HBA"

    # Reload PostgreSQL configuration
    systemctl reload postgresql

    # Setup database and user
    su - postgres << EOF
psql -c "CREATE USER $SSH_DB_USER WITH PASSWORD '$SSH_DB_PASSWORD';"
psql -c "CREATE DATABASE $SSH_DB_NAME OWNER $SSH_DB_USER;"
psql -c "GRANT ALL PRIVILEGES ON DATABASE $SSH_DB_NAME TO $SSH_DB_USER;"
psql -c "ALTER SYSTEM SET password_encryption = 'md5';"
EOF

    # Verify database connection
    if ! PGPASSWORD="$SSH_DB_PASSWORD" psql -h localhost -U "$SSH_DB_USER" -d "$SSH_DB_NAME" -c '\q'; then
        log "ERROR" "Database connection verification failed"
        return 1
    fi

    log "INFO" "Database setup completed successfully"
}

# Setup environment for Python scripts
setup_python_environment() {
    log "INFO" "Setting up Python environment..."
    
    # Create virtual environment
    python3 -m venv "$PANEL_DIR/venv"
    
    # Create helper script to set environment variables
    cat > "$PANEL_DIR/venv/bin/set_env.py" << 'EOL'
#!/usr/bin/env python3
import os
import yaml

def load_config():
    config_file = "/etc/enhanced_ssh/config.yaml"
    if not os.path.exists(config_file):
        print("Configuration file not found!")
        exit(1)
        
    with open(config_file, "r") as f:
        config = yaml.safe_load(f)
        
    # Set environment variables
    os.environ["SSH_DB_HOST"] = config.get("db_host", "localhost")
    os.environ["SSH_DB_PORT"] = str(config.get("db_port", 5432))
    os.environ["SSH_DB_NAME"] = config.get("db_name", "ssh_manager")
    os.environ["SSH_DB_USER"] = config.get("db_user", "irssh_admin")
    os.environ["SSH_DB_PASSWORD"] = config.get("db_password", "")

if __name__ == "__main__":
    load_config()
EOL

    chmod +x "$PANEL_DIR/venv/bin/set_env.py"
    
    # Install required Python packages
    source "$PANEL_DIR/venv/bin/activate"
    pip install --upgrade pip
    pip install pyyaml psycopg2-binary requests prometheus_client
    deactivate
    
    log "INFO" "Python environment setup completed"
}

# Setup systemd services with proper environment
setup_services() {
    log "INFO" "Setting up systemd services..."
    
    # Create service for main panel
    cat > /etc/systemd/system/irssh-panel.service << EOL
[Unit]
Description=IRSSH Panel Service
After=network.target postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=$PANEL_DIR/modules/protocols
Environment=PYTHONPATH=$PANEL_DIR/venv/lib/python3.8/site-packages
ExecStartPre=$PANEL_DIR/venv/bin/python3 $PANEL_DIR/venv/bin/set_env.py
ExecStart=$PANEL_DIR/venv/bin/python3 $PANEL_DIR/modules/protocols/ssh-script.py
Restart=always

[Install]
WantedBy=multi-user.target
EOL

    # Create service for backend
    cat > /etc/systemd/system/irssh-backend.service << EOL
[Unit]
Description=IRSSH Panel Backend
After=network.target postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=$PANEL_DIR/backend
Environment=NODE_ENV=production
EnvironmentFile=/etc/enhanced_ssh/backend.env
ExecStart=/usr/bin/node src/index.js
Restart=always

[Install]
WantedBy=multi-user.target
EOL

    # Create backend environment file
    cat > /etc/enhanced_ssh/backend.env << EOL
PORT=8000
JWT_SECRET=$JWT_SECRET
FRONTEND_URL=http://localhost:$WEB_PORT
DB_HOST=$SSH_DB_HOST
DB_PORT=$SSH_DB_PORT
DB_NAME=$SSH_DB_NAME
DB_USER=$SSH_DB_USER
DB_PASS=$SSH_DB_PASSWORD
EOL

    chmod 600 /etc/enhanced_ssh/backend.env
    
    # Reload systemd and start services
    systemctl daemon-reload
    systemctl enable irssh-panel irssh-backend
    systemctl start irssh-panel irssh-backend
    
    log "INFO" "Services setup completed"
}

# Main installation flow would call these functions in sequence
# main() {
#     setup_configuration
#     setup_database
#     setup_python_environment
#     setup_services
#     # ... other setup functions ...
# }
