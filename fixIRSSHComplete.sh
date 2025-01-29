#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
DB_NAME="irssh_panel"
DB_USER="irssh_admin"
DB_PASS="new_password" # رمز عبور جدید شما
BACKEND_DIR="/opt/irssh-panel/backend"
NGINX_CONFIG="/etc/nginx/sites-available/irssh-panel"

# Log output
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Step 1: Find pg_hba.conf and update
update_pg_hba_conf() {
    log "Finding and updating PostgreSQL authentication configuration (pg_hba.conf)..."
    
    PG_HBA_CONF=$(sudo find /etc/postgresql -name pg_hba.conf | head -1)
    
    if [[ -z "$PG_HBA_CONF" ]]; then
        error "pg_hba.conf not found. Ensure PostgreSQL is installed."
    fi
    
    log "Found pg_hba.conf at: $PG_HBA_CONF"
    
    if grep -q "local   all   $DB_USER" "$PG_HBA_CONF"; then
        log "pg_hba.conf already has the correct entry for $DB_USER."
    else
        echo "local   all   $DB_USER   md5" | sudo tee -a "$PG_HBA_CONF" > /dev/null
        log "Added authentication entry for $DB_USER in pg_hba.conf."
    fi

    # Reload PostgreSQL to apply changes
    sudo systemctl reload postgresql || error "Failed to reload PostgreSQL after updating pg_hba.conf."
}

# Step 2: Check and configure PostgreSQL database and user
setup_database() {
    log "Checking PostgreSQL database and user..."

    # Check if the database exists
    sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'" | grep -q 1 || {
        log "Database $DB_NAME not found. Creating database..."
        sudo -u postgres psql -c "CREATE DATABASE $DB_NAME;"
    }

    # Check if the user exists
    sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname = '$DB_USER'" | grep -q 1 || {
        log "User $DB_USER not found. Creating user..."
        sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
    }

    # Update user password
    log "Updating password for user $DB_USER..."
    sudo -u postgres psql -c "ALTER USER $DB_USER WITH PASSWORD '$DB_PASS';"

    # Grant privileges to the user
    log "Granting privileges to user $DB_USER on database $DB_NAME..."
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"

    # Verify database connection
    log "Verifying database connection..."
    PGPASSWORD="$DB_PASS" psql -h localhost -U "$DB_USER" -d "$DB_NAME" -c "\q" || error "Failed to connect to the database. Check credentials."
}

# Step 3: Restart PostgreSQL service
restart_postgresql() {
    log "Restarting PostgreSQL service..."
    sudo systemctl restart postgresql || error "Failed to restart PostgreSQL service."
}

# Step 4: Check and configure Backend service
setup_backend() {
    log "Checking backend service..."

    if ! systemctl is-active --quiet backend.service; then
        log "Backend service not found. Setting up backend service..."
        cat <<EOF | sudo tee /etc/systemd/system/backend.service
[Unit]
Description=IRSSH Backend Service
After=network.target postgresql.service

[Service]
User=root
WorkingDirectory=$BACKEND_DIR
ExecStart=$BACKEND_DIR/venv/bin/python3 app/main.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF
        sudo systemctl daemon-reload
        sudo systemctl enable backend.service
        sudo systemctl start backend.service
    fi

    log "Verifying backend service status..."
    systemctl is-active --quiet backend.service || error "Backend service is not running."
}

# Step 5: Check and configure NGINX
setup_nginx() {
    log "Checking NGINX configuration..."

    if [[ ! -f "$NGINX_CONFIG" ]]; then
        log "Creating NGINX configuration..."
        cat <<EOF | sudo tee "$NGINX_CONFIG"
server {
    listen 80;
    listen [::]:80;
    server_name localhost;

    root /opt/irssh-panel/frontend/build;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location /api {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
        sudo ln -sf "$NGINX_CONFIG" /etc/nginx/sites-enabled/
        sudo nginx -t || error "NGINX configuration test failed."
        sudo systemctl restart nginx
    fi

    log "Verifying NGINX status..."
    systemctl is-active --quiet nginx || error "NGINX is not running."
}

# Step 6: Test API connectivity
test_api() {
    log "Testing API connectivity..."
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost/api/auth/login \
        -H "Content-Type: application/json" \
        -d '{"username":"admin", "password":"admin_password"}')

    if [[ "$RESPONSE" -eq 200 ]]; then
        log "API is working correctly."
    else
        error "API is not responding correctly. HTTP Code: $RESPONSE"
    fi
}

# Main script execution
main() {
    log "Starting troubleshooting and setup script..."
    update_pg_hba_conf
    restart_postgresql
    setup_database
    setup_backend
    setup_nginx
    test_api
    log "All checks and configurations completed successfully!"
}

main
