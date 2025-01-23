#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Step 1: Check admin credentials
check_admin_credentials() {
    log "Checking admin credentials..."
    ADMIN_FILE="/opt/irssh-panel/config/admin.env"
    if [[ ! -f "$ADMIN_FILE" ]]; then
        error "Admin credentials file not found at $ADMIN_FILE"
    fi

    source "$ADMIN_FILE"
    if [[ -z "$ADMIN_USER" || -z "$ADMIN_PASS" ]]; then
        error "Admin credentials are missing in $ADMIN_FILE"
    fi

    log "Admin username: $ADMIN_USER"
    log "Admin password: $ADMIN_PASS"
}

# Step 2: Verify PostgreSQL service
check_postgresql_service() {
    log "Checking PostgreSQL service..."
    if ! systemctl is-active --quiet postgresql; then
        log "PostgreSQL is not active. Starting it..."
        systemctl start postgresql || error "Failed to start PostgreSQL service."
    fi
    log "PostgreSQL is running."
}

# Step 3: Verify database and user
verify_database() {
    log "Verifying database and user in PostgreSQL..."
    sudo -u postgres psql -c "\du" | grep -q "irssh_admin" || error "Database user 'irssh_admin' does not exist."
    sudo -u postgres psql -c "\l" | grep -q "irssh" || error "Database 'irssh' does not exist."

    log "Database and user verification passed."
}

# Step 4: Test API connectivity
test_api_connectivity() {
    log "Testing API connectivity..."
    RESPONSE=$(curl -s -X POST http://localhost:8000/api/auth/token \
        -d "username=$ADMIN_USER&password=$ADMIN_PASS" \
        -H "Content-Type: application/x-www-form-urlencoded")

    if [[ "$RESPONSE" == *"access_token"* ]]; then
        log "API connectivity is working. Login successful."
    else
        error "API connectivity failed. Response: $RESPONSE"
    fi
}

# Step 5: Check backend logs
check_backend_logs() {
    log "Checking backend logs..."
    LOG_FILE="/var/log/irssh/uvicorn.err.log"

    if [[ ! -f "$LOG_FILE" ]]; then
        error "Backend log file not found at $LOG_FILE"
    fi

    echo -e "${BLUE}[LOGS FROM BACKEND]${NC}"
    tail -n 20 "$LOG_FILE"
}

# Step 6: Restart services
restart_services() {
    log "Restarting backend and Nginx..."
    supervisorctl restart irssh-panel || error "Failed to restart backend service."
    systemctl restart nginx || error "Failed to restart Nginx."
    log "Services restarted successfully."
}

# Step 7: Verify and update database admin password
update_database_password() {
    log "Ensuring database user 'irssh_admin' has the correct password..."
    sudo -u postgres psql -d irssh -c "UPDATE users SET password = crypt('$ADMIN_PASS', gen_salt('bf')) WHERE username = '$ADMIN_USER';" || error "Failed to update admin user password in database."
    log "Admin user password updated in database."
}

# Step 8: Verify Python dependencies
check_python_dependencies() {
    log "Checking Python dependencies..."
    source /opt/irssh-panel/venv/bin/activate
    pip install --upgrade fastapi[all] uvicorn[standard] bcrypt==3.2.0 sqlalchemy[asyncio] psycopg2-binary python-jose[cryptography] passlib || error "Failed to install Python dependencies."
    log "Python dependencies are up-to-date."
}

# Main function
main() {
    check_admin_credentials
    check_postgresql_service
    verify_database
    update_database_password
    test_api_connectivity
    check_backend_logs
    check_python_dependencies
    restart_services

    log "All checks and fixes completed successfully."
}

# Execute the main function
main
