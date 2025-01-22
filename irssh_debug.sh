#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Log function
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check admin credentials file
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

# Check PostgreSQL service
check_postgresql() {
    log "Checking PostgreSQL service..."
    if ! systemctl is-active --quiet postgresql; then
        log "PostgreSQL is not active. Starting it..."
        systemctl start postgresql || error "Failed to start PostgreSQL service."
    fi

    log "PostgreSQL is running."
}

# Verify database and user
verify_database() {
    log "Verifying database and user in PostgreSQL..."
    sudo -u postgres psql -c "\du" | grep -q "irssh_admin" || error "Database user 'irssh_admin' does not exist."
    sudo -u postgres psql -c "\l" | grep -q "irssh" || error "Database 'irssh' does not exist."

    log "Database and user verification passed."
}

# Test API connectivity
test_api() {
    log "Testing API connectivity..."
    ADMIN_FILE="/opt/irssh-panel/config/admin.env"
    source "$ADMIN_FILE"

    RESPONSE=$(curl -s -X POST http://localhost:8000/api/auth/token \
        -d "username=$ADMIN_USER&password=$ADMIN_PASS" \
        -H "Content-Type: application/x-www-form-urlencoded")

    if [[ "$RESPONSE" == *"access_token"* ]]; then
        log "API connectivity is working. Login successful."
    else
        error "API connectivity failed. Response: $RESPONSE"
    fi
}

# Check backend logs
check_logs() {
    log "Checking backend logs for errors..."
    LOG_FILE="/var/log/irssh/uvicorn.err.log"

    if [[ ! -f "$LOG_FILE" ]]; then
        error "Backend log file not found at $LOG_FILE"
    fi

    tail -n 20 "$LOG_FILE"
}

# Restart services
restart_services() {
    log "Restarting backend and Nginx..."
    supervisorctl restart irssh-panel || error "Failed to restart backend service."
    systemctl restart nginx || error "Failed to restart Nginx."

    log "Services restarted successfully."
}

# Main function
main() {
    check_admin_credentials
    check_postgresql
    verify_database
    test_api
    check_logs
    restart_services

    log "All checks and fixes completed successfully."
}

# Run the main function
main
