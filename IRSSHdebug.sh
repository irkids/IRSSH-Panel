#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Log function
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Step 1: Verify admin credentials
check_admin_credentials() {
    log "Verifying admin credentials..."
    ADMIN_FILE="/opt/irssh-panel/config/admin.env"

    if [[ ! -f "$ADMIN_FILE" ]]; then
        error "Admin credentials file not found: $ADMIN_FILE"
    fi

    source "$ADMIN_FILE"

    if [[ -z "$ADMIN_USER" || -z "$ADMIN_PASS" ]]; then
        error "Admin username or password is missing in $ADMIN_FILE"
    fi

    log "Admin credentials found: Username=${ADMIN_USER}, Password=${ADMIN_PASS}"
}

# Step 2: Verify database connection and data
check_database() {
    log "Checking PostgreSQL database..."

    sudo -u postgres psql -d irssh -c "\dt" &>/dev/null
    if [[ $? -ne 0 ]]; then
        error "Database 'irssh' is not accessible. Check PostgreSQL service or user permissions."
    fi

    log "Database 'irssh' is accessible."

    # Check if admin user exists in database
    USER_EXISTS=$(sudo -u postgres psql -d irssh -t -c "SELECT COUNT(*) FROM users WHERE username='$ADMIN_USER';")
    if [[ $USER_EXISTS -eq 0 ]]; then
        warn "Admin user '$ADMIN_USER' does not exist in the database. Creating user..."
        sudo -u postgres psql -d irssh -c "INSERT INTO users (username, password) VALUES ('$ADMIN_USER', crypt('$ADMIN_PASS', gen_salt('bf')));"
        log "Admin user '$ADMIN_USER' created successfully."
    else
        log "Admin user '$ADMIN_USER' exists in the database."
    fi
}

# Step 3: Verify backend service
check_backend_service() {
    log "Checking backend service..."

    BACKEND_LOG="/var/log/irssh/uvicorn.err.log"
    if [[ ! -f "$BACKEND_LOG" ]]; then
        error "Backend log file not found: $BACKEND_LOG"
    fi

    supervisorctl status irssh-panel | grep -q "RUNNING"
    if [[ $? -ne 0 ]]; then
        warn "Backend service is not running. Attempting to restart..."
        supervisorctl restart irssh-panel
        sleep 5
        supervisorctl status irssh-panel | grep -q "RUNNING" || error "Failed to start backend service. Check logs."
    fi

    log "Backend service is running."
}

# Step 4: Test API connectivity
test_api() {
    log "Testing API connectivity..."

    API_RESPONSE=$(curl -s -X POST "http://localhost:8000/api/auth/token" \
        -d "username=$ADMIN_USER&password=$ADMIN_PASS" \
        -H "Content-Type: application/x-www-form-urlencoded")

    if [[ "$API_RESPONSE" != *"access_token"* ]]; then
        error "API connectivity failed. Response: $API_RESPONSE"
    fi

    log "API connectivity is working. Access token received."
}

# Step 5: Verify frontend installation
check_frontend() {
    log "Checking frontend installation..."

    FRONTEND_DIR="/opt/irssh-panel/frontend/build"
    if [[ ! -d "$FRONTEND_DIR" ]]; then
        error "Frontend build directory not found: $FRONTEND_DIR"
    fi

    log "Frontend build directory exists."
}

# Step 6: Final report and fix confirmation
fix_and_report() {
    log "Generating final report..."

    echo
    echo -e "${YELLOW}Summary:${NC}"
    echo "1. Admin credentials: Verified"
    echo "2. Database: Verified and Admin user ensured"
    echo "3. Backend service: Running"
    echo "4. API connectivity: Successful"
    echo "5. Frontend installation: Verified"
    echo

    warn "If any issues persist, review logs or contact support."
}

# Main function
main() {
    log "Starting advanced IRSSH Panel diagnostic and fix tool..."

    check_admin_credentials
    check_database
    check_backend_service
    test_api
    check_frontend
    fix_and_report

    log "All checks and fixes completed successfully!"
}

# Execute main function
main
