#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Database configuration
DB_NAME="irssh_panel"
DB_USER="irssh_admin"
DB_PASS="new_password" # رمز عبور جدید که با فایل `database.env` بک‌اند مطابقت دارد

# Log output
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Step 1: Check and configure PostgreSQL database
setup_database() {
    log "Checking PostgreSQL database and user..."

    # Change to a safe directory to avoid permission issues
    cd /tmp

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

    # Update user password to ensure it matches
    log "Updating password for user $DB_USER..."
    sudo -u postgres psql -c "ALTER USER $DB_USER WITH PASSWORD '$DB_PASS';"

    # Grant privileges to the user
    log "Granting privileges to user $DB_USER on database $DB_NAME..."
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"

    # Verify database connection
    log "Verifying database connection..."
    PGPASSWORD="$DB_PASS" psql -h localhost -U "$DB_USER" -d "$DB_NAME" -c "\q" || error "Failed to connect to the database. Check credentials."
}

# Main script execution
main() {
    log "Starting troubleshooting and setup script..."
    setup_database
    log "All checks and configurations completed successfully!"
}

main
