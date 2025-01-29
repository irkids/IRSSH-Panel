#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Database configuration
DB_NAME="irssh_panel"
DB_USER="irssh_admin"
DB_PASS="new_password" # رمز عبور دلخواه شما
PG_HBA_CONF="/etc/postgresql/12/main/pg_hba.conf" # مسیر فایل pg_hba.conf (ورژن PostgreSQL خود را بررسی کنید)

# Log output
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Step 1: Update pg_hba.conf
update_pg_hba_conf() {
    log "Updating PostgreSQL authentication configuration (pg_hba.conf)..."

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

    # Change directory to avoid "Permission denied" error
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

# Step 3: Restart PostgreSQL to ensure all configurations are applied
restart_postgresql() {
    log "Restarting PostgreSQL service..."
    sudo systemctl restart postgresql || error "Failed to restart PostgreSQL service."
}

# Main script execution
main() {
    log "Starting troubleshooting and setup script..."
    update_pg_hba_conf
    restart_postgresql
    setup_database
    log "All checks and configurations completed successfully!"
}

main
