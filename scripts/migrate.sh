#!/bin/bash

set -e

# Configuration
APP_NAME="irssh-panel"
MIGRATIONS_DIR="./migrations"
MONGODB_URI=${MONGODB_URI:-"mongodb://localhost:27017"}
DATABASE_NAME=${DATABASE_NAME:-"irssh"}

# Function to execute a migration
execute_migration() {
    local file=$1
    echo "Executing migration: $file"
    
    # Extract version number from filename
    version=$(echo $file | cut -d'-' -f1)
    
    # Check if migration has been applied
    if mongo $MONGODB_URI/$DATABASE_NAME --eval "db.migrations.findOne({version: '$version'})" | grep -q "$version"; then
        echo "Migration $version already applied"
        return
    fi
    
    # Execute migration
    mongo $MONGODB_URI/$DATABASE_NAME $MIGRATIONS_DIR/$file
    
    # Record migration
    mongo $MONGODB_URI/$DATABASE_NAME --eval "db.migrations.insertOne({version: '$version', appliedAt: new Date()})"
    
    echo "Migration $version completed"
}

# Create migrations collection if it doesn't exist
mongo $MONGODB_URI/$DATABASE_NAME --eval "db.createCollection('migrations')"

# Execute all migrations in order
for file in $(ls $MIGRATIONS_DIR/*.js | sort); do
    execute_migration $(basename $file)
done

echo "All migrations completed successfully!"
