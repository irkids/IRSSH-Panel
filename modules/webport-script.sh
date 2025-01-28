#!/bin/bash

# Dependency check function
check_dependencies() {
    local dependencies=("python3" "psql" "jq" "nodejs" "npm")
    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            echo "Error: $dep is not installed. Please install it first."
            exit 1
        fi
    done
}

# Python-based port validation module
python_port_validator() {
    python3 - << EOF
import random
import socket

def is_port_in_range(port):
    return 1024 <= port <= 65000

def is_port_available(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('localhost', port))
        return result != 0
    except Exception as e:
        print(f"Error checking port: {e}")
        return False

def generate_random_port():
    return random.randint(1024, 65000)

def validate_port(port):
    port = int(port)
    reserved_ports = {
        'SSH': 22,
        'SSH-DROPBEAR': 22022,
        'SSH-TLS': 444,
        'L2TPv3/IPSec': 500,
        'IKEv2/IPSec': 4500,
        'Cisco AnyConnect': 443,
        'WireGuard': 51820,
        'SingBox Protocols': [
            1080,  # Shadowsocks
            2087,  # Tuic
            443,   # VLess
            8443   # Hysteria2
        ]
    }

    if not is_port_in_range(port):
        print("Port out of allowed range (1024-65000)")
        return False

    if not is_port_available(port):
        print("Port is already in use")
        return False

    # Check against reserved ports
    for proto, reserved_port in reserved_ports.items():
        if isinstance(reserved_port, list):
            if port in reserved_port:
                print(f"Port conflicts with {proto} protocol")
                return False
        elif port == reserved_port:
            print(f"Port conflicts with {proto} protocol")
            return False

    return True

# Main execution point for Python validation
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
        print(validate_port(port))
    else:
        print(generate_random_port())
EOF
}

# JavaScript configuration generator
javascript_config_generator() {
    node - << EOF
const fs = require('fs');

function generateWebConfig(port) {
    const config = {
        server: {
            port: port,
            host: 'localhost',
            environment: 'production'
        },
        security: {
            corsEnabled: true,
            rateLimitEnabled: true
        }
    };

    fs.writeFileSync('server_config.json', JSON.stringify(config, null, 2));
    console.log('Web configuration generated successfully');
}

const port = process.argv[2];
generateWebConfig(parseInt(port));
EOF
}

# PostgreSQL database registration function
register_port_in_database() {
    local port=$1
    
    # PostgreSQL connection parameters (adjust as needed)
    local DB_NAME="system_config"
    local DB_USER="admin"
    local DB_HOST="localhost"

    # SQL to create table if not exists and insert/update port
    psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "
    CREATE TABLE IF NOT EXISTS system_ports (
        id SERIAL PRIMARY KEY,
        port_number INTEGER UNIQUE,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    INSERT INTO system_ports (port_number) 
    VALUES ($port) 
    ON CONFLICT (port_number) 
    DO UPDATE SET last_updated = CURRENT_TIMESTAMP;
    "
}

# Main script execution
main() {
    check_dependencies

    # Random port generation
    random_port=$(python_port_validator)
    echo "Suggested Random Port: $random_port"

    # User port input
    read -p "Enter desired port (or press Enter to use suggested port): " user_port
    user_port=${user_port:-$random_port}

    # Validate port
    port_valid=$(python_port_validator "$user_port")

    if [ "$port_valid" == "True" ]; then
        echo "Port $user_port is valid and available."
        
        # Generate web configuration
        javascript_config_generator "$user_port"
        
        # Register in PostgreSQL
        register_port_in_database "$user_port"
        
        echo "Port $user_port has been successfully configured and registered."
    else
        echo "Invalid port selection. Please choose a different port."
        exit 1
    fi
}

# Execute main script
main
