#!/usr/bin/env python3

import os
import sys
import subprocess
import shutil
import logging
import psycopg2
from datetime import datetime
import socket
import re

# Advanced Logging Configuration
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler('/var/log/badvpn_udpgw.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class NetworkUtils:
    @staticmethod
    def validate_port(port):
        """
        Validate UDP port with comprehensive checks
        """
        try:
            port_num = int(port)
            if 1024 <= port_num <= 65535:
                return port_num
            raise ValueError("Port must be between 1024 and 65535")
        except ValueError:
            logger.error("Invalid port number")
            return None

    @staticmethod
    def detect_primary_network_interface():
        """
        Automatically detect primary network interface
        """
        try:
            # Detect default route interface
            result = subprocess.run(
                ["ip", "route", "show", "default"], 
                capture_output=True, 
                text=True, 
                check=True
            )
            
            interface_match = re.search(r'dev\s+(\w+)', result.stdout)
            if interface_match:
                return interface_match.group(1)
            
            # Fallback to first active non-loopback interface
            result = subprocess.run(
                ["ip", "-o", "link", "show", "up"], 
                capture_output=True, 
                text=True, 
                check=True
            )
            
            interfaces = re.findall(r'\d+:\s+(\w+)@\w+:', result.stdout)
            non_loopback = [iface for iface in interfaces if iface != 'lo']
            
            return non_loopback[0] if non_loopback else 'default'
        
        except (subprocess.CalledProcessError, IndexError):
            logger.warning("Could not automatically detect network interface")
            return 'default'

class DatabaseConfigManager:
    def __init__(self, dbname='main_server_config', user='postgres', password='secure_password', host='localhost'):
        """
        Initialize database connection with secure parameters
        """
        try:
            self.conn = psycopg2.connect(
                dbname=dbname,
                user=user,
                password=password,
                host=host,
                port='5432',
                application_name='BadVPN UDPGW Config Manager'
            )
            self.cursor = self.conn.cursor()
            self._create_config_table()
        except Exception as e:
            logger.error(f"Database connection error: {e}")
            sys.exit(1)

    def _create_config_table(self):
        """
        Create comprehensive configuration table
        """
        create_table_query = """
        CREATE TABLE IF NOT EXISTS badvpn_config (
            id SERIAL PRIMARY KEY,
            port INTEGER NOT NULL,
            max_clients INTEGER DEFAULT 999,
            encryption_enabled BOOLEAN DEFAULT FALSE,
            network_interface VARCHAR(50) DEFAULT 'default',
            tls_enabled BOOLEAN DEFAULT FALSE,
            performance_mode VARCHAR(20) DEFAULT 'standard',
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
        try:
            self.cursor.execute(create_table_query)
            self.conn.commit()
        except Exception as e:
            logger.error(f"Table creation error: {e}")

    def insert_initial_configuration(self, port):
        """
        Insert initial configuration with default settings
        """
        insert_query = """
        INSERT INTO badvpn_config 
        (port, max_clients, encryption_enabled, network_interface, tls_enabled, performance_mode)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        try:
            network_interface = NetworkUtils.detect_primary_network_interface()
            self.cursor.execute(insert_query, (
                port, 
                999,  # Default max clients
                False,  # Encryption disabled by default
                network_interface,
                False,  # TLS disabled by default
                'standard'  # Standard performance mode
            ))
            self.conn.commit()
            logger.info("Initial BadVPN configuration inserted")
        except Exception as e:
            logger.error(f"Configuration insertion error: {e}")

    def close(self):
        """Close database connection"""
        if self.conn:
            self.cursor.close()
            self.conn.close()

def run_command(command, capture_output=False):
    """Execute system commands with error handling"""
    try:
        if capture_output:
            result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
            return result.stdout.strip()
        else:
            subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Command execution error: {command}")
        sys.exit(1)

def update_env_file(port):
    """Update .env file with new UDP gateway port"""
    env_path = "/var/www/html/app/.env"
    try:
        with open(env_path, 'r') as f:
            content = f.read()
        
        updated_content = content.replace(
            f"PORT_UDPGW={content.split('PORT_UDPGW=')[1].split('\n')[0]}", 
            f"PORT_UDPGW={port}"
        )
        
        with open(env_path, 'w') as f:
            f.write(updated_content)
    except Exception as e:
        logger.error(f".env file update error: {e}")
        sys.exit(1)

def main():
    # Clear screen
    os.system('clear')

    # Default UDP port
    default_udp_port = 7300

    # User input for port (only port, as requested)
    print("\nBadVPN UDP Gateway Installation")
    user_port = input(f"Enter UDP port (default {default_udp_port}): ") or str(default_udp_port)
    
    # Validate port
    udp_port = NetworkUtils.validate_port(user_port) or default_udp_port

    # Initialize database manager
    db_manager = DatabaseConfigManager()

    # Insert initial configuration
    db_manager.insert_initial_configuration(udp_port)

    # System update and dependency installation
    run_command("apt update -y")
    run_command("apt install git cmake -y")

    # Remove existing BadVPN directory if exists
    if os.path.exists("/root/badvpn"):
        shutil.rmtree("/root/badvpn")

    # Clone BadVPN repository
    run_command("git clone https://github.com/ambrop72/badvpn.git /root/badvpn")

    # Prepare build directory
    os.makedirs("/root/badvpn/badvpn-build", exist_ok=True)
    os.chdir("/root/badvpn/badvpn-build")

    # Compile BadVPN
    run_command("cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1")
    run_command("make")

    # Copy executable
    shutil.copy("udpgw/badvpn-udpgw", "/usr/local/bin/")

    # Create systemd service file with default configurations
    service_content = f"""[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
ExecStart=/usr/local/bin/badvpn-udpgw \
    --loglevel info \
    --listen-addr 127.0.0.1:{udp_port} \
    --max-clients 999

User=videocall
Group=videocall

# Enhanced security parameters
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target"""

    with open("/etc/systemd/system/videocall.service", "w") as f:
        f.write(service_content)

    # Create service user
    run_command("useradd -m videocall")

    # Enable and start service
    run_command("systemctl enable videocall")
    run_command("systemctl start videocall")

    # Update environment file
    update_env_file(udp_port)

    # Close database connection
    db_manager.close()

    print("BadVPN UDP Gateway installation completed successfully.")
    print(f"Installed on port {udp_port}")
    print("Further configuration can be done through the web interface.")

if __name__ == "__main__":
    # Root access check
    if os.geteuid() != 0:
        print("This script requires root access. Please use sudo.")
        sys.exit(1)

    main()
