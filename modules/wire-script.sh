#!/bin/bash

# Enhanced WireGuard Installation & Configuration Script
# Implements advanced features including automated port management, container orchestration,
# and intelligent failover capabilities

set -euo pipefail
trap 'error_handler $? $LINENO $BASH_LINENO "$BASH_COMMAND" $(printf "::%s" ${FUNCNAME[@]:-})' ERR

# Global configuration
CONFIG_DIR="/etc/wireguard"
DOCKER_COMPOSE_FILE="/etc/wireguard/docker-compose.yml"
ANSIBLE_PLAYBOOK_DIR="/etc/wireguard/ansible"
ENV_FILE="/etc/wireguard/.env"
PROMETHEUS_CONFIG="/etc/prometheus/prometheus.yml"
GRAFANA_PROVISIONING="/etc/grafana/provisioning"

# Logging configuration
LOG_FILE="/var/log/wireguard-setup.log"
AUDIT_LOG="/var/log/wireguard-audit.log"

# Function to handle errors
error_handler() {
    local exit_code=$1
    local line_number=$2
    local bash_lineno=$3
    local last_command=$4
    local func_stack=$5
    
    logger -p local0.err "Error $exit_code occurred on line $line_number: $last_command"
    echo "Error $exit_code occurred on line $line_number: $last_command" >> "$AUDIT_LOG"
    
    # Attempt recovery if possible
    case $exit_code in
        1) 
            logger -p local0.notice "Attempting to recover from general error"
            cleanup_failed_installation
            ;;
        *)
            logger -p local0.err "Unrecoverable error occurred"
            ;;
    esac
}

# Advanced logging function with severity levels
log() {
    local severity=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$severity] $message" >> "$LOG_FILE"
    logger -p "local0.$severity" "$message"
    
    if [[ "$severity" == "ERROR" ]]; then
        echo "[$timestamp] [$severity] $message" >&2
    fi
}

# Function to validate system requirements
validate_system_requirements() {
    log "INFO" "Validating system requirements"
    
    # Check minimum system resources
    local min_memory=2048  # 2GB RAM
    local min_cpu_cores=2
    local min_disk_space=10240  # 10GB
    
    local total_memory=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
    local cpu_cores=$(nproc)
    local disk_space=$(df / | awk 'NR==2 {print int($4/1024)}')
    
    [[ $total_memory -lt $min_memory ]] && { log "ERROR" "Insufficient memory"; exit 1; }
    [[ $cpu_cores -lt $min_cpu_cores ]] && { log "ERROR" "Insufficient CPU cores"; exit 1; }
    [[ $disk_space -lt $min_disk_space ]] && { log "ERROR" "Insufficient disk space"; exit 1; }
    
    # Verify kernel modules
    for module in wireguard iptable_nat ip6table_nat; do
        if ! modprobe -n $module &>/dev/null; then
            log "ERROR" "Required kernel module $module not available"
            exit 1
        fi
    done
}

# Function to install and configure Docker
setup_docker() {
    log "INFO" "Setting up Docker and Docker Compose"
    
    # Install Docker if not present
    if ! command -v docker &>/dev/null; then
        curl -fsSL https://get.docker.com -o get-docker.sh
        sh get-docker.sh
        
        # Configure Docker daemon
        cat > /etc/docker/daemon.json <<EOF
{
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "100m",
        "max-file": "3"
    },
    "default-ulimits": {
        "nofile": {
            "Name": "nofile",
            "Hard": 64000,
            "Soft": 64000
        }
    },
    "metrics-addr": "127.0.0.1:9323",
    "experimental": true
}
EOF
        systemctl restart docker
    fi
    
    # Install Docker Compose if not present
    if ! command -v docker-compose &>/dev/null; then
        curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
            -o /usr/local/bin/docker-compose
        chmod +x /usr/local/bin/docker-compose
    fi
}

# Function to setup Ansible
setup_ansible() {
    log "INFO" "Setting up Ansible"
    
    # Install Ansible
    apt-get update
    apt-get install -y ansible
    
    # Create Ansible directory structure
    mkdir -p "$ANSIBLE_PLAYBOOK_DIR"/{playbooks,roles,inventory,group_vars,host_vars}
    
    # Create main playbook for WireGuard management
    cat > "$ANSIBLE_PLAYBOOK_DIR/playbooks/wireguard.yml" <<EOF
---
- name: WireGuard Management
  hosts: wireguard_servers
  become: yes
  
  roles:
    - role: wireguard
    - role: monitoring
    - role: database
    
  vars:
    wireguard_port: "{{ lookup('env', 'WG_PORT') | default(51820, true) }}"
    postgres_version: 13
    monitoring_enabled: true
    
  tasks:
    - name: Check WireGuard service status
      systemd:
        name: wg-quick@wg0
        state: started
      register: wg_status
      
    - name: Update port if current is blocked
      include_role:
        name: port_management
      when: wg_status.failed
EOF
    
    # Create inventory file
    cat > "$ANSIBLE_PLAYBOOK_DIR/inventory/hosts" <<EOF
[wireguard_servers]
localhost ansible_connection=local
EOF
}

# Function to setup PostgreSQL with replication
setup_postgresql_cluster() {
    log "INFO" "Setting up PostgreSQL cluster with replication"
    
    # Generate PostgreSQL configuration
    cat > "$CONFIG_DIR/postgresql/postgresql.conf" <<EOF
listen_addresses = '*'
max_connections = 1000
shared_buffers = 256MB
effective_cache_size = 768MB
work_mem = 16MB
maintenance_work_mem = 64MB
random_page_cost = 1.1
effective_io_concurrency = 200
wal_level = replica
max_wal_senders = 10
max_replication_slots = 10
hot_standby = on
synchronous_commit = on
archive_mode = on
archive_command = 'test ! -f /var/lib/postgresql/13/archive/%f && cp %p /var/lib/postgresql/13/archive/%f'
EOF
    
    # Generate Docker Compose configuration for PostgreSQL cluster
    cat > "$DOCKER_COMPOSE_FILE" <<EOF
version: '3.8'

services:
  postgres_master:
    image: postgres:13
    container_name: wg_postgres_master
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: wireguard_vpn
    volumes:
      - postgres_master_data:/var/lib/postgresql/data
      - ${CONFIG_DIR}/postgresql/postgresql.conf:/etc/postgresql/postgresql.conf
    command: postgres -c config_file=/etc/postgresql/postgresql.conf
    networks:
      - wg_network
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5

  postgres_slave:
    image: postgres:13
    container_name: wg_postgres_slave
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_slave_data:/var/lib/postgresql/data
    command: |
      bash -c "until pg_basebackup -h postgres_master -U replicator -D /var/lib/postgresql/data -P -v; do sleep 1; done; 
      echo 'primary_conninfo = host=postgres_master port=5432 user=replicator password=${POSTGRES_PASSWORD}' >> /var/lib/postgresql/data/postgresql.conf;
      echo 'hot_standby = on' >> /var/lib/postgresql/data/postgresql.conf;
      touch /var/lib/postgresql/data/standby.signal;
      postgres"
    depends_on:
      - postgres_master
    networks:
      - wg_network
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G

networks:
  wg_network:
    driver: bridge

volumes:
  postgres_master_data:
  postgres_slave_data:
EOF
}

# Function to setup monitoring with Prometheus and Grafana
setup_monitoring() {
    log "INFO" "Setting up monitoring infrastructure"
    
    # Create monitoring configuration directory
    mkdir -p "$CONFIG_DIR/monitoring"
    
    # Generate Prometheus configuration
    cat > "$PROMETHEUS_CONFIG" <<EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - localhost:9093

rule_files:
  - "/etc/prometheus/rules/*.yml"

scrape_configs:
  - job_name: 'wireguard'
    static_configs:
      - targets: ['localhost:9586']
    
  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']
    
  - job_name: 'postgres'
    static_configs:
      - targets: ['localhost:9187']
EOF
    
    # Setup Grafana dashboards
    mkdir -p "$GRAFANA_PROVISIONING/dashboards"
    
    # WireGuard dashboard configuration
    cat > "$GRAFANA_PROVISIONING/dashboards/wireguard.json" <<EOF
{
  "annotations": {
    "list": []
  },
  "editable": true,
  "fiscalYearStartMonth": 0,
  "graphTooltip": 0,
  "links": [],
  "liveNow": false,
  "panels": [
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "palette-classic"
          },
          "custom": {
            "axisCenteredZero": false,
            "axisColorMode": "text",
            "axisLabel": "",
            "axisPlacement": "auto",
            "barAlignment": 0,
            "drawStyle": "line",
            "fillOpacity": 10,
            "gradientMode": "none",
            "hideFrom": {
              "legend": false,
              "tooltip": false,
              "viz": false
            },
            "insertNulls": false,
            "lineInterpolation": "linear",
            "lineWidth": 1,
            "pointSize": 5,
            "scaleDistribution": {
              "type": "linear"
            },
            "showPoints": "never",
            "spanNulls": false,
            "stacking": {
              "group": "A",
              "mode": "none"
            },
            "thresholdsStyle": {
              "mode": "off"
            }
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              }
            ]
          },
          "unit": "bytes"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 0
      },
      "id": 1,
      "options": {
        "legend": {
          "calcs": [],
          "displayMode": "list",
          "placement": "bottom",
          "showLegend": true
        },
        "tooltip": {
          "mode": "multi",
          "sort": "none"
        }
      },
      "targets": [
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "expr": "rate(wireguard_received_bytes_total[5m])",
          "intervalFactor": 2,
          "legendFormat": "{{peer}} received",
          "refId": "A"
        },
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "expr": "rate(wireguard_sent_bytes_total[5m])",
          "intervalFactor": 2,
          "legendFormat": "{{peer}} sent",
          "refId": "B"
        }
      ],
      "title": "WireGuard Traffic",
      "type": "timeseries"
    }
  ],
  "refresh": "5s",
  "schemaVersion": 36,
  "style": "dark",
  "tags": [],
  "templating": {
    "list": []
  },
  "time": {
    "from": "now-1h",
    "to": "now"
  },
  "timepicker": {},
  "timezone": "",
  "title": "WireGuard Dashboard",
  "version": 0,
  "weekStart": ""
}
EOF
}

# Function to implement automatic port management
setup_port_management() {
    log "INFO" "Setting up automatic port management"
    
    # Create Python script for port scanning and management
    cat > "$CONFIG_DIR/port_management.py" <<'EOF'
#!/usr/bin/env python3
import socket
import psycopg2
import subprocess
import time
from typing import List, Tuple
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='/var/log/wireguard/port_management.log'
)

logger = logging.getLogger('port_management')

class PortManager:
    def __init__(self, db_params: dict):
        self.db_params = db_params
        self.current_port = None
        self.reserved_ports = set(range(51820, 51830))
        
    def check_port(self, port: int) -> bool:
        """Check if a port is open and usable"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.bind(('', port))
                return True
        except:
            return False
            
    def get_next_available_port(self) -> int:
        """Find the next available port from the reserved range"""
        for port in self.reserved_ports:
            if self.check_port(port):
                return port
        return None
        
    # Continuing from the previous code...

    def update_wireguard_config(self, port):
        """Update WireGuard configuration with new port"""
        try:
            config_path = "/etc/wireguard/wg0.conf"
            with open(config_path, 'r') as f:
                config = f.read()
            
            # Update ListenPort in the config
            new_config = re.sub(r'ListenPort = \d+', f'ListenPort = {port}', config)
            
            # Write updated config
            with open(config_path, 'w') as f:
                f.write(new_config)
            
            # Update PostgreSQL database with new port
            with psycopg2.connect(self.db_connection_string) as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        UPDATE server_config 
                        SET port = %s, 
                            updated_at = CURRENT_TIMESTAMP 
                        WHERE id = 1
                    """, (port,))
                conn.commit()

            # Restart WireGuard interface
            subprocess.run(['systemctl', 'restart', 'wg-quick@wg0'], check=True)
            
            # Log port change
            self.logger.info(f"Successfully updated WireGuard port to {port}")
            return True
        
        except Exception as e:
            self.logger.error(f"Failed to update WireGuard configuration: {e}")
            return False

    def setup_port_monitoring(self):
        """Set up port monitoring using Prometheus"""
        try:
            # Configure Prometheus port monitoring
            prometheus_config = {
                'global': {
                    'scrape_interval': '15s',
                    'evaluation_interval': '15s'
                },
                'scrape_configs': [{
                    'job_name': 'wireguard_ports',
                    'static_configs': [{
                        'targets': ['localhost:9586']
                    }]
                }]
            }
            
            with open('/etc/prometheus/wireguard_ports.yml', 'w') as f:
                yaml.dump(prometheus_config, f)

            # Set up custom port metrics
            self.register_port_metrics()
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to setup port monitoring: {e}")
            return False

    def register_port_metrics(self):
        """Register custom Prometheus metrics for port monitoring"""
        try:
            metrics = {
                'wireguard_port_status': GaugeMetricFamily(
                    'wireguard_port_status',
                    'Status of WireGuard ports (1=open, 0=closed)',
                    labels=['port']
                ),
                'wireguard_port_latency': GaugeMetricFamily(
                    'wireguard_port_latency',
                    'Latency of WireGuard ports in milliseconds',
                    labels=['port']
                )
            }
            
            # Register metrics with Prometheus
            for metric in metrics.values():
                REGISTRY.register(metric)
                
            return metrics
        except Exception as e:
            self.logger.error(f"Failed to register port metrics: {e}")
            return None

    def setup_ansible_automation(self):
        """Configure Ansible for automated port management"""
        try:
            ansible_playbook = {
                'name': 'WireGuard Port Management',
                'hosts': 'localhost',
                'tasks': [
                    {
                        'name': 'Check port status',
                        'script': '/usr/local/bin/check_wireguard_ports.py',
                        'register': 'port_status'
                    },
                    {
                        'name': 'Update port if needed',
                        'script': '/usr/local/bin/update_wireguard_port.py',
                        'when': 'port_status.changed'
                    }
                ]
            }
            
            # Write Ansible playbook
            with open('/etc/ansible/wireguard-ports.yml', 'w') as f:
                yaml.dump(ansible_playbook, f)

            # Set up cron job for regular execution
            cron_job = '*/5 * * * * root ansible-playbook /etc/ansible/wireguard-ports.yml'
            with open('/etc/cron.d/wireguard-port-check', 'w') as f:
                f.write(cron_job)

            return True
        except Exception as e:
            self.logger.error(f"Failed to setup Ansible automation: {e}")
            return False

    def setup_docker_environment(self):
        """Set up Docker environment for WireGuard"""
        try:
            docker_compose = {
                'version': '3.8',
                'services': {
                    'wireguard': {
                        'image': 'wireguard',
                        'build': '.',
                        'container_name': 'wireguard',
                        'cap_add': ['NET_ADMIN', 'SYS_MODULE'],
                        'environment': [
                            'PUID=1000',
                            'PGID=1000',
                            'TZ=UTC'
                        ],
                        'volumes': [
                            '/etc/wireguard:/etc/wireguard',
                            '/lib/modules:/lib/modules'
                        ],
                        'ports': [
                            '51820:51820/udp'
                        ],
                        'sysctls': [
                            'net.ipv4.conf.all.src_valid_mark=1',
                            'net.ipv4.ip_forward=1'
                        ],
                        'restart': 'unless-stopped'
                    },
                    'prometheus': {
                        'image': 'prom/prometheus',
                        'container_name': 'prometheus',
                        'volumes': [
                            '/etc/prometheus:/etc/prometheus'
                        ],
                        'command': [
                            '--config.file=/etc/prometheus/prometheus.yml'
                        ],
                        'ports': [
                            '9090:9090'
                        ],
                        'restart': 'unless-stopped'
                    }
                }
            }
            
            # Write Docker Compose file
            with open('/etc/wireguard/docker-compose.yml', 'w') as f:
                yaml.dump(docker_compose, f)

            # Build and start containers
            subprocess.run(['docker-compose', '-f', '/etc/wireguard/docker-compose.yml', 'up', '-d'], check=True)
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to setup Docker environment: {e}")
            return False

    def setup_logging(self):
        """Configure comprehensive logging system"""
        try:
            logging_config = {
                'version': 1,
                'formatters': {
                    'detailed': {
                        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                    }
                },
                'handlers': {
                    'file': {
                        'class': 'logging.handlers.RotatingFileHandler',
                        'filename': '/var/log/wireguard/port_manager.log',
                        'maxBytes': 10485760,  # 10MB
                        'backupCount': 5,
                        'formatter': 'detailed'
                    },
                    'syslog': {
                        'class': 'logging.handlers.SysLogHandler',
                        'address': '/dev/log',
                        'facility': 'local0',
                        'formatter': 'detailed'
                    }
                },
                'root': {
                    'level': 'INFO',
                    'handlers': ['file', 'syslog']
                }
            }
            
            # Create log directory
            os.makedirs('/var/log/wireguard', exist_ok=True)
            
            # Apply logging configuration
            logging.config.dictConfig(logging_config)
            
            return True
        except Exception as e:
            print(f"Failed to setup logging: {e}")
            return False

    def initialize(self):
        """Initialize the WireGuard port manager"""
        try:
            # Setup required components
            self.setup_logging()
            self.setup_port_monitoring()
            self.setup_ansible_automation()
            self.setup_docker_environment()
            
            # Initial port check
            current_port = self.get_current_port()
            if not self.check_port(current_port):
                new_port = self.find_available_port()
                if new_port:
                    self.update_wireguard_config(new_port)
                else:
                    self.logger.error("No available ports found")
                    
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize port manager: {e}")
            return False

def main():
    """Main execution function"""
    try:
        # Initialize port manager
        manager = WireGuardPortManager(
            db_host='localhost',
            db_name='wireguard_vpn',
            db_user='wireguard_admin',
            db_password='your_password'
        )
        
        # Start port management system
        if manager.initialize():
            print("WireGuard port management system initialized successfully")
        else:
            print("Failed to initialize WireGuard port management system")
            
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
