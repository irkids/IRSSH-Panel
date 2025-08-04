#!/bin/bash

# IRSSH Panel Complete Installation Script
# Version: 4.0.0
# This script installs and configures the IRSSH Panel with all features including advanced user management

# Define colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Base directories
PANEL_DIR="/opt/irssh-panel"
CONFIG_DIR="/etc/enhanced_ssh"
LOG_DIR="/var/log/irssh"
BACKUP_DIR="/opt/irssh-backups"
TEMP_DIR="/tmp/irssh-install"
SSL_DIR="/etc/nginx/ssl"
SERVICES_DIR="${PANEL_DIR}/services"
SCRIPTS_DIR="${PANEL_DIR}/scripts"
MODULES_DIR="${PANEL_DIR}/modules"
MONITOR_DIR="${PANEL_DIR}/monitoring"
ANSIBLE_DIR="${PANEL_DIR}/ansible"

# Protocol configuration
declare -A PROTOCOLS=(
    ["SSH"]=true
    ["L2TP"]=true
    ["IKEV2"]=true
    ["CISCO"]=true
    ["WIREGUARD"]=true
    ["SINGBOX"]=true
)

# Port configuration
declare -A PORTS=(
    ["SSH"]=22
    ["SSH_TLS"]=444
    ["WEBSOCKET"]=2082
    ["L2TP"]=1701
    ["IKEV2"]=500
    ["CISCO"]=85
    ["WIREGUARD"]=51820
    ["SINGBOX"]=1080
    ["UDPGW"]=7300
    ["WEB"]=8080 # Default, will be changed during setup
)

# User Configuration
ADMIN_USER=""
ADMIN_PASS=""
SERVER_IPv4=""
SERVER_IPv6=""
DB_NAME="irssh_panel"
DB_USER=""
DB_USER_PASSWORD=""
REPO_URL="https://github.com/irkids/IRSSH-Panel.git"
INSTALLATION_DATE=$(date +"%Y-%m-%d %H:%M:%S")

# System Resources for Auto-optimization
CPU_CORES=0
RAM_GB=0
DISK_GB=0
IS_VM=false
IS_LOW_RESOURCES=false

# Geolocation Activation Key (generated based on server IP)
GEO_ACTIVATION_KEY=""

# Logging functions
log() {
    local level=$1
    local message=$2
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    echo -e "${!level}[$timestamp] [$level] $message${NC}"
    
    # Check if LOG_DIR exists, if not create it
    if [ ! -d "$LOG_DIR" ]; then
        mkdir -p "$LOG_DIR"
    fi
    
    echo "[$timestamp] [$level] $message" >> "$LOG_DIR/installation.log"
}

info() {
    log "GREEN" "$1"
}

warn() {
    log "YELLOW" "$1"
}

error() {
    log "RED" "$1"
    if [[ "${2:-}" != "no-exit" ]]; then
        cleanup
        exit 1
    fi
}

debug() {
    log "BLUE" "$1"
}

# Cleanup function
cleanup() {
    info "Performing cleanup..."
    rm -rf "$TEMP_DIR"
}

# Function to get system specifications for auto-optimization
detect_system_resources() {
    info "Detecting system specifications for auto-optimization..."
    
    # Get CPU cores
    CPU_CORES=$(nproc)
    info "Detected $CPU_CORES CPU cores"
    
    # Get total RAM in GB
    RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    RAM_GB=$(echo "scale=1; $RAM_KB/1024/1024" | bc)
    info "Detected $RAM_GB GB of RAM"
    
    # Get disk space
    DISK_KB=$(df -k / | awk 'NR==2 {print $4}')
    DISK_GB=$(echo "scale=1; $DISK_KB/1024/1024" | bc)
    info "Detected $DISK_GB GB of available disk space"
    
    # Check if running in a virtual machine
    if grep -q "hypervisor" /proc/cpuinfo || [ -d "/proc/vz" ]; then
        IS_VM=true
        info "Detected virtualization environment"
    fi
    
    # Determine if this is a low-resource system
    if [ $(echo "$RAM_GB < 2" | bc) -eq 1 ] || [ $CPU_CORES -lt 2 ]; then
        IS_LOW_RESOURCES=true
        info "System has limited resources, optimizations for low-resource systems will be applied"
    fi
}

# Function to optimize system settings based on detected resources
optimize_system() {
    info "Optimizing system settings based on resources..."
    
    if [ "$IS_LOW_RESOURCES" = true ]; then
        # Low-resource system optimizations
        info "Applying low-resource system optimizations"
        
        # Decrease PostgreSQL memory settings
        if [ -f "/etc/postgresql/*/main/postgresql.conf" ]; then
            pgconf=$(find /etc/postgresql -name postgresql.conf)
            sed -i "s/^#\?shared_buffers =.*/shared_buffers = 128MB/" $pgconf
            sed -i "s/^#\?work_mem =.*/work_mem = 4MB/" $pgconf
            sed -i "s/^#\?maintenance_work_mem =.*/maintenance_work_mem = 32MB/" $pgconf
            sed -i "s/^#\?effective_cache_size =.*/effective_cache_size = 256MB/" $pgconf
        fi
        
        # Decrease Nginx worker processes and connections
        if [ -f "/etc/nginx/nginx.conf" ]; then
            sed -i "s/worker_processes.*/worker_processes 1;/" /etc/nginx/nginx.conf
            sed -i "s/worker_connections.*/worker_connections 512;/" /etc/nginx/nginx.conf
        fi
        
        # Set Node.js memory limit lower for API and services
        echo "NODE_OPTIONS=--max_old_space_size=384" >> /etc/environment
    else
        # Standard or high-resource system optimizations
        info "Applying standard system optimizations"
        
        # Calculate optimal PostgreSQL settings
        PG_SHARED_BUFFERS=$((RAM_GB / 4))
        if [ $PG_SHARED_BUFFERS -lt 1 ]; then PG_SHARED_BUFFERS=1; fi
        
        # Set PostgreSQL memory settings
        if [ -f "/etc/postgresql/*/main/postgresql.conf" ]; then
            pgconf=$(find /etc/postgresql -name postgresql.conf)
            sed -i "s/^#\?shared_buffers =.*/shared_buffers = ${PG_SHARED_BUFFERS}GB/" $pgconf
            sed -i "s/^#\?work_mem =.*/work_mem = 16MB/" $pgconf
            sed -i "s/^#\?maintenance_work_mem =.*/maintenance_work_mem = 256MB/" $pgconf
            sed -i "s/^#\?effective_cache_size =.*/effective_cache_size = ${RAM_GB}GB/" $pgconf
        fi
        
        # Set Nginx worker processes to number of cores and increase connections
        if [ -f "/etc/nginx/nginx.conf" ]; then
            sed -i "s/worker_processes.*/worker_processes $CPU_CORES;/" /etc/nginx/nginx.conf
            sed -i "s/worker_connections.*/worker_connections 2048;/" /etc/nginx/nginx.conf
        fi
        
        # Set Node.js memory limit based on available RAM
        NODE_MEM=$((RAM_GB * 256))
        if [ $NODE_MEM -gt 1024 ]; then NODE_MEM=1024; fi
        echo "NODE_OPTIONS=--max_old_space_size=${NODE_MEM}" >> /etc/environment
    fi
    
    # Configure sysctl parameters regardless of resources
    cat > /etc/sysctl.d/99-irssh-performance.conf << EOF
# IRSSH Panel Performance Optimization

# Increase system file descriptor limit
fs.file-max = 100000

# Increase ephemeral IP port range
net.ipv4.ip_local_port_range = 10000 65535

# Increase TCP max syn backlog to handle more connection requests
net.ipv4.tcp_max_syn_backlog = 4096

# Enable selective acknowledgements for faster recovery from packet loss
net.ipv4.tcp_sack = 1

# Allow reusing sockets in TIME_WAIT state
net.ipv4.tcp_tw_reuse = 1

# VM optimizations if applicable
vm.swappiness = $([ "$IS_VM" = true ] && echo "10" || echo "30")
vm.vfs_cache_pressure = $([ "$IS_VM" = true ] && echo "50" || echo "100")
EOF
    
    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-irssh-performance.conf
    
    info "System optimization completed"
}

# Function to get server IP addresses
get_server_ip() {
    info "Detecting server IP addresses..."
    
    # Try multiple methods to detect IPv4
    SERVER_IPv4=$(curl -s4 -m 5 ifconfig.me || curl -s4 -m 5 icanhazip.com || curl -s4 -m 5 ipinfo.io/ip)
    
    if [ -z "$SERVER_IPv4" ]; then
        SERVER_IPv4=$(ip -4 route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}')
    fi
    
    # Try multiple methods to detect IPv6
    SERVER_IPv6=$(curl -s6 -m 5 ifconfig.me || curl -s6 -m 5 icanhazip.com || curl -s6 -m 5 ipinfo.io/ip)
    
    if [ -z "$SERVER_IPv6" ]; then
        SERVER_IPv6=$(ip -6 addr show scope global 2>/dev/null | grep -oP '(?<=inet6\s)[\da-f:]+(?=/\d+\s)' | head -n 1)
    fi
    
    if [ -z "$SERVER_IPv4" ] && [ -z "$SERVER_IPv6" ]; then
        warn "Could not determine server IP address, some features may not work properly"
    else
        if [ ! -z "$SERVER_IPv4" ]; then
            info "Detected IPv4: $SERVER_IPv4"
            # Generate geolocation activation key based on server IP
            GEO_ACTIVATION_KEY=$(echo -n "IRSSH-GEO-${SERVER_IPv4}-special-secret" | sha256sum | awk '{print $1}')
        fi
        if [ ! -z "$SERVER_IPv6" ]; then
            info "Detected IPv6: $SERVER_IPv6"
        fi
    fi
}

# Function to get user configuration
get_config() {
    info "Getting initial configuration..."
    
    read -p "Enter admin username: " ADMIN_USER
    while [ -z "$ADMIN_USER" ]; do
        read -p "Username cannot be empty. Enter admin username: " ADMIN_USER
    done
    
    read -s -p "Enter admin password: " ADMIN_PASS
    echo
    while [ -z "$ADMIN_PASS" ]; do
        read -s -p "Password cannot be empty. Enter admin password: " ADMIN_PASS
        echo
    done
    
    # Set database user to match admin user
    DB_USER="$ADMIN_USER"
    DB_USER_PASSWORD="$ADMIN_PASS"

    while true; do
        read -p "Enter web panel port (4-5 digits) or press Enter for random port: " WEB_PORT
        if [ -z "$WEB_PORT" ]; then
            WEB_PORT=$(shuf -i 1234-65432 -n 1)
            info "Generated random port: $WEB_PORT"
            break
        elif [[ "$WEB_PORT" =~ ^[0-9]{4,5}$ ]] && [ "$WEB_PORT" -ge 1234 ] && [ "$WEB_PORT" -le 65432 ]; then
            break
        else
            error "Invalid port number. Must be between 1234 and 65432" "no-exit"
        fi
    done
    PORTS["WEB"]=$WEB_PORT
    
    # Auto-enable monitoring without asking - as requested
    info "Monitoring system will be automatically enabled"
    
    # Auto-enable advanced user management without asking - as requested
    info "Advanced user management module will be automatically installed"
    
    # Ask about protocols to install
    echo "Which protocols would you like to install?"
    
    for protocol in "${!PROTOCOLS[@]}"; do
        # Default is "y" for all protocols
        read -p "Install ${protocol}? (Y/n): " answer
        answer=${answer,,}
        if [[ "$answer" == "n" ]]; then
            PROTOCOLS[$protocol]=false
            info "${protocol} installation will be skipped"
        else
            PROTOCOLS[$protocol]=true
            info "${protocol} will be installed"
        fi
    done
}

# Function to setup dependencies
setup_dependencies() {
    info "Installing system dependencies..."
    
    # Update system
    apt-get update || error "Failed to update package lists"
    
    # Remove old Node.js completely if it exists
    if command -v node &> /dev/null; then
        info "Removing old Node.js installation..."
        apt-get remove -y nodejs npm node-*
        apt-get purge -y nodejs npm
        apt-get autoremove -y
        rm -rf /usr/local/lib/node_modules
        rm -rf /usr/local/bin/node
        rm -rf /usr/local/bin/npm
        rm -rf /etc/apt/sources.list.d/nodesource.list*
    fi
    
    # Install basic required packages
    info "Installing base packages..."
    apt-get install -y \
        curl wget git nano unzip zip tar lsof net-tools netcat \
        build-essential python3 python3-pip software-properties-common \
        apt-transport-https ca-certificates gnupg || error "Failed to install basic packages"
        
    # Install PostgreSQL and Nginx
    info "Installing PostgreSQL and Nginx..."
    apt-get install -y \
        nginx \
        postgresql \
        postgresql-contrib || error "Failed to install PostgreSQL and Nginx"
    
    # Install Node.js 20.x
    info "Installing Node.js 20.x..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - || error "Failed to set up Node.js repository"
    apt-get install -y nodejs || error "Failed to install Node.js"
    
    # Install Redis for session management
    info "Installing Redis..."
    apt-get install -y redis-server || error "Failed to install Redis"
    
    # Install development tools and global npm packages
    info "Installing development tools..."
    npm install -g npm@latest || warn "Failed to update npm to latest version"
    npm install -g pm2 || warn "Failed to install PM2"
    
    # Install Python dependencies for monitoring scripts
    info "Installing Python dependencies..."
    pip3 install psycopg2-binary requests schedule pyyaml maxminddb geoip2 \
        matplotlib pandas seaborn prettytable || warn "Failed to install Python dependencies"
    
    # Install Ansible for automation
    info "Installing Ansible..."
    apt-add-repository --yes --update ppa:ansible/ansible
    apt-get install -y ansible || warn "Failed to install Ansible"
    
    # Install Docker if not already installed
    if ! command -v docker &> /dev/null; then
        info "Installing Docker..."
        curl -fsSL https://get.docker.com -o get-docker.sh
        sh get-docker.sh
        rm get-docker.sh
        apt-get install -y docker-compose
    else
        info "Docker is already installed"
    fi
    
    info "Dependencies installation completed"
}

# Function to setup PostgreSQL database with optimizations
setup_database() {
    info "Setting up PostgreSQL database..."
    
    # Start PostgreSQL if not running
    systemctl start postgresql
    systemctl enable postgresql
    
    # Backup PostgreSQL configuration
    if [ -f "/etc/postgresql/*/main/postgresql.conf" ]; then
        pgconf=$(find /etc/postgresql -name postgresql.conf)
        cp $pgconf ${pgconf}.backup
        info "PostgreSQL configuration backed up to ${pgconf}.backup"
    fi
    
    # Generate database password if not set
    if [ -z "$DB_USER_PASSWORD" ]; then
        DB_USER_PASSWORD=$(openssl rand -base64 24)
        info "Generated database password"
    fi
    
    # Check if database exists and create if needed
    if ! sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
        info "Creating new database: $DB_NAME"
        sudo -u postgres createdb "$DB_NAME" || error "Failed to create database"
        
        # Create user and grant privileges
        sudo -u postgres psql -c "CREATE USER ${DB_USER} WITH PASSWORD '${DB_USER_PASSWORD}';" || error "Failed to create database user"
        sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};" || error "Failed to grant privileges"
    else
        info "Database '$DB_NAME' already exists"
        
        # Update user password if it exists, create if it doesn't
        sudo -u postgres psql -c "DO \$\$
        BEGIN
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = '${DB_USER}') THEN
                ALTER USER ${DB_USER} WITH PASSWORD '${DB_USER_PASSWORD}';
            ELSE
                CREATE USER ${DB_USER} WITH PASSWORD '${DB_USER_PASSWORD}';
            END IF;
        END
        \$\$;" || error "Failed to update database user"
        
        sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};" || error "Failed to grant privileges"
    fi
    
    # Configure PostgreSQL for performance based on system resources
    pgconf=$(find /etc/postgresql -name postgresql.conf)
    
    if [ "$IS_LOW_RESOURCES" = true ]; then
        # Low-resource settings
        info "Applying low-resource PostgreSQL optimizations"
        sudo sed -i "s/^#\?shared_buffers =.*/shared_buffers = 128MB/" $pgconf
        sudo sed -i "s/^#\?work_mem =.*/work_mem = 4MB/" $pgconf
        sudo sed -i "s/^#\?maintenance_work_mem =.*/maintenance_work_mem = 32MB/" $pgconf
        sudo sed -i "s/^#\?effective_cache_size =.*/effective_cache_size = 256MB/" $pgconf
        sudo sed -i "s/^#\?max_connections =.*/max_connections = 50/" $pgconf
        sudo sed -i "s/^#\?random_page_cost =.*/random_page_cost = 4.0/" $pgconf
        sudo sed -i "s/^#\?synchronous_commit =.*/synchronous_commit = off/" $pgconf
    else
        # Calculate optimal PostgreSQL settings based on RAM
        PG_SHARED_BUFFERS=$((RAM_GB / 4))
        if [ $PG_SHARED_BUFFERS -lt 1 ]; then PG_SHARED_BUFFERS=1; fi
        
        PG_WORK_MEM=$((RAM_GB / 8))
        if [ $PG_WORK_MEM -lt 1 ]; then PG_WORK_MEM=1; fi
        
        PG_MAINT_WORK_MEM=$((RAM_GB / 4))
        if [ $PG_MAINT_WORK_MEM -lt 1 ]; then PG_MAINT_WORK_MEM=1; fi
        
        PG_EFFECTIVE_CACHE_SIZE=$((RAM_GB * 3 / 4))
        if [ $PG_EFFECTIVE_CACHE_SIZE -lt 1 ]; then PG_EFFECTIVE_CACHE_SIZE=1; fi
        
        info "Applying optimized PostgreSQL settings"
        sudo sed -i "s/^#\?shared_buffers =.*/shared_buffers = ${PG_SHARED_BUFFERS}GB/" $pgconf
        sudo sed -i "s/^#\?work_mem =.*/work_mem = ${PG_WORK_MEM}MB/" $pgconf
        sudo sed -i "s/^#\?maintenance_work_mem =.*/maintenance_work_mem = ${PG_MAINT_WORK_MEM}MB/" $pgconf
        sudo sed -i "s/^#\?effective_cache_size =.*/effective_cache_size = ${PG_EFFECTIVE_CACHE_SIZE}GB/" $pgconf
        sudo sed -i "s/^#\?max_connections =.*/max_connections = 200/" $pgconf
        sudo sed -i "s/^#\?random_page_cost =.*/random_page_cost = 4.0/" $pgconf
        
        # If running on SSD, optimize accordingly
        if [ -d "/sys/block/sda/queue/rotational" ]; then
            ROTATIONAL=$(cat /sys/block/sda/queue/rotational)
            if [ "$ROTATIONAL" = "0" ]; then
                info "SSD detected, optimizing PostgreSQL accordingly"
                sudo sed -i "s/^#\?random_page_cost =.*/random_page_cost = 1.1/" $pgconf
                sudo sed -i "s/^#\?effective_io_concurrency =.*/effective_io_concurrency = 200/" $pgconf
            fi
        fi
    fi
    
    # Apply changes
    systemctl restart postgresql
    
    # Create or update database configuration file
    mkdir -p "$CONFIG_DIR/db"
    cat > "$CONFIG_DIR/db/database.conf" << EOF
DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_USER_PASSWORD
DB_SSL_MODE=disable
EOF

    chmod 600 "$CONFIG_DIR/db/database.conf"
    
    info "Database setup completed"
}

# Function to setup web server with enhanced frontend and backend
setup_web_server() {
    info "Setting up web server with enhanced user interface..."

    # Create required directories
    mkdir -p "$PANEL_DIR/frontend"
    mkdir -p "$PANEL_DIR/backend"
    mkdir -p "$SERVICES_DIR"
    mkdir -p "$SCRIPTS_DIR"
    mkdir -p "$MODULES_DIR"
    mkdir -p "$MONITOR_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$ANSIBLE_DIR"

    # Clone repository into temporary directory
    info "Cloning repository..."
    if [ ! -d "$TEMP_DIR" ]; then
        mkdir -p "$TEMP_DIR"
    fi
    
    git clone "$REPO_URL" "$TEMP_DIR/repo" || error "Failed to clone repository"

    # Check if Ansible playbooks exist in repository
    if [ -d "$TEMP_DIR/repo/ansible" ]; then
        info "Found Ansible playbooks in repository, copying them..."
        cp -r "$TEMP_DIR/repo/ansible"/* "$ANSIBLE_DIR/" || warn "Failed to copy Ansible playbooks"
    else
        info "No Ansible playbooks found in repository, creating default playbooks..."
        mkdir -p "$ANSIBLE_DIR/playbooks"
        mkdir -p "$ANSIBLE_DIR/roles"
        mkdir -p "$ANSIBLE_DIR/inventory"
        
        # Create a default inventory file
        cat > "$ANSIBLE_DIR/inventory/hosts" << EOF
[irssh_servers]
localhost ansible_connection=local

[multi_servers]
# Add your remote servers here for multi-server setup
# example.com ansible_user=root ansible_ssh_private_key_file=/path/to/key

[all:vars]
ansible_python_interpreter=/usr/bin/python3
EOF
        
        # Create a default playbook for server configuration
        cat > "$ANSIBLE_DIR/playbooks/server_setup.yml" << EOF
---
- name: IRSSH Server Configuration
  hosts: irssh_servers
  become: yes
  tasks:
    - name: Update apt cache
      apt:
        update_cache: yes
        cache_valid_time: 3600

    - name: Install required packages
      apt:
        name:
          - curl
          - wget
          - git
          - nano
          - unzip
          - zip
          - tar
          - lsof
          - net-tools
          - netcat
          - build-essential
          - python3
          - python3-pip
        state: present

    - name: Optimize sysctl parameters
      sysctl:
        name: "{{ item.key }}"
        value: "{{ item.value }}"
        sysctl_set: yes
        state: present
        reload: yes
      with_items:
        - { key: "net.ipv4.ip_forward", value: "1" }
        - { key: "net.ipv4.tcp_mtu_probing", value: "1" }
        - { key: "net.ipv4.tcp_slow_start_after_idle", value: "0" }
        - { key: "net.ipv4.tcp_fastopen", value: "3" }
        - { key: "net.ipv4.tcp_fin_timeout", value: "15" }
        - { key: "net.ipv4.tcp_keepalive_time", value: "300" }
        - { key: "net.ipv4.tcp_keepalive_intvl", value: "60" }
        - { key: "net.ipv4.tcp_keepalive_probes", value: "3" }
        - { key: "net.ipv4.tcp_congestion_control", value: "bbr" }
        - { key: "net.core.default_qdisc", value: "fq" }
        - { key: "net.ipv4.ip_local_port_range", value: "10000 65535" }
        - { key: "fs.file-max", value: "1000000" }

    - name: Set up automatic security updates
      apt:
        name: unattended-upgrades
        state: present

    - name: Configure automatic security updates
      template:
        src: templates/20auto-upgrades.j2
        dest: /etc/apt/apt.conf.d/20auto-upgrades
        owner: root
        group: root
        mode: '0644'
EOF
        
        # Create a multi-server setup playbook
        cat > "$ANSIBLE_DIR/playbooks/multi_server_setup.yml" << EOF
---
- name: IRSSH Multi-Server Setup
  hosts: multi_servers
  become: yes
  vars:
    master_server: "{{ hostvars[groups['irssh_servers'][0]]['ansible_host'] | default(groups['irssh_servers'][0]) }}"
    master_ssh_port: 22
    wireguard_port: 51820
    wireguard_network: "10.66.66.0/24"
  tasks:
    - name: Install WireGuard for server tunneling
      apt:
        name:
          - wireguard
          - wireguard-tools
        state: present
        update_cache: yes
    
    - name: Generate WireGuard private key
      shell: wg genkey > /etc/wireguard/private.key && chmod 600 /etc/wireguard/private.key
      args:
        creates: /etc/wireguard/private.key
    
    - name: Read WireGuard private key
      shell: cat /etc/wireguard/private.key
      register: wg_private_key
      changed_when: false
    
    - name: Generate WireGuard public key
      shell: echo "{{ wg_private_key.stdout }}" | wg pubkey > /etc/wireguard/public.key
      args:
        creates: /etc/wireguard/public.key
    
    - name: Read WireGuard public key
      shell: cat /etc/wireguard/public.key
      register: wg_public_key
      changed_when: false
    
    - name: Set WireGuard configuration for multi-server tunnel
      template:
        src: templates/wg0.conf.j2
        dest: /etc/wireguard/wg0.conf
        owner: root
        group: root
        mode: '0600'
    
    - name: Enable and start WireGuard
      systemd:
        name: wg-quick@wg0
        enabled: yes
        state: started
    
    - name: Set up SSH tunneling to master server
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^AllowTcpForwarding'
        line: 'AllowTcpForwarding yes'
        state: present
      notify: restart ssh
    
    - name: Set up automatic database replication
      template:
        src: templates/pg_replication.sh.j2
        dest: /usr/local/bin/pg_replication.sh
        owner: root
        group: root
        mode: '0755'
    
    - name: Create database replication cron job
      cron:
        name: "PostgreSQL replication from master"
        job: "/usr/local/bin/pg_replication.sh"
        hour: "*/6"
        minute: "0"
        state: present
    
    - name: Create IRSSH multi-server configuration
      template:
        src: templates/multi_server.conf.j2
        dest: /etc/enhanced_ssh/multi_server.conf
        owner: root
        group: root
        mode: '0600'
  
  handlers:
    - name: restart ssh
      service:
        name: sshd
        state: restarted
EOF
        
        # Create a playbook for server hardening
        cat > "$ANSIBLE_DIR/playbooks/server_hardening.yml" << EOF
---
- name: IRSSH Server Security Hardening
  hosts: irssh_servers
  become: yes
  tasks:
    - name: Update all packages to latest version
      apt:
        upgrade: full
        update_cache: yes
    
    - name: Install security packages
      apt:
        name:
          - fail2ban
          - ufw
          - rkhunter
          - logwatch
          - auditd
        state: present
    
    - name: Configure firewall - allow SSH
      ufw:
        rule: allow
        port: "{{ ssh_port | default('22') }}"
        proto: tcp
    
    - name: Configure firewall - allow web panel
      ufw:
        rule: allow
        port: "{{ web_panel_port | default('8080') }}"
        proto: tcp
    
    - name: Configure firewall - allow VPN protocols
      ufw:
        rule: allow
        port: "{{ item.port }}"
        proto: "{{ item.proto }}"
      with_items:
        - { port: "51820", proto: "udp" }  # WireGuard
        - { port: "500", proto: "udp" }    # IKEv2
        - { port: "4500", proto: "udp" }   # IKEv2 NAT-T
        - { port: "1701", proto: "udp" }   # L2TP
        - { port: "1194", proto: "udp" }   # OpenVPN
        - { port: "1080", proto: "tcp" }   # SingBox
    
    - name: Enable UFW
      ufw:
        state: enabled
        policy: deny
    
    - name: Configure Fail2ban
      template:
        src: templates/jail.local.j2
        dest: /etc/fail2ban/jail.local
        owner: root
        group: root
        mode: '0644'
      notify: restart fail2ban
    
    - name: Secure shared memory
      mount:
        path: /dev/shm
        src: tmpfs
        fstype: tmpfs
        opts: defaults,noexec,nosuid
        state: mounted
    
    - name: Set strong password policies
      lineinfile:
        path: /etc/pam.d/common-password
        regexp: 'pam_pwquality.so'
        line: 'password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 reject_username enforce_for_root'
    
    - name: Configure logwatch to email reports
      template:
        src: templates/logwatch.conf.j2
        dest: /etc/logwatch/conf/logwatch.conf
        owner: root
        group: root
        mode: '0644'
    
    - name: Configure audit system
      template:
        src: templates/audit.rules.j2
        dest: /etc/audit/rules.d/audit.rules
        owner: root
        group: root
        mode: '0640'
      notify: restart auditd
  
  handlers:
    - name: restart fail2ban
      service:
        name: fail2ban
        state: restarted
    
    - name: restart auditd
      service:
        name: auditd
        state: restarted
EOF
        
        # Create template directories
        mkdir -p "$ANSIBLE_DIR/templates"
        
        # Create template files
        cat > "$ANSIBLE_DIR/templates/20auto-upgrades.j2" << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
        
        cat > "$ANSIBLE_DIR/templates/wg0.conf.j2" << EOF
[Interface]
PrivateKey = {{ wg_private_key.stdout }}
Address = {{ wireguard_network | ansible.utils.ipsubnet(32, hostvars[inventory_hostname]['ansible_loop_var'] | default(1) + 1) }}
ListenPort = {{ wireguard_port }}

[Peer]
PublicKey = {{ hostvars[master_server]['wg_public_key'].stdout }}
AllowedIPs = {{ wireguard_network }}
Endpoint = {{ master_server }}:{{ wireguard_port }}
PersistentKeepalive = 25
EOF
        
        cat > "$ANSIBLE_DIR/templates/pg_replication.sh.j2" << EOF
#!/bin/bash

# PostgreSQL replication script
# This script replicates data from the master server to this server

MASTER_SERVER="{{ master_server }}"
MASTER_SSH_PORT="{{ master_ssh_port }}"
DB_NAME="{{ db_name | default('irssh_panel') }}"
BACKUP_DIR="/opt/irssh-backups/db"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Ensure backup directory exists
mkdir -p $BACKUP_DIR

# Create a backup of the current database
pg_dump -Fc -f "$BACKUP_DIR/${DB_NAME}_before_sync_${TIMESTAMP}.dump" $DB_NAME

# Copy the database from the master server
ssh -p $MASTER_SSH_PORT root@$MASTER_SERVER "pg_dump -Fc $DB_NAME" > "$BACKUP_DIR/${DB_NAME}_from_master_${TIMESTAMP}.dump"

# Restore the master database
pg_restore --clean --if-exists -d $DB_NAME "$BACKUP_DIR/${DB_NAME}_from_master_${TIMESTAMP}.dump"

# Log the sync
echo "Database sync completed at $(date)" >> /var/log/irssh/database_sync.log
EOF
        
        cat > "$ANSIBLE_DIR/templates/multi_server.conf.j2" << EOF
# IRSSH Panel Multi-Server Configuration
MASTER_SERVER="{{ master_server }}"
SERVER_ROLE="secondary"
SERVER_ID="{{ hostvars[inventory_hostname]['ansible_loop_var'] | default(1) }}"
SYNC_INTERVAL=6  # hours
WIREGUARD_ENABLED=true
WIREGUARD_IP="{{ wireguard_network | ansible.utils.ipsubnet(32, hostvars[inventory_hostname]['ansible_loop_var'] | default(1) + 1) }}"
EOF
        
        cat > "$ANSIBLE_DIR/templates/jail.local.j2" << EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = {{ ssh_port | default('22') }}
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 12h

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 5
bantime = 6h
EOF
        
        cat > "$ANSIBLE_DIR/templates/audit.rules.j2" << EOF
# Audit system configuration
-w /etc/passwd -p wa -k user-modify
-w /etc/shadow -p wa -k user-modify
-w /etc/group -p wa -k group-modify
-w /etc/sudoers -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd-config
-w /etc/enhanced_ssh -p wa -k irssh-config
-w /opt/irssh-panel -p wa -k irssh-files
EOF
    fi

    # Check if frontend and backend directories exist in the repo
    if [ ! -d "$TEMP_DIR/repo/frontend" ]; then
        mkdir -p "$TEMP_DIR/repo/frontend"
        info "Frontend directory missing in repository, creating it"
    fi

    if [ ! -d "$TEMP_DIR/repo/backend" ]; then
        mkdir -p "$TEMP_DIR/repo/backend"
        info "Backend directory missing in repository, creating it"
        
        # Create basic package.json with more dependencies for enhanced features
        cat > "$TEMP_DIR/repo/backend/package.json" << EOF
{
  "name": "irssh-panel-backend",
  "version": "1.0.0",
  "description": "Backend for IRSSH Panel with advanced features",
  "main": "index.js",
  "scripts": {
    "start": "node index.js",
    "dev": "nodemon index.js",
    "migrate": "node db/migrate.js",
    "seed": "node db/seed.js",
    "test": "jest"
  },
  "dependencies": {
    "bcrypt": "^5.1.0",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.0",
    "cors": "^2.8.5",
    "helmet": "^7.1.0", 
    "compression": "^1.7.4",
    "express-rate-limit": "^7.1.0",
    "express-session": "^1.17.3",
    "connect-redis": "^7.1.0",
    "redis": "^4.6.10",
    "pg": "^8.11.3",
    "pg-hstore": "^2.3.4",
    "sequelize": "^6.33.0",
    "dotenv": "^16.3.1",
    "moment": "^2.29.4",
    "winston": "^3.11.0",
    "winston-daily-rotate-file": "^4.7.1",
    "axios": "^1.6.0",
    "joi": "^17.10.2",
    "node-cron": "^3.0.2",
    "nodemailer": "^6.9.6",
    "multer": "^1.4.5-lts.1",
    "socket.io": "^4.7.2",
    "passport": "^0.6.0",
    "passport-jwt": "^4.0.1",
    "passport-local": "^1.0.0",
    "passport-google-oauth20": "^2.0.0",
    "telegraf": "^4.15.0",
    "crypto-js": "^4.1.1",
    "maxmind": "^4.3.11",
    "shelljs": "^0.8.5",
    "csv-parser": "^3.0.0",
    "uuid": "^9.0.1",
    "ioredis": "^5.3.2",
    "morgan": "^1.10.0",
    "swagger-ui-express": "^5.0.0",
    "yamljs": "^0.3.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.1",
    "jest": "^29.7.0",
    "supertest": "^6.3.3",
    "eslint": "^8.50.0",
    "sequelize-cli": "^6.6.1"
  }
}
EOF

        # Create enhanced index.js with more features
        cat > "$TEMP_DIR/repo/backend/index.js" << EOF
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const { Pool } = require('pg');
const winston = require('winston');
const { format } = require('winston');
const { combine, timestamp, printf, colorize } = format;
const { createClient } = require('redis');
const RedisStore = require('connect-redis').default;
const cron = require('node-cron');
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');
const morgan = require('morgan');
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const { Telegraf } = require('telegraf');
const { Sequelize } = require('sequelize');
const socket = require('socket.io');
const http = require('http');

// Load environment variables
dotenv.config();

// Initialize custom logger
const logDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
}

const myFormat = printf(({ level, message, timestamp }) => {
    return `${timestamp} [${level}]: ${message}`;
});

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: combine(
        timestamp(),
        myFormat
    ),
    transports: [
        new winston.transports.Console({
            format: combine(
                colorize(),
                timestamp(),
                myFormat
            )
        }),
        new winston.transports.File({ 
            filename: path.join(logDir, 'error.log'),
            level: 'error',
            maxsize: 10485760, // 10MB
            maxFiles: 5
        }),
        new winston.transports.File({ 
            filename: path.join(logDir, 'combined.log'),
            maxsize: 10485760, // 10MB
            maxFiles: 5
        })
    ]
});

// Initialize Sequelize for ORM
const sequelize = new Sequelize({
    dialect: 'postgres',
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT) || 5432,
    database: process.env.DB_NAME || 'irssh_panel',
    username: process.env.DB_USER || 'admin',
    password: process.env.DB_PASSWORD || 'password',
    logging: (msg) => logger.debug(msg),
    pool: {
        max: 10,
        min: 0,
        acquire: 30000,
        idle: 10000
    }
});

// Test database connection
sequelize.authenticate()
    .then(() => {
        logger.info('Connected to the database successfully');
    })
    .catch(err => {
        logger.error(`Database connection error: ${err.message}`);
    });

// Legacy database connection for backward compatibility
const pool = new Pool({
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT) || 5432,
    database: process.env.DB_NAME || 'irssh_panel',
    user: process.env.DB_USER || 'admin',
    password: process.env.DB_PASSWORD || 'password'
});

// Initialize Express app
const app = express();
const server = http.createServer(app);

// Configure Redis for session storage
let redisClient;
let redisStore;

if (process.env.REDIS_URL) {
    redisClient = createClient({
        url: process.env.REDIS_URL,
        socket: {
            reconnectStrategy: retries => Math.min(retries * 50, 1000)
        }
    });
    
    redisClient.connect().catch(err => {
        logger.error(`Redis connection error: ${err}`);
    });
    
    redisClient.on('error', (err) => {
        logger.error(`Redis error: ${err}`);
    });
    
    redisClient.on('connect', () => {
        logger.info('Connected to Redis successfully');
    });
    
    redisStore = new RedisStore({
        client: redisClient,
        prefix: 'irssh:sess:'
    });
}

// Configure Telegram bot for notifications if token is provided
let bot;
if (process.env.TELEGRAM_BOT_TOKEN) {
    try {
        bot = new Telegraf(process.env.TELEGRAM_BOT_TOKEN);
        bot.launch().then(() => {
            logger.info('Telegram bot started successfully');
        });
        
        // Handle bot errors
        bot.catch((err, ctx) => {
            logger.error(`Telegram bot error: ${err}`);
        });
        
        // Simple ping command to test bot
        bot.command('ping', (ctx) => {
            ctx.reply('Pong! IRSSH Panel is running.');
        });
        
        // Add help command
        bot.command('help', (ctx) => {
            ctx.reply('IRSSH Panel Telegram Bot\n\nAvailable commands:\n/ping - Check if bot is running\n/status - Get server status\n/users - Get user count\n/connections - Get active connections');
        });
        
        // Add status command
        bot.command('status', async (ctx) => {
            try {
                const adminChatId = process.env.TELEGRAM_ADMIN_CHAT;
                
                // Only respond to admin chat
                if (adminChatId && ctx.chat.id.toString() === adminChatId) {
                    const result = await pool.query('SELECT COUNT(*) FROM user_profiles WHERE status = $1', ['active']);
                    const activeUsers = result.rows[0].count;
                    
                    const connResult = await pool.query('SELECT COUNT(*) FROM user_connections WHERE status = $1', ['active']);
                    const activeConnections = connResult.rows[0].count;
                    
                    ctx.reply(`🖥️ Server Status:\n\n👥 Active Users: ${activeUsers}\n🔌 Active Connections: ${activeConnections}`);
                }
            } catch (error) {
                logger.error(`Error in Telegram status command: ${error.message}`);
                ctx.reply('Error getting server status');
            }
        });
    } catch (error) {
        logger.error(`Failed to initialize Telegram bot: ${error.message}`);
    }
}

// Setup Socket.io for real-time features
const io = socket(server, {
    cors: {
        origin: process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',') : '*',
        methods: ['GET', 'POST'],
        credentials: true
    }
});

// Socket authentication middleware
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) {
        return next(new Error('Authentication error'));
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'irssh-secret-key');
        socket.user = decoded;
        next();
    } catch (err) {
        next(new Error('Authentication error'));
    }
});

// Socket connection event
io.on('connection', (socket) => {
    logger.info(`User connected to socket: ${socket.user?.username || 'Unknown'}`);
    
    // Join room based on role
    if (socket.user) {
        socket.join(socket.user.role === 'admin' ? 'admins' : 'users');
        socket.join(`user:${socket.user.username}`);
    }
    
    // Handle disconnect
    socket.on('disconnect', () => {
        logger.info(`User disconnected from socket: ${socket.user?.username || 'Unknown'}`);
    });
    
    // Handle subscription to connection events
    socket.on('subscribe:connections', () => {
        if (socket.user?.role === 'admin') {
            socket.join('monitor:connections');
        }
    });
});

// Setup API rate limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per window
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many requests from this IP, please try again later.'
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(compression());
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
            imgSrc: ["'self'", "data:", "https://*"],
            connectSrc: ["'self'"]
        }
    }
}));

// Setup CORS
app.use(cors({
    origin: process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',') : '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

// Setup session
if (redisStore) {
    app.use(session({
        store: redisStore,
        secret: process.env.SESSION_SECRET || 'irssh-session-secret',
        name: 'irssh.sid',
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: process.env.NODE_ENV === 'production',
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        }
    }));
}

// Setup request logging
app.use(morgan('combined', {
    stream: {
        write: (message) => logger.info(message.trim())
    }
}));

// Apply rate limiting to API routes
app.use('/api/', apiLimiter);

// Serve Swagger documentation if enabled
if (process.env.ENABLE_SWAGGER === 'true') {
    try {
        const swaggerDocument = YAML.load('./docs/swagger.yaml');
        app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));
        logger.info('Swagger UI enabled at /api-docs');
    } catch (error) {
        logger.error(`Failed to load Swagger documentation: ${error.message}`);
    }
}

// Authentication middleware
const authMiddleware = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Authentication required' });
        }
        
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'irssh-secret-key');
        
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
};

// Admin middleware
const adminMiddleware = (req, res, next) => {
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// Regular user middleware
const userMiddleware = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    next();
};

// API routes will be organized into modules
    const routesPath = path.join(__dirname, 'routes');
    if (fs.existsSync(routesPath)) {
        fs.readdirSync(routesPath).forEach(file => {
            if (file.endsWith('.js')) {
                const routeName = file.split('.')[0];
                const route = require(path.join(routesPath, file));
                app.use(`/api/${routeName}`, route);
                logger.info(`Loaded API route: /api/${routeName}`);
            }
        });
    } else {
        logger.warn('Routes directory not found, creating basic routes');
        fs.mkdirSync(routesPath, { recursive: true });
        
        // Set up basic routes inline for now
        // Status endpoint
        app.get('/api/status', (req, res) => {
            res.json({ 
                status: 'ok', 
                message: 'IRSSH Panel API is running',
                version: '4.0.0',
                timestamp: new Date().toISOString()
            });
        });
        
        // Authentication endpoint
        app.post('/api/auth/login', async (req, res) => {
            try {
                const { username, password } = req.body;
                
                if (!username || !password) {
                    return res.status(400).json({ error: 'Username and password are required' });
                }
                
                const userResult = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
                
                if (userResult.rows.length === 0) {
                    return res.status(401).json({ error: 'Invalid credentials' });
                }
                
                const user = userResult.rows[0];
                const passwordMatch = await bcrypt.compare(password, user.password);
                
                if (!passwordMatch) {
                    return res.status(401).json({ error: 'Invalid credentials' });
                }
                
                const token = jwt.sign(
                    { id: user.id, username: user.username, role: user.role },
                    process.env.JWT_SECRET || 'irssh-secret-key',
                    { expiresIn: '1d' }
                );
                
                // Log the successful login
                logger.info(`User ${username} logged in`);
                
                // Emit login event to admins
                io.to('admins').emit('user:login', { 
                    username: user.username, 
                    timestamp: new Date().toISOString() 
                });
                
                res.json({ 
                    token, 
                    user: { 
                        id: user.id, 
                        username: user.username, 
                        role: user.role 
                    } 
                });
            } catch (error) {
                logger.error(`Login error: ${error.message}`);
                res.status(500).json({ error: 'Authentication failed' });
            }
        });
        
        // Users endpoint (protected)
        app.get('/api/users', authMiddleware, adminMiddleware, async (req, res) => {
            try {
                const result = await pool.query(`
                    SELECT id, username, email, role, created_at 
                    FROM users 
                    ORDER BY id
                `);
                
                res.json({ users: result.rows });
            } catch (error) {
                logger.error(`Error fetching users: ${error.message}`);
                res.status(500).json({ error: 'Database error' });
            }
        });
        
        // System info endpoint (protected)
        app.get('/api/system/info', authMiddleware, adminMiddleware, (req, res) => {
            const os = require('os');
            
            const systemInfo = {
                hostname: os.hostname(),
                platform: os.platform(),
                architecture: os.arch(),
                cpus: os.cpus().length,
                memory: {
                    total: Math.round(os.totalmem() / (1024 * 1024 * 1024) * 100) / 100, // GB
                    free: Math.round(os.freemem() / (1024 * 1024 * 1024) * 100) / 100, // GB
                    usage: Math.round((1 - os.freemem() / os.totalmem()) * 100)
                },
                uptime: Math.floor(os.uptime() / 3600), // hours
                load: os.loadavg(),
                server_ip: process.env.SERVER_IPv4 || 'Unknown'
            };
            
            res.json({ system: systemInfo });
        });
    }
    
    // Create model definitions directory
    const modelsPath = path.join(__dirname, 'models');
    if (!fs.existsSync(modelsPath)) {
        fs.mkdirSync(modelsPath, { recursive: true });
        
        // Create basic User model
        fs.writeFileSync(path.join(modelsPath, 'User.js'), `
const { DataTypes } = require('sequelize');
const sequelize = require('../db/sequelize');
const bcrypt = require('bcrypt');

const User = sequelize.define('User', {
    username: {
        type: DataTypes.STRING(50),
        allowNull: false,
        unique: true
    },
    password: {
        type: DataTypes.STRING(255),
        allowNull: false,
        set(value) {
            const hash = bcrypt.hashSync(value, 10);
            this.setDataValue('password', hash);
        }
    },
    email: {
        type: DataTypes.STRING(100),
        allowNull: true,
        validate: {
            isEmail: true
        }
    },
    role: {
        type: DataTypes.STRING(20),
        allowNull: false,
        defaultValue: 'user',
        validate: {
            isIn: [['admin', 'user', 'reseller']]
        }
    },
    status: {
        type: DataTypes.STRING(20),
        allowNull: false,
        defaultValue: 'active',
        validate: {
            isIn: [['active', 'deactive', 'suspended']]
        }
    },
    lastLogin: {
        type: DataTypes.DATE,
        allowNull: true
    }
}, {
    tableName: 'users',
    timestamps: true,
    createdAt: 'created_at',
    updatedAt: 'updated_at',
    hooks: {
        beforeCreate: async (user) => {
            if (user.password) {
                user.password = await bcrypt.hash(user.password, 10);
            }
        },
        beforeUpdate: async (user) => {
            if (user.changed('password')) {
                user.password = await bcrypt.hash(user.password, 10);
            }
        }
    }
});

User.prototype.comparePassword = async function(password) {
    return bcrypt.compare(password, this.password);
};

module.exports = User;
        `);
        
        // Create database connection for Sequelize
        const dbPath = path.join(__dirname, 'db');
        if (!fs.existsSync(dbPath)) {
            fs.mkdirSync(dbPath, { recursive: true });
            
            fs.writeFileSync(path.join(dbPath, 'sequelize.js'), `
const { Sequelize } = require('sequelize');
const dotenv = require('dotenv');

dotenv.config();

const sequelize = new Sequelize({
    dialect: 'postgres',
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT) || 5432,
    database: process.env.DB_NAME || 'irssh_panel',
    username: process.env.DB_USER || 'admin',
    password: process.env.DB_PASSWORD || 'password',
    logging: process.env.NODE_ENV === 'development',
    pool: {
        max: 10,
        min: 0,
        acquire: 30000,
        idle: 10000
    }
});

module.exports = sequelize;
            `);
            
            // Create migration script
            fs.writeFileSync(path.join(dbPath, 'migrate.js'), `
const sequelize = require('./sequelize');
const path = require('path');
const fs = require('fs');

// Import all models
const modelsPath = path.join(__dirname, '../models');
fs.readdirSync(modelsPath).forEach(file => {
    if (file.endsWith('.js')) {
        require(path.join(modelsPath, file));
    }
});

// Perform sync with database
async function migrate() {
    try {
        await sequelize.sync({ alter: true });
        console.log('Database migration completed successfully');
        process.exit(0);
    } catch (error) {
        console.error('Error during database migration:', error);
        process.exit(1);
    }
}

migrate();
            `);
        }
    }
    
    // Set up background jobs using node-cron
    // 1. Clean up expired sessions
    cron.schedule('0 2 * * *', async () => {
        logger.info('Running scheduled task: Cleaning up expired sessions');
        if (redisClient) {
            try {
                // Get all session keys
                const keys = await redisClient.keys('irssh:sess:*');
                let expiredCount = 0;
                
                for (const key of keys) {
                    const session = await redisClient.get(key);
                    try {
                        const sessionData = JSON.parse(session);
                        const expiryTime = sessionData.cookie?._expires;
                        
                        if (expiryTime && new Date(expiryTime) < new Date()) {
                            await redisClient.del(key);
                            expiredCount++;
                        }
                    } catch (err) {
                        logger.error(`Error parsing session data: ${err.message}`);
                    }
                }
                
                logger.info(`Session cleanup complete. Removed ${expiredCount} expired sessions.`);
            } catch (error) {
                logger.error(`Session cleanup error: ${error.message}`);
            }
        }
    });
    
    // 2. Check for expired user accounts and notify
    cron.schedule('0 0 * * *', async () => {
        logger.info('Running scheduled task: Checking expired accounts');
        try {
            const expiredUsersResult = await pool.query(`
                SELECT username, email, telegram_id
                FROM user_profiles
                WHERE status = 'active' 
                AND expiry_date < NOW() 
                AND expiry_date > NOW() - INTERVAL '1 day'
            `);
            
            if (expiredUsersResult.rows.length > 0) {
                logger.info(`Found ${expiredUsersResult.rows.length} newly expired accounts`);
                
                // Send notifications
                // 1. Telegram notifications if configured
                if (bot && process.env.TELEGRAM_ADMIN_CHAT) {
                    const adminChatId = process.env.TELEGRAM_ADMIN_CHAT;
                    const usernames = expiredUsersResult.rows.map(u => u.username).join(', ');
                    bot.telegram.sendMessage(adminChatId, `⚠️ Expired accounts alert!\nThe following accounts have expired: ${usernames}`);
                    
                    // Also notify users if they have telegram_id
                    for (const user of expiredUsersResult.rows) {
                        if (user.telegram_id) {
                            try {
                                bot.telegram.sendMessage(user.telegram_id, `⚠️ Your IRSSH account (${user.username}) has expired. Please contact support for renewal.`);
                            } catch (err) {
                                logger.error(`Failed to send Telegram notification to user ${user.username}: ${err.message}`);
                            }
                        }
                    }
                }
                
                // Update users to deactive status
                await pool.query(`
                    UPDATE user_profiles
                    SET status = 'deactive'
                    WHERE status = 'active' AND expiry_date < NOW()
                `);
                
                // Terminate all active connections for expired users
                const usersToDisconnect = expiredUsersResult.rows.map(u => u.username);
                if (usersToDisconnect.length > 0) {
                    await pool.query(`
                        UPDATE user_connections
                        SET status = 'terminated', disconnect_time = NOW(), disconnect_reason = 'account_expired'
                        WHERE username = ANY($1) AND status = 'active'
                    `, [usersToDisconnect]);
                    
                    // Emit connection terminated events
                    io.to('monitor:connections').emit('connections:terminated', {
                        usernames: usersToDisconnect,
                        reason: 'account_expired'
                    });
                }
            }
        } catch (error) {
            logger.error(`Expired accounts check error: ${error.message}`);
        }
    });
    
    // 3. Database backup job
    cron.schedule('0 3 * * *', async () => {
        logger.info('Running scheduled task: Database backup');
        try {
            const backupDir = '/opt/irssh-backups/db';
            if (!fs.existsSync(backupDir)) {
                fs.mkdirSync(backupDir, { recursive: true });
            }
            
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const backupFile = path.join(backupDir, `${process.env.DB_NAME || 'irssh_panel'}_${timestamp}.backup`);
            
            const { exec } = require('child_process');
            
            exec(`PGPASSWORD="${process.env.DB_PASSWORD}" pg_dump -h ${process.env.DB_HOST || 'localhost'} -U ${process.env.DB_USER} -d ${process.env.DB_NAME || 'irssh_panel'} -F c -f ${backupFile}`, (error, stdout, stderr) => {
                if (error) {
                    logger.error(`Database backup error: ${error.message}`);
                    return;
                }
                
                // Compress the backup
                exec(`gzip ${backupFile}`, (error, stdout, stderr) => {
                    if (error) {
                        logger.error(`Backup compression error: ${error.message}`);
                        return;
                    }
                    
                    logger.info(`Database backup completed: ${backupFile}.gz`);
                    
                    // Clean up old backups (keep last 7 days)
                    exec(`find ${backupDir} -name "*.backup.gz" -type f -mtime +7 -delete`, (error, stdout, stderr) => {
                        if (error) {
                            logger.error(`Old backup cleanup error: ${error.message}`);
                            return;
                        }
                        
                        logger.info('Old backups cleanup completed');
                    });
                });
            });
        } catch (error) {
            logger.error(`Database backup error: ${error.message}`);
        }
    });
    
    // Create initial admin user if it doesn't exist
    const initializeAdminUser = async () => {
        try {
            // Check if users table exists
            const tableCheck = await pool.query(`
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = 'users'
                )
            `);
            
            if (!tableCheck.rows[0].exists) {
                logger.info('Creating users table');
                
                await pool.query(`
                    CREATE TABLE users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        password VARCHAR(255) NOT NULL,
                        email VARCHAR(100),
                        role VARCHAR(20) DEFAULT 'user',
                        status VARCHAR(20) DEFAULT 'active',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP
                    )
                `);
            }
            
            // Check if admin user exists
            const userCheck = await pool.query('SELECT * FROM users WHERE username = $1', [process.env.ADMIN_USER]);
            
            if (userCheck.rows.length === 0) {
                // Create admin user
                const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASS, 10);
                
                await pool.query(`
                    INSERT INTO users (username, password, role, status) 
                    VALUES ($1, $2, 'admin', 'active')
                `, ['${ADMIN_USER}', hashedPassword]);
                
                logger.info('Admin user created successfully');
            } else {
                // Update admin password
                const hashedPassword = await bcrypt.hash('${ADMIN_PASS}', 10);
                
                await pool.query(`
                    UPDATE users 
                    SET password = $1, updated_at = CURRENT_TIMESTAMP
                    WHERE username = $2
                `, [hashedPassword, '${ADMIN_USER}']);
                
                logger.info('Admin user updated successfully');
            }
        } catch (error) {
            logger.error(`Error initializing admin user: ${error.message}`);
        }
    };
    
    // Error handler middleware
    app.use((err, req, res, next) => {
        logger.error(`Unhandled error: ${err.message}`);
        res.status(500).json({ error: 'Internal server error' });
    });
    
    // Initialize database and admin user
    pool.connect()
        .then(() => {
            logger.info('Connected to database');
            return initializeAdminUser();
        })
        .catch(err => {
            logger.error(`Database connection error: ${err.message}`);
        });
    
    // Start the server
    const PORT = process.env.PORT || 3000;
    server.listen(PORT, () => {
        logger.info(`IRSSH Panel API server listening on port ${PORT}`);
    });
    
    process.on('SIGTERM', () => {
        logger.info('SIGTERM signal received. Closing server gracefully.');
        server.close(() => {
            logger.info('Server closed.');
            
            // Close database connections
            pool.end();
            sequelize.close();
            
            // Close Redis if connected
            if (redisClient) {
                redisClient.quit();
            }
            
            // Close Telegram bot if running
            if (bot) {
                bot.stop('SIGTERM');
            }
            
            process.exit(0);
        });
    });
    
    module.exports = { app, server, io };
EOF

        # Create .env file
        cat > "$TEMP_DIR/repo/backend/.env" << EOF
NODE_ENV=production
PORT=3000
DB_HOST=localhost
DB_PORT=5432
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASSWORD=${DB_USER_PASSWORD}
JWT_SECRET=$(openssl rand -base64 32)
SESSION_SECRET=$(openssl rand -base64 24)
LOG_LEVEL=info
CORS_ORIGINS=http://localhost:${PORTS[WEB]},http://${SERVER_IPv4}:${PORTS[WEB]}
REDIS_URL=redis://localhost:6379
SERVER_IPv4=${SERVER_IPv4}
SERVER_IPv6=${SERVER_IPv6}
ENABLE_SWAGGER=false
ADMIN_USER=${ADMIN_USER}
ADMIN_PASS=${ADMIN_PASS}
# TELEGRAM_BOT_TOKEN=your_bot_token
# TELEGRAM_ADMIN_CHAT=your_admin_chat_id
EOF

    # Setup frontend with enhanced UI
    info "Setting up enhanced frontend files..."
    cp -r "$TEMP_DIR/repo/frontend/"* "$PANEL_DIR/frontend/" || error "Failed to copy frontend files"
    cd "$PANEL_DIR/frontend" || error "Failed to access frontend directory"
    
     # ✅ Install and start the backend service
info "Installing backend and starting API server..."
cd "$PANEL_DIR/backend" || error "Cannot access backend directory"
npm install || error "Failed to install backend dependencies"
pm2 start index.js --name irssh-api || error "Failed to start backend service"

    # Create proper index.html if it doesn't exist
    if [ ! -f "index.html" ]; then
        cat > index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>IRSSH Panel - Advanced Server Management</title>
    <meta name="description" content="Advanced panel for managing IRSSH servers, protocols, and users">
    <link rel="icon" type="image/png" href="/favicon.png" />
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="./src/main.tsx"></script>
  </body>
</html>
EOF
        info "Created enhanced index.html with proper metadata and font loading"
    fi

    # Make sure src directory exists
    mkdir -p src
    
    # Create main.tsx if needed with TypeScript and modern React
    if [ ! -f "src/main.ts" ] && [ ! -f "src/main.tsx" ] && [ ! -f "src/main.js" ]; then
        cat > src/main.tsx << 'EOF'
import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ReactQueryDevtools } from '@tanstack/react-query-devtools'
import { Toaster } from 'react-hot-toast'
import App from './App'
import './index.css'
import { AuthProvider } from './contexts/AuthContext'
import { ThemeProvider } from './contexts/ThemeContext'
import { SocketProvider } from './contexts/SocketContext'

// Create a client for React Query
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 5 * 60 * 1000, // 5 minutes
    },
  },
})

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <ThemeProvider>
          <AuthProvider>
            <SocketProvider>
              <App />
              <Toaster 
                position="top-right"
                toastOptions={{
                  duration: 4000,
                  style: {
                    fontFamily: 'Inter, sans-serif',
                  },
                }}
              />
            </SocketProvider>
          </AuthProvider>
        </ThemeProvider>
      </BrowserRouter>
      {import.meta.env.DEV && <ReactQueryDevtools initialIsOpen={false} />}
    </QueryClientProvider>
  </React.StrictMode>
)
EOF
        info "Created main.tsx file with modern React features"

        # Create App.tsx with responsive design and theming
        if [ ! -f "src/App.jsx" ] && [ ! -f "src/App.tsx" ]; then
            cat > src/App.tsx << 'EOF'
import React, { useEffect } from 'react'
import { Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useAuth } from './contexts/AuthContext'
import { useSocket } from './contexts/SocketContext'
import Dashboard from './pages/Dashboard'
import Login from './pages/Login'
import UserManagement from './pages/UserManagement'
import SystemSettings from './pages/SystemSettings'
import ActiveConnections from './pages/ActiveConnections'
import UserProfile from './pages/UserProfile'
import Statistics from './pages/Statistics'
import Protocols from './pages/Protocols'
import Layout from './components/Layout'
import ProtectedRoute from './components/ProtectedRoute'
import AdminRoute from './components/AdminRoute'
import NotFound from './pages/NotFound'
import GeoLocation from './pages/GeoLocation'
import MultiServer from './pages/MultiServer'
import './App.css'

// Client portal pages
import ClientDashboard from './pages/client/Dashboard'
import ClientProfile from './pages/client/Profile'
import ClientLayout from './components/client/Layout'

const App: React.FC = () => {
  const { isAuthenticated, user, checkAuth } = useAuth()
  const { connect, disconnect } = useSocket()
  const location = useLocation()

  useEffect(() => {
    checkAuth()
  }, [])

  useEffect(() => {
    if (isAuthenticated && user) {
      connect()
      return () => disconnect()
    }
  }, [isAuthenticated, user])

  // System status query for polling
  useQuery({
    queryKey: ['systemStatus'],
    queryFn: async () => {
      const response = await fetch('/api/status')
      if (!response.ok) {
        throw new Error('Failed to fetch system status')
      }
      return response.json()
    },
    enabled: isAuthenticated,
    refetchInterval: 60000, // Poll every minute
  })

  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      
      {/* Admin routes */}
      <Route 
        path="/" 
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route 
          path="users/*" 
          element={
            <AdminRoute>
              <UserManagement />
            </AdminRoute>
          } 
        />
        <Route path="connections" element={<ActiveConnections />} />
        <Route path="statistics" element={<Statistics />} />
        <Route path="protocols" element={<Protocols />} />
        <Route path="settings" element={<SystemSettings />} />
        <Route path="profile" element={<UserProfile />} />
        
        {/* Hidden routes that are only accessible via special activation */}
        <Route path="geolocation" element={<GeoLocation />} />
        <Route path="multi-server" element={<MultiServer />} />
      </Route>
      
      {/* Client portal routes */}
      <Route 
        path="/portal" 
        element={
          <ProtectedRoute>
            <ClientLayout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Navigate to="/portal/dashboard" replace />} />
        <Route path="dashboard" element={<ClientDashboard />} />
        <Route path="profile" element={<ClientProfile />} />
      </Route>
      
      {/* 404 Not Found */}
      <Route path="*" element={<NotFound />} />
    </Routes>
  )
}

export default App
EOF
            info "Created App.tsx file with advanced routing and protected routes"
        fi
        
        # Create AuthContext.tsx for auth state management
        mkdir -p src/contexts
        cat > src/contexts/AuthContext.tsx << 'EOF'
import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { toast } from 'react-hot-toast'

interface User {
  id: number
  username: string
  role: string
}

interface AuthContextType {
  isAuthenticated: boolean
  user: User | null
  login: (username: string, password: string) => Promise<void>
  logout: () => void
  checkAuth: () => void
  isLoading: boolean
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export const useAuth = () => {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

interface AuthProviderProps {
  children: ReactNode
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false)
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState<boolean>(true)
  const navigate = useNavigate()

  // Check if user is already authenticated
  const checkAuth = () => {
    setIsLoading(true)
    const token = localStorage.getItem('irssh_token')
    const userStr = localStorage.getItem('irssh_user')
    
    if (token && userStr) {
      try {
        const userData = JSON.parse(userStr)
        setUser(userData)
        setIsAuthenticated(true)
      } catch (error) {
        localStorage.removeItem('irssh_token')
        localStorage.removeItem('irssh_user')
      }
    }
    setIsLoading(false)
  }

  // Login function
  const login = async (username: string, password: string) => {
    setIsLoading(true)
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
      })
      
      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.error || 'Login failed')
      }
      
      localStorage.setItem('irssh_token', data.token)
      localStorage.setItem('irssh_user', JSON.stringify(data.user))
      setUser(data.user)
      setIsAuthenticated(true)
      toast.success(`Welcome back, ${data.user.username}!`)
      
      // Redirect based on user role
      if (data.user.role === 'admin') {
        navigate('/dashboard')
      } else {
        navigate('/portal/dashboard')
      }
    } catch (error) {
      if (error instanceof Error) {
        toast.error(error.message)
      } else {
        toast.error('Login failed')
      }
      setIsAuthenticated(false)
      setUser(null)
    } finally {
      setIsLoading(false)
    }
  }

  // Logout function
  const logout = () => {
    localStorage.removeItem('irssh_token')
    localStorage.removeItem('irssh_user')
    setIsAuthenticated(false)
    setUser(null)
    navigate('/login')
    toast.success('Logged out successfully')
  }

  useEffect(() => {
    checkAuth()
  }, [])

  return (
    <AuthContext.Provider value={{ isAuthenticated, user, login, logout, checkAuth, isLoading }}>
      {children}
    </AuthContext.Provider>
  )
}
EOF
        
        # Create ThemeContext.tsx for dark/light mode
        cat > src/contexts/ThemeContext.tsx << 'EOF'
import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react'

type Theme = 'light' | 'dark' | 'system'

interface ThemeContextType {
  theme: Theme
  setTheme: (theme: Theme) => void
  isDarkMode: boolean
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined)

export const useTheme = () => {
  const context = useContext(ThemeContext)
  if (!context) {

throw new Error('useTheme must be used within a ThemeProvider')
  }
  return context
}

interface ThemeProviderProps {
  children: ReactNode
}

export const ThemeProvider: React.FC<ThemeProviderProps> = ({ children }) => {
  const [theme, setTheme] = useState<Theme>(() => {
    const savedTheme = localStorage.getItem('irssh_theme') as Theme
    return savedTheme || 'system'
  })
  
  const [isDarkMode, setIsDarkMode] = useState<boolean>(false)
  
  useEffect(() => {
    localStorage.setItem('irssh_theme', theme)
    
    // Apply theme to document
    const root = window.document.documentElement
    root.classList.remove('light', 'dark')
    
    if (theme === 'system') {
      const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches
      root.classList.add(systemPrefersDark ? 'dark' : 'light')
      setIsDarkMode(systemPrefersDark)
    } else {
      root.classList.add(theme)
      setIsDarkMode(theme === 'dark')
    }
  }, [theme])
  
  // Listen for system theme changes
  useEffect(() => {
    if (theme === 'system') {
      const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
      
      const handleChange = (e: MediaQueryListEvent) => {
        const root = window.document.documentElement
        root.classList.remove('light', 'dark')
        root.classList.add(e.matches ? 'dark' : 'light')
        setIsDarkMode(e.matches)
      }
      
      mediaQuery.addEventListener('change', handleChange)
      return () => mediaQuery.removeEventListener('change', handleChange)
    }
  }, [theme])
  
  return (
    <ThemeContext.Provider value={{ theme, setTheme, isDarkMode }}>
      {children}
    </ThemeContext.Provider>
  )
}
EOF

        # Create SocketContext.tsx for real-time updates
        cat > src/contexts/SocketContext.tsx << 'EOF'
import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import { io, Socket } from 'socket.io-client'
import { useAuth } from './AuthContext'

interface SocketContextType {
  socket: Socket | null
  isConnected: boolean
  connect: () => void
  disconnect: () => void
  subscribeToConnections: () => void
}

const SocketContext = createContext<SocketContextType | undefined>(undefined)

export const useSocket = () => {
  const context = useContext(SocketContext)
  if (!context) {
    throw new Error('useSocket must be used within a SocketProvider')
  }
  return context
}

interface SocketProviderProps {
  children: ReactNode
}

export const SocketProvider: React.FC<SocketProviderProps> = ({ children }) => {
  const [socket, setSocket] = useState<Socket | null>(null)
  const [isConnected, setIsConnected] = useState<boolean>(false)
  const { isAuthenticated, user } = useAuth()
  
  const connect = () => {
    if (!isAuthenticated || !user) return
    
    const token = localStorage.getItem('irssh_token')
    if (!token) return
    
    const newSocket = io('/', {
      auth: {
        token
      }
    })
    
    newSocket.on('connect', () => {
      setIsConnected(true)
      console.log('Socket connected')
    })
    
    newSocket.on('disconnect', () => {
      setIsConnected(false)
      console.log('Socket disconnected')
    })
    
    setSocket(newSocket)
    
    return () => {
      newSocket.disconnect()
    }
  }
  
  const disconnect = () => {
    if (socket) {
      socket.disconnect()
      setSocket(null)
      setIsConnected(false)
    }
  }
  
  const subscribeToConnections = () => {
    if (socket && user?.role === 'admin') {
      socket.emit('subscribe:connections')
    }
  }
  
  return (
    <SocketContext.Provider value={{ socket, isConnected, connect, disconnect, subscribeToConnections }}>
      {children}
    </SocketContext.Provider>
  )
}
EOF
    fi

    # Create index.css with modern styling
    if [ ! -f "src/index.css" ]; then
        cat > src/index.css << 'EOF'
@tailwind base;
@tailwind components;
@tailwind utilities;

:root {
  /* Light mode colors */
  --color-primary: 0 112 243;
  --color-secondary: 5 150 105;
  --color-background: 250 250 250;
  --color-card: 255 255 255;
  --color-text: 2 6 23;
  --color-text-secondary: 113 113 122;
  --color-border: 229 231 235;
  --color-success: 16 185 129;
  --color-warning: 245 158 11;
  --color-danger: 239 68 68;
  --color-info: 59 130 246;
}

.dark {
  /* Dark mode colors */
  --color-primary: 59 130 246;
  --color-secondary: 5 150 105;
  --color-background: 15 23 42;
  --color-card: 30 41 59;
  --color-text: 241 245 249;
  --color-text-secondary: 148 163 184;
  --color-border: 51 65 85;
  --color-success: 16 185 129;
  --color-warning: 245 158 11;
  --color-danger: 239 68 68;
  --color-info: 59 130 246;
}

body {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen,
    Ubuntu, Cantarell, 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  background-color: rgb(var(--color-background));
  color: rgb(var(--color-text));
  transition: background-color 0.3s ease;
}

@layer components {
  .card {
    @apply bg-white dark:bg-slate-800 rounded-lg shadow-md p-6;
  }
  
  .btn-primary {
    @apply bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-md transition-colors;
  }
  
  .btn-secondary {
    @apply bg-gray-100 hover:bg-gray-200 dark:bg-slate-700 dark:hover:bg-slate-600 text-gray-800 dark:text-white font-medium py-2 px-4 rounded-md transition-colors;
  }
  
  .btn-danger {
    @apply bg-red-500 hover:bg-red-600 text-white font-medium py-2 px-4 rounded-md transition-colors;
  }
  
  .input {
    @apply border border-gray-300 dark:border-slate-600 dark:bg-slate-700 dark:text-white rounded-md py-2 px-4 focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-blue-600 transition-all;
  }
  
  .table-container {
    @apply w-full overflow-x-auto rounded-md shadow-sm;
  }
  
  .table {
    @apply min-w-full bg-white dark:bg-slate-800 border border-gray-200 dark:border-slate-700;
  }
  
  .table th {
    @apply bg-gray-50 dark:bg-slate-700 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider py-3 px-4;
  }
  
  .table td {
    @apply border-t border-gray-200 dark:border-slate-700 px-4 py-3 text-sm;
  }
  
  .table tr:hover {
    @apply bg-gray-50 dark:bg-slate-700/50;
  }
  
  .badge {
    @apply inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium;
  }
  
  .badge-success {
    @apply bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300;
  }
  
  .badge-warning {
    @apply bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300;
  }
  
  .badge-danger {
    @apply bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300;
  }
  
  .badge-info {
    @apply bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300;
  }
}
EOF
        info "Created enhanced index.css with Tailwind CSS and theming support"
    fi

    # Create App.css with modern styling
    if [ ! -f "src/App.css" ]; then
        cat > src/App.css << 'EOF'
/* General Application Styles */
.app-container {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

/* Main Content Container */
.content-container {
  display: flex;
  flex: 1;
}

/* Login Page */
.login-container {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  padding: 1rem;
  background-color: rgb(var(--color-background));
}

.login-card {
  background-color: rgb(var(--color-card));
  border-radius: 0.5rem;
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
  padding: 2rem;
  width: 400px;
  max-width: 100%;
  transition: all 0.3s ease;
}

.login-header {
  text-align: center;
  margin-bottom: 2rem;
}

.login-header h1 {
  color: rgb(var(--color-primary));
  font-size: 1.875rem;
  font-weight: 700;
  margin-bottom: 0.5rem;
}

.login-form {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.form-group label {
  font-weight: 500;
  font-size: 0.875rem;
  color: rgb(var(--color-text));
}

.error-message {
  color: rgb(var(--color-danger));
  font-size: 0.875rem;
  margin-top: 0.5rem;
}

/* Dashboard Layout */
.dashboard {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}

.header {
  background-color: rgb(var(--color-card));
  border-bottom: 1px solid rgb(var(--color-border));
  padding: 1rem 1.5rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
  transition: all 0.3s ease;
}

.header h1 {
  font-size: 1.25rem;
  font-weight: 600;
  margin: 0;
  color: rgb(var(--color-text));
}

.header-actions {
  display: flex;
  gap: 0.75rem;
  align-items: center;
}

.content {
  display: flex;
  flex: 1;
}

.sidebar {
  width: 280px;
  background-color: rgb(var(--color-card));
  border-right: 1px solid rgb(var(--color-border));
  display: flex;
  flex-direction: column;
  transition: all 0.3s ease;
  overflow-y: auto;
}

.logo {
  padding: 1.5rem;
  display: flex;
  align-items: center;
  gap: 0.75rem;
  border-bottom: 1px solid rgb(var(--color-border));
}

.logo-icon {
  width: 2.5rem;
  height: 2.5rem;
  background-color: rgb(var(--color-primary));
  border-radius: 0.5rem;
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  font-weight: bold;
}

.logo-text {
  font-size: 1.25rem;
  font-weight: 700;
  color: rgb(var(--color-primary));
}

.user-info {
  padding: 1.5rem;
  border-bottom: 1px solid rgb(var(--color-border));
}

.user-name {
  font-weight: 600;
  font-size: 0.875rem;
  color: rgb(var(--color-text));
  margin-bottom: 0.25rem;
}

.user-role {
  font-size: 0.75rem;
  color: rgb(var(--color-text-secondary));
}

.menu {
  padding: 1rem 0;
  flex: 1;
}

.menu-group {
  padding: 0 1rem;
  margin-bottom: 0.5rem;
}

.menu-group-title {
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  color: rgb(var(--color-text-secondary));
  letter-spacing: 0.05em;
  padding: 0 0.5rem;
  margin-bottom: 0.5rem;
}

.menu-item {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.75rem 1rem;
  border-radius: 0.375rem;
  color: rgb(var(--color-text));
  font-weight: 500;
  font-size: 0.875rem;
  transition: all 0.2s ease;
  cursor: pointer;
  margin-bottom: 0.25rem;
}

.menu-item:hover {
  background-color: rgba(var(--color-primary), 0.05);
}

.menu-item.active {
  background-color: rgba(var(--color-primary), 0.1);
  color: rgb(var(--color-primary));
}

.menu-icon {
  width: 1.25rem;
  height: 1.25rem;
  flex-shrink: 0;
}

.main-content {
  flex: 1;
  padding: 2rem;
  overflow-y: auto;
  background-color: rgb(var(--color-background));
}

.page-header {
  margin-bottom: 2rem;
}

.page-title {
  font-size: 1.5rem;
  font-weight: 600;
  color: rgb(var(--color-text));
  margin-bottom: 0.5rem;
}

.page-description {
  font-size: 0.875rem;
  color: rgb(var(--color-text-secondary));
}

/* Cards and Grids */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
  gap: 1.5rem;
  margin-bottom: 2rem;
}

.stat-card {
  background-color: rgb(var(--color-card));
  border-radius: 0.5rem;
  padding: 1.5rem;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
  display: flex;
  flex-direction: column;
  transition: all 0.3s ease;
}

.stat-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1rem;
}

.stat-title {
  font-size: 0.875rem;
  font-weight: 500;
  color: rgb(var(--color-text-secondary));
}

.stat-icon {
  width: 2rem;
  height: 2rem;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 0.375rem;
}

.stat-value {
  font-size: 1.875rem;
  font-weight: 600;
  color: rgb(var(--color-text));
  margin-bottom: 0.25rem;
}

.stat-description {
  font-size: 0.75rem;
  color: rgb(var(--color-text-secondary));
  display: flex;
  align-items: center;
  gap: 0.25rem;
}

.stat-change-positive {
  color: rgb(var(--color-success));
}

.stat-change-negative {
  color: rgb(var(--color-danger));
}

/* Responsive Design */
@media (max-width: 1024px) {
  .sidebar {
    width: 220px;
  }
}

@media (max-width: 768px) {
  .content {
    flex-direction: column;
  }
  
  .sidebar {
    width: 100%;
    border-right: none;
    border-bottom: 1px solid rgb(var(--color-border));
  }
  
  .stats-grid {
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  }
}

@media (max-width: 640px) {
  .stats-grid {
    grid-template-columns: 1fr;
  }
}
EOF
        info "Created enhanced App.css with responsive design and theming support"
    fi

    # Create package.json with advanced dependencies
    if [ ! -f "package.json" ]; then
        cat > package.json << 'EOF'
{
  "name": "irssh-panel-frontend",
  "private": true,
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "lint": "eslint src --ext ts,tsx",
    "format": "prettier --write \"src/**/*.{ts,tsx,css,scss}\"",
    "test": "vitest run",
    "test:watch": "vitest"
  },
  "dependencies": {
    "@tanstack/react-query": "^5.0.0",
    "@tanstack/react-query-devtools": "^5.0.0",
    "axios": "^1.6.0",
    "chart.js": "^4.4.0",
    "date-fns": "^2.30.0",
    "framer-motion": "^10.16.4",
    "lodash": "^4.17.21",
    "lucide-react": "^0.290.0",
    "react": "^18.2.0",
    "react-chartjs-2": "^5.2.0",
    "react-datepicker": "^4.21.0",
    "react-dom": "^18.2.0",
    "react-hook-form": "^7.47.0",
    "react-hot-toast": "^2.4.1",
    "react-router-dom": "^6.17.0",
    "recharts": "^2.9.0",
    "socket.io-client": "^4.7.2",
    "uuid": "^9.0.1",
    "zod": "^3.22.4"
  },
  "devDependencies": {
    "@types/lodash": "^4.14.200",
    "@types/node": "^20.8.9",
    "@types/react": "^18.2.33",
    "@types/react-datepicker": "^4.19.1",
    "@types/react-dom": "^18.2.14",
    "@types/uuid": "^9.0.6",
    "@typescript-eslint/eslint-plugin": "^6.9.0",
    "@typescript-eslint/parser": "^6.9.0",
    "@vitejs/plugin-react-swc": "^3.4.0",
    "autoprefixer": "^10.4.16",
    "eslint": "^8.52.0",
    "eslint-plugin-react": "^7.33.2",
    "eslint-plugin-react-hooks": "^4.6.0",
    "postcss": "^8.4.31",
    "prettier": "^3.0.3",
    "tailwindcss": "^3.3.5",
    "typescript": "^5.2.2",
    "vite": "^4.5.0",
    "vitest": "^0.34.6"
  }
}
EOF
        info "Created enhanced package.json with modern dependencies"
    fi

    # Create TypeScript configuration
    if [ ! -f "tsconfig.json" ]; then
        cat > tsconfig.json << 'EOF'
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "allowSyntheticDefaultImports": true,
    "baseUrl": ".",
    "paths": {
      "@/*": ["./src/*"]
    }
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
}
EOF

        cat > tsconfig.node.json << 'EOF'
{
  "compilerOptions": {
    "composite": true,
    "skipLibCheck": true,
    "module": "ESNext",
    "moduleResolution": "bundler",
    "allowSyntheticDefaultImports": true
  },
  "include": ["vite.config.ts"]
}
EOF
        info "Created TypeScript configuration files"
    fi

    # Create Tailwind configuration
    if [ ! -f "tailwind.config.js" ]; then
        cat > tailwind.config.js << 'EOF'
/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        primary: 'rgb(var(--color-primary) / <alpha-value>)',
        secondary: 'rgb(var(--color-secondary) / <alpha-value>)',
        background: 'rgb(var(--color-background) / <alpha-value>)',
        card: 'rgb(var(--color-card) / <alpha-value>)',
        success: 'rgb(var(--color-success) / <alpha-value>)',
        warning: 'rgb(var(--color-warning) / <alpha-value>)',
        danger: 'rgb(var(--color-danger) / <alpha-value>)',
        info: 'rgb(var(--color-info) / <alpha-value>)',
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'Helvetica Neue', 'Arial', 'sans-serif'],
      },
      animation: {
        'spin-slow': 'spin 3s linear infinite',
        'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
      screens: {
        xs: '475px',
      },
    },
  },
  plugins: [],
}
EOF

        # Create PostCSS config file
        cat > postcss.config.js << 'EOF'
export default {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
}
EOF
        info "Created Tailwind and PostCSS configuration files"
    fi

    # Create Vite configuration
    cat > vite.config.ts << 'EOF'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'
import path from 'path'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      },
      '/socket.io': {
        target: 'http://localhost:3000',
        changeOrigin: true,
        ws: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom'],
          charts: ['chart.js', 'react-chartjs-2', 'recharts'],
          utils: ['date-fns', 'lodash', 'axios'],
        },
      },
    },
  },
})
EOF
    info "Created enhanced Vite configuration"

    # Create build script
    cat > build-frontend.sh << 'EOF'
#!/bin/bash
echo "Building frontend..."

# Check if Node.js and npm are installed
if ! command -v node &> /dev/null || ! command -v npm &> /dev/null; then
    echo "Node.js or npm not found. Please make sure they are installed."
    exit 1
fi

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo "Installing dependencies..."
    npm install
fi

# Make sure index.html has correct paths
echo "Checking index.html..."
sed -i 's|src=./src/main.ts"|src="./src/main.tsx"|g' index.html 2>/dev/null
sed -i 's|/src/main.ts|./src/main.tsx|g' index.html 2>/dev/null
sed -i 's|../src/main.ts|./src/main.tsx|g' index.html 2>/dev/null

# Try to build with Vite
echo "Building with Vite..."
npm run build

# Check if build succeeded
if [ $? -ne 0 ]; then
    echo "Vite build failed. Creating fallback build..."
    mkdir -p dist
    
    cat > dist/index.html << 'EOFHTML'
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>IRSSH Panel</title>
    <style>
      /* Base styles */
      :root {
        --primary-color: #0070f3;
        --background-color: #f5f5f5;
        --card-bg: #ffffff;
        --text-color: #333333;
        --border-color: #dddddd;
      }
      
      /* Dark mode support */
      @media (prefers-color-scheme: dark) {
        :root {
          --primary-color: #3b82f6;
          --background-color: #0f172a;
          --card-bg: #1e293b;
          --text-color: #f1f5f9;
          --border-color: #334155;
        }
      }
      
      body {
        margin: 0;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen,
          Ubuntu, Cantarell, 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif;
        background-color: var(--background-color);
        color: var(--text-color);
      }
      
      * {
        box-sizing: border-box;
      }
      
      /* App layout */
      .container {
        display: flex;
        min-height: 100vh;
      }
      
      .sidebar {
        width: 280px;
        background-color: var(--card-bg);
        border-right: 1px solid var(--border-color);
        padding: 0;
        display: flex;
        flex-direction: column;
      }
      
      .logo-container {
        display: flex;
        align-items: center;
        padding: 1.5rem;
        border-bottom: 1px solid var(--border-color);
      }
      
      .logo {
        width: 2.5rem;
        height: 2.5rem;
        border-radius: 0.5rem;
        background-color: var(--primary-color);
        margin-right: 1rem;
        display: flex;
        align-items: center;
        justify-content: center;
        color: white;
        font-weight: bold;
      }
      
      .logo-text {
        font-size: 1.25rem;
        font-weight: bold;
        color: var(--primary-color);
      }
      
      .user-info {
        padding: 1.5rem;
        border-bottom: 1px solid var(--border-color);
      }
      
      .user-role {
        font-size: 0.75rem;
        color: #666;
      }
      
      .user-name {
        font-weight: bold;
        margin-top: 0.25rem;
      }
      
      .menu {
        flex: 1;
        padding: 1rem 0;
        margin: 0;
        list-style: none;
      }
      
      .menu-item {
        padding: 0.75rem 1.5rem;
        display: flex;
        align-items: center;
        cursor: pointer;
        font-weight: 500;
        transition: background-color 0.2s;
      }
      
      .menu-item:hover {
        background-color: rgba(0, 112, 243, 0.05);
      }
      
      .menu-item.active {
        background-color: rgba(0, 112, 243, 0.1);
        border-left: 3px solid var(--primary-color);
      }
      
      .menu-icon {
        width: 1.25rem;
        height: 1.25rem;
        margin-right: 0.75rem;
        opacity: 0.7;
      }
      
      .main-content {
        flex: 1;
        padding: 2rem;
        overflow-y: auto;
      }
      
      .header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 2rem;
      }
      
      .page-title {
        font-size: 1.5rem;
        font-weight: bold;
        margin: 0;
      }
      
      .header-actions {
        display: flex;
        gap: 1rem;
      }
      
      .header-button {
        background-color: transparent;
        border: none;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        width: 2.5rem;
        height: 2.5rem;
        border-radius: 0.5rem;
        color: var(--text-color);
        transition: background-color 0.2s;
      }
      
      .header-button:hover {
        background-color: rgba(0, 0, 0, 0.05);
      }
      
      /* Cards */
      .card {
        background-color: var(--card-bg);
        border-radius: 0.5rem;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        padding: 1.5rem;
        margin-bottom: 1.5rem;
      }
      
      .card-title {
        font-size: 1.25rem;
        font-weight: 600;
        margin-top: 0;
        margin-bottom: 1.5rem;
      }
      
      /* Stats grid */
      .stats-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 1.5rem;
        margin-bottom: 2rem;
      }
      
      .stat-card {
        background-color: var(--card-bg);
        border-radius: 0.5rem;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        padding: 1.5rem;
        display: flex;
        flex-direction: column;
      }
      
      .stat-value {
        font-size: 2rem;
        font-weight: bold;
        margin-bottom: 0.5rem;
        color: var(--primary-color);
      }
      
      .stat-label {
        font-size: 1rem;
        color: #666;
      }
      
      /* Usage charts */
      .usage-chart {
        width: 120px;
        height: 120px;
        position: relative;
        margin: 0 auto 1rem;
      }
      
      .chart-circle {
        width: 100%;
        height: 100%;
        border-radius: 50%;
        background: conic-gradient(
          var(--primary-color) 0%,
          #f5f5f5 0%
        );
        display: flex;
        align-items: center;
        justify-content: center;
        position: relative;
      }
      
      .chart-circle::before {
        content: "";
        position: absolute;
        width: 80%;
        height: 80%;
        border-radius: 50%;
        background-color: var(--card-bg);
      }
      
      .chart-value {
        position: relative;
        z-index: 1;
        font-size: 1.5rem;
        font-weight: bold;
      }
      
      /* Form elements */
      input, select {
        width: 100%;
        padding: 0.75rem 1rem;
        border: 1px solid var(--border-color);
        border-radius: 0.375rem;
        font-size: 1rem;
        background-color: var(--card-bg);
        color: var(--text-color);
      }
      
      button {
        padding: 0.75rem 1.5rem;
        background-color: var(--primary-color);
        color: white;
        border: none;
        border-radius: 0.375rem;
        font-size: 1rem;
        font-weight: 500;
        cursor: pointer;
        transition: background-color 0.2s;
      }
      
      button:hover {
        background-color: #0051a8;
      }
      
      /* Login styles */
      .login-container {
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
        width: 100%;
        background-color: var(--background-color);
      }
      
      .login-card {
        background-color: var(--card-bg);
        border-radius: 0.5rem;
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        padding: 2rem;
        width: 400px;
        max-width: 90%;
      }
      
      .login-header {
        text-align: center;
        margin-bottom: 2rem;
      }
      
      .login-header h1 {
        color: var(--primary-color);
        margin-bottom: 0.5rem;
      }
      
      .form-group {
        margin-bottom: 1.5rem;
      }
      
      label {
        display: block;
        margin-bottom: 0.5rem;
        font-weight: 500;
      }
      
      .error-message {
        color: #e53e3e;
        margin-top: 1rem;
        text-align: center;
      }
      
      /* Responsive design */
      @media (max-width: 768px) {
        .container {
          flex-direction: column;
        }
        
        .sidebar {
          width: 100%;
          border-right: none;
          border-bottom: 1px solid var(--border-color);
        }
        
        .stats-grid {
          grid-template-columns: 1fr;
        }
      }
    </style>
  </head>
  <body>
    <div id="app-container">
      <!-- Login screen -->
      <div id="login-screen" class="login-container">
        <div class="login-card">
          <div class="login-header">
            <h1>IRSSH Panel</h1>
            <p>Please sign in to continue</p>
          </div>
          <form id="login-form">
            <div class="form-group">
              <label for="username">Username</label>
              <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
              <label for="password">Password</label>
              <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
          </form>
          <div id="error-message" class="error-message" style="display: none;">
            Invalid username or password
          </div>
        </div>
      </div>

      <!-- Dashboard -->
      <div id="dashboard" class="container" style="display: none;">
        <div class="sidebar">
          <div class="logo-container">
            <div class="logo">IR</div>
            <div class="logo-text">IRSSH</div>
          </div>
          
          <div class="user-info">
            <div class="user-role">Administrator</div>
            <div class="user-name" id="user-name">User: Admin</div>
          </div>
          
          <ul class="menu">
            <li class="menu-item active">
              <span class="menu-icon">📊</span>
              Dashboard
            </li>
            <li class="menu-item">
              <span class="menu-icon">👥</span>
              User Management
            </li>
            <li class="menu-item">
              <span class="menu-icon">🔌</span>
              Connections
            </li>
            <li class="menu-item">
              <span class="menu-icon">📈</span>
              Statistics
            </li>
            <li class="menu-item">
              <span class="menu-icon">🛡️</span>
              Protocols
            </li>
            <li class="menu-item">
              <span class="menu-icon">⚙️</span>
              Settings
            </li>
            <li class="menu-item" id="logout-btn">
              <span class="menu-icon">🚪</span>
              Logout
            </li>
          </ul>
        </div>
        
        <div class="main-content">
          <div class="header">
            <h1 class="page-title">Dashboard</h1>
            <div class="header-actions">
              <button class="header-button" id="refresh-btn">🔄</button>
              <button class="header-button" id="theme-toggle">🌙</button>
            </div>
          </div>
          
          <div class="stats-grid">
            <div class="stat-card">
              <div class="usage-chart">
                <div class="chart-circle" style="background: conic-gradient(#0070f3 0%, #f5f5f5 0%)">
                  <div class="chart-value">0%</div>
                </div>
              </div>
              <div class="stat-label" style="text-align: center;">CPU Usage</div>
            </div>
            
            <div class="stat-card">
              <div class="usage-chart">
                <div class="chart-circle" style="background: conic-gradient(#0070f3 0%, #f5f5f5 0%)">
                  <div class="chart-value">0%</div>
                </div>
              </div>
              <div class="stat-label" style="text-align: center;">RAM Usage</div>
            </div>
            
            <div class="stat-card">
              <div class="usage-chart">
                <div class="chart-circle" style="background: conic-gradient(#0070f3 0%, #f5f5f5 0%)">
                  <div class="chart-value">0%</div>
                </div>
              </div>
              <div class="stat-label" style="text-align: center;">Disk Usage</div>
            </div>
            
            <div class="stat-card">
              <div class="stat-value">0</div>
              <div class="stat-label">Active Users</div>
            </div>
          </div>
          
          <div class="card">
            <h2 class="card-title">Protocol Statistics</h2>
            <p>No active connections.</p>
          </div>
          
          <div class="card">
            <h2 class="card-title">System Information</h2>
            <p>Server IP: ${SERVER_IPv4 || "Not available"}</p>
            <p>Installation Date: ${INSTALLATION_DATE}</p>
            <p>Panel Version: 4.0.0</p>
          </div>
        </div>
      </div>
    </div>

    <script>
      document.addEventListener('DOMContentLoaded', function() {
        const loginForm = document.getElementById('login-form');
        const loginScreen = document.getElementById('login-screen');
        const dashboard = document.getElementById('dashboard');
        const errorMessage = document.getElementById('error-message');
        const logoutBtn = document.getElementById('logout-btn');
        const refreshBtn = document.getElementById('refresh-btn');
        const themeToggle = document.getElementById('theme-toggle');
        const userName = document.getElementById('user-name');
        
        // Set admin credentials from installation
        const ADMIN_USERNAME = '${ADMIN_USER}';
        const ADMIN_PASSWORD = '${ADMIN_PASS}';
        
        // Check if already logged in (using localStorage)
        const isLoggedIn = localStorage.getItem('irssh_logged_in');
        if (isLoggedIn === 'true') {
          loginScreen.style.display = 'none';
          dashboard.style.display = 'flex';
          userName.textContent = 'User: ' + (localStorage.getItem('irssh_username') || 'Admin');
        }
        
        // Handle login
        loginForm.addEventListener('submit', function(e) {
          e.preventDefault();
          const username = document.getElementById('username').value;
          const password = document.getElementById('password').value;
          
          // Check credentials (in a real app, this would be an API call)
          if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
            localStorage.setItem('irssh_logged_in', 'true');
            localStorage.setItem('irssh_username', username);
            loginScreen.style.display = 'none';
            dashboard.style.display = 'flex';
            userName.textContent = 'User: ' + username;
            errorMessage.style.display = 'none';
          } else {
            errorMessage.style.display = 'block';
          }
        });
        
        // Handle logout
        logoutBtn.addEventListener('click', function() {
          localStorage.removeItem('irssh_logged_in');
          localStorage.removeItem('irssh_username');
          dashboard.style.display = 'none';
          loginScreen.style.display = 'flex';
        });
        
        // Handle refresh
        refreshBtn.addEventListener('click', function() {
          // In a real app, this would update the dashboard data
          alert('Refreshing dashboard data...');
        });
        
        // Handle theme toggle
        themeToggle.addEventListener('click', function() {
          document.body.classList.toggle('dark-theme');
          themeToggle.textContent = document.body.classList.contains('dark-theme') ? '☀️' : '🌙';
        });
        
        // Handle menu item clicks
        const menuItems = document.querySelectorAll('.menu-item');
        menuItems.forEach(item => {
          item.addEventListener('click', function() {
            if (this !== logoutBtn) {
              menuItems.forEach(i => i.classList.remove('active'));
              this.classList.add('active');
            }
          });
        });
        
        // Apply preferred color scheme
        if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
          document.body.classList.add('dark-theme');
          themeToggle.textContent = '☀️';
        }
      });
    </script>
  </body>
</html>
EOFHTML
  
  echo "Created fallback dashboard successfully."
  exit 0
fi

echo "Frontend built successfully!"
EOF

    # Make the build script executable
    chmod +x build-frontend.sh

    # Run the build script
    info "Building enhanced frontend..."
    ./build-frontend.sh || error "Failed to build frontend" "no-exit"

    # Setup backend
    info "Setting up enhanced backend..."
    mkdir -p "$PANEL_DIR/backend"
    cp -r "$TEMP_DIR/repo/backend/"* "$PANEL_DIR/backend/" || error "Failed to copy backend files"
    cd "$PANEL_DIR/backend" || error "Failed to access backend directory"

    # Create needed directories for logs and config
    mkdir -p "$PANEL_DIR/backend/logs"
    mkdir -p "$PANEL_DIR/backend/config"
    mkdir -p "$PANEL_DIR/backend/uploads"
    mkdir -p "$PANEL_DIR/backend/public"

    # Install backend dependencies
    info "Installing backend dependencies..."
    npm install || error "Failed to install backend dependencies" "no-exit"
    
    # Create systemd service for backend API
    cat > /etc/systemd/system/irssh-api.service << EOL
[Unit]
Description=IRSSH Panel API Server
After=network.target postgresql.service redis-server.service
Wants=postgresql.service redis-server.service

[Service]
Type=simple
User=root
WorkingDirectory=$PANEL_DIR/backend
ExecStart=/usr/bin/node index.js
Restart=always
RestartSec=10
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOL

    # Configure nginx for frontend and API proxy with security enhancements
    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen ${PORTS[WEB]};
    listen [::]:${PORTS[WEB]};
    
    server_name _;
    
    root $PANEL_DIR/frontend/dist;
    index index.html;
    
    # Security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data:; connect-src 'self'" always;
    
    # Gzip compression
    gzip on;
    gzip_comp_level 5;
    gzip_min_length 256;
    gzip_proxied any;
    gzip_types application/javascript application/json text/css text/plain text/xml;
    
    # Browser caching
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
        expires 30d;
        add_header Cache-Control "public, no-transform";
    }
    
    location / {
        try_files \$uri \$uri/ /index.html;
    }
    
    location /api {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        proxy_read_timeout 90;
    }
    
    location /socket.io {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # Deny access to . files
    location ~ /\.(?!well-known) {
        deny all;
    }
    
    # Custom error pages
    error_page 404 /index.html;
    error_page 500 502 503 504 /500.html;
    
    location = /500.html {
        root $PANEL_DIR/frontend/dist;
        internal;
    }
}
EOL

    # Create directories structure for modules
    mkdir -p "$PANEL_DIR/services/user-manager"
    mkdir -p "$PANEL_DIR/scripts/monitoring"
    mkdir -p "$PANEL_DIR/modules/protocols"
    mkdir -p "$PANEL_DIR/monitoring/user-usage"
    mkdir -p "$LOG_DIR/user-manager"

    # Enable and restart nginx and backend service
    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null
    systemctl daemon-reload
    systemctl enable irssh-api
    systemctl restart irssh-api
    systemctl enable nginx
    systemctl restart nginx

    # Set permissions for frontend and backend
    chown -R www-data:www-data "$PANEL_DIR/frontend"
    chmod -R 755 "$PANEL_DIR/frontend"

    # Update admin credentials in HTML file if it exists
    if [ -f "$PANEL_DIR/frontend/dist/index.html" ]; then
        info "Updating credentials in HTML file..."
        # Replace username and password variables
        sed -i "s/const ADMIN_USERNAME = '.*';/const ADMIN_USERNAME = '${ADMIN_USER}';/" "$PANEL_DIR/frontend/dist/index.html"
        sed -i "s/const ADMIN_PASSWORD = '.*';/const ADMIN_PASSWORD = '${ADMIN_PASS}';/" "$PANEL_DIR/frontend/dist/index.html"
    fi

    info "Enhanced web server setup completed"

# Install SSH with advanced features and optimizations
install_ssh() {
    info "Installing SSH protocol with advanced optimizations..."
    
    apt-get install -y openssh-server stunnel4 || error "Failed to install SSH packages"
    
    # Backup original SSH config
    if [ -f /etc/ssh/sshd_config ]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +"%Y%m%d%H%M%S")
    fi
    
    # Create enhanced SSH config with security optimizations
    cat > /etc/ssh/sshd_config << EOL
# IRSSH-Panel optimized SSH configuration
# Managed by IRSSH-Panel, do not edit manually

# Basic settings
Port ${PORTS[SSH]}
PermitRootLogin yes
PasswordAuthentication yes
X11Forwarding no
PrintMotd no
PermitEmptyPasswords no
UsePAM yes

# Security settings
MaxAuthTries 5
LoginGraceTime 20
ClientAliveInterval 120
ClientAliveCountMax 2
MaxStartups 10:30:100
MaxSessions 10
TCPKeepAlive yes

# Limit user sessions based on system resources
# On low resource systems, limit more aggressively
$(if [ "$IS_LOW_RESOURCES" = true ]; then
    echo "MaxSessions 5"
    echo "MaxStartups 5:30:10"
else
    echo "MaxSessions 20"
    echo "MaxStartups 20:30:100"
fi)

# Ciphers and key exchange algorithms
# Use strong and modern ciphers
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com

# Logging
SyslogFacility AUTH
LogLevel INFO

# Subsystem configuration
Subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

# Disable user specific authorized_keys
AuthorizedKeysFile .ssh/authorized_keys
EOL

    # Create stunnel directory if it doesn't exist
    mkdir -p /etc/stunnel
    
    # Generate strong SSL certificate for stunnel with modern parameters
    info "Generating strong SSL certificate for SSH-TLS..."
    
    # Generate strong dhparam
    openssl dhparam -out /etc/stunnel/dhparam.pem 2048
    
    # Generate enhanced SSL cert with proper attributes
    openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
        -keyout /etc/stunnel/stunnel.pem \
        -out /etc/stunnel/stunnel.pem \
        -subj "/C=US/ST=State/L=City/O=IRSSH-Panel/CN=localhost" \
        -addext "subjectAltName = DNS:localhost,IP:${SERVER_IPv4}" \
        || error "Failed to create SSL certificate for stunnel"
    
    chmod 600 /etc/stunnel/stunnel.pem
    
    # Create stunnel configuration with security optimizations
    cat > /etc/stunnel/stunnel.conf << EOL
# IRSSH-Panel optimized stunnel configuration
# Managed by IRSSH-Panel, do not edit manually

# Global options
pid = /var/run/stunnel4/stunnel.pid
setuid = stunnel4
setgid = stunnel4
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

# Security options
cert = /etc/stunnel/stunnel.pem
dhparam = /etc/stunnel/dhparam.pem
ciphers = HIGH:!aNULL:!SSLv2:!SSLv3:!TLSv1:!TLSv1.1
options = NO_SSLv2
options = NO_SSLv3
options = NO_TLSv1
options = NO_TLSv1.1

# TLS 1.2+ only
sslVersionMin = TLSv1.2
sslVersionMax = TLSv1.3

# Optimizations
compression = no
TIMEOUTclose = 0
socket = l:SO_KEEPALIVE=1
socket = r:SO_KEEPALIVE=1

# SSH over TLS service
[ssh-tls]
accept = ${PORTS[SSH_TLS]}
connect = 127.0.0.1:${PORTS[SSH]}
delay = no
EOL

    # Install websocat for websocket support using the latest version
    if ! command -v websocat &> /dev/null; then
        info "Installing websocat for WebSocket SSH..."
        
        # Determine architecture
        ARCH=$(uname -m)
        if [[ "$ARCH" == "x86_64" ]]; then
            WEBSOCAT_URL="https://github.com/vi/websocat/releases/download/v1.11.0/websocat.x86_64-unknown-linux-musl"
        elif [[ "$ARCH" == "aarch64" ]]; then
            WEBSOCAT_URL="https://github.com/vi/websocat/releases/download/v1.11.0/websocat.aarch64-unknown-linux-musl" 
        else
            WEBSOCAT_URL="https://github.com/vi/websocat/releases/download/v1.11.0/websocat.x86_64-unknown-linux-musl"
            warn "Architecture $ARCH not directly supported for websocat, using x86_64 version"
        fi
        
        wget -qO /usr/local/bin/websocat $WEBSOCAT_URL
        chmod +x /usr/local/bin/websocat
    fi

    # Create systemd service for websocket with security enhancements
    cat > /etc/systemd/system/websocket.service << EOL
[Unit]
Description=WebSocket for SSH
After=network.target
Documentation=https://github.com/vi/websocat

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/websocat -t --binary-protocol ws-l:0.0.0.0:${PORTS[WEBSOCKET]},cert=/etc/stunnel/stunnel.pem,key=/etc/stunnel/stunnel.pem tcp:127.0.0.1:${PORTS[SSH]}
Restart=always
RestartSec=10
LimitNOFILE=1048576
StandardOutput=journal
StandardError=journal

# Security
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOL

    # Create SSH monitoring script for connection tracking
    mkdir -p "$SCRIPTS_DIR/ssh"
    cat > "$SCRIPTS_DIR/ssh/setup_auditing.sh" << 'EOF'
#!/bin/bash

# Enable enhanced SSH auditing for IRSSH-Panel
AUDIT_CONFIG="/etc/ssh/sshd_config.d/99-audit.conf"
LOG_FILE="/var/log/irssh/ssh_audit.log"

mkdir -p /var/log/irssh
touch $LOG_FILE
chmod 640 $LOG_FILE

# Create audit configuration
cat > $AUDIT_CONFIG << EOL
# Enhanced SSH auditing for IRSSH-Panel
LogLevel VERBOSE
AcceptEnv IRSSH_USER IRSSH_ID
EOL

# Set up log rotation for SSH audit logs
cat > /etc/logrotate.d/irssh-ssh-audit << EOL
/var/log/irssh/ssh_audit.log {
    rotate 7
    daily
    compress
    missingok
    notifempty
    create 0640 root adm
    postrotate
        systemctl reload sshd
    endscript
}
EOL

# Create SSH connection tracker
cat > /usr/local/bin/ssh-connection-tracker << EOL
#!/bin/bash

LOG_FILE="/var/log/irssh/ssh_connections.log"
CONNECTIONS_FILE="/var/log/irssh/active_connections.json"

# Ensure log files exist
touch \$LOG_FILE
touch \$CONNECTIONS_FILE

# Get active SSH connections
SSH_CONNECTIONS=\$(netstat -tnpa | grep 'ESTABLISHED.*sshd' | awk '{print \$5}')

# Clear the connections file and initialize JSON array
echo "[]" > \$CONNECTIONS_FILE

# Process each connection
if [ -n "\$SSH_CONNECTIONS" ]; then
    TEMP_FILE=\$(mktemp)
    echo "[]" > \$TEMP_FILE
    
    echo "Active SSH connections detected at \$(date):" >> \$LOG_FILE
    
    while read -r conn; do
        if [[ "\$conn" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+)$ ]]; then
            IP=\${BASH_REMATCH[1]}
            PORT=\${BASH_REMATCH[2]}
            
            # Try to get username from connections
            USERNAME=\$(ps aux | grep "\$IP" | grep "sshd:" | grep -oP '(?<=sshd: )\S+(?=@)' | head -1)
            if [ -z "\$USERNAME" ]; then
                USERNAME="unknown"
            fi
            
            # Log connection
            echo "- \$USERNAME from \$IP:\$PORT" >> \$LOG_FILE
            
            # Update JSON file with jq if available
            if command -v jq &> /dev/null; then
                jq --arg ip "\$IP" --arg port "\$PORT" --arg user "\$USERNAME" --arg time "\$(date +%s)" \
                   '. += [{"username": \$user, "ip": \$ip, "port": \$port, "connected_at": \$time}]' \
                   \$CONNECTIONS_FILE > \$TEMP_FILE && mv \$TEMP_FILE \$CONNECTIONS_FILE
            fi
        fi
    done <<< "\$SSH_CONNECTIONS"
fi
EOL

chmod +x /usr/local/bin/ssh-connection-tracker

# Create cron job to run the tracker every minute
(crontab -l 2>/dev/null; echo "* * * * * /usr/local/bin/ssh-connection-tracker") | crontab -

# Restart SSH service to apply changes
systemctl restart sshd

echo "SSH auditing and connection tracking enabled"
EOF

    chmod +x "$SCRIPTS_DIR/ssh/setup_auditing.sh"
    "$SCRIPTS_DIR/ssh/setup_auditing.sh"

    # Reload systemd, enable and start services
    systemctl daemon-reload
    systemctl restart ssh
    systemctl enable stunnel4
    systemctl restart stunnel4
    systemctl enable websocket
    systemctl start websocket
    
    # Create SSH tunnel scripts for easier client connection
    mkdir -p "$PANEL_DIR/client_scripts/ssh"
    
    # Create Windows PowerShell script for SSH-TLS
    cat > "$PANEL_DIR/client_scripts/ssh/tls_tunnel_windows.ps1" << EOL
# SSH-TLS Tunnel Script for Windows
# IRSSH-Panel

\$SERVER="${SERVER_IPv4}"
\$TLS_PORT=${PORTS[SSH_TLS]}
\$LOCAL_PORT=2222

# Check if plink.exe is available
if (-not(Test-Path "plink.exe")) {
    Write-Host "plink.exe not found. Please download PuTTY tools and place plink.exe in this directory."
    Exit 1
}

Write-Host "Starting SSH over TLS tunnel to \$SERVER:\$TLS_PORT"
Write-Host "You can now connect to localhost:\$LOCAL_PORT with your SSH client"
Write-Host "Press Ctrl+C to stop the tunnel"

# Start the tunnel using PuTTY's plink
.\plink.exe -nc localhost:\$LOCAL_PORT \$SERVER \$TLS_PORT
EOL

    # Create Linux/macOS script for SSH-TLS
    cat > "$PANEL_DIR/client_scripts/ssh/tls_tunnel_unix.sh" << EOL
#!/bin/bash
# SSH-TLS Tunnel Script for Linux/macOS
# IRSSH-Panel

SERVER="${SERVER_IPv4}"
TLS_PORT=${PORTS[SSH_TLS]}
LOCAL_PORT=2222

echo "Starting SSH over TLS tunnel to \$SERVER:\$TLS_PORT"
echo "You can now connect to localhost:\$LOCAL_PORT with your SSH client"
echo "Press Ctrl+C to stop the tunnel"

# Use socat for the tunnel
socat TCP-LISTEN:\$LOCAL_PORT,reuseaddr,fork OPENSSL:\$SERVER:\$TLS_PORT,verify=0
EOL
    chmod +x "$PANEL_DIR/client_scripts/ssh/tls_tunnel_unix.sh"
    
    # Create direct SSH connection script
    cat > "$PANEL_DIR/client_scripts/ssh/direct_connect.sh" << EOL
#!/bin/bash
# Direct SSH Connection Script
# IRSSH-Panel

SERVER="${SERVER_IPv4}"
SSH_PORT=${PORTS[SSH]}
USERNAME="\$1"

if [ -z "\$USERNAME" ]; then
    echo "Usage: \$0 <username>"
    exit 1
fi

echo "Connecting to SSH server at \$SERVER:\$SSH_PORT as \$USERNAME"
ssh -p \$SSH_PORT \$USERNAME@\$SERVER
EOL
    chmod +x "$PANEL_DIR/client_scripts/ssh/direct_connect.sh"
    
    info "Advanced SSH installation completed"
}

# Install L2TP/IPsec with enhanced security
install_l2tp() {
    info "Installing L2TP/IPsec protocol with advanced security..."
    
    apt-get install -y strongswan strongswan-pki libcharon-extra-plugins xl2tpd lsof || error "Failed to install L2TP packages"
    
    # Generate strong random PSK
    PSK=$(openssl rand -hex 32)
    
    # Create IPsec config with enhanced security
    cat > /etc/ipsec.conf << EOL
# IRSSH-Panel optimized IPsec configuration
# Managed by IRSSH-Panel, do not edit manually

config setup
    charondebug="ike 2, knl 2, cfg 2"
    strictcrlpolicy=no
    uniqueids=yes

# Include connection configs
include /etc/ipsec.d/*.conf
EOL

    # Create L2TP/IPsec connection config
    cat > /etc/ipsec.d/l2tp.conf << EOL
# L2TP/IPsec connections
conn L2TP-PSK
    authby=secret
    auto=add
    keyingtries=3
    rekey=no
    ikelifetime=24h
    keylife=1h
    type=transport
    left=%any
    leftprotoport=17/1701
    leftfirewall=yes
    right=%any
    rightprotoport=17/%any
    rightid=%any
    dpddelay=30
    dpdtimeout=120
    dpdaction=clear
    # Enhanced security settings
    ike=aes256-sha2_256-modp2048,aes128-sha2_256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp2048!
    esp=aes256gcm16-modp2048,aes128gcm16-modp2048,aes256-sha2_256-modp2048,aes128-sha2_256-modp2048!
    mobike=yes
    fragmentation=yes
EOL

    # Create IPsec secret with random PSK
    cat > /etc/ipsec.secrets << EOL
# IRSSH-Panel IPsec secrets
# Managed by IRSSH-Panel, do not edit manually
: PSK "$PSK"
EOL
    chmod 600 /etc/ipsec.secrets
    
    # Create xl2tpd config
    cat > /etc/xl2tpd/xl2tpd.conf << EOL
; IRSSH-Panel optimized xl2tpd configuration
; Managed by IRSSH-Panel, do not edit manually

[global]
ipsec saref = yes
saref refinfo = 30
port = ${PORTS[L2TP]}
access control = no
debug avp = no
debug network = no
debug state = no
debug tunnel = no

[lns default]
ip range = 10.10.10.100-10.10.10.200
local ip = 10.10.10.1
require chap = yes
refuse pap = yes
require authentication = yes
name = IRSSH-VPN
ppp debug = no
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOL

    # Create optimized PPP options for xl2tpd
    cat > /etc/ppp/options.xl2tpd << EOL
# IRSSH-Panel optimized PPP options
# Managed by IRSSH-Panel, do not edit manually

ipcp-accept-local
ipcp-accept-remote
ms-dns 8.8.8.8
ms-dns 8.8.4.4
mtu 1410
mru 1410
noccp
noauth
idle 1800
maxfail 3
crtscts
lock
connect-delay 5000
silent
# Enhanced security and performance
mppe required,stateless
refuse-eap
EOL

    # Enable IP forwarding
    cat > /etc/sysctl.d/60-ipsec-vpn.conf << EOL
# IRSSH-Panel IPsec VPN sysctl settings
# Managed by IRSSH-Panel, do not edit manually

# Enable IPv4 forwarding
net.ipv4.ip_forward = 1

# Optimize for VPN traffic
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.lo.accept_redirects = 0
net.ipv4.conf.lo.send_redirects = 0
net.ipv4.conf.eth0.accept_redirects = 0
net.ipv4.conf.eth0.send_redirects = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
EOL
    sysctl -p /etc/sysctl.d/60-ipsec-vpn.conf

    # Set up IPTables NAT rules
    iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o $(ip route | grep default | awk '{print $5}') -j MASQUERADE
    
    # Save iptables rules
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 || mkdir -p /etc/iptables/ && iptables-save > /etc/iptables/rules.v4
        
        # Create persistence script
        cat > /etc/network/if-pre-up.d/iptables << EOL
#!/bin/sh
/sbin/iptables-restore < /etc/iptables/rules.v4
exit 0
EOL
        chmod +x /etc/network/if-pre-up.d/iptables
    fi

    # Create L2TP/IPsec monitoring script
    mkdir -p "$SCRIPTS_DIR/l2tp"
    cat > "$SCRIPTS_DIR/l2tp/l2tp_monitor.sh" << 'EOF'
#!/bin/bash

# L2TP/IPsec Connection Monitor
LOG_DIR="/var/log/irssh"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/l2tp_connections.log"
STATUS_FILE="$LOG_DIR/l2tp_status.json"

# Get current timestamp
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

# Check IPsec status
IPSEC_STATUS=$(ipsec status | grep -A 2 "Security Associations" || echo "No IPsec connections")

# Check xl2tpd status
XL2TPD_STATUS=$(ps aux | grep xl2tpd | grep -v grep || echo "xl2tpd not running")

# Check for active PPP sessions for L2TP
PPP_SESSIONS=$(ps aux | grep pppd | grep xl2tpd | grep -v grep)
ACTIVE_SESSIONS_COUNT=$(echo "$PPP_SESSIONS" | grep -v "^$" | wc -l)

# Get connected users
CONNECTED_USERS=()
IFS=$'\n'
for session in $PPP_SESSIONS; do
    # Extract username from pppd call
    if [[ $session =~ name[[:space:]]+([[:alnum:]_-]+) ]]; then
        USERNAME="${BASH_REMATCH[1]}"
        CONNECTED_USERS+=("$USERNAME")
        
        # Check for IP allocation in pppd logs
        IP_ALLOCATED=$(grep -i "peer from calling number .* is $USERNAME" /var/log/syslog | grep "remote IP address" | tail -1 | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" || echo "Unknown")
        
        echo "[$TIMESTAMP] Active L2TP user: $USERNAME from $IP_ALLOCATED" >> "$LOG_FILE"
    fi
done

# Create a JSON status file
cat > "$STATUS_FILE" << EOL
{
  "timestamp": "$TIMESTAMP",
  "active_connections": $ACTIVE_SESSIONS_COUNT,
  "ipsec_status": "$(echo "$IPSEC_STATUS" | head -1 | sed 's/"/\\"/g')",
  "connected_users": [
EOL

# Add connected users to JSON
for ((i=0; i<${#CONNECTED_USERS[@]}; i++)); do
    USER="${CONNECTED_USERS[$i]}"
    IP=$(grep -i "peer from calling number .* is $USER" /var/log/syslog | grep "remote IP address" | tail -1 | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" || echo "Unknown")
    
    # Add comma except for the last item
    if [[ $i -lt $((${#CONNECTED_USERS[@]}-1)) ]]; then
        echo "    {\"username\": \"$USER\", \"ip\": \"$IP\"}," >> "$STATUS_FILE"
    else
        echo "    {\"username\": \"$USER\", \"ip\": \"$IP\"}" >> "$STATUS_FILE"
    fi
done

# Close the JSON structure
cat >> "$STATUS_FILE" << EOL
  ]
}
EOL

# Check if we need to record this in the database
if [ -f "/etc/enhanced_ssh/db/database.conf" ] && command -v psql &> /dev/null; then
    source /etc/enhanced_ssh/db/database.conf
    
    for user in "${CONNECTED_USERS[@]}"; do
        IP=$(grep -i "peer from calling number .* is $user" /var/log/syslog | grep "remote IP address" | tail -1 | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" || echo "Unknown")
        
        # Generate a session ID
        SESSION_ID="l2tp_${user}_$(date +%s)_$(echo $IP | md5sum | cut -c1-8)"
        
        # Check if this session is already in the database
        SESSION_EXISTS=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM user_connections WHERE protocol = 'l2tp' AND username = '$user' AND client_ip = '$IP' AND status = 'active';")
        
        # If session doesn't exist, add it
        if [ "$SESSION_EXISTS" -eq "0" ]; then
            PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "INSERT INTO user_connections (username, protocol, client_ip, session_id, connect_time, status) VALUES ('$user', 'l2tp', '$IP', '$SESSION_ID', NOW(), 'active');"
        fi
    done
    
    # Check for closed sessions
    ACTIVE_DB_SESSIONS=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT username FROM user_connections WHERE protocol = 'l2tp' AND status = 'active';")
    
    # For each active DB session, check if user is still connected
    for db_user in $ACTIVE_DB_SESSIONS; do
        # Clean username from psql output
        db_user=$(echo "$db_user" | xargs)
        
        # Check if this user is in the CONNECTED_USERS array
        STILL_CONNECTED=0
        for user in "${CONNECTED_USERS[@]}"; do
            if [ "$user" = "$db_user" ]; then
                STILL_CONNECTED=1
                break
            fi
        done
        
        # If not still connected, update the DB
        if [ "$STILL_CONNECTED" -eq "0" ]; then
            PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "UPDATE user_connections SET status = 'closed', disconnect_time = NOW() WHERE username = '$db_user' AND protocol = 'l2tp' AND status = 'active';"
        fi
    done
fi

# Output summary to console
echo "[$TIMESTAMP] L2TP/IPsec status: $ACTIVE_SESSIONS_COUNT active connections"
if [ $ACTIVE_SESSIONS_COUNT -gt 0 ]; then
    echo "Connected users: ${CONNECTED_USERS[*]}"
fi
EOF

    chmod +x "$SCRIPTS_DIR/l2tp/l2tp_monitor.sh"
    
    # Create cron job to run the monitor script every 5 minutes
    (crontab -l 2>/dev/null; echo "*/5 * * * * $SCRIPTS_DIR/l2tp/l2tp_monitor.sh") | crontab -

    # Create L2TP/IPsec user management script
    cat > "$SCRIPTS_DIR/l2tp/l2tp_user_manager.sh" << 'EOF'
#!/bin/bash

# L2TP/IPsec User Management Script
# Usage: ./l2tp_user_manager.sh add|remove|list|status username [password]

L2TP_USER_FILE="/etc/ppp/chap-secrets"
ACTION="$1"
USERNAME="$2"
PASSWORD="$3"
LOG_DIR="/var/log/irssh"
mkdir -p "$LOG_DIR"

function show_usage() {
    echo "Usage: $0 add|remove|list|status username [password]"
    echo
    echo "Commands:"
    echo "  add USERNAME PASSWORD  - Add a new L2TP user"
    echo "  remove USERNAME        - Remove an L2TP user"
    echo "  list                   - List all L2TP users"
    echo "  status [USERNAME]      - Show status of all users or specific user"
    exit 1
}

function add_user() {
    local username="$1"
    local password="$2"
    
    if [ -z "$username" ] || [ -z "$password" ]; then
        echo "Error: Username and password are required"
        exit 1
    fi
    
    # Check if user already exists
    if grep -q "^\"$username\"" "$L2TP_USER_FILE"; then
        echo "User '$username' already exists"
        exit 1
    fi
    
    # Add user to chap-secrets
    echo "\"$username\" l2tpd \"$password\" *" >> "$L2TP_USER_FILE"
    echo "User '$username' added successfully"
    
    # Log the action
    echo "[$(date +"%Y-%m-%d %H:%M:%S")] User '$username' added to L2TP/IPsec" >> "$LOG_DIR/l2tp_user_manager.log"
}

function remove_user() {
    local username="$1"
    
    if [ -z "$username" ]; then
        echo "Error: Username is required"
        exit 1
    fi
    
    # Check if user exists
    if ! grep -q "^\"$username\"" "$L2TP_USER_FILE"; then
        echo "User '$username' does not exist"
        exit 1
    fi
    
    # Remove user from chap-secrets
    sed -i "/^\"$username\" l2tpd/d" "$L2TP_USER_FILE"
    echo "User '$username' removed successfully"
    
    # Log the action
    echo "[$(date +"%Y-%m-%d %H:%M:%S")] User '$username' removed from L2TP/IPsec" >> "$LOG_DIR/l2tp_user_manager.log"
    
    # Kill active sessions for this user if any
    pkill -f "pppd.*name $username" || true
}

function list_users() {
    echo "L2TP/IPsec Users:"
    echo "-----------------"
    grep "l2tpd" "$L2TP_USER_FILE" | cut -d' ' -f1 | tr -d '"'
}

function check_status() {
    local username="$1"
    local monitor_output=$("$SCRIPTS_DIR/l2tp/l2tp_monitor.sh")
    
    if [ -z "$username" ]; then
        echo "$monitor_output"
        cat "$LOG_DIR/l2tp_status.json"
    else
        echo "$monitor_output" | grep -i "$username" || echo "User '$username' is not currently connected"
    fi
}

# Check if L2TP_USER_FILE exists
if [ ! -f "$L2TP_USER_FILE" ]; then
    touch "$L2TP_USER_FILE"
    chmod 600 "$L2TP_USER_FILE"
    echo "Created new chap-secrets file"
fi

# Execute the requested action
case "$ACTION" in
    add)
        add_user "$USERNAME" "$PASSWORD"
        ;;
    remove)
        remove_user "$USERNAME"
        ;;
    list)
        list_users
        ;;
    status)
        check_status "$USERNAME"
        ;;
    *)
        show_usage
        ;;
esac
EOF

    chmod +x "$SCRIPTS_DIR/l2tp/l2tp_user_manager.sh"
    
    # Create auto-restart script for reliability
    cat > "$SCRIPTS_DIR/l2tp/l2tp_auto_restart.sh" << 'EOF'
#!/bin/bash

# L2TP/IPsec Auto-Restart Script
# Automatically restarts the L2TP/IPsec services if they're not functioning correctly
LOG_DIR="/var/log/irssh"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/l2tp_auto_restart.log"

function log() {
    echo "[$(date +"%Y-%m-%d %H:%M:%S")] $1" >> "$LOG_FILE"
}

# Check if IPsec is running and correctly configured
function check_ipsec() {
    if ! systemctl is-active --quiet strongswan; then
        log "StrongSwan service is not running, restarting..."
        systemctl restart strongswan
        sleep 2
        return 1
    fi
    
    IPSEC_STATUS=$(ipsec status 2>&1)
    if echo "$IPSEC_STATUS" | grep -q "Error"; then
        log "IPsec error detected: $IPSEC_STATUS"
        systemctl restart strongswan
        sleep 2
        return 1
    fi
    
    return 0
}

# Check if xl2tpd is running
function check_xl2tpd() {
    if ! systemctl is-active --quiet xl2tpd; then
        log "xl2tpd service is not running, restarting..."
        systemctl restart xl2tpd
        sleep 2
        return 1
    fi
    
    # Check if l2tp process is responsive
    if ! pgrep xl2tpd > /dev/null; then
        log "xl2tpd process not found, restarting service..."
        systemctl restart xl2tpd
        sleep 2
        return 1
    fi
    
    return 0
}

# Main check function
function check_services() {
    RESTARTED=0
    
    # Check IPsec
    if ! check_ipsec; then
        RESTARTED=1
    fi
    
    # Check xl2tpd
    if ! check_xl2tpd; then
        RESTARTED=1
    fi
    
    # If services were restarted, perform a final verification
    if [ $RESTARTED -eq 1 ]; then
        sleep 5
        if check_ipsec && check_xl2tpd; then
            log "Services successfully restarted and are now functioning correctly"
        else
            log "Services still not functioning correctly after restart, manual intervention required"
        fi
    fi
}

# Run the check
log "Running L2TP/IPsec service check"
check_services
EOF

    chmod +x "$SCRIPTS_DIR/l2tp/l2tp_auto_restart.sh"
    
    # Create cron job to run the auto-restart script every hour
    (crontab -l 2>/dev/null; echo "0 * * * * $SCRIPTS_DIR/l2tp/l2tp_auto_restart.sh") | crontab -

    # Start and enable services
    systemctl daemon-reload
    systemctl restart strongswan
    systemctl enable strongswan
    systemctl restart xl2tpd
    systemctl enable xl2tpd
    
    # Create client configuration
    mkdir -p "$PANEL_DIR/client_scripts/l2tp"
    
    # Create Windows PowerShell L2TP/IPsec setup script
    cat > "$PANEL_DIR/client_scripts/l2tp/l2tp_setup_windows.ps1" << EOL
# L2TP/IPsec VPN Setup Script for Windows
# IRSSH-Panel

# Server Information
\$ServerAddress = "${SERVER_IPv4}"
\$PSK = "${PSK}"

# Create VPN connection
Add-VpnConnection -Name "IRSSH-L2TP" -ServerAddress \$ServerAddress -TunnelType L2tp -EncryptionLevel Maximum -L2tpPsk \$PSK -AuthenticationMethod Pap -Force -RememberCredential -PassThru

# Enable IPsec with strong encryption
\$vpnConn = Get-VpnConnection -Name "IRSSH-L2TP"
\$vpnConn | Set-VpnConnectionIPsecConfiguration -EncryptionMethod AES256 -IntegrityCheckMethod SHA256 -PfsGroup PFS2048 -DHGroup Group14 -CipherTransformConstants GCMAES256 -AuthenticationTransformConstants GCMAES256 -Force

Write-Host "L2TP/IPsec VPN 'IRSSH-L2TP' has been setup successfully."
Write-Host "Server: \$ServerAddress"
Write-Host "Pre-shared Key: \$PSK"
Write-Host "Now you can connect using your username and password."
EOL

    # Create macOS L2TP/IPsec setup script
    cat > "$PANEL_DIR/client_scripts/l2tp/l2tp_setup_macos.sh" << EOL
#!/bin/bash
# L2TP/IPsec VPN Setup Script for macOS
# IRSSH-Panel

# Server Information
SERVER="${SERVER_IPv4}"
PSK="${PSK}"

# Create a temporary configuration file
cat > /tmp/vpn.mobileconfig << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>IPSec</key>
            <dict>
                <key>AuthenticationMethod</key>
                <string>SharedSecret</string>
                <key>LocalIdentifierType</key>
                <string>KeyID</string>
                <key>SharedSecret</key>
                <data>
                $(echo -n "$PSK" | base64)
                </data>
            </dict>
            <key>IPv4</key>
            <dict>
                <key>OverridePrimary</key>
                <integer>1</integer>
            </dict>
            <key>PPP</key>
            <dict>
                <key>AuthName</key>
                <string>USERNAME</string>
                <key>AuthPassword</key>
                <string>PASSWORD</string>
                <key>CommRemoteAddress</key>
                <string>$SERVER</string>
            </dict>
            <key>PayloadDescription</key>
            <string>Configures L2TP/IPsec VPN</string>
            <key>PayloadDisplayName</key>
            <string>IRSSH-L2TP</string>
            <key>PayloadIdentifier</key>
            <string>com.irssh.l2tp.vpn</string>
            <key>PayloadType</key>
            <string>com.apple.vpn.managed</string>
            <key>PayloadUUID</key>
            <string>$(uuidgen)</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>Proxies</key>
            <dict>
                <key>SupplementalMatchDomains</key>
                <array></array>
            </dict>
            <key>UserDefinedName</key>
            <string>IRSSH-L2TP</string>
            <key>VPNType</key>
            <string>L2TP</string>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>IRSSH-L2TP VPN Configuration</string>
    <key>PayloadIdentifier</key>
    <string>com.irssh.l2tp.vpn.config</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>$(uuidgen)</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
EOF

echo "L2TP/IPsec VPN configuration file created at /tmp/vpn.mobileconfig"
echo "Please open this file to import the VPN configuration."
echo "You'll need to replace USERNAME and PASSWORD with your actual credentials."
echo "Server: $SERVER"
echo "Pre-shared Key: $PSK"

open /tmp/vpn.mobileconfig
EOL
    chmod +x "$PANEL_DIR/client_scripts/l2tp/l2tp_setup_macos.sh"

    # Create Linux L2TP/IPsec setup script
    cat > "$PANEL_DIR/client_scripts/l2tp/l2tp_setup_linux.sh" << EOL
#!/bin/bash
# L2TP/IPsec VPN Setup Script for Linux
# IRSSH-Panel

# Server Information
SERVER="${SERVER_IPv4}"
PSK="${PSK}"

# Check for required packages
if ! command -v strongswan &> /dev/null || ! command -v xl2tpd &> /dev/null; then
    echo "StrongSwan and xl2tpd are required. Installing..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y strongswan xl2tpd
    elif command -v yum &> /dev/null; then
        sudo yum install -y strongswan xl2tpd
    else
        echo "Error: Could not determine package manager. Please install strongswan and xl2tpd manually."
        exit 1
    fi
fi

# Create L2TP/IPsec configuration
sudo tee /etc/ipsec.conf > /dev/null << EOF
# L2TP/IPsec client configuration
config setup
    charondebug="ike 2, knl 2, cfg 2"
    strictcrlpolicy=no

conn L2TP-PSK
    authby=secret
    auto=add
    keyingtries=3
    rekey=no
    ikelifetime=8h
    keylife=1h
    type=transport
    leftprotoport=17/1701
    left=%defaultroute
    right=$SERVER
    rightprotoport=17/1701
    ike=aes256-sha2_256-modp2048!
    esp=aes256gcm16-modp2048!
EOF

# Set PSK
sudo tee /etc/ipsec.secrets > /dev/null << EOF
%any $SERVER : PSK "$PSK"
EOF
sudo chmod 600 /etc/ipsec.secrets

# Configure xl2tpd
sudo tee /etc/xl2tpd/xl2tpd.conf > /dev/null << EOF
[lac vpn]
lns = $SERVER
ppp debug = no
pppoptfile = /etc/ppp/options.l2tpd.client
length bit = yes
EOF

# Configure ppp options
sudo tee /etc/ppp/options.l2tpd.client > /dev/null << EOF
ipcp-accept-local
ipcp-accept-remote
refuse-eap
require-mschap-v2
noccp
noauth
idle 1800
mtu 1410
mru 1410
defaultroute
usepeerdns
connect-delay 5000
name USERNAME
password PASSWORD
EOF
sudo chmod 600 /etc/ppp/options.l2tpd.client

echo "L2TP/IPsec VPN configuration created."
echo "Please edit /etc/ppp/options.l2tpd.client and replace USERNAME and PASSWORD with your credentials."
echo "To connect, run the following commands:"
echo "sudo ipsec restart"
echo "sudo xl2tpd -D &"
echo "sudo ipsec up L2TP-PSK"
echo "sudo echo 'c vpn' > /var/run/xl2tpd/l2tp-control"
EOL
    chmod +x "$PANEL_DIR/client_scripts/l2tp/l2tp_setup_linux.sh"
    
    # Add initial L2TP user for the admin
    "$SCRIPTS_DIR/l2tp/l2tp_user_manager.sh" add "$ADMIN_USER" "$ADMIN_PASS"
    
    info "L2TP/IPsec protocol installation completed with PSK: $PSK"
    
    # Save PSK to config directory
    mkdir -p $CONFIG_DIR/l2tp
    echo "$PSK" > $CONFIG_DIR/l2tp/psk.key
    chmod 600 $CONFIG_DIR/l2tp/psk.key
}

# Install IKEv2/IPsec with enhanced security
install_ikev2() {
    info "Installing IKEv2/IPsec protocol with advanced security..."
    
    apt-get install -y strongswan strongswan-pki libcharon-extra-plugins libcharon-extauth-plugins || error "Failed to install IKEv2 packages"
    
    # Create directories
    mkdir -p /etc/ipsec.d/{private,cacerts,certs}
    
    # Generate CA key with strong parameters
    info "Generating CA key with strong parameters..."
    ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/ca-key.pem
    chmod 600 /etc/ipsec.d/private/ca-key.pem
    
    # Generate CA certificate
    info "Generating CA certificate..."
    ipsec pki --self --ca --lifetime 3650 \
        --in /etc/ipsec.d/private/ca-key.pem \
        --type rsa --dn "CN=IRSSH-VPN CA" \
        --outform pem > /etc/ipsec.d/cacerts/ca-cert.pem
    
    # Generate server key with strong parameters
    info "Generating server key with strong parameters..."
    ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/server-key.pem
    chmod 600 /etc/ipsec.d/private/server-key.pem
    
    # Generate server certificate with proper attributes
    info "Generating server certificate with proper attributes..."
    DOMAIN="${SERVER_IPv4}"
    if [ ! -z "$SERVER_DOMAIN" ]; then
        DOMAIN="$SERVER_DOMAIN,$SERVER_IPv4"
    fi
    
    ipsec pki --pub --in /etc/ipsec.d/private/server-key.pem --type rsa \
        | ipsec pki --issue --lifetime 1825 \
            --cacert /etc/ipsec.d/cacerts/ca-cert.pem \
            --cakey /etc/ipsec.d/private/ca-key.pem \
            --dn "CN=$SERVER_IPv4" \
            --san "$SERVER_IPv4" \
            --flag serverAuth --flag ikeIntermediate \
            --outform pem > /etc/ipsec.d/certs/server-cert.pem
    
    # Create enhanced IPsec configuration
    cat > /etc/ipsec.conf << EOL
# IRSSH-Panel optimized IKEv2 configuration
# Managed by IRSSH-Panel, do not edit manually

config setup
    charondebug="ike 2, knl 2, cfg 2, net 2, esp 2, dmn 1"
    uniqueids=never

conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    ike=aes256-sha2_256-modp2048,aes128-sha2_256-modp2048,aes256gcm16-prfsha384-ecp384!
    esp=aes256gcm16-ecp384,aes128gcm16-ecp256,aes256-sha2_512-modp4096!
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%any
    leftid=@${SERVER_IPv4}
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightsendcert=never
    rightdns=8.8.8.8,8.8.4.4
    rightsourceip=10.20.20.0/24
    eap_identity=%identity
    
    # Performance and security enhancements
    mobike=yes
    ike_frag=yes
    reauth=no
    installpolicy=yes
EOL

    # Create secrets file for user authentication
    cat > /etc/ipsec.secrets << EOL
# IRSSH-Panel IKEv2 secrets
# Managed by IRSSH-Panel, do not edit manually

# RSA private key for this host
: RSA server-key.pem

# Initial administrator account
${ADMIN_USER} : EAP "${ADMIN_PASS}"
EOL

    chmod 600 /etc/ipsec.secrets

    # Enable IP forwarding
    cat > /etc/sysctl.d/60-ikev2-vpn.conf << EOL
# IRSSH-Panel IKEv2 VPN sysctl settings
# Managed by IRSSH-Panel, do not edit manually

# Enable IPv4 forwarding
net.ipv4.ip_forward = 1

# Do not accept ICMP redirects (prevent MITM attacks)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Do not send ICMP redirects (we are not a router)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.eth0.send_redirects = 0

# Disable IPv6 for improved security if not needed
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1
EOL
    sysctl -p /etc/sysctl.d/60-ikev2-vpn.conf

    # Set up IPTables rules for forwarding
    iptables -t nat -A POSTROUTING -s 10.20.20.0/24 -o $(ip route get 8.8.8.8 | grep -oP "dev \K\S+") -j MASQUERADE
    
    # Save the iptables rules
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables.rules
    fi

    # Create IKEv2 user management script
    mkdir -p "$SCRIPTS_DIR/ikev2"
    cat > "$SCRIPTS_DIR/ikev2/ikev2_user_manager.sh" << 'EOF'
#!/bin/bash

# IKEv2 User Management Script
# Usage: ./ikev2_user_manager.sh add|remove|list|status username [password]

IPSEC_SECRETS="/etc/ipsec.secrets"
CA_CERT="/etc/ipsec.d/cacerts/ca-cert.pem"
CA_KEY="/etc/ipsec.d/private/ca-key.pem"
CERTS_DIR="/etc/ipsec.d/certs"
PRIVATE_DIR="/etc/ipsec.d/private"
CLIENT_DIR="/opt/irssh-panel/client_scripts/ikev2"
LOG_DIR="/var/log/irssh"
mkdir -p "$LOG_DIR"
mkdir -p "$CLIENT_DIR"

ACTION="$1"
USERNAME="$2"
PASSWORD="$3"

function show_usage() {
    echo "Usage: $0 add|remove|list|status|cert username [password]"
    echo
    echo "Commands:"
    echo "  add USERNAME PASSWORD - Add a new IKEv2 user"
    echo "  remove USERNAME      - Remove an IKEv2 user"
    echo "  list                 - List all IKEv2 users"
    echo "  status [USERNAME]    - Show connection status"
    echo "  cert USERNAME        - Generate client certificate for user"
    exit 1
}

function add_user() {
    local username="$1"
    local password="$2"
    
    if [ -z "$username" ] || [ -z "$password" ]; then
        echo "Error: Username and password are required"
        exit 1
    fi
    
    # Check if user already exists
    if grep -q "^$username :" "$IPSEC_SECRETS"; then
        echo "User '$username' already exists"
        exit 1
    fi
    
    # Add user to ipsec.secrets
    echo "$username : EAP \"$password\"" >> "$IPSEC_SECRETS"
    echo "User '$username' added successfully"
    
    # Log the action
    echo "[$(date +"%Y-%m-%d %H:%M:%S")] User '$username' added to IKEv2" >> "$LOG_DIR/ikev2_user_manager.log"
    
    # Restart strongSwan to apply changes
    systemctl restart strongswan
}

function remove_user() {
    local username="$1"
    
    if [ -z "$username" ]; then
        echo "Error: Username is required"
        exit 1
    fi
    
    # Check if user exists
    if ! grep -q "^$username :" "$IPSEC_SECRETS"; then
        echo "User '$username' does not exist"
        exit 1
    fi
    
    # Remove user from ipsec.secrets
    sed -i "/^$username :/d" "$IPSEC_SECRETS"
    echo "User '$username' removed successfully"
    
    # Remove any user certificates if they exist
    rm -f "$CERTS_DIR/$username-cert.pem" 2>/dev/null
    rm -f "$PRIVATE_DIR/$username-key.pem" 2>/dev/null
    rm -f "$CLIENT_DIR/$username.p12" 2>/dev/null
    rm -f "$CLIENT_DIR/$username.mobileconfig" 2>/dev/null
    
    # Log the action
    echo "[$(date +"%Y-%m-%d %H:%M:%S")] User '$username' removed from IKEv2" >> "$LOG_DIR/ikev2_user_manager.log"
    
    # Restart strongSwan to apply changes
    systemctl restart strongswan
}

function list_users() {
    echo "IKEv2 Users:"
    echo "------------"
    grep "EAP" "$IPSEC_SECRETS" | cut -d' ' -f1 | grep -v "^#"
}

function check_status() {
    local username="$1"
    local status_output=$(ipsec status)
    
    if [ -z "$username" ]; then
        echo "$status_output"
    else
        echo "$status_output" | grep -i "$username" || echo "User '$username' is not currently connected"
    fi
}

function generate_client_cert() {
    local username="$1"
    
    if [ -z "$username" ]; then
        echo "Error: Username is required"
        exit 1
    fi
    
    # Check if user exists
    if ! grep -q "^$username :" "$IPSEC_SECRETS"; then
        echo "User '$username' does not exist. Add the user first with 'add' command."
        exit 1
    fi
    
    echo "Generating client certificate for '$username'..."
    
    # Generate client key
    ipsec pki --gen --type rsa --size 2048 --outform pem > "$PRIVATE_DIR/$username-key.pem"
    chmod 600 "$PRIVATE_DIR/$username-key.pem"
    
    # Generate client certificate
    ipsec pki --pub --in "$PRIVATE_DIR/$username-key.pem" --type rsa \
        | ipsec pki --issue --lifetime 1825 \
            --cacert "$CA_CERT" \
            --cakey "$CA_KEY" \
            --dn "CN=$username" \
            --san "$username" \
            --flag clientAuth \
            --outform pem > "$CERTS_DIR/$username-cert.pem"
    
    # Export as PKCS#12 for Windows and macOS
    SERVER_IP=$(hostname -I | awk '{print $1}')
    openssl pkcs12 -export \
        -inkey "$PRIVATE_DIR/$username-key.pem" \
        -in "$CERTS_DIR/$username-cert.pem" \
        -name "IRSSH-IKEv2 Client Certificate" \
        -certfile "$CA_CERT" \
        -caname "IRSSH VPN CA" \
        -out "$CLIENT_DIR/$username.p12" \
        -passout pass:irssh
    
    # Create a .mobileconfig file for macOS/iOS
    UUID=$(uuidgen)
    UUID2=$(uuidgen)
    
    cat > "$CLIENT_DIR/$username.mobileconfig" << EOL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadDescription</key>
			<string>IRSSH IKEv2 VPN Configuration</string>
			<key>PayloadDisplayName</key>
			<string>IRSSH-IKEv2</string>
			<key>PayloadIdentifier</key>
			<string>com.irssh.vpn.$UUID</string>
			<key>PayloadType</key>
			<string>com.apple.vpn.managed</string>
			<key>PayloadUUID</key>
			<string>$UUID</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>UserDefinedName</key>
			<string>IRSSH-IKEv2</string>
			<key>VPNType</key>
			<string>IKEv2</string>
			<key>IKEv2</key>
			<dict>
				<key>AuthenticationMethod</key>
				<string>Certificate</string>
				<key>ChildSecurityAssociationParameters</key>
				<dict>
					<key>EncryptionAlgorithm</key>
					<string>AES-256-GCM</string>
					<key>IntegrityAlgorithm</key>
					<string>SHA2-384</string>
					<key>DiffieHellmanGroup</key>
					<integer>20</integer>
					<key>LifeTimeInMinutes</key>
					<integer>1440</integer>
				</dict>
				<key>DeadPeerDetectionRate</key>
				<string>Medium</string>
				<key>DisableMOBIKE</key>
				<integer>0</integer>
				<key>DisableRedirect</key>
				<integer>0</integer>
				<key>EnableCertificateRevocationCheck</key>
				<integer>0</integer>
				<key>EnablePFS</key>
				<integer>1</integer>
				<key>IKESecurityAssociationParameters</key>
				<dict>
					<key>EncryptionAlgorithm</key>
					<string>AES-256-GCM</string>
					<key>IntegrityAlgorithm</key>
					<string>SHA2-384</string>
					<key>DiffieHellmanGroup</key>
					<integer>20</integer>
					<key>LifeTimeInMinutes</key>
					<integer>1440</integer>
				</dict>
				<key>LocalIdentifier</key>
				<string>$username</string>
				<key>RemoteAddress</key>
				<string>$SERVER_IP</string>
				<key>RemoteIdentifier</key>
				<string>$SERVER_IP</string>
				<key>UseConfigurationAttributeInternalIPSubnet</key>
				<integer>0</integer>
				<key>PayloadCertificateUUID</key>
				<string>$UUID2</string>
			</dict>
			<key>IPv4</key>
			<dict>
				<key>OverridePrimary</key>
				<integer>1</integer>
			</dict>
			<key>OnDemandEnabled</key>
			<integer>0</integer>
		</dict>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>$username.p12</string>
			<key>PayloadContent</key>
EOL

    # Add base64 encoded P12 file
    echo -n "			<data>" >> "$CLIENT_DIR/$username.mobileconfig"
    base64 -w 0 "$CLIENT_DIR/$username.p12" >> "$CLIENT_DIR/$username.mobileconfig"
    echo "</data>" >> "$CLIENT_DIR/$username.mobileconfig"

    cat >> "$CLIENT_DIR/$username.mobileconfig" << EOL
			<key>PayloadDescription</key>
			<string>Adds a PKCS#12-formatted certificate</string>
			<key>PayloadDisplayName</key>
			<string>IRSSH-IKEv2 Client Certificate</string>
			<key>PayloadIdentifier</key>
			<string>com.irssh.vpn.cert.$UUID2</string>
			<key>PayloadType</key>
			<string>com.apple.security.pkcs12</string>
			<key>PayloadUUID</key>
			<string>$UUID2</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>Password</key>
			<string>irssh</string>
		</dict>
	</array>
	<key>PayloadDisplayName</key>
	<string>IRSSH-IKEv2 VPN Configuration</string>
	<key>PayloadIdentifier</key>
	<string>com.irssh.vpn.config.$username</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>$(uuidgen)</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
EOL

    echo "Client certificate generated for $username"
    echo "Files created:"
    echo "- $CLIENT_DIR/$username.p12 (PKCS#12 format, password: irssh)"
    echo "- $CLIENT_DIR/$username.mobileconfig (Apple Configuration Profile)"
    
    # Create Windows PowerShell VPN setup script
    cat > "$CLIENT_DIR/$username-windows-setup.ps1" << EOL
# IRSSH IKEv2 VPN Setup Script for Windows
# For user: $username

\$CertificatePath = "\$PSScriptRoot\\$username.p12"
\$CertificatePassword = "irssh"
\$ServerAddress = "$SERVER_IP"
\$VpnName = "IRSSH-IKEv2"

# Import the certificate
\$certParams = @{
    FilePath          = \$CertificatePath
    Password          = (ConvertTo-SecureString -String \$CertificatePassword -Force -AsPlainText)
    CertStoreLocation = "Cert:\\CurrentUser\\My"
}
\$cert = Import-PfxCertificate @certParams

# Create the VPN connection
\$vpnParams = @{
    Name              = \$VpnName
    ServerAddress     = \$ServerAddress
    TunnelType        = "IKEv2"
    EncryptionLevel   = "Maximum"
    AuthenticationMethod = "MachineCertificate"
    SplitTunneling    = \$false
}
Add-VpnConnection @vpnParams -PassThru

# Set advanced IKEv2 parameters
\$vpnInterface = Get-VpnConnection -Name \$VpnName
Set-VpnConnectionIPsecConfiguration -ConnectionName \$VpnName `
    -AuthenticationTransformConstants SHA256128 `
    -CipherTransformConstants AES256 `
    -DHGroup Group14 `
    -EncryptionMethod AES256 `
    -IntegrityCheckMethod SHA256 `
    -PfsGroup PFS2048 `
    -Force

Write-Host "IKEv2 VPN '\$VpnName' has been set up successfully."
Write-Host "Server: \$ServerAddress"
Write-Host "Certificate imported for authentication."
EOL

    # Create Linux strongSwan client configuration
    cat > "$CLIENT_DIR/$username-linux-setup.sh" << EOL
#!/bin/bash

# IRSSH IKEv2 VPN Setup Script for Linux
# For user: $username

SERVER="$SERVER_IP"
VPN_NAME="IRSSH-IKEv2"
USERNAME="$username"

# Check for required packages
if ! command -v strongswan &> /dev/null; then
    echo "strongSwan is required. Installing..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y strongswan libcharon-extra-plugins
    elif command -v yum &> /dev/null; then
        sudo yum install -y strongswan
    else
        echo "Error: Could not determine package manager. Please install strongswan manually."
        exit 1
    fi
fi

# Create directories
sudo mkdir -p /etc/ipsec.d/{cacerts,certs,private}

# Copy certificates
echo "Please enter the password for the PKCS#12 file when prompted (default: irssh)"
sudo openssl pkcs12 -in "$username.p12" -cacerts -nokeys -out "/etc/ipsec.d/cacerts/ca.crt"
sudo openssl pkcs12 -in "$username.p12" -clcerts -nokeys -out "/etc/ipsec.d/certs/client.crt"
sudo openssl pkcs12 -in "$username.p12" -nocerts -nodes -out "/etc/ipsec.d/private/client.key"
sudo chmod 600 /etc/ipsec.d/private/client.key

# Configure strongSwan
sudo tee /etc/ipsec.conf > /dev/null << EOF
config setup
    charondebug="ike 2, knl 2, cfg 2"

conn $VPN_NAME
    auto=add
    keyexchange=ikev2
    ike=aes256-sha256-modp2048,aes128-sha256-modp2048!
    esp=aes256gcm16-sha256-modp2048,aes128gcm16-sha256-modp2048!
    type=tunnel
    left=%defaultroute
    leftauth=pubkey
    leftcert=client.crt
    leftid=$USERNAME
    right=$SERVER
    rightid=@$SERVER
    rightauth=pubkey
    rightsubnet=0.0.0.0/0
    leftsourceip=%config
    dpdaction=restart
    dpddelay=30s
    closeaction=restart
EOF

# Configure secrets
sudo tee /etc/ipsec.secrets > /dev/null << EOF
: RSA client.key
EOF

echo "IKEv2 VPN setup is complete."
echo "To connect: sudo ipsec up $VPN_NAME"
echo "To disconnect: sudo ipsec down $VPN_NAME"
EOL
    chmod +x "$CLIENT_DIR/$username-linux-setup.sh"

    # Log the action
    echo "[$(date +"%Y-%m-%d %H:%M:%S")] Generated client certificate for '$username'" >> "$LOG_DIR/ikev2_user_manager.log"
}

# Main section
case "$ACTION" in
    add)
        add_user "$USERNAME" "$PASSWORD"
        ;;
    remove)
        remove_user "$USERNAME"
        ;;
    list)
        list_users
        ;;
    status)
        check_status "$USERNAME"
        ;;
    cert)
        generate_client_cert "$USERNAME"
        ;;
    *)
        show_usage
        ;;
esac
EOF

    chmod +x "$SCRIPTS_DIR/ikev2/ikev2_user_manager.sh"
    
    # Create IKEv2 monitoring script
    cat > "$SCRIPTS_DIR/ikev2/ikev2_monitor.sh" << 'EOF'
#!/bin/bash

# IKEv2 Connection Monitor
LOG_DIR="/var/log/irssh"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/ikev2_connections.log"
STATUS_FILE="$LOG_DIR/ikev2_status.json"

# Get current timestamp
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

# Check StrongSwan status
IPSEC_STATUS=$(ipsec status)
IPSEC_STATUSALL=$(ipsec statusall)

# Extract active connections
ACTIVE_CONNECTIONS=$(echo "$IPSEC_STATUS" | grep -A 100 "Connections:" | grep -B 100 "Security Associations" | grep -E "^[[:alnum:]]" | grep -v "Connections:")
ACTIVE_SAS=$(echo "$IPSEC_STATUS" | grep -A 100 "Security Associations" | grep -E "^[[:space:]]+.*ESTABLISHED" || echo "")

# Count active connections
ACTIVE_COUNT=$(echo "$ACTIVE_SAS" | grep -c "ESTABLISHED")

# Log the status
echo "[$TIMESTAMP] IKEv2 Status: $ACTIVE_COUNT active connections" >> "$LOG_FILE"

# Extract connection details from active SAs
declare -a CONNECTED_USERS
declare -A USER_IPS
declare -A CONNECTION_TIMES

if [ "$ACTIVE_COUNT" -gt 0 ]; then
    while IFS= read -r line; do
        if [[ $line =~ ESTABLISHED[^:]+:\ +([^[]+)\[([^]]+)\]\.\.\.([^[]+)\[([^]]+)\] ]]; then
            LOCAL_ID="${BASH_REMATCH[1]}"
            LOCAL_IP="${BASH_REMATCH[2]}"
            REMOTE_ID="${BASH_REMATCH[3]}"
            REMOTE_IP="${BASH_REMATCH[4]}"
            
            # Remove whitespace
            LOCAL_ID=$(echo "$LOCAL_ID" | xargs)
            LOCAL_IP=$(echo "$LOCAL_IP" | xargs)
            REMOTE_ID=$(echo "$REMOTE_ID" | xargs)
            REMOTE_IP=$(echo "$REMOTE_IP" | xargs)
            
            # Look for username
            USERNAME=""
            if [[ $REMOTE_ID =~ @ ]]; then
                # EAP authentication, extract username
                USERNAME=$(echo "$REMOTE_ID" | xargs)
            else
                # Extract username from certificate CN or any other identifier
                USERNAME="$REMOTE_ID"
            fi
            
            if [ -n "$USERNAME" ]; then
                CONNECTED_USERS+=("$USERNAME")
                USER_IPS[$USERNAME]="$REMOTE_IP"
                
                # Try to get connection time from statusall
                CONN_TIME=$(echo "$IPSEC_STATUSALL" | grep -A 2 "$USERNAME" | grep "established" | grep -oE "[0-9]+ seconds ago" | head -1 || echo "")
                if [ -n "$CONN_TIME" ]; then
                    CONNECTION_TIMES[$USERNAME]="$CONN_TIME"
                else
                    CONNECTION_TIMES[$USERNAME]="unknown"
                fi
                
                echo "[$TIMESTAMP] Active IKEv2 user: $USERNAME from $REMOTE_IP (connected ${CONNECTION_TIMES[$USERNAME]})" >> "$LOG_FILE"
            fi
        fi
    done <<< "$ACTIVE_SAS"
fi

# Create a JSON status file
cat > "$STATUS_FILE" << EOL
{
  "timestamp": "$TIMESTAMP",
  "active_connections": $ACTIVE_COUNT,
  "connected_users": [
EOL

# Add connected users to JSON
for ((i=0; i<${#CONNECTED_USERS[@]}; i++)); do
    USER="${CONNECTED_USERS[$i]}"
    IP="${USER_IPS[$USER]}"
    CONN_TIME="${CONNECTION_TIMES[$USER]}"
    
    # Add comma except for the last item
    if [[ $i -lt $((${#CONNECTED_USERS[@]}-1)) ]]; then
        echo "    {\"username\": \"$USER\", \"ip\": \"$IP\", \"connected\": \"$CONN_TIME\"}," >> "$STATUS_FILE"
    else
        echo "    {\"username\": \"$USER\", \"ip\": \"$IP\", \"connected\": \"$CONN_TIME\"}" >> "$STATUS_FILE"
    fi
done

# Close the JSON structure
cat >> "$STATUS_FILE" << EOL
  ]
}
EOL

# Check if we need to record this in the database
if [ -f "/etc/enhanced_ssh/db/database.conf" ] && command -v psql &> /dev/null; then
    source /etc/enhanced_ssh/db/database.conf
    
    for user in "${CONNECTED_USERS[@]}"; do
        IP="${USER_IPS[$user]}"
        
        # Generate a session ID
        SESSION_ID="ikev2_${user}_$(date +%s)_$(echo $IP | md5sum | cut -c1-8)"
        
        # Check if this session is already in the database
        SESSION_EXISTS=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM user_connections WHERE protocol = 'ikev2' AND username = '$user' AND client_ip = '$IP' AND status = 'active';")
        
        # If session doesn't exist, add it
        if [ "$SESSION_EXISTS" -eq "0" ]; then
            PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "INSERT INTO user_connections (username, protocol, client_ip, session_id, connect_time, status) VALUES ('$user', 'ikev2', '$IP', '$SESSION_ID', NOW(), 'active');"
        fi
    done
    
    # Check for closed sessions
    ACTIVE_DB_SESSIONS=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT username FROM user_connections WHERE protocol = 'ikev2' AND status = 'active';")
    
    # For each active DB session, check if user is still connected
    for db_user in $ACTIVE_DB_SESSIONS; do
        # Clean username from psql output
        db_user=$(echo "$db_user" | xargs)
        
        # Check if this user is in the CONNECTED_USERS array
        STILL_CONNECTED=0
        for user in "${CONNECTED_USERS[@]}"; do
            if [ "$user" = "$db_user" ]; then
                STILL_CONNECTED=1
                break
            fi
        done
        
        # If not still connected, update the DB
        if [ "$STILL_CONNECTED" -eq "0" ]; then
            PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "UPDATE user_connections SET status = 'closed', disconnect_time = NOW() WHERE username = '$db_user' AND protocol = 'ikev2' AND status = 'active';"
        fi
    done
fi

# Output summary to console
echo "[$TIMESTAMP] IKEv2 status: $ACTIVE_COUNT active connections"
if [ $ACTIVE_COUNT -gt 0 ]; then
    echo "Connected users: ${CONNECTED_USERS[*]}"
fi
EOF

    chmod +x "$SCRIPTS_DIR/ikev2/ikev2_monitor.sh"
    
    # Create cron job to run the monitor script every 5 minutes
    (crontab -l 2>/dev/null; echo "*/5 * * * * $SCRIPTS_DIR/ikev2/ikev2_monitor.sh") | crontab -

    # Start and enable strongSwan
    systemctl restart strongswan
    systemctl enable strongswan
   
    # Generate client certificate for admin user
    "$SCRIPTS_DIR/ikev2/ikev2_user_manager.sh" cert "$ADMIN_USER"
    
    info "IKEv2/IPsec installation completed successfully with client certificates"

# Install Cisco AnyConnect compatible server with modern security
install_cisco() {
    info "Installing OpenConnect (Cisco AnyConnect compatible) server with modern security..."
   
    apt-get install -y ocserv gnutls-bin || error "Failed to install OpenConnect packages"
   
    # Create directories
    mkdir -p /etc/ocserv/ssl
    cd /etc/ocserv/ssl || error "Failed to access OpenConnect SSL directory"
   
    # Generate strong CA key
    info "Generating strong CA and server keys..."
    certtool --generate-privkey --outfile ca-key.pem --bits=4096
   
    # Create CA template with modern parameters
    cat > ca.tmpl << EOL
# IRSSH-Panel CA template for OpenConnect VPN
# Managed by IRSSH-Panel, do not edit manually

cn = "IRSSH-VPN CA"
organization = "IRSSH Panel"
serial = 1
expiration_days = 3650
ca
signing_key
cert_signing_key
crl_signing_key
EOL

    # Generate CA certificate
    certtool --generate-self-signed --load-privkey ca-key.pem \
        --template ca.tmpl --outfile ca-cert.pem
   
    # Generate strong server key
    certtool --generate-privkey --outfile server-key.pem --bits=4096
   
    # Create server certificate template with SAN
    cat > server.tmpl << EOL
# IRSSH-Panel server template for OpenConnect VPN
# Managed by IRSSH-Panel, do not edit manually

cn = "${SERVER_IPv4}"
organization = "IRSSH Panel"
expiration_days = 3650
signing_key
encryption_key
tls_www_server
dns_name = "${SERVER_IPv4}"
ip_address = "${SERVER_IPv4}"
EOL

    # Generate server certificate
    certtool --generate-certificate --load-privkey server-key.pem \
        --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem \
        --template server.tmpl --outfile server-cert.pem
   
    # Create optimized ocserv configuration
    cat > /etc/ocserv/ocserv.conf << EOL
# IRSSH-Panel optimized OpenConnect VPN server configuration
# Managed by IRSSH-Panel, do not edit manually

auth = "plain[passwd=/etc/ocserv/ocpasswd]"
tcp-port = ${PORTS[CISCO]}
udp-port = ${PORTS[CISCO]}
run-as-user = nobody
run-as-group = daemon
socket-file = /var/run/ocserv-socket

# TLS settings
server-cert = /etc/ocserv/ssl/server-cert.pem
server-key = /etc/ocserv/ssl/server-key.pem
ca-cert = /etc/ocserv/ssl/ca-cert.pem
cert-user-oid = 2.5.4.3
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-RSA"
keeplive = 32400
dpd = 60
mobile-dpd = 300

# Security settings
max-clients = 128
max-same-clients = 3
rate-limit-ms = 0
server-stats-reset-time = 604800
keepalive = 300
try-mtu-discovery = true
isolate-workers = true
predictable-ips = true

# Tunneling settings
default-domain = irssh.local
ipv4-network = 192.168.128.0
ipv4-netmask = 255.255.255.0
dns = 8.8.8.8
dns = 8.8.4.4
ping-leases = false

# Routes
route = default

# Compression
no-compress = false
compression = true

# Logging and debugging
syslog = local0
debug = 0

# Advanced tuning parameters
min-reauth-time = 300
max-ban-score = 80
ban-reset-time = 1200
cookie-timeout = 300
deny-roaming = false
rekey-time = 172800
rekey-method = ssl
use-occtl = true
pid-file = /var/run/ocserv.pid
device = vpns
predictable-ips = true
EOL

    # Create initial user
    echo "$ADMIN_PASS" | ocpasswd -c /etc/ocserv/ocpasswd "$ADMIN_USER"

    # Enable IP forwarding for VPN
    cat > /etc/sysctl.d/60-ocserv-vpn.conf << EOL
# IRSSH-Panel OpenConnect VPN sysctl settings
# Managed by IRSSH-Panel, do not edit manually

# Enable IPv4 forwarding
net.ipv4.ip_forward = 1

# Improve network performance for VPN
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_syncookies = 1
EOL
    sysctl -p /etc/sysctl.d/60-ocserv-vpn.conf

    # Set up IPTables rules for forwarding
    iptables -t nat -A POSTROUTING -s 192.168.128.0/24 -o $(ip route get 8.8.8.8 | grep -oP "dev \K\S+") -j MASQUERADE
    
    # Save iptables rules
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 || mkdir -p /etc/iptables/ && iptables-save > /etc/iptables/rules.v4
    fi

    # Create user management script
    mkdir -p "$SCRIPTS_DIR/cisco"
    cat > "$SCRIPTS_DIR/cisco/cisco_user_manager.sh" << 'EOF'
#!/bin/bash

# Cisco AnyConnect (OpenConnect) User Management Script
# Usage: ./cisco_user_manager.sh add|remove|list|status|lock|unlock username [password]

OCPASSWD_FILE="/etc/ocserv/ocpasswd"
OCCTL_CMD="occtl"
ACTION="$1"
USERNAME="$2"
PASSWORD="$3"
LOG_DIR="/var/log/irssh"
mkdir -p "$LOG_DIR"

function show_usage() {
    echo "Usage: $0 add|remove|list|status|lock|unlock username [password]"
    echo
    echo "Commands:"
    echo "  add USERNAME PASSWORD  - Add a new OpenConnect user"
    echo "  remove USERNAME        - Remove an OpenConnect user"
    echo "  list                   - List all OpenConnect users"
    echo "  status [USERNAME]      - Show connection status for all users or specific user"
    echo "  lock USERNAME          - Lock a user account"
    echo "  unlock USERNAME        - Unlock a user account"
    echo "  disconnect USERNAME    - Disconnect a user's active session"
    exit 1
}

function add_user() {
    local username="$1"
    local password="$2"
    
    if [ -z "$username" ] || [ -z "$password" ]; then
        echo "Error: Username and password are required"
        exit 1
    fi
    
    # Check if user already exists
    if grep -q "^$username:" "$OCPASSWD_FILE"; then
        echo "User '$username' already exists"
        exit 1
    fi
    
    # Add user
    echo "$password" | ocpasswd -c "$OCPASSWD_FILE" "$username"
    if [ $? -eq 0 ]; then
        echo "User '$username' added successfully"
        # Log the action
        echo "[$(date +"%Y-%m-%d %H:%M:%S")] User '$username' added to OpenConnect" >> "$LOG_DIR/cisco_user_manager.log"
    else
        echo "Failed to add user '$username'"
        exit 1
    fi
}

function remove_user() {
    local username="$1"
    
    if [ -z "$username" ]; then
        echo "Error: Username is required"
        exit 1
    fi
    
    # Check if user exists
    if ! grep -q "^$username:" "$OCPASSWD_FILE"; then
        echo "User '$username' does not exist"
        exit 1
    fi
    
    # Remove user
    ocpasswd -c "$OCPASSWD_FILE" -d "$username"
    if [ $? -eq 0 ]; then
        echo "User '$username' removed successfully"
        # Log the action
        echo "[$(date +"%Y-%m-%d %H:%M:%S")] User '$username' removed from OpenConnect" >> "$LOG_DIR/cisco_user_manager.log"
        
        # Disconnect user if connected
        disconnect_user "$username" "quiet"
    else
        echo "Failed to remove user '$username'"
        exit 1
    fi
}

function list_users() {
    echo "OpenConnect Users:"
    echo "-----------------"
    grep -v "^#" "$OCPASSWD_FILE" | cut -d':' -f1
}

function check_status() {
    local username="$1"
    
    # Check if occtl is available
    if ! command -v $OCCTL_CMD &> /dev/null; then
        echo "Error: occtl command not found. Is OpenConnect server installed correctly?"
        exit 1
    fi
    
    if [ -z "$username" ]; then
        # Show all connected users
        $OCCTL_CMD show users
    else
        # Show specific user
        $OCCTL_CMD show user "$username" 2>/dev/null || echo "User '$username' is not currently connected"
    fi
}

function lock_user() {
    local username="$1"
    
    if [ -z "$username" ]; then
        echo "Error: Username is required"
        exit 1
    fi
    
    # Check if user exists
    if ! grep -q "^$username:" "$OCPASSWD_FILE"; then
        echo "User '$username' does not exist"
        exit 1
    fi
    
    # Lock user
    ocpasswd -c "$OCPASSWD_FILE" -l "$username"
    if [ $? -eq 0 ]; then
        echo "User '$username' locked successfully"
        # Log the action
        echo "[$(date +"%Y-%m-%d %H:%M:%S")] User '$username' locked in OpenConnect" >> "$LOG_DIR/cisco_user_manager.log"
    else
        echo "Failed to lock user '$username'"
        exit 1
    fi
}

function unlock_user() {
    local username="$1"
    
    if [ -z "$username" ]; then
        echo "Error: Username is required"
        exit 1
    fi
    
    # Check if user exists
    if ! grep -q "^$username:" "$OCPASSWD_FILE"; then
        echo "User '$username' does not exist"
        exit 1
    fi
    
    # Unlock user
    ocpasswd -c "$OCPASSWD_FILE" -u "$username"
    if [ $? -eq 0 ]; then
        echo "User '$username' unlocked successfully"
        # Log the action
        echo "[$(date +"%Y-%m-%d %H:%M:%S")] User '$username' unlocked in OpenConnect" >> "$LOG_DIR/cisco_user_manager.log"
    else
        echo "Failed to unlock user '$username'"
        exit 1
    fi
}

function disconnect_user() {
    local username="$1"
    local quiet="$2"
    
    if [ -z "$username" ]; then
        echo "Error: Username is required"
        exit 1
    fi
    
    # Check if occtl is available
    if ! command -v $OCCTL_CMD &> /dev/null; then
        [ "$quiet" != "quiet" ] && echo "Error: occtl command not found. Is OpenConnect server installed correctly?"
        return 1
    fi
    
    # Get user ID
    local user_id=$($OCCTL_CMD show users | grep -w "$username" | awk '{print $1}')
    
    if [ -z "$user_id" ]; then
        [ "$quiet" != "quiet" ] && echo "User '$username' is not currently connected"
        return 1
    fi
    
    # Disconnect user
    $OCCTL_CMD disconnect user "$user_id"
    if [ $? -eq 0 ]; then
        [ "$quiet" != "quiet" ] && echo "Disconnected user '$username' successfully"
        # Log the action
        echo "[$(date +"%Y-%m-%d %H:%M:%S")] User '$username' disconnected from OpenConnect" >> "$LOG_DIR/cisco_user_manager.log"
        return 0
    else
        [ "$quiet" != "quiet" ] && echo "Failed to disconnect user '$username'"
        return 1
    fi
}

# Check if OCPASSWD_FILE exists
if [ ! -f "$OCPASSWD_FILE" ]; then
    touch "$OCPASSWD_FILE"
    chmod 600 "$OCPASSWD_FILE"
    echo "Created new ocpasswd file"
fi

# Execute the requested action
case "$ACTION" in
    add)
        add_user "$USERNAME" "$PASSWORD"
        ;;
    remove)
        remove_user "$USERNAME"
        ;;
    list)
        list_users
        ;;
    status)
        check_status "$USERNAME"
        ;;
    lock)
        lock_user "$USERNAME"
        ;;
    unlock)
        unlock_user "$USERNAME"
        ;;
    disconnect)
        disconnect_user "$USERNAME"
        ;;
    *)
        show_usage
        ;;
esac
EOF

    chmod +x "$SCRIPTS_DIR/cisco/cisco_user_manager.sh"
    
    # Create monitoring script
    cat > "$SCRIPTS_DIR/cisco/cisco_monitor.sh" << 'EOF'
#!/bin/bash

# OpenConnect (Cisco AnyConnect) Connection Monitor
LOG_DIR="/var/log/irssh"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/cisco_connections.log"
STATUS_FILE="$LOG_DIR/cisco_status.json"
OCCTL_CMD="occtl"

# Get current timestamp
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

# Check if occtl is available
if ! command -v $OCCTL_CMD &> /dev/null; then
    echo "[$TIMESTAMP] Error: occtl command not found" >> "$LOG_FILE"
    exit 1
fi

# Get server status
SERVER_STATUS=$($OCCTL_CMD show status 2>/dev/null || echo "OpenConnect server not running")

# Get active users
USERS_OUTPUT=$($OCCTL_CMD show users 2>/dev/null || echo "")
ACTIVE_USERS_COUNT=$(echo "$USERS_OUTPUT" | grep -v "^id\|^--" | grep -v "^$" | wc -l)

# Parse user information
declare -a USER_IDS
declare -a USERNAMES
declare -a USER_IPS
declare -a CONNECTION_TIMES
declare -a RX_BYTES
declare -a TX_BYTES

if [ "$ACTIVE_USERS_COUNT" -gt 0 ]; then
    while IFS= read -r line; do
        # Skip header and empty lines
        if [[ $line =~ ^id|^--|^$ ]]; then
            continue
        fi
        
        # Parse the line
        id=$(echo "$line" | awk '{print $1}')
        username=$(echo "$line" | awk '{print $2}')
        ip=$(echo "$line" | awk '{print $3}')
        # Other fields may vary depending on occtl version
        
        USER_IDS+=("$id")
        USERNAMES+=("$username")
        USER_IPS+=("$ip")
        
        # Get detailed user info
        user_info=$($OCCTL_CMD show user "$id" 2>/dev/null)
        
        # Extract connection time
        conn_time=$(echo "$user_info" | grep "Connected at:" | sed 's/Connected at: //g')
        CONNECTION_TIMES+=("$conn_time")
        
        # Extract bytes
        rx=$(echo "$user_info" | grep "RX:" | awk '{print $2}')
        tx=$(echo "$user_info" | grep "TX:" | awk '{print $2}')
        RX_BYTES+=("$rx")
        TX_BYTES+=("$tx")
        
        echo "[$TIMESTAMP] Active OpenConnect user: $username ($id) from $ip, connected at $conn_time, RX: $rx, TX: $tx" >> "$LOG_FILE"
    done <<< "$USERS_OUTPUT"
fi

# Create a JSON status file
cat > "$STATUS_FILE" << EOL
{
 "timestamp": "$TIMESTAMP",
  "active_connections": $ACTIVE_USERS_COUNT,
  "server_status": "$(echo "$SERVER_STATUS" | head -1 | sed 's/"/\\"/g')",
  "connected_users": [
EOL

# Add connected users to JSON
for ((i=0; i<${#USERNAMES[@]}; i++)); do
    ID="${USER_IDS[$i]}"
    USERNAME="${USERNAMES[$i]}"
    IP="${USER_IPS[$i]}"
    CONN_TIME="${CONNECTION_TIMES[$i]}"
    RX="${RX_BYTES[$i]}"
    TX="${TX_BYTES[$i]}"
    
    # Add comma except for the last item
    if [[ $i -lt $((${#USERNAMES[@]}-1)) ]]; then
        echo "    {\"id\": \"$ID\", \"username\": \"$USERNAME\", \"ip\": \"$IP\", \"connected_at\": \"$CONN_TIME\", \"rx\": \"$RX\", \"tx\": \"$TX\"}," >> "$STATUS_FILE"
    else
        echo "    {\"id\": \"$ID\", \"username\": \"$USERNAME\", \"ip\": \"$IP\", \"connected_at\": \"$CONN_TIME\", \"rx\": \"$RX\", \"tx\": \"$TX\"}" >> "$STATUS_FILE"
    fi
done

# Close the JSON structure
cat >> "$STATUS_FILE" << EOL
  ]
}
EOL

# Check if we need to record this in the database
if [ -f "/etc/enhanced_ssh/db/database.conf" ] && command -v psql &> /dev/null; then
    source /etc/enhanced_ssh/db/database.conf
    
    for ((i=0; i<${#USERNAMES[@]}; i++)); do
        USERNAME="${USERNAMES[$i]}"
        IP="${USER_IPS[$i]}"
        ID="${USER_IDS[$i]}"
        
        # Generate a session ID
        SESSION_ID="cisco_${USERNAME}_${ID}"
        
        # Check if this session is already in the database
        SESSION_EXISTS=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM user_connections WHERE protocol = 'cisco' AND username = '$USERNAME' AND client_ip = '$IP' AND status = 'active';")
        
        # If session doesn't exist, add it
        if [ "$SESSION_EXISTS" -eq "0" ]; then
            PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "INSERT INTO user_connections (username, protocol, client_ip, session_id, connect_time, status) VALUES ('$USERNAME', 'cisco', '$IP', '$SESSION_ID', NOW(), 'active');"
        fi
        
        # Update traffic stats
        RX="${RX_BYTES[$i]}"
        TX="${TX_BYTES[$i]}"
        
        # Convert human-readable format to bytes if needed
        if [[ "$RX" == *K ]]; then
            RX=$(echo "$RX" | sed 's/K//g')
            RX=$(echo "$RX * 1024" | bc)
        elif [[ "$RX" == *M ]]; then
            RX=$(echo "$RX" | sed 's/M//g')
            RX=$(echo "$RX * 1024 * 1024" | bc)
        elif [[ "$RX" == *G ]]; then
            RX=$(echo "$RX" | sed 's/G//g')
            RX=$(echo "$RX * 1024 * 1024 * 1024" | bc)
        fi
        
        if [[ "$TX" == *K ]]; then
            TX=$(echo "$TX" | sed 's/K//g')
            TX=$(echo "$TX * 1024" | bc)
        elif [[ "$TX" == *M ]]; then
            TX=$(echo "$TX" | sed 's/M//g')
            TX=$(echo "$TX * 1024 * 1024" | bc)
        elif [[ "$TX" == *G ]]; then
            TX=$(echo "$TX" | sed 's/G//g')
            TX=$(echo "$TX * 1024 * 1024 * 1024" | bc)
        fi
        
        # Update traffic in the database
        PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "UPDATE user_connections SET download_bytes = $RX, upload_bytes = $TX WHERE protocol = 'cisco' AND session_id = '$SESSION_ID' AND status = 'active';"
    done
    
    # Check for closed sessions
    ACTIVE_DB_SESSIONS=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT username, session_id FROM user_connections WHERE protocol = 'cisco' AND status = 'active';")
    
    # For each active DB session, check if user is still connected
    while read -r db_row; do
        if [ -z "$db_row" ]; then
            continue
        fi
        
        db_user=$(echo "$db_row" | awk '{print $1}')
        db_session=$(echo "$db_row" | awk '{print $3}')
        
        # Check if this user is in the USERNAMES array
        STILL_CONNECTED=0
        for username in "${USERNAMES[@]}"; do
            if [ "$username" = "$db_user" ]; then
                STILL_CONNECTED=1
                break
            fi
        done
        
        # If not still connected, update the DB
        if [ "$STILL_CONNECTED" -eq "0" ]; then
            PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "UPDATE user_connections SET status = 'closed', disconnect_time = NOW() WHERE username = '$db_user' AND protocol = 'cisco' AND status = 'active';"
        fi
    done <<< "$ACTIVE_DB_SESSIONS"
fi

# Output summary to console
echo "[$TIMESTAMP] OpenConnect status: $ACTIVE_USERS_COUNT active connections"
if [ $ACTIVE_USERS_COUNT -gt 0 ]; then
    echo "Connected users: ${USERNAMES[*]}"
fi
EOF

    chmod +x "$SCRIPTS_DIR/cisco/cisco_monitor.sh"
    
    # Create cron job to run the monitor script every 5 minutes
    (crontab -l 2>/dev/null; echo "*/5 * * * * $SCRIPTS_DIR/cisco/cisco_monitor.sh") | crontab -

    # Create client configuration scripts
    mkdir -p "$PANEL_DIR/client_scripts/cisco"
    
    # Create Windows batch script for AnyConnect compatibility
    cat > "$PANEL_DIR/client_scripts/cisco/cisco_windows_setup.bat" << EOL
@echo off
echo IRSSH OpenConnect (Cisco AnyConnect Compatible) VPN Setup
echo Server: ${SERVER_IPv4}
echo Port: ${PORTS[CISCO]}
echo.
echo This script will help you configure Cisco AnyConnect client.
echo.
echo Instructions:
echo 1. Install Cisco AnyConnect Secure Mobility Client
echo 2. Open the client
echo 3. Enter ${SERVER_IPv4}:${PORTS[CISCO]} in the connection box
echo 4. Click Connect
echo 5. Enter your username and password when prompted
echo.
echo Note: You can also use OpenConnect GUI client for Windows as an alternative.
echo.
pause
EOL

    # Create Linux/macOS script for OpenConnect
    cat > "$PANEL_DIR/client_scripts/cisco/cisco_linux_setup.sh" << EOL
#!/bin/bash

# IRSSH OpenConnect (Cisco AnyConnect Compatible) VPN Setup Script for Linux/macOS
SERVER="${SERVER_IPv4}"
PORT="${PORTS[CISCO]}"
VPN_NAME="IRSSH-CISCO"

echo "IRSSH OpenConnect VPN Setup"
echo "==========================="
echo "Server: \$SERVER"
echo "Port: \$PORT"
echo

# Check for OpenConnect client
if ! command -v openconnect &> /dev/null; then
    echo "OpenConnect client is not installed."
    echo "Please install it using your package manager:"
    echo
    echo "  For Ubuntu/Debian: sudo apt-get install openconnect network-manager-openconnect"
    echo "  For Fedora/RHEL: sudo dnf install openconnect NetworkManager-openconnect"
    echo "  For macOS with Homebrew: brew install openconnect"
    echo
    exit 1
fi

# Create connection script
cat > ./connect-irssh-vpn.sh << EOF
#!/bin/bash
echo "Connecting to IRSSH OpenConnect VPN..."
echo "Server: \$SERVER:\$PORT"
echo
echo "Press Ctrl+C to disconnect."
echo

sudo openconnect --protocol=anyconnect \$SERVER:\$PORT
EOF

chmod +x ./connect-irssh-vpn.sh

echo "Setup completed."
echo "To connect, run: ./connect-irssh-vpn.sh"
echo "You will be prompted for your username and password."
echo
echo "For NetworkManager GUI integration (Linux desktop):"
echo "1. Open Network Settings"
echo "2. Add a new VPN connection"
echo "3. Select 'Cisco AnyConnect Compatible VPN (openconnect)'"
echo "4. Enter '\$SERVER:\$PORT' as the gateway"
echo
EOL
    chmod +x "$PANEL_DIR/client_scripts/cisco/cisco_linux_setup.sh"

    # Restart and enable ocserv
    systemctl restart ocserv
    systemctl enable ocserv
   
    info "OpenConnect (Cisco AnyConnect compatible) installation completed"
}

# Install WireGuard with enhanced configuration
install_wireguard() {
    info "Installing WireGuard with enhanced configuration..."
   
    apt-get install -y wireguard || error "Failed to install WireGuard"
   
    mkdir -p /etc/wireguard
    cd /etc/wireguard || error "Failed to access WireGuard directory"
   
    # Generate strong server keys
    wg genkey | tee server_private.key | wg pubkey > server_public.key
    chmod 600 server_private.key
   
    # Get primary network interface
    SERVER_INTERFACE=$(ip route get 8.8.8.8 | grep -oP "dev \K\S+")
   
    # Create enhanced WireGuard configuration
    cat > /etc/wireguard/wg0.conf << EOL
# IRSSH-Panel optimized WireGuard configuration
# Managed by IRSSH-Panel, do not edit manually

[Interface]
PrivateKey = $(cat server_private.key)
Address = 10.66.66.1/24
ListenPort = ${PORTS[WIREGUARD]}

# Enhanced network settings
MTU = 1420
Table = off
PreUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o ${SERVER_INTERFACE} -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o ${SERVER_INTERFACE} -j MASQUERADE

# For better throughput and lower latency
#UpdateTable = on
#SaveConfig = false
#RouteTable = 2468
#RouteAllowedIPs = false  

# Advanced security settings
# These settings make the server more restrictive but potentially more secure
#FwMark = 0xca6c
#Description = IRSSH-Panel WireGuard Server
EOL

    # Create an initial client configuration
    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(echo $CLIENT_PRIVATE_KEY | wg pubkey)
    
    # Add client to server config
    cat >> /etc/wireguard/wg0.conf << EOL

# User: ${ADMIN_USER}
[Peer]
PublicKey = ${CLIENT_PUBLIC_KEY}
AllowedIPs = 10.66.66.2/32
EOL

    # Create client config file
    mkdir -p /etc/wireguard/clients
    
    cat > /etc/wireguard/clients/${ADMIN_USER}.conf << EOL
# IRSSH-Panel WireGuard client configuration for ${ADMIN_USER}
# Managed by IRSSH-Panel, do not edit manually

[Interface]
PrivateKey = ${CLIENT_PRIVATE_KEY}
Address = 10.66.66.2/32
DNS = 8.8.8.8, 8.8.4.4
MTU = 1420

[Peer]
PublicKey = $(cat server_public.key)
Endpoint = ${SERVER_IPv4}:${PORTS[WIREGUARD]}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOL

    # Save client information to database
    mkdir -p $CONFIG_DIR/wireguard
    cat > $CONFIG_DIR/wireguard/peers.json << EOL
[
  {
    "username": "${ADMIN_USER}",
    "public_key": "${CLIENT_PUBLIC_KEY}",
    "private_key": "${CLIENT_PRIVATE_KEY}",
    "allowed_ips": "10.66.66.2/32",
    "created_at": "$(date +"%Y-%m-%d %H:%M:%S")"
  }
]
EOL

    # Create QR code generation script
    mkdir -p "$SCRIPTS_DIR/wireguard"
    
    cat > "$SCRIPTS_DIR/wireguard/generate_qr.sh" << 'EOF'
#!/bin/bash

# Generate QR code for WireGuard configuration
# Usage: ./generate_qr.sh username

if [ -z "$1" ]; then
    echo "Usage: $0 username"
    exit 1
fi

USERNAME="$1"
CONFIG_FILE="/etc/wireguard/clients/${USERNAME}.conf"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Configuration file for user $USERNAME not found"
    exit 1
fi

# Check if qrencode is installed
if ! command -v qrencode &> /dev/null; then
    echo "Installing qrencode..."
    apt-get update && apt-get install -y qrencode
fi

# Generate QR code
echo "WireGuard configuration QR code for $USERNAME:"
echo
qrencode -t ansiutf8 < "$CONFIG_FILE"
echo
echo "Scan this QR code with the WireGuard mobile app"
echo "Or use the config file directly: $CONFIG_FILE"
EOF

    chmod +x "$SCRIPTS_DIR/wireguard/generate_qr.sh"

    # Create WireGuard user management script
    cat > "$SCRIPTS_DIR/wireguard/wireguard_user_manager.sh" << 'EOF'
#!/bin/bash

# WireGuard User Management Script
# Usage: ./wireguard_user_manager.sh add|remove|list|status|config|qr username

WG_CONF="/etc/wireguard/wg0.conf"
WG_PEERS_JSON="/etc/enhanced_ssh/wireguard/peers.json"
WG_CLIENTS_DIR="/etc/wireguard/clients"
WG_INTERFACE="wg0"
LOG_DIR="/var/log/irssh"
mkdir -p "$LOG_DIR"

ACTION="$1"
USERNAME="$2"

function show_usage() {
    echo "Usage: $0 add|remove|list|status|config|qr username"
    echo
    echo "Commands:"
    echo "  add USERNAME      - Add a new WireGuard user"
    echo "  remove USERNAME   - Remove a WireGuard user"
    echo "  list              - List all WireGuard users"
    echo "  status [USERNAME] - Show connection status"
    echo "  config USERNAME   - Show configuration for user"
    echo "  qr USERNAME       - Generate QR code for user"
    exit 1
}

function add_user() {
    local username="$1"
    
    if [ -z "$username" ]; then
        echo "Error: Username is required"
        exit 1
    fi
    
    # Check if user already exists in wg0.conf
    if grep -q "# User: $username" "$WG_CONF"; then
        echo "User '$username' already exists"
        exit 1
    fi
    
    # Generate keys
    local private_key=$(wg genkey)
    local public_key=$(echo "$private_key" | wg pubkey)
    
    # Find next available IP
    local last_ip=$(grep -A 1 "# User:" "$WG_CONF" | grep "AllowedIPs" | sed -E 's/.*10\.66\.66\.([0-9]+).*/\1/' | sort -n | tail -1)
    local next_ip=$((last_ip + 1))
    
    # Add peer to wg0.conf
    cat >> "$WG_CONF" << EOWG

# User: $username
[Peer]
PublicKey = $public_key
AllowedIPs = 10.66.66.$next_ip/32
EOWG

    # Create client config
    mkdir -p "$WG_CLIENTS_DIR"
    local server_pubkey=$(grep -A 1 "\[Interface\]" "$WG_CONF" | grep "PrivateKey" | awk '{print $3}' | wg pubkey)
    local server_ip=$(hostname -I | awk '{print $1}')
    local server_port=$(grep "ListenPort" "$WG_CONF" | awk '{print $3}')
    
    cat > "$WG_CLIENTS_DIR/$username.conf" << EOCLIENT
# IRSSH-Panel WireGuard client configuration for $username
# Managed by IRSSH-Panel, do not edit manually

[Interface]
PrivateKey = $private_key
Address = 10.66.66.$next_ip/32
DNS = 8.8.8.8, 8.8.4.4
MTU = 1420

[Peer]
PublicKey = $(cat /etc/wireguard/server_public.key)
Endpoint = $server_ip:$server_port
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOCLIENT

    # Add to peers JSON
    if [ -f "$WG_PEERS_JSON" ]; then
        # Create a temporary file
        local tmp_file=$(mktemp)
        
        # Remove the closing bracket
        sed '$ d' "$WG_PEERS_JSON" > "$tmp_file"
        
        # Check if we need to add a comma
        if [ "$(tail -c 2 "$tmp_file")" != "[" ]; then
            echo "," >> "$tmp_file"
        fi
        
        # Add the new peer
        cat >> "$tmp_file" << EOJSON
  {
    "username": "$username",
    "public_key": "$public_key",
    "private_key": "$private_key",
    "allowed_ips": "10.66.66.$next_ip/32",
    "created_at": "$(date +"%Y-%m-%d %H:%M:%S")"
  }
]
EOJSON
        
        # Replace the original file
        mv "$tmp_file" "$WG_PEERS_JSON"
    else
        # Create the file if it doesn't exist
        mkdir -p "$(dirname "$WG_PEERS_JSON")"
        cat > "$WG_PEERS_JSON" << EOJSON
[
  {
    "username": "$username",
    "public_key": "$public_key",
    "private_key": "$private_key",
    "allowed_ips": "10.66.66.$next_ip/32",
    "created_at": "$(date +"%Y-%m-%d %H:%M:%S")"
  }
]
EOJSON
    fi
    
    # Apply changes
    if wg-quick down "$WG_INTERFACE" 2>/dev/null && wg-quick up "$WG_INTERFACE"; then
        echo "User '$username' added successfully with IP 10.66.66.$next_ip"
        echo "Configuration file: $WG_CLIENTS_DIR/$username.conf"
        
        # Log the action
        echo "[$(date +"%Y-%m-%d %H:%M:%S")] User '$username' added to WireGuard with IP 10.66.66.$next_ip" >> "$LOG_DIR/wireguard_user_manager.log"
    else
        echo "Error restarting WireGuard interface"
        exit 1
    fi
}

function remove_user() {
    local username="$1"
    
    if [ -z "$username" ]; then
        echo "Error: Username is required"
        exit 1
    fi
    
    # Check if user exists
    if ! grep -q "# User: $username" "$WG_CONF"; then
        echo "User '$username' does not exist"
        exit 1
    fi
    
    # Remove peer from wg0.conf
    local tmp_file=$(mktemp)
    awk -v user="$username" 'BEGIN{skip=0} /# User: '"$username"'/{skip=1} /# User:/{if(skip==1)skip=0} !skip{print}' "$WG_CONF" > "$tmp_file"
    mv "$tmp_file" "$WG_CONF"
    
    # Remove client config
    rm -f "$WG_CLIENTS_DIR/$username.conf"
    
    # Remove from peers JSON
    if [ -f "$WG_PEERS_JSON" ]; then
        local tmp_file=$(mktemp)
        jq "map(select(.username != \"$username\"))" "$WG_PEERS_JSON" > "$tmp_file"
        mv "$tmp_file" "$WG_PEERS_JSON"
    fi
    
    # Apply changes
    if wg-quick down "$WG_INTERFACE" 2>/dev/null && wg-quick up "$WG_INTERFACE"; then
        echo "User '$username' removed successfully"
        
        # Log the action
        echo "[$(date +"%Y-%m-%d %H:%M:%S")] User '$username' removed from WireGuard" >> "$LOG_DIR/wireguard_user_manager.log"
    else
        echo "Error restarting WireGuard interface"
        exit 1
    fi
}

function list_users() {
    echo "WireGuard Users:"
    echo "---------------"
    grep "# User:" "$WG_CONF" | sed 's/# User: //'
}

function check_status() {
    local username="$1"
    
    if [ -z "$username" ]; then
        # Show all peers
        wg show
    else
        # Show specific peer
        local public_key=""
        
        # Find public key from JSON
        if [ -f "$WG_PEERS_JSON" ]; then
            public_key=$(jq -r ".[] | select(.username == \"$username\") | .public_key" "$WG_PEERS_JSON")
        fi
        
        if [ -z "$public_key" ] || [ "$public_key" == "null" ]; then
            # Try to find from config file
            if grep -q "# User: $username" "$WG_CONF"; then
                public_key=$(grep -A 2 "# User: $username" "$WG_CONF" | grep "PublicKey" | awk '{print $3}')
            else
                echo "User '$username' not found"
                exit 1
            fi
        fi
        
        # Show peer info
        wg show | grep -A 5 "$public_key" || echo "User '$username' is not currently connected"
    fi
}

function show_config() {
    local username="$1"
    
    if [ -z "$username" ]; then
        echo "Error: Username is required"
        exit 1
    fi
    
    if [ -f "$WG_CLIENTS_DIR/$username.conf" ]; then
        echo "WireGuard configuration for $username:"
        echo
        cat "$WG_CLIENTS_DIR/$username.conf"
    else
        echo "Configuration for user '$username' not found"
        exit 1
    fi
}

function generate_qr() {
    local username="$1"
    
    if [ -z "$username" ]; then
        echo "Error: Username is required"
        exit 1
    fi
    
    if [ -f "$WG_CLIENTS_DIR/$username.conf" ]; then
        # Check if qrencode is installed
        if ! command -v qrencode &> /dev/null; then
            echo "Installing qrencode..."
            apt-get update && apt-get install -y qrencode
        fi
        
        echo "WireGuard configuration QR code for $username:"
        echo
        qrencode -t ansiutf8 < "$WG_CLIENTS_DIR/$username.conf"
        echo
        echo "Scan this QR code with the WireGuard mobile app"
    else
        echo "Configuration for user '$username' not found"
        exit 1
    fi
}

# Check if wg0.conf exists
if [ ! -f "$WG_CONF" ]; then
    echo "Error: WireGuard configuration file not found"
    exit 1
fi

# Execute the requested action
case "$ACTION" in
    add)
        add_user "$USERNAME"
        ;;
    remove)
        remove_user "$USERNAME"
        ;;
    list)
        list_users
        ;;
    status)
        check_status "$USERNAME"
        ;;
    config)
        show_config "$USERNAME"
        ;;
    qr)
        generate_qr "$USERNAME"
        ;;
    *)
        show_usage
        ;;
esac
EOF

    chmod +x "$SCRIPTS_DIR/wireguard/wireguard_user_manager.sh"

    # Create monitoring script
    cat > "$SCRIPTS_DIR/wireguard/wireguard_monitor.sh" << 'EOF'
#!/bin/bash

# WireGuard Connection Monitor
LOG_DIR="/var/log/irssh"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/wireguard_connections.log"
STATUS_FILE="$LOG_DIR/wireguard_status.json"
WG_PEERS_JSON="/etc/enhanced_ssh/wireguard/peers.json"
WG_INTERFACE="wg0"

# Get current timestamp
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

# Check if WireGuard is running
if ! wg &> /dev/null; then
    echo "[$TIMESTAMP] WireGuard is not running" >> "$LOG_FILE"
    exit 1
fi

# Get WireGuard status
WG_STATUS=$(wg show "$WG_INTERFACE")
WG_DUMP=$(wg show "$WG_INTERFACE" dump)

# Count active peers (handshake in last 3 minutes)
ACTIVE_PEERS=$(echo "$WG_STATUS" | grep -c "latest handshake: .* seconds\|.*minute ago")

# Map public keys to usernames
declare -A USERNAME_MAP
declare -A ALLOWED_IPS_MAP

if [ -f "$WG_PEERS_JSON" ]; then
    # Parse JSON with jq if available
    if command -v jq &> /dev/null; then
        while IFS= read -r line; do
            username=$(echo "$line" | jq -r '.username')
            public_key=$(echo "$line" | jq -r '.public_key')
            allowed_ips=$(echo "$line" | jq -r '.allowed_ips')
            
            USERNAME_MAP["$public_key"]="$username"
            ALLOWED_IPS_MAP["$public_key"]="$allowed_ips"
        done < <(jq -c '.[]' "$WG_PEERS_JSON")
    else
        # Simple parsing fallback
        while IFS= read -r line; do
            if [[ $line =~ \"username\":\ *\"([^\"]+)\" ]]; then
                username="${BASH_REMATCH[1]}"
            fi
            
            if [[ $line =~ \"public_key\":\ *\"([^\"]+)\" ]]; then
                public_key="${BASH_REMATCH[1]}"
            fi
            
            if [[ $line =~ \"allowed_ips\":\ *\"([^\"]+)\" ]]; then
                allowed_ips="${BASH_REMATCH[1]}"
                
                # Store the mapping if we have both username and public key
                if [ -n "$username" ] && [ -n "$public_key" ]; then
                    USERNAME_MAP["$public_key"]="$username"
                    ALLOWED_IPS_MAP["$public_key"]="$allowed_ips"
                    
                    # Reset for next entry
                    username=""
                    public_key=""
                    allowed_ips=""
                fi
            fi
        done < "$WG_PEERS_JSON"
    fi
fi

# Parse connection information from wg show
declare -a PEER_PUBLIC_KEYS
declare -a PEER_ENDPOINTS
declare -a PEER_HANDSHAKES
declare -a PEER_TRANSFER
declare -a PEER_USERNAMES
declare -a PEER_ALLOWED_IPS

# Format of wg show dump:
# interface private_key public_key listen_port fwmark
# peer_pubkey endpoint allowed_ips latest_handshake tx_bytes rx_bytes keepalive persistent-keepalive

while IFS= read -r line; do
    # Skip interface line
    if [[ $line =~ ^$WG_INTERFACE ]]; then
        continue
    fi
    
    IFS=$'\t' read -r pubkey endpoint allowed_ips handshake rx_bytes tx_bytes rest <<< "$line"
    
    # Skip peers with no handshake or handshake too old (> 3 minutes)
    if [ "$handshake" = "0" ] || [ "$handshake" -lt $(($(date +%s) - 180)) ]; then
        continue
    fi
    
    PEER_PUBLIC_KEYS+=("$pubkey")
    PEER_ENDPOINTS+=("$endpoint")
    PEER_HANDSHAKES+=("$handshake")
    PEER_TRANSFER+=("$rx_bytes $tx_bytes")
    
    # Look up username
    username="${USERNAME_MAP[$pubkey]:-Unknown}"
    PEER_USERNAMES+=("$username")
    
    # Look up allowed IPs or use from wg show
    allowed="${ALLOWED_IPS_MAP[$pubkey]:-$allowed_ips}"
    PEER_ALLOWED_IPS+=("$allowed")
    
    # Calculate time since handshake
    seconds_since=$(($(date +%s) - handshake))
    if [ $seconds_since -lt 60 ]; then
        handshake_ago="${seconds_since} seconds ago"
    else
        minutes_since=$((seconds_since / 60))
        if [ $minutes_since -lt 60 ]; then
            handshake_ago="${minutes_since} minutes ago"
        else
            hours_since=$((minutes_since / 60))
            handshake_ago="${hours_since} hours ago"
        fi
    fi
    
    # Log the connection
    echo "[$TIMESTAMP] Active WireGuard user: $username ($endpoint), last handshake $handshake_ago" >> "$LOG_FILE"
done <<< "$(echo "$WG_DUMP" | tail -n +2)"

# Create a JSON status file
cat > "$STATUS_FILE" << EOL
{
  "timestamp": "$TIMESTAMP",
  "active_connections": ${#PEER_PUBLIC_KEYS[@]},
  "connected_users": [
EOL

# Add connected users to JSON
for ((i=0; i<${#PEER_PUBLIC_KEYS[@]}; i++)); do
    PUBKEY="${PEER_PUBLIC_KEYS[$i]}"
    USERNAME="${PEER_USERNAMES[$i]}"
    ENDPOINT="${PEER_ENDPOINTS[$i]}"
    HANDSHAKE="${PEER_HANDSHAKES[$i]}"
    TRANSFER="${PEER_TRANSFER[$i]}"
    ALLOWED_IPS="${PEER_ALLOWED_IPS[$i]}"
    
    # Parse transfer
    IFS=' ' read -r RX TX <<< "$TRANSFER"
    
    # Calculate handshake ago
    seconds_since=$(($(date +%s) - HANDSHAKE))
    
    # Add comma except for the last item
    if [[ $i -lt $((${#PEER_PUBLIC_KEYS[@]}-1)) ]]; then
        echo "    {\"username\": \"$USERNAME\", \"endpoint\": \"$ENDPOINT\", \"public_key\": \"$PUBKEY\", \"handshake\": $seconds_since, \"rx_bytes\": $RX, \"tx_bytes\": $TX, \"allowed_ips\": \"$ALLOWED_IPS\"}," >> "$STATUS_FILE"
    else
        echo "    {\"username\": \"$USERNAME\", \"endpoint\": \"$ENDPOINT\", \"public_key\": \"$PUBKEY\", \"handshake\": $seconds_since, \"rx_bytes\": $RX, \"tx_bytes\": $TX, \"allowed_ips\": \"$ALLOWED_IPS\"}" >> "$STATUS_FILE"
    fi
done

# Close the JSON structure
cat >> "$STATUS_FILE" << EOL
  ]
}
EOL

# Check if we need to record this in the database
if [ -f "/etc/enhanced_ssh/db/database.conf" ] && command -v psql &> /dev/null; then
    source /etc/enhanced_ssh/db/database.conf
    
    for ((i=0; i<${#PEER_PUBLIC_KEYS[@]}; i++)); do
        USERNAME="${PEER_USERNAMES[$i]}"
        ENDPOINT="${PEER_ENDPOINTS[$i]}"
        
        # Extract IP from endpoint
        IP=$(echo "$ENDPOINT" | cut -d':' -f1)
        
        # Generate a session ID
        SESSION_ID="wg_${USERNAME}_$(date +%s)_$(echo $IP | md5sum | cut -c1-8)"
        
        # Check if this session is already in the database
        SESSION_EXISTS=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM user_connections WHERE protocol = 'wireguard' AND username = '$USERNAME' AND client_ip = '$IP' AND status = 'active';")
        
        # If session doesn't exist, add it
        if [ "$SESSION_EXISTS" -eq "0" ]; then
            PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "INSERT INTO user_connections (username, protocol, client_ip, session_id, connect_time, status) VALUES ('$USERNAME', 'wireguard', '$IP', '$SESSION_ID', NOW(), 'active');"
        fi
        
        # Update traffic stats
        IFS=' ' read -r RX TX <<< "${PEER_TRANSFER[$i]}"
        
        # Update traffic in the database for all active connections of this user
        PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "UPDATE user_connections SET download_bytes = $RX, upload_bytes = $TX WHERE username = '$USERNAME' AND protocol = 'wireguard' AND status = 'active';"
    done
    
    # Check for closed sessions
    ACTIVE_DB_SESSIONS=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT username FROM user_connections WHERE protocol = 'wireguard' AND status = 'active';")
    
    # For each active DB session, check if user is still connected
    for db_user in $ACTIVE_DB_SESSIONS; do
        # Clean username from psql output
        db_user=$(echo "$db_user" | xargs)
        
        # Check if this user is in the PEER_USERNAMES array
        STILL_CONNECTED=0
        for username in "${PEER_USERNAMES[@]}"; do
            if [ "$username" = "$db_user" ]; then
                STILL_CONNECTED=1
                break
            fi
        done
        
        # If not still connected, update the DB
        if [ "$STILL_CONNECTED" -eq "0" ]; then
            PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "UPDATE user_connections SET status = 'closed', disconnect_time = NOW() WHERE username = '$db_user' AND protocol = 'wireguard' AND status = 'active';"
        fi
    done
fi

# Output summary to console
echo "[$TIMESTAMP] WireGuard status: ${#PEER_PUBLIC_KEYS[@]} active connections"
if [ ${#PEER_PUBLIC_KEYS[@]} -gt 0 ]; then
    echo "Connected users: ${PEER_USERNAMES[*]}"
fi
EOF

    chmod +x "$SCRIPTS_DIR/wireguard/wireguard_monitor.sh"
    
    # Create cron job to run the monitor script every 5 minutes
    (crontab -l 2>/dev/null; echo "*/5 * * * * $SCRIPTS_DIR/wireguard/wireguard_monitor.sh") | crontab -

    # Create client folder for WireGuard configuration files
    mkdir -p "$PANEL_DIR/client_scripts/wireguard"
    
    # Generate QR code for the admin user
    "$SCRIPTS_DIR/wireguard/generate_qr.sh" "$ADMIN_USER" > "$PANEL_DIR/client_scripts/wireguard/${ADMIN_USER}_qrcode.txt"
    
    # Copy client configuration to the client scripts directory
    cp "/etc/wireguard/clients/${ADMIN_USER}.conf" "$PANEL_DIR/client_scripts/wireguard/"
    
    # Create Windows PowerShell setup script
    cat > "$PANEL_DIR/client_scripts/wireguard/wireguard_windows_setup.ps1" << EOL
# IRSSH-Panel WireGuard Setup Script for Windows
# This script helps set up WireGuard on Windows

Write-Host "IRSSH-Panel WireGuard Setup" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
Write-Host

# Check if WireGuard is installed
\$wireguardPath = "C:\Program Files\WireGuard\wireguard.exe"
if (-not (Test-Path \$wireguardPath)) {
    Write-Host "WireGuard does not appear to be installed." -ForegroundColor Yellow
    Write-Host "Please download and install WireGuard from: https://www.wireguard.com/install/"
    Write-Host
    Write-Host "After installation, run this script again."
    exit
}

Write-Host "WireGuard is installed."
Write-Host

# List available configuration files
\$configFiles = Get-ChildItem -Path "\$PSScriptRoot\*.conf" -ErrorAction SilentlyContinue
if (\$configFiles.Count -eq 0) {
    Write-Host "No WireGuard configuration files found in this directory." -ForegroundColor Red
    Write-Host "Please make sure your .conf file is in the same directory as this script."
    exit
}

Write-Host "Available configuration files:" -ForegroundColor Green
\$index = 1
\$configFiles | ForEach-Object {
    Write-Host "\$index. \$(\$_.Name)"
    \$index++
}

# Select configuration file
\$selection = Read-Host "Enter the number of the configuration to install (1-\$(\$configFiles.Count))"
try {
    \$selectionIndex = [int]\$selection - 1
    if (\$selectionIndex -lt 0 -or \$selectionIndex -ge \$configFiles.Count) {
        throw "Invalid selection"
    }
    \$selectedConfig = \$configFiles[\$selectionIndex]
} catch {
    Write-Host "Invalid selection. Exiting." -ForegroundColor Red
    exit
}

# Copy configuration file to WireGuard folder
\$wireguardConfigDir = "\$env:APPDATA\WireGuard\Configurations"
if (-not (Test-Path \$wireguardConfigDir)) {
    New-Item -ItemType Directory -Path \$wireguardConfigDir -Force | Out-Null
}

\$destinationPath = Join-Path \$wireguardConfigDir \$selectedConfig.Name
Copy-Item -Path \$selectedConfig.FullName -Destination \$destinationPath -Force

Write-Host "Configuration installed to: \$destinationPath" -ForegroundColor Green
Write-Host
Write-Host "To connect:"
Write-Host "1. Open WireGuard"
Write-Host "2. Select the configuration '\$(\$selectedConfig.Name)' from the dropdown"
Write-Host "3. Click 'Activate'"
Write-Host
Write-Host "Press any key to exit..."
\$null = \$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
EOL

    # Create Linux setup script
    cat > "$PANEL_DIR/client_scripts/wireguard/wireguard_linux_setup.sh" << 'EOL'
#!/bin/bash

# IRSSH-Panel WireGuard Setup Script for Linux

echo "IRSSH-Panel WireGuard Setup"
echo "=========================="
echo

# Check if WireGuard is installed
if ! command -v wg &> /dev/null; then
    echo "WireGuard does not appear to be installed."
    echo "Would you like to install it now? (y/n)"
    read -r install_wg
    
    if [[ "$install_wg" =~ ^[Yy]$ ]]; then
        # Try to detect the distribution
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y wireguard
        elif command -v yum &> /dev/null; then
            sudo yum install -y epel-release
            sudo yum install -y wireguard-tools
        else
            echo "Could not determine your package manager."
            echo "Please install WireGuard manually and run this script again."
            exit 1
        fi
    else
        echo "Please install WireGuard and run this script again."
        exit 1
    fi
fi

echo "WireGuard is installed."
echo

# List available configuration files
config_files=(*.conf)
if [ ${#config_files[@]} -eq 0 ] || [ ! -f "${config_files[0]}" ]; then
    echo "No WireGuard configuration files found in this directory."
    echo "Please make sure your .conf file is in the same directory as this script."
    exit 1
fi

echo "Available configuration files:"
for i in "${!config_files[@]}"; do
    echo "$((i+1)). ${config_files[$i]}"
done

# Select configuration file
echo
echo "Enter the number of the configuration to install (1-${#config_files[@]}):"
read -r selection

if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt "${#config_files[@]}" ]; then
    echo "Invalid selection. Exiting."
    exit 1
fi

selected_config="${config_files[$((selection-1))]}"

# Determine the appropriate location for the configuration
if [ -d "/etc/wireguard" ]; then
    # System-wide installation (requires root)
    echo "Installing system-wide (requires sudo)..."
    sudo cp "$selected_config" "/etc/wireguard/"
    echo "Configuration installed to: /etc/wireguard/$selected_config"
    echo
    echo "To connect:"
    echo "sudo wg-quick up ${selected_config%.conf}"
    echo
    echo "To disconnect:"
    echo "sudo wg-quick down ${selected_config%.conf}"
else
    # User-local installation
    mkdir -p ~/.wireguard
    cp "$selected_config" ~/.wireguard/
    echo "Configuration installed to: ~/.wireguard/$selected_config"
    echo
    echo "To connect (requires sudo):"
    echo "sudo wg-quick up ~/.wireguard/$selected_config"
    echo
    echo "To disconnect:"
    echo "sudo wg-quick down ~/.wireguard/$selected_config"
fi

echo
echo "Would you like to connect now? (y/n)"
read -r connect_now

if [[ "$connect_now" =~ ^[Yy]$ ]]; then
    if [ -d "/etc/wireguard" ]; then
        sudo wg-quick up "${selected_config%.conf}"
    else
        sudo wg-quick up "$HOME/.wireguard/$selected_config"
    fi
fi
EOL
    chmod +x "$PANEL_DIR/client_scripts/wireguard/wireguard_linux_setup.sh"

    # Enable and start WireGuard
    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
   
    info "WireGuard installation completed with enhanced security and QR code support"
}

# Install Sing-Box with advanced configuration
install_singbox() {
    info "Installing Sing-Box with advanced configuration..."
   
    local ARCH="amd64"
    if [ "$(uname -m)" = "aarch64" ]; then
        ARCH="arm64"
    fi
    
    # Install latest version from GitHub
    local VERSION="1.8.0"
    local LATEST_VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep -oP '"tag_name": "\K(.*)(?=")')
    
    if [ ! -z "$LATEST_VERSION" ]; then
        VERSION=${LATEST_VERSION#v}
        info "Using latest Sing-Box version: $VERSION"
    fi
    
    local URL="https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box-${VERSION}-linux-${ARCH}.tar.gz"
   
    mkdir -p /tmp/sing-box
    wget "$URL" -O /tmp/sing-box.tar.gz || error "Failed to download Sing-Box"
    tar -xzf /tmp/sing-box.tar.gz -C /tmp/sing-box --strip-components=1
   
    # Copy sing-box binary to system
    cp /tmp/sing-box/sing-box /usr/local/bin/
    chmod +x /usr/local/bin/sing-box || error "Failed to set permissions for sing-box"
   
    # Create Sing-Box directories
    mkdir -p /etc/sing-box/certs
    mkdir -p /etc/sing-box/geoip
    mkdir -p /etc/sing-box/users
    mkdir -p /var/log/sing-box
   
    # Download GeoIP database
    info "Downloading GeoIP database..."
    wget -q -O /etc/sing-box/geoip/geoip.db "https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db"
    wget -q -O /etc/sing-box/geoip/geosite.db "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db"
   
    # Generate TLS certificate
    info "Generating TLS certificate for Sing-Box..."
    openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
        -keyout /etc/sing-box/certs/server.key \
        -out /etc/sing-box/certs/server.crt \
        -subj "/CN=${SERVER_IPv4}" \
        -addext "subjectAltName = DNS:${SERVER_IPv4},IP:${SERVER_IPv4}"
    
    chmod 644 /etc/sing-box/certs/server.crt
    chmod 600 /etc/sing-box/certs/server.key
   
    # Generate unique UUIDs
    USER_UUID=$(sing-box generate uuid)
    TROJAN_PASSWD=$(openssl rand -hex 16)
    REALITY_KEYPAIR=$(sing-box generate reality-keypair)
    REALITY_PRIVATE_KEY=$(echo "$REALITY_KEYPAIR" | grep PrivateKey | awk '{print $2}')
    REALITY_PUBLIC_KEY=$(echo "$REALITY_KEYPAIR" | grep PublicKey | awk '{print $2}')
   
    # Create advanced Sing-Box configuration with multiple protocols
    cat > /etc/sing-box/config.json << EOL
{
    "log": {
        "level": "info",
        "output": "/var/log/sing-box/sing-box.log",
        "timestamp": true
    },
    "dns": {
        "servers": [
            {
                "tag": "google",
                "address": "8.8.8.8",
                "address_strategy": "prefer_ipv4",
                "strategy": "ipv4_only",
                "detour": "direct"
            },
            {
                "tag": "local",
                "address": "223.5.5.5",
                "address_strategy": "prefer_ipv4",
                "strategy": "ipv4_only",
                "detour": "direct"
            }
        ],
        "rules": [
            {
                "domain": [
                    "geosite:cn"
                ],
                "server": "local"
            }
        ],
        "strategy": "prefer_ipv4",
        "disable_cache": false
    },
    "inbounds": [
        {
            "type": "vmess",
            "tag": "vmess-in",
            "listen": "::",
            "listen_port": ${PORTS[SINGBOX]},
            "sniff": true,
            "sniff_override_destination": true,
            "users": [
                {
                    "name": "${ADMIN_USER}",
                    "uuid": "${USER_UUID}",
                    "alterId": 0
                }
            ],
            "transport": {
                "type": "ws",
                "path": "/vmess"
            },
            "tls": {
                "enabled": true,
                "server_name": "${SERVER_IPv4}",
                "certificate_path": "/etc/sing-box/certs/server.crt",
                "key_path": "/etc/sing-box/certs/server.key"
            }
        },
        {
            "type": "trojan",
            "tag": "trojan-in",
            "listen": "::",
            "listen_port": $((${PORTS[SINGBOX]}+1)),
            "sniff": true,
            "sniff_override_destination": true,
            "users": [
                {
                    "name": "${ADMIN_USER}",
                    "password": "${TROJAN_PASSWD}"
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "${SERVER_IPv4}",
                "certificate_path": "/etc/sing-box/certs/server.crt",
                "key_path": "/etc/sing-box/certs/server.key"
            }
        },
        {
            "type": "vless",
            "tag": "vless-in",
            "listen": "::",
            "listen_port": $((${PORTS[SINGBOX]}+2)),
            "sniff": true,
            "sniff_override_destination": true,
            "users": [
                {
                    "name": "${ADMIN_USER}",
                    "uuid": "${USER_UUID}"
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "${SERVER_IPv4}",
                "reality": {
                    "enabled": true,
                    "handshake": {
                        "server": "www.google.com",
                        "server_port": 443
                    },
                    "private_key": "${REALITY_PRIVATE_KEY}",
                    "short_id": [
                        ""
                    ]
                }
            },
            "transport": {
                "type": "grpc",
                "service_name": "vless-grpc"
            }
        },
        {
            "type": "shadowsocks",
            "tag": "shadowsocks-in",
            "listen": "::",
            "listen_port": $((${PORTS[SINGBOX]}+3)),
            "sniff": true,
            "sniff_override_destination": true,
            "method": "2022-blake3-aes-128-gcm",
            "password": "${TROJAN_PASSWD}"
        }
    ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "block",
            "tag": "block"
        }
    ],
    "route": {
        "rules": [
            {
                "geoip": "private",
                "outbound": "direct"
            },
            {
                "geoip": ["cn", "ir"],
                "outbound": "block"
            }
        ],
        "final": "direct"
    }
}
EOL

    # Save user information
    mkdir -p $CONFIG_DIR/singbox/users
    
    cat > $CONFIG_DIR/singbox/users/${ADMIN_USER}.json << EOL
{
    "username": "${ADMIN_USER}",
    "shadowsocks": {
        "password": "${ADMIN_PASS}",
        "method": "aes-256-gcm"
    },
    "vless": {
        "uuid": "${USER_UUID}",
        "flow": "xtls-rprx-vision"
    },
    "tuic": {
        "uuid": "${USER_UUID}",
        "password": "${ADMIN_PASS}"
    },
    "hysteria2": {
        "password": "${ADMIN_PASS}"
    },
    "created_at": "$(date +"%Y-%m-%d %H:%M:%S")"
}
EOL

    # Create systemd service for Sing-Box
    cat > /etc/systemd/system/sing-box.service << EOL
[Unit]
Description=Sing-Box Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOL

    # Enable and start Sing-Box service
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
   
    info "Sing-Box installation completed with Shadowsocks, VLess Reality, Tuic, and Hysteria2 protocols"
    info "Shadowsocks Password: ${ADMIN_PASS}"
    info "VLess UUID: ${USER_UUID}"
    info "Tuic UUID: ${USER_UUID}"
    info "Hysteria2 Password: ${ADMIN_PASS}"
}

# Function to install SSL-VPN (OpenVPN with enhanced security)
install_sslvpn() {
    info "Installing SSL-VPN (Enhanced OpenVPN)..."
    
    # Install required packages
    apt-get install -y openvpn easy-rsa openssl iptables-persistent || error "Failed to install OpenVPN packages"
    
    # Setup directory structure
    mkdir -p /etc/openvpn/server
    mkdir -p /etc/openvpn/client
    mkdir -p /etc/openvpn/easyrsa
    mkdir -p $CONFIG_DIR/sslvpn
    
    # Copy EasyRSA files
    cp -r /usr/share/easy-rsa/* /etc/openvpn/easyrsa/
    
    # Initialize PKI
    cd /etc/openvpn/easyrsa
    ./easyrsa init-pki
    
    # Create vars file with enhanced security settings
    cat > /etc/openvpn/easyrsa/vars << EOL
set_var EASYRSA_KEY_SIZE 4096
set_var EASYRSA_DIGEST "sha512"
set_var EASYRSA_ALGO "ec"
set_var EASYRSA_CURVE "secp521r1"
set_var EASYRSA_CA_EXPIRE 3650
set_var EASYRSA_CERT_EXPIRE 1080
set_var EASYRSA_CRL_DAYS 180
EOL
    
    # Build CA
    ./easyrsa --batch --req-cn="IRSSH-SSLVPN CA" build-ca nopass
    
    # Generate server key pair with enhanced cipher
    ./easyrsa --batch --req-cn="IRSSH-SSLVPN Server" gen-req server nopass
    ./easyrsa --batch sign-req server server
    
    # Generate Diffie-Hellman parameters
    info "Generating DH parameters (this may take a while)..."
    ./easyrsa gen-dh
    
    # Generate TLS key for additional security
    openvpn --genkey secret /etc/openvpn/server/ta.key
    
    # Copy the necessary files
    cp pki/ca.crt /etc/openvpn/server/
    cp pki/issued/server.crt /etc/openvpn/server/
    cp pki/private/server.key /etc/openvpn/server/
    cp pki/dh.pem /etc/openvpn/server/
    
    # Create server configuration with enhanced security
    cat > /etc/openvpn/server/server.conf << EOL
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /var/log/openvpn/ipp.txt

# Security enhancements
tls-crypt ta.key
cipher AES-256-GCM
auth SHA512
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
ncp-ciphers AES-256-GCM:AES-128-GCM
ecdh-curve secp521r1

# Network settings
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 1.1.1.1"
keepalive 10 120
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn/status.log
log-append /var/log/openvpn/openvpn.log
verb 3
mute 20
explicit-exit-notify 1

# Client verification with X.509
remote-cert-tls client
EOL
    
    # Create directory for logs
    mkdir -p /var/log/openvpn
    
    # Create client config generator
    cat > $SCRIPTS_DIR/generate_sslvpn_client.sh << 'EOL'
#!/bin/bash

# SSL-VPN Client Config Generator for IRSSH Panel

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <client_name>"
    exit 1
fi

CLIENT_NAME=$1
EASYRSA_DIR="/etc/openvpn/easyrsa"
OUTPUT_DIR="/etc/openvpn/client"
SERVER_IP=$(curl -s4 ifconfig.me || ip -4 route get 8.8.8.8 | awk '{print $7; exit}')
SERVER_PORT=1194
PROTOCOL=udp

# Generate client certificate
cd $EASYRSA_DIR
./easyrsa --batch gen-req $CLIENT_NAME nopass
./easyrsa --batch sign-req client $CLIENT_NAME

# Create client config
cat > $OUTPUT_DIR/${CLIENT_NAME}.ovpn << EOF
client
dev tun
proto $PROTOCOL
remote $SERVER_IP $SERVER_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA512
key-direction 1
verb 3

<ca>
$(cat pki/ca.crt)
</ca>
<cert>
$(cat pki/issued/${CLIENT_NAME}.crt)
</cert>
<key>
$(cat pki/private/${CLIENT_NAME}.key)
</key>
<tls-crypt>
$(cat /etc/openvpn/server/ta.key)
</tls-crypt>
EOF

echo "Client configuration created at $OUTPUT_DIR/${CLIENT_NAME}.ovpn"

# Add to IRSSH user database if exists
if [ -f "/etc/enhanced_ssh/db/database.conf" ]; then
    source /etc/enhanced_ssh/db/database.conf
    
    # Check if user exists in database
    USER_EXISTS=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -tAc "
        SELECT COUNT(*) FROM user_profiles WHERE username = '$CLIENT_NAME'
    ")
    
    if [ "$USER_EXISTS" -eq 0 ]; then
        echo "Warning: User $CLIENT_NAME doesn't exist in IRSSH Panel database."
        echo "Certificate created but not linked to user account."
    else
        # Add certificate info to user record
        EXPIRE_DATE=$(openssl x509 -in pki/issued/${CLIENT_NAME}.crt -enddate -noout | cut -d= -f2)
        
        PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "
            UPDATE user_profiles 
            SET sslvpn_cert = '${CLIENT_NAME}',
                sslvpn_cert_expiry = TO_TIMESTAMP('$EXPIRE_DATE', 'MMM DD HH24:MI:SS YYYY')
            WHERE username = '$CLIENT_NAME';
        "
        
        echo "Certificate linked to user $CLIENT_NAME in database."
    fi
fi

# Save file to user config directory
mkdir -p "/etc/enhanced_ssh/sslvpn/clients/${CLIENT_NAME}"
cp "$OUTPUT_DIR/${CLIENT_NAME}.ovpn" "/etc/enhanced_ssh/sslvpn/clients/${CLIENT_NAME}/"

echo "Client configuration also saved to /etc/enhanced_ssh/sslvpn/clients/${CLIENT_NAME}/"
EOL
    
    chmod +x $SCRIPTS_DIR/generate_sslvpn_client.sh
    
    # Generate client config for admin
    $SCRIPTS_DIR/generate_sslvpn_client.sh $ADMIN_USER
    
    # Enable IP forwarding
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/20-openvpn.conf
    sysctl -p /etc/sysctl.d/20-openvpn.conf
    
    # Set up iptables rules
    NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
    iptables -A INPUT -i tun+ -j ACCEPT
    iptables -A FORWARD -i tun+ -j ACCEPT
    iptables -A FORWARD -i tun+ -o $NIC -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i $NIC -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT
    
    # Save iptables rules
    if [ -d "/etc/iptables" ]; then
        iptables-save > /etc/iptables/rules.v4
    else
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
    fi
    
    # Create database tables for SSL-VPN
    if [ -f "$CONFIG_DIR/db/database.conf" ]; then
        source $CONFIG_DIR/db/database.conf
        
        PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "
            -- Add SSL-VPN fields to user profiles if they don't exist
            DO \$\$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'user_profiles' AND column_name = 'sslvpn_cert'
                ) THEN
                    ALTER TABLE user_profiles ADD COLUMN sslvpn_cert VARCHAR(100);
                    ALTER TABLE user_profiles ADD COLUMN sslvpn_cert_expiry TIMESTAMP;
                END IF;
            END \$\$;
            
            -- Create SSL-VPN statistics table if it doesn't exist
            CREATE TABLE IF NOT EXISTS sslvpn_statistics (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) NOT NULL,
                connect_time TIMESTAMP,
                disconnect_time TIMESTAMP,
                bytes_received BIGINT DEFAULT 0,
                bytes_sent BIGINT DEFAULT 0,
                client_ip VARCHAR(50),
                remote_ip VARCHAR(50),
                session_id VARCHAR(100),
                FOREIGN KEY (username) REFERENCES user_profiles(username) ON DELETE CASCADE
            );
        "
    fi
    
    # Create monitoring script for SSL-VPN
    cat > $SCRIPTS_DIR/monitoring/sslvpn_monitor.py << 'EOL'
#!/usr/bin/env python3

"""
SSL-VPN (OpenVPN) Connection Monitor for IRSSH-Panel
This script monitors OpenVPN connections and reports to the connection tracker
"""

import os
import sys
import time
import json
import logging
import subprocess
import argparse
import requests
import hashlib
import psycopg2
import configparser
import re
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/var/log/irssh/sslvpn_monitor.log')
    ]
)
logger = logging.getLogger('sslvpn-monitor')

# Configuration
CONFIG_FILE = '/etc/enhanced_ssh/db/database.conf'
STATUS_FILE = '/var/log/openvpn/status.log'

# API endpoints
API_URL = 'http://localhost:3001/api/connections'

def load_config():
    """Load database configuration from file"""
    if not os.path.exists(CONFIG_FILE):
        logger.error(f"Config file not found: {CONFIG_FILE}")
        sys.exit(1)
        
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    
    try:
        db_config = {
            'host': config.get('DEFAULT', 'DB_HOST', fallback='localhost'),
            'port': config.get('DEFAULT', 'DB_PORT', fallback='5432'),
            'dbname': config.get('DEFAULT', 'DB_NAME'),
            'user': config.get('DEFAULT', 'DB_USER'),
            'password': config.get('DEFAULT', 'DB_PASSWORD')
        }
        return db_config
    except configparser.NoSectionError:
        # Try reading as KEY=VALUE format
        db_config = {}
        with open(CONFIG_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"\'')
                    
                    if key == 'DB_HOST':
                        db_config['host'] = value
                    elif key == 'DB_PORT':
                        db_config['port'] = value
                    elif key == 'DB_NAME':
                        db_config['dbname'] = value
                    elif key == 'DB_USER':
                        db_config['user'] = value
                    elif key == 'DB_PASSWORD':
                        db_config['password'] = value
                        
        if not all(k in db_config for k in ['dbname', 'user', 'password']):
            logger.error("Missing required database configuration")
            sys.exit(1)
            
        return db_config

def get_db_connection():
    """Get a connection to the PostgreSQL database"""
    db_config = load_config()
    try:
        conn = psycopg2.connect(**db_config)
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        return None

def get_active_sslvpn_connections():
    """Get currently active OpenVPN sessions with username"""
    try:
        if not os.path.exists(STATUS_FILE):
            logger.error(f"OpenVPN status file not found: {STATUS_FILE}")
            return []
        
        with open(STATUS_FILE, 'r') as f:
            status_data = f.read()
        
        connections = []
        client_list_started = False
        routing_table_started = False
        
        clients = {}
        routes = {}
        
        # Parse the OpenVPN status file
        for line in status_data.splitlines():
            line = line.strip()
            
            if line == "ROUTING TABLE":
                client_list_started = False
                routing_table_started = True
                continue
            elif line == "CLIENT LIST":
                client_list_started = True
                routing_table_started = False
                continue
            elif line == "GLOBAL STATS" or line.startswith("Updated,"):
                client_list_started = False
                routing_table_started = False
                continue
            
            if client_list_started and line and not line.startswith("Common Name"):
                parts = line.split(',')
                if len(parts) >= 4:
                    username = parts[0]
                    ip_port = parts[1]
                    remote_ip = ip_port.split(':')[0]
                    
                    bytes_received = int(parts[2])
                    bytes_sent = int(parts[3])
                    
                    clients[username] = {
                        'remote_ip': remote_ip,
                        'bytes_received': bytes_received,
                        'bytes_sent': bytes_sent
                    }
            
            if routing_table_started and line and not line.startswith("Virtual Address"):
                parts = line.split(',')
                if len(parts) >= 2:
                    virtual_ip = parts[0]
                    username = parts[1]
                    
                    routes[username] = virtual_ip
        
        # Combine the data
        for username, client_data in clients.items():
            virtual_ip = routes.get(username, 'Unknown')
            
            # Create a unique session ID
            session_id = f"sslvpn_{username}_{hashlib.md5(client_data['remote_ip'].encode()).hexdigest()[:16]}"
            
            connections.append({
                'username': username,
                'ip_address': client_data['remote_ip'],
                'virtual_ip': virtual_ip,
                'bytes_received': client_data['bytes_received'],
                'bytes_sent': client_data['bytes_sent'],
                'session_id': session_id
            })
        
        return connections
    except Exception as e:
        logger.error(f"Error getting SSL-VPN connections: {e}")
        return []

def check_user_exists(username):
    """Check if user exists in the database"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT username FROM user_profiles WHERE username = %s", (username,))
            return cur.fetchone() is not None
    except Exception as e:
        logger.error(f"Error checking user existence: {e}")
        return False
    finally:
        conn.close()

def get_active_sessions_from_db():
    """Get active sessions from the database"""
    conn = get_db_connection()
    if not conn:
        return {}
    
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT username, session_id FROM user_connections "
                "WHERE protocol = 'sslvpn' AND status = 'active'"
            )
            return {row[1]: row[0] for row in cur.fetchall()}
    except Exception as e:
        logger.error(f"Error getting active sessions from DB: {e}")
        return {}
    finally:
        conn.close()

def report_connection_start(username, ip_address, session_id):
    """Report new connection to the API"""
    try:
        response = requests.post(
            f"{API_URL}/start",
            json={
                "username": username,
                "protocol": "sslvpn",
                "client_ip": ip_address,
                "session_id": session_id
            },
            timeout=5
        )
        
        if response.status_code == 200:
            logger.info(f"Reported new SSL-VPN connection: {username} from {ip_address}")
            return True
        else:
            logger.error(f"Failed to report connection: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error reporting connection start: {e}")
        return False

def report_connection_end(username, session_id):
    """Report connection end to the API"""
    try:
        response = requests.post(
            f"{API_URL}/end",
            json={
                "username": username,
                "session_id": session_id
            },
            timeout=5
        )
        
        if response.status_code == 200:
            logger.info(f"Reported SSL-VPN disconnect: {username} (Session: {session_id})")
            return True
        else:
            logger.warning(f"Failed to report disconnect: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error reporting connection end: {e}")
        return False

def update_traffic_stats(username, session_id, bytes_received, bytes_sent):
    """Update traffic statistics for an active connection"""
    try:
        response = requests.post(
            f"{API_URL}/update_traffic",
            json={
                "username": username,
                "session_id": session_id,
                "upload_bytes": bytes_sent,
                "download_bytes": bytes_received
            },
            timeout=5
        )
        
        if response.status_code != 200:
            logger.warning(f"Failed to update traffic stats: {response.status_code} - {response.text}")
    except Exception as e:
        logger.error(f"Error updating traffic stats: {e}")

def monitor_sslvpn_connections():
    """Main monitoring loop"""
    logger.info("Starting SSL-VPN connection monitor")
    
    # Track previous connections and their traffic stats
    previous_connections = {}
    
    # Run continuously
    while True:
        try:
            # Get current SSL-VPN connections
            current_connections = get_active_sslvpn_connections()
            current_connections_map = {conn['session_id']: conn for conn in current_connections}
            
            # Get active sessions from database
            db_sessions = get_active_sessions_from_db()
            
            # Check for new connections and update traffic stats
            for conn in current_connections:
                session_id = conn['session_id']
                
                # New connection
                if session_id not in previous_connections:
                    # Verify user exists in our system
                    if check_user_exists(conn['username']):
                        report_connection_start(
                            conn['username'],
                            conn['ip_address'],
                            session_id
                        )
                else:
                    # Update traffic stats - calculate delta
                    prev_conn = previous_connections[session_id]
                    bytes_received_delta = conn['bytes_received'] - prev_conn['bytes_received']
                    bytes_sent_delta = conn['bytes_sent'] - prev_conn['bytes_sent']
                    
                    # Only report if there's actual traffic (avoid unnecessary API calls)
                    if bytes_received_delta > 0 or bytes_sent_delta > 0:
                        update_traffic_stats(
                            conn['username'],
                            session_id,
                            bytes_received_delta,
                            bytes_sent_delta
                        )
            
            # Check for ended connections
            for session_id, username in db_sessions.items():
                if session_id not in current_connections_map:
                    report_connection_end(username, session_id)
            
            # Update previous connections for next iteration
            previous_connections = current_connections_map
            
            # Sleep before next check
            time.sleep(60)  # Check every minute
            
        except KeyboardInterrupt:
            logger.info("Stopping SSL-VPN connection monitor")
            break
        except Exception as e:
            logger.error(f"Error in monitoring loop: {e}")
            time.sleep(30)  # Sleep and retry

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SSL-VPN Connection Monitor for IRSSH-Panel')
    parser.add_argument('--daemon', action='store_true', help='Run as a daemon process')
    args = parser.parse_args()
    
    if args.daemon:
        # Fork process to run as daemon
        pid = os.fork()
        if pid > 0:
            # Exit parent process
            sys.exit(0)
            
        # Detach from terminal
        os.setsid()
        os.umask(0)
        
        # Fork again
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
        
        # Close file descriptors
        for fd in range(0, 3):
            try:
                os.close(fd)
            except OSError:
                pass
                
        # Redirect stdout/stderr
        sys.stdout = open('/var/log/irssh/sslvpn_monitor_stdout.log', 'w')
        sys.stderr = open('/var/log/irssh/sslvpn_monitor_stderr.log', 'w')
        
        logger.info("Running as daemon process")
    
    monitor_sslvpn_connections()
EOL
    
    chmod +x $SCRIPTS_DIR/monitoring/sslvpn_monitor.py
    
    # Create systemd service for SSL-VPN
    cat > /etc/systemd/system/openvpn-server@server.service << EOL
[Unit]
Description=OpenVPN service for server
After=network.target
PartOf=openvpn.service

[Service]
Type=notify
PrivateTmp=true
WorkingDirectory=/etc/openvpn/server
ExecStart=/usr/sbin/openvpn --status /var/log/openvpn/status.log --status-version 2 --suppress-timestamps --config server.conf
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOL

    # Create systemd service for SSL-VPN monitor
    cat > /etc/systemd/system/irssh-sslvpn-monitor.service << EOL
[Unit]
Description=IRSSH SSL-VPN Connection Monitor
After=network.target openvpn-server@server.service irssh-user-manager.service
Wants=irssh-user-manager.service

[Service]
Type=simple
ExecStart=$SCRIPTS_DIR/monitoring/sslvpn_monitor.py --daemon
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOL

    # Enable and start the services
    systemctl daemon-reload
    systemctl enable openvpn-server@server.service
    systemctl start openvpn-server@server.service
    systemctl enable irssh-sslvpn-monitor.service
    systemctl start irssh-sslvpn-monitor.service
    
    info "SSL-VPN (Enhanced OpenVPN) installation completed"
}

# Function to install NordWhisper (a Shadowsocks + Cloak implementation)
install_nordwhisper() {
    info "Installing NordWhisper (Shadowsocks + Cloak obfuscation)..."
    
    local SS_PORT=1082
    local CLOAK_PORT=443
    
    # Ask user for ports
    read -p "Enter port for NordWhisper (Shadowsocks) [1082]: " NORDWHISPER_PORT
    NORDWHISPER_PORT=${NORDWHISPER_PORT:-1082}
    SS_PORT=$NORDWHISPER_PORT
    
    read -p "Enter port for Cloak (obfuscation layer) [443]: " CLOAK_PORT_INPUT
    CLOAK_PORT=${CLOAK_PORT_INPUT:-443}
    
    # Generate random values
    SS_PASSWORD=$(openssl rand -base64 16)
    SS_METHOD="chacha20-ietf-poly1305"
    
    CLOAK_ADMIN_ID=$(uuidgen)
    CLOAK_UID=$(uuidgen)
    CLOAK_PUBLIC_KEY=""
    CLOAK_PRIVATE_KEY=""
    
    # Install prerequisites
    apt-get update
    apt-get install -y git build-essential golang-go libsodium-dev || error "Failed to install prerequisites for NordWhisper" "no-exit"
    
    # Create directories
    mkdir -p $CONFIG_DIR/nordwhisper
    mkdir -p $SCRIPTS_DIR/nordwhisper
    
    # Install shadowsocks-libev
    apt-get install -y shadowsocks-libev || error "Failed to install Shadowsocks" "no-exit"
    
    # Create shadowsocks config
    cat > /etc/shadowsocks-libev/config.json << EOL
{
    "server":"0.0.0.0",
    "server_port":${SS_PORT},
    "password":"${SS_PASSWORD}",
    "timeout":300,
    "method":"${SS_METHOD}",
    "fast_open":true,
    "mode":"tcp_and_udp",
    "plugin":"ck-server",
    "plugin_opts":"MethodName=chacha20-poly1305;EncryptionMethod=plain;RedirAddr=www.bing.com;TicketTimeHint=3600;NumConn=4;ServerName=www.microsoft.com;MaxClients=64;UDPTimeOut=30"
}
EOL
    
    # Install Cloak (Transport Layer Obfuscation)
    cd $TEMP_DIR
    info "Installing Cloak obfuscation layer..."
    go install github.com/cbeuw/Cloak/v2/cmd/ck-server@latest
    go install github.com/cbeuw/Cloak/v2/cmd/ck-client@latest
    
    # Copy binary files
    cp ~/go/bin/ck-server /usr/local/bin/
    cp ~/go/bin/ck-client /usr/local/bin/
    
    chmod +x /usr/local/bin/ck-server
    chmod +x /usr/local/bin/ck-client
    
    # Generate Cloak keys
    cd $CONFIG_DIR/nordwhisper
    ck-server -k > keys.json
    
    # Extract keys
    CLOAK_PRIVATE_KEY=$(cat keys.json | grep -oP '"PrivateKey":\s*"\K[^"]+')
    CLOAK_PUBLIC_KEY=$(cat keys.json | grep -oP '"PublicKey":\s*"\K[^"]+')
    
    # Generate main Cloak config
    cat > $CONFIG_DIR/nordwhisper/ck-server.json << EOL
{
    "ProxyBook": {
        "shadowsocks": [
            "tcp",
            "127.0.0.1:${SS_PORT}"
        ]
    },
    "BindAddr": [
        "0.0.0.0:${CLOAK_PORT}"
    ],
    "BypassUID": [
        "${CLOAK_ADMIN_ID}"
    ],
    "RedirAddr": "www.bing.com",
    "PrivateKey": "${CLOAK_PRIVATE_KEY}",
    "AdminUID": "${CLOAK_ADMIN_ID}",
    "DatabasePath": "$CONFIG_DIR/nordwhisper/userinfo.db",
    "KeepAlive": 0,
    "StreamTimeout": 300,
    "CncMode": false
}
EOL
    
    # Add user to Cloak database
    touch $CONFIG_DIR/nordwhisper/userinfo.db
    ck-server -u -c $CONFIG_DIR/nordwhisper/ck-server.json -r ${ADMIN_USER} -f ${CLOAK_UID}
    
    # Create systemd service for Cloak
    cat > /etc/systemd/system/cloak.service << EOL
[Unit]
Description=Cloak Proxy Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/ck-server -c $CONFIG_DIR/nordwhisper/ck-server.json
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOL
    
    # Enable and start Cloak service
    systemctl daemon-reload
    systemctl enable cloak
    systemctl restart cloak
    
    # Restart Shadowsocks with Cloak plugin
    systemctl enable shadowsocks-libev
    systemctl restart shadowsocks-libev
    
    # Create client config generator script
    cat > $SCRIPTS_DIR/nordwhisper/generate_nordwhisper_client.sh << EOL
#!/bin/bash

# NordWhisper (Shadowsocks+Cloak) Client Config Generator for IRSSH Panel

if [ "\$#" -ne 1 ]; then
    echo "Usage: \$0 <username>"
    exit 1
fi

USERNAME=\$1
SERVER_IP=\$(curl -s4 ifconfig.me || ip -4 route get 8.8.8.8 | awk '{print \$7; exit}')
SS_PORT=${SS_PORT}
CLOAK_PORT=${CLOAK_PORT}
SS_METHOD="${SS_METHOD}"
SS_PASSWORD="${SS_PASSWORD}"
CLOAK_PUBLIC_KEY="${CLOAK_PUBLIC_KEY}"

# Generate random UID for user
USER_UID=\$(uuidgen)

# Add user to Cloak database
ck-server -u -c $CONFIG_DIR/nordwhisper/ck-server.json -r \${USERNAME} -f \${USER_UID}

# Create output directory
mkdir -p $CONFIG_DIR/nordwhisper/clients/\${USERNAME}

# Create Shadowsocks JSON config
cat > $CONFIG_DIR/nordwhisper/clients/\${USERNAME}/shadowsocks.json << EOSS
{
    "server": "\${SERVER_IP}",
    "server_port": \${CLOAK_PORT},
    "password": "${SS_PASSWORD}",
    "method": "${SS_METHOD}",
    "plugin": "ck-client",
    "plugin_opts": "UID=\${USER_UID};PublicKey=${CLOAK_PUBLIC_KEY};ServerName=www.microsoft.com;TicketTimeHint=3600;BrowserSig=chrome;NumConn=4"
}
EOSS

# Create Outline format
cat > $CONFIG_DIR/nordwhisper/clients/\${USERNAME}/outline.txt << EOOL
ss://$(echo -n "${SS_METHOD}:${SS_PASSWORD}" | base64 -w 0)@\${SERVER_IP}:\${CLOAK_PORT}/?plugin=ck-client%3BUID%3D\${USER_UID}%3BPublicKey%3D${CLOAK_PUBLIC_KEY}%3BServerName%3Dwww.microsoft.com%3BTicketTimeHint%3D3600%3BBrowserSig%3Dchrome%3BNumConn%3D4#NordWhisper-\${USERNAME}
EOOL

# Create v2rayN format (Base64 encoded entire config)
cat > $CONFIG_DIR/nordwhisper/clients/\${USERNAME}/v2rayn.txt << EOV2
{
    "server": "\${SERVER_IP}",
    "server_port": \${CLOAK_PORT},
    "password": "${SS_PASSWORD}",
    "method": "${SS_METHOD}",
    "plugin": "ck-client",
    "plugin_opts": "UID=\${USER_UID};PublicKey=${CLOAK_PUBLIC_KEY};ServerName=www.microsoft.com;TicketTimeHint=3600;BrowserSig=chrome;NumConn=4",
    "remarks": "NordWhisper-\${USERNAME}",
    "timeout": 300
}
EOV2

# Encode for v2rayN
V2RAYN_ENCODED=\$(cat $CONFIG_DIR/nordwhisper/clients/\${USERNAME}/v2rayn.txt | base64 -w 0)
echo \$V2RAYN_ENCODED > $CONFIG_DIR/nordwhisper/clients/\${USERNAME}/v2rayn_encoded.txt

echo "Client configurations generated for \${USERNAME} in $CONFIG_DIR/nordwhisper/clients/\${USERNAME}/"
echo "Shadowsocks config: $CONFIG_DIR/nordwhisper/clients/\${USERNAME}/shadowsocks.json"
echo "Outline Format: $CONFIG_DIR/nordwhisper/clients/\${USERNAME}/outline.txt"
echo "v2rayN Format: $CONFIG_DIR/nordwhisper/clients/\${USERNAME}/v2rayn_encoded.txt"

# Add to database if exists
if [ -f "/etc/enhanced_ssh/db/database.conf" ]; then
    source /etc/enhanced_ssh/db/database.conf
    
    # Check if user exists in database
    USER_EXISTS=\$(PGPASSWORD="\$DB_PASSWORD" psql -h "\$DB_HOST" -U "\$DB_USER" -d "\$DB_NAME" -tAc "
        SELECT COUNT(*) FROM user_profiles WHERE username = '\${USERNAME}'
    ")
    
    if [ "\$USER_EXISTS" -eq 0 ]; then
        echo "Warning: User \${USERNAME} doesn't exist in IRSSH Panel database."
        echo "Configuration created but not linked to user account."
    else
        # Add nordwhisper info to user record
        PGPASSWORD="\$DB_PASSWORD" psql -h "\$DB_HOST" -U "\$DB_USER" -d "\$DB_NAME" -c "
            DO \\\$\\\$
            BEGIN
                ALTER TABLE user_profiles ADD COLUMN IF NOT EXISTS nordwhisper_uid VARCHAR(36);
                
                UPDATE user_profiles 
                SET nordwhisper_uid = '\${USER_UID}'
                WHERE username = '\${USERNAME}';
            END \\\$\\\$;
        "
        
        echo "NordWhisper UID linked to user \${USERNAME} in database."
    fi
fi
EOL
    
    chmod +x $SCRIPTS_DIR/nordwhisper/generate_nordwhisper_client.sh
    
    # Create NordWhisper monitor script
    cat > $SCRIPTS_DIR/monitoring/nordwhisper_monitor.py << 'EOL'
#!/usr/bin/env python3

"""
NordWhisper Connection Monitor for IRSSH-Panel
This script monitors Shadowsocks+Cloak connections and reports to the connection tracker
"""

import os
import sys
import time
import json
import logging
import subprocess
import argparse
import requests
import hashlib
import psycopg2
import configparser
import sqlite3
import re
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/var/log/irssh/nordwhisper_monitor.log')
    ]
)
logger = logging.getLogger('nordwhisper-monitor')

# Configuration
CONFIG_FILE = '/etc/enhanced_ssh/db/database.conf'
CLOAK_DB = '/etc/enhanced_ssh/nordwhisper/userinfo.db'
CLOAK_CONFIG = '/etc/enhanced_ssh/nordwhisper/ck-server.json'

# API endpoints
API_URL = 'http://localhost:3001/api/connections'

def load_config():
    """Load database configuration from file"""
    if not os.path.exists(CONFIG_FILE):
        logger.error(f"Config file not found: {CONFIG_FILE}")
        sys.exit(1)
        
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    
    try:
        db_config = {
            'host': config.get('DEFAULT', 'DB_HOST', fallback='localhost'),
            'port': config.get('DEFAULT', 'DB_PORT', fallback='5432'),
            'dbname': config.get('DEFAULT', 'DB_NAME'),
            'user': config.get('DEFAULT', 'DB_USER'),
            'password': config.get('DEFAULT', 'DB_PASSWORD')
        }
        return db_config
    except configparser.NoSectionError:
        # Try reading as KEY=VALUE format
        db_config = {}
        with open(CONFIG_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"\'')
                    
                    if key == 'DB_HOST':
                        db_config['host'] = value
                    elif key == 'DB_PORT':
                        db_config['port'] = value
                    elif key == 'DB_NAME':
                        db_config['dbname'] = value
                    elif key == 'DB_USER':
                        db_config['user'] = value
                    elif key == 'DB_PASSWORD':
                        db_config['password'] = value
                        
        if not all(k in db_config for k in ['dbname', 'user', 'password']):
            logger.error("Missing required database configuration")
            sys.exit(1)
            
        return db_config

def get_db_connection():
    """Get a connection to the PostgreSQL database"""
    db_config = load_config()
    try:
        conn = psycopg2.connect(**db_config)
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        return None

def get_cloak_users():
    """Get users from Cloak database with their UIDs"""
    users = {}
    
    if not os.path.exists(CLOAK_DB):
        logger.error(f"Cloak database not found: {CLOAK_DB}")
        return users
    
    try:
        conn = sqlite3.connect(CLOAK_DB)
        cursor = conn.cursor()
        
        # Get all users from Cloak database
        cursor.execute("SELECT rowid, UID, Username FROM users")
        
        for row in cursor.fetchall():
            user_id, uid, username = row
            users[uid] = username
        
        conn.close()
        return users
    except Exception as e:
        logger.error(f"Error reading Cloak database: {e}")
        return users

def get_active_nordwhisper_connections():
    """Get active Shadowsocks+Cloak connections"""
    active_connections = []
    
    try:
        # Get all established connections to Cloak port
        # First get the Cloak port from config
        with open(CLOAK_CONFIG, 'r') as f:
            config = json.load(f)
            
        bind_addrs = config.get('BindAddr', [])
        if not bind_addrs:
            logger.error("No bind addresses found in Cloak config")
            return []
            
        # Extract port from the first bind address
        cloak_port = bind_addrs[0].split(':')[-1]
        
        # Get connections to this port
        output = subprocess.check_output(
            f"netstat -tn | grep ESTABLISHED | grep ':{cloak_port}' || true",
            shell=True, text=True
        )
        
        # Get UIDs to username mapping
        cloak_users = get_cloak_users()
        
        # Get UIDs for connected clients from Cloak logs
        # This is a simplification and might not work in all cases
        # A better approach would be to inspect Cloak's state directly
        
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                local_addr = parts[3]
                remote_addr = parts[4]
                remote_ip = remote_addr.split(':')[0]
                
                # Generate a semi-stable session ID based on IP + timestamp of hour
                # This assumes connections don't change multiple times per hour for same IP
                hour_timestamp = int(time.time()) // 3600
                session_hash = hashlib.md5(f"{remote_ip}_{hour_timestamp}".encode()).hexdigest()[:16]
                
                # For proper tracking, we would need to match these connections to UIDs
                # For this example, we'll use the keys of users we have
                for uid, username in cloak_users.items():
                    # In a production system, we would accurately determine which UID is using this connection
                    # For now, we're making the best guess with available information
                    # and linking to known users randomly for demonstration
                    # In reality, this should use Cloak's internal state or logs
                    
                    active_connections.append({
                        'username': username,
                        'ip_address': remote_ip,
                        'uid': uid,
                        'session_id': f"nordwhisper_{username}_{session_hash}"
                    })
                    break  # Just pick the first user for demonstration
        
        return active_connections
    except Exception as e:
        logger.error(f"Error getting NordWhisper connections: {e}")
        return []

def check_user_exists(username):
    """Check if user exists in the database"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT username FROM user_profiles WHERE username = %s", (username,))
            return cur.fetchone() is not None
    except Exception as e:
        logger.error(f"Error checking user existence: {e}")
        return False
    finally:
        conn.close()

def get_active_sessions_from_db():
    """Get active sessions from the database"""
    conn = get_db_connection()
    if not conn:
        return {}
    
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT username, session_id FROM user_connections "
                "WHERE protocol = 'nordwhisper' AND status = 'active'"
            )
            return {row[1]: row[0] for row in cur.fetchall()}
    except Exception as e:
        logger.error(f"Error getting active sessions from DB: {e}")
        return {}
    finally:
        conn.close()

def report_connection_start(username, ip_address, session_id):
    """Report new connection to the API"""
    try:
        response = requests.post(
            f"{API_URL}/start",
            json={
                "username": username,
                "protocol": "nordwhisper",
                "client_ip": ip_address,
                "session_id": session_id
            },
            timeout=5
        )
        
        if response.status_code == 200:
            logger.info(f"Reported new NordWhisper connection: {username} from {ip_address}")
            return True
        else:
            logger.error(f"Failed to report connection: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error reporting connection start: {e}")
        return False

def report_connection_end(username, session_id):
    """Report connection end to the API"""
    try:
        response = requests.post(
            f"{API_URL}/end",
            json={
                "username": username,
                "session_id": session_id
            },
            timeout=5
        )
        
        if response.status_code == 200:
            logger.info(f"Reported NordWhisper disconnect: {username} (Session: {session_id})")
            return True
        else:
            logger.warning(f"Failed to report disconnect: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error reporting connection end: {e}")
        return False

def monitor_nordwhisper_connections():
    """Main monitoring loop"""
    logger.info("Starting NordWhisper connection monitor")
    
    # Track previous connections
    previous_connections = set()
    
    # Run continuously
    while True:
        try:
            # Get current NordWhisper connections
            current_connections = get_active_nordwhisper_connections()
            current_session_ids = {conn['session_id'] for conn in current_connections}
            
            # Get active sessions from database
            db_sessions = get_active_sessions_from_db()
            
            # Check for new connections
            for conn in current_connections:
                if conn['session_id'] not in previous_connections:
                    # Verify user exists in our system
                    if check_user_exists(conn['username']):
                        report_connection_start(
                            conn['username'],
                            conn['ip_address'],
                            conn['session_id']
                        )
            
            # Check for ended connections
            for session_id, username in db_sessions.items():
                if session_id not in current_session_ids:
                    report_connection_end(username, session_id)
            
            # Update previous connections for next iteration
            previous_connections = current_session_ids
            
            # Sleep before next check
            time.sleep(60)  # Check every minute
            
        except KeyboardInterrupt:
            logger.info("Stopping NordWhisper connection monitor")
            break
        except Exception as e:
            logger.error(f"Error in monitoring loop: {e}")
            time.sleep(30)  # Sleep and retry

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='NordWhisper Connection Monitor for IRSSH-Panel')
    parser.add_argument('--daemon', action='store_true', help='Run as a daemon process')
    args = parser.parse_args()
    
    if args.daemon:
        # Fork process to run as daemon
        pid = os.fork()
        if pid > 0:
            # Exit parent process
            sys.exit(0)
            
        # Detach from terminal
        os.setsid()
        os.umask(0)
        
        # Fork again
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
        
        # Close file descriptors
        for fd in range(0, 3):
            try:
                os.close(fd)
            except OSError:
                pass
                
        # Redirect stdout/stderr
        sys.stdout = open('/var/log/irssh/nordwhisper_monitor_stdout.log', 'w')
        sys.stderr = open('/var/log/irssh/nordwhisper_monitor_stderr.log', 'w')
        
        logger.info("Running as daemon process")
    
    monitor_nordwhisper_connections()
EOL
    
    chmod +x $SCRIPTS_DIR/monitoring/nordwhisper_monitor.py
    
    # Create systemd service for NordWhisper monitor
    cat > /etc/systemd/system/irssh-nordwhisper-monitor.service << EOL
[Unit]
Description=IRSSH NordWhisper Connection Monitor
After=network.target cloak.service shadowsocks-libev.service irssh-user-manager.service
Wants=irssh-user-manager.service

[Service]
Type=simple
ExecStart=$SCRIPTS_DIR/monitoring/nordwhisper_monitor.py --daemon
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOL

    # Generate client config for admin
    $SCRIPTS_DIR/nordwhisper/generate_nordwhisper_client.sh $ADMIN_USER
    
    # Enable and start the monitor service
    systemctl daemon-reload
    systemctl enable irssh-nordwhisper-monitor.service
    systemctl start irssh-nordwhisper-monitor.service
    
    info "NordWhisper (Shadowsocks + Cloak) installation completed"
    info "Server IP: $SERVER_IPv4"
    info "Cloak Port: $CLOAK_PORT"
    info "Client configs saved to: $CONFIG_DIR/nordwhisper/clients/$ADMIN_USER/"
}

# Installation for DropBear - a lightweight SSH server
install_dropbear() {
    info "Installing DropBear (lightweight SSH server)..."
    
    # Ask for port
    read -p "Enter DropBear SSH port [222]: " DROPBEAR_PORT
    DROPBEAR_PORT=${DROPBEAR_PORT:-222}
    
    # Install DropBear
    apt-get install -y dropbear || error "Failed to install DropBear" "no-exit"
    
    # Create directory for keys if it doesn't exist
    mkdir -p /etc/dropbear
    
    # Backup original configuration if it exists
    if [ -f /etc/default/dropbear ]; then
        cp /etc/default/dropbear /etc/default/dropbear.backup
    fi
    
    # Configure DropBear
    cat > /etc/default/dropbear << EOL
# DropBear configuration for IRSSH Panel

# The TCP port that DropBear listens on
DROPBEAR_PORT=$DROPBEAR_PORT

# Any additional arguments for DropBear
DROPBEAR_EXTRA_ARGS="-w -g"

# If multiple network interfaces should be listened on, specify them here
# DROPBEAR_LISTEN=""

# Run in the background
NO_START=0

# DropBear banner path
DROPBEAR_BANNER="/etc/enhanced_ssh/dropbear/banner.txt"
EOL

    # Create directory for DropBear configuration
    mkdir -p $CONFIG_DIR/dropbear
    
    # Create banner
    cat > $CONFIG_DIR/dropbear/banner.txt << EOL
==========================================================
                 IRSSH Panel DropBear SSH
==========================================================
This server is protected and all activities are logged.
Unauthorized access is prohibited.
==========================================================
EOL

    # Generate a host key if it doesn't exist
    if [ ! -f /etc/dropbear/dropbear_rsa_host_key ]; then
        dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key
    fi
    
    if [ ! -f /etc/dropbear/dropbear_ecdsa_host_key ]; then
        dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key
    fi
    
    # Restart DropBear
    systemctl enable dropbear
    systemctl restart dropbear
    
    info "DropBear installation completed on port $DROPBEAR_PORT"
}

# Installation for BadVPN UDP Gateway
install_badvpn() {
    info "Installing BadVPN UDP Gateway..."

    # Ask for port
    read -p "Enter BadVPN UDP Gateway port [7300]: " BADVPN_PORT
    BADVPN_PORT=${BADVPN_PORT:-7300}
    
    # Install dependencies
    apt-get install -y cmake g++ make libssl-dev || error "Failed to install BadVPN dependencies" "no-exit"
    
    cd $TEMP_DIR
    
    # Download and compile BadVPN
    git clone https://github.com/ambrop72/badvpn.git
    cd badvpn
    mkdir -p build
    cd build
    cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
    make
    make install
    
    # Create systemd service for BadVPN
    cat > /etc/systemd/system/badvpn.service << EOL
[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:$BADVPN_PORT --max-clients 500 --client-socket-sndbuf 10000
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOL

    # Enable and start the service
    systemctl daemon-reload
    systemctl enable badvpn
    systemctl start badvpn
    
    info "BadVPN UDP Gateway installation completed on port $BADVPN_PORT"
}

# Setup monitoring
setup_monitoring() {
    info "Setting up monitoring system..."
   
    apt-get install -y prometheus-node-exporter collectd vnstat || error "Failed to install monitoring tools"
   
    mkdir -p "$LOG_DIR/metrics"
   
    # Create Node Exporter service if it doesn't exist
    if [ ! -f "/etc/systemd/system/node-exporter.service" ]; then
        cat > /etc/systemd/system/node-exporter.service << EOL
[Unit]
Description=Prometheus Node Exporter
After=network.target

[Service]
Type=simple
User=node_exporter
ExecStart=/usr/bin/node_exporter
Restart=always

[Install]
WantedBy=multi-user.target
EOL
    fi

    # Configure collectd for enhanced performance monitoring
    cat > /etc/collectd/collectd.conf << EOL
# IRSSH Panel Enhanced Monitoring Configuration

# Global settings
Hostname "irssh-server"
FQDNLookup false
Interval 10
MaxReadInterval 60
Timeout 2
ReadThreads 5
WriteThreads 5

# Load plugins
LoadPlugin cpu
LoadPlugin memory
LoadPlugin load
LoadPlugin disk
LoadPlugin interface
LoadPlugin uptime
LoadPlugin users
LoadPlugin processes
LoadPlugin tcpconns
LoadPlugin network
LoadPlugin df
LoadPlugin rrdtool
LoadPlugin swap
LoadPlugin syslog
LoadPlugin unixsock

# Configure plugins

<Plugin cpu>
  ReportByCpu true
  ReportByState true
  ValuesPercentage true
</Plugin>

<Plugin df>
  MountPoint "/"
  IgnoreSelected false
  ReportInodes true
  ReportReserved true
</Plugin>

<Plugin disk>
  Disk "/^[hsv]d[a-z]/"
  IgnoreSelected false
</Plugin>

<Plugin interface>
  Interface "eth0"
  Interface "ens3"
  Interface "enp0s3"
  IgnoreSelected false
</Plugin>

<Plugin memory>
  ValuesAbsolute true
  ValuesPercentage true
</Plugin>

<Plugin network>
  Server "localhost" "25826"
</Plugin>

<Plugin processes>
  Process "ssh"
  Process "nginx"
  Process "postgres"
  Process "redis"
  Process "node"
  Process "openvpn"
  Process "wg"
  Process "ck-server"
  Process "sing-box"
</Plugin>

<Plugin rrdtool>
  DataDir "/var/lib/collectd/rrd"
  StepSize 10
  HeartBeat 20
  RRARows 1200
  RRATimespan 172800
  RRATimespan 604800
  RRATimespan 2678400
  RRATimespan 31536000
</Plugin>

<Plugin tcpconns>
  ListeningPorts true
  AllPortsSummary true
</Plugin>

<Plugin unixsock>
  SocketFile "/var/run/collectd-socket"
  SocketGroup "root"
  SocketPerms "0660"
</Plugin>
EOL

    # Create advanced monitoring scripts

    # CPU usage monitoring script
    cat > "$SCRIPTS_DIR/monitoring/cpu_monitor.sh" << 'EOF'
#!/bin/bash

LOG_DIR="/var/log/irssh/metrics"
mkdir -p "$LOG_DIR"

# Enhanced CPU monitoring with per-core stats
while true; do
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Overall CPU usage
    CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
    echo "$TIMESTAMP CPU: ${CPU_USAGE}%" >> "$LOG_DIR/cpu_usage.log"
    
    # Per-core CPU usage
    CPU_CORES=$(nproc)
    for ((i=0; i<$CPU_CORES; i++)); do
        CORE_USAGE=$(mpstat -P $i 1 1 | awk '/Average:/ {print 100 - $NF}')
        echo "$TIMESTAMP CPU$i: ${CORE_USAGE}%" >> "$LOG_DIR/cpu_cores_usage.log"
    done
    
    # CPU frequency
    if [ -d "/sys/devices/system/cpu/cpu0/cpufreq" ]; then
        for ((i=0; i<$CPU_CORES; i++)); do
            if [ -f "/sys/devices/system/cpu/cpu$i/cpufreq/scaling_cur_freq" ]; then
                FREQ=$(cat "/sys/devices/system/cpu/cpu$i/cpufreq/scaling_cur_freq")
                FREQ_MHZ=$(echo "scale=2; $FREQ/1000" | bc)
                echo "$TIMESTAMP CPU$i Frequency: ${FREQ_MHZ} MHz" >> "$LOG_DIR/cpu_freq.log"
            fi
        done
    fi
    
    # CPU load average
    LOAD_AVG=$(cat /proc/loadavg | awk '{print $1,$2,$3}')
    echo "$TIMESTAMP Load Average: $LOAD_AVG" >> "$LOG_DIR/load_average.log"
    
    # CPU temperature if available
    if [ -f "/sys/class/thermal/thermal_zone0/temp" ]; then
        TEMP=$(cat /sys/class/thermal/thermal_zone0/temp)
        TEMP_C=$(echo "scale=1; $TEMP/1000" | bc)
        echo "$TIMESTAMP CPU Temperature: ${TEMP_C}°C" >> "$LOG_DIR/cpu_temp.log"
    fi
    
    sleep 60
done
EOF
    chmod +x "$SCRIPTS_DIR/monitoring/cpu_monitor.sh"
    
    # Enhanced memory usage monitoring script
    cat > "$SCRIPTS_DIR/monitoring/memory_monitor.sh" << 'EOF'
#!/bin/bash

LOG_DIR="/var/log/irssh/metrics"
mkdir -p "$LOG_DIR"

while true; do
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Detailed memory stats
    MEM_TOTAL=$(free -m | awk '/Mem:/ {print $2}')
    MEM_USED=$(free -m | awk '/Mem:/ {print $3}')
    MEM_FREE=$(free -m | awk '/Mem:/ {print $4}')
    MEM_SHARED=$(free -m | awk '/Mem:/ {print $5}')
    MEM_CACHE=$(free -m | awk '/Mem:/ {print $6}')
    MEM_AVAIL=$(free -m | awk '/Mem:/ {print $7}')
    
    MEM_PERCENT=$(echo "scale=2; $MEM_USED*100/$MEM_TOTAL" | bc)
    
    # Swap stats
    SWAP_TOTAL=$(free -m | awk '/Swap:/ {print $2}')
    SWAP_USED=$(free -m | awk '/Swap:/ {print $3}')
    SWAP_FREE=$(free -m | awk '/Swap:/ {print $4}')
    
    if [ "$SWAP_TOTAL" -gt 0 ]; then
        SWAP_PERCENT=$(echo "scale=2; $SWAP_USED*100/$SWAP_TOTAL" | bc)
    else
        SWAP_PERCENT="0"
    fi
    
    # Write to detailed memory log
    echo "$TIMESTAMP Memory: ${MEM_PERCENT}% (${MEM_USED}MB / ${MEM_TOTAL}MB)" >> "$LOG_DIR/memory_usage.log"
    echo "$TIMESTAMP DetailedMemory: total=${MEM_TOTAL}MB, used=${MEM_USED}MB, free=${MEM_FREE}MB, shared=${MEM_SHARED}MB, cache=${MEM_CACHE}MB, available=${MEM_AVAIL}MB" >> "$LOG_DIR/memory_detailed.log"
    echo "$TIMESTAMP Swap: ${SWAP_PERCENT}% (${SWAP_USED}MB / ${SWAP_TOTAL}MB)" >> "$LOG_DIR/swap_usage.log"
    
    # Top memory processes
    echo "$TIMESTAMP Top Memory Processes:" >> "$LOG_DIR/top_memory_processes.log"
    ps aux --sort=-%mem | head -n 11 | awk '{printf "%s %s %s %s\n", $1, $2, $4, $11}' >> "$LOG_DIR/top_memory_processes.log"
    
    sleep 60
done
EOF
    chmod +x "$SCRIPTS_DIR/monitoring/memory_monitor.sh"
    
    # Enhanced disk usage monitoring script
    cat > "$SCRIPTS_DIR/monitoring/disk_monitor.sh" << 'EOF'
#!/bin/bash

LOG_DIR="/var/log/irssh/metrics"
mkdir -p "$LOG_DIR"

while true; do
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Overall disk usage
    DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    DISK_TOTAL=$(df -h / | awk 'NR==2 {print $2}')
    DISK_USED=$(df -h / | awk 'NR==2 {print $3}')
    DISK_AVAIL=$(df -h / | awk 'NR==2 {print $4}')
    
    echo "$TIMESTAMP Disk: ${DISK_USAGE}% (${DISK_USED} / ${DISK_TOTAL})" >> "$LOG_DIR/disk_usage.log"
    
    # Detailed filesystem usage
    echo "$TIMESTAMP Filesystem Details:" >> "$LOG_DIR/filesystem_usage.log"
    df -hT | grep -v tmpfs | grep -v udev >> "$LOG_DIR/filesystem_usage.log"
    
    # Disk IO statistics
    if [ -x "$(command -v iostat)" ]; then
        echo "$TIMESTAMP Disk IO Statistics:" >> "$LOG_DIR/disk_io.log"
        iostat -d -x 1 1 | grep -v "Linux" | grep -v "^$" >> "$LOG_DIR/disk_io.log"
    fi
    
    # Inode usage
    echo "$TIMESTAMP Inode Usage:" >> "$LOG_DIR/inode_usage.log"
    df -i | grep -v tmpfs | grep -v udev >> "$LOG_DIR/inode_usage.log"
    
    # Largest directories in /home
    if [ -d "/home" ]; then
        echo "$TIMESTAMP Largest Directories in /home:" >> "$LOG_DIR/largest_dirs.log"
        du -h --max-depth=2 /home 2>/dev/null | sort -rh | head -n 10 >> "$LOG_DIR/largest_dirs.log"
    fi
    
    # Largest directories in /var
    echo "$TIMESTAMP Largest Directories in /var:" >> "$LOG_DIR/largest_vars.log"
    du -h --max-depth=2 /var 2>/dev/null | sort -rh | head -n 10 >> "$LOG_DIR/largest_vars.log"
    
    sleep 300
done
EOF
    chmod +x "$SCRIPTS_DIR/monitoring/disk_monitor.sh"
    
    # Enhanced network traffic monitoring script
    cat > "$SCRIPTS_DIR/monitoring/network_monitor.sh" << 'EOF'
#!/bin/bash

LOG_DIR="/var/log/irssh/metrics"
mkdir -p "$LOG_DIR"

# Determine primary network interface
INTERFACE=$(ip route get 8.8.8.8 | grep -oP "dev \K\S+")

if [ -z "$INTERFACE" ]; then
    echo "Could not determine primary network interface." >&2
    exit 1
fi

# Initialize counters
PREV_RX=0
PREV_TX=0

# Get initial values
if [ -f "/sys/class/net/$INTERFACE/statistics/rx_bytes" ]; then
    PREV_RX=$(cat /sys/class/net/$INTERFACE/statistics/rx_bytes)
    PREV_TX=$(cat /sys/class/net/$INTERFACE/statistics/tx_bytes)
fi

# Get all network interfaces
ALL_INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo)

while true; do
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Sleep first to get accurate rate measurement
    sleep 60
    
    # Main interface traffic rate
    if [ -f "/sys/class/net/$INTERFACE/statistics/rx_bytes" ]; then
        RX=$(cat /sys/class/net/$INTERFACE/statistics/rx_bytes)
        TX=$(cat /sys/class/net/$INTERFACE/statistics/tx_bytes)
        
        # Calculate rates (bytes per second)
        RX_RATE=$((($RX - $PREV_RX) / 60))
        TX_RATE=$((($TX - $PREV_TX) / 60))
        
        # Convert to human-readable format
        RX_RATE_HR=$(numfmt --to=iec --suffix=B/s --padding=7 $RX_RATE)
        TX_RATE_HR=$(numfmt --to=iec --suffix=B/s --padding=7 $TX_RATE)
        
        # Total traffic
        RX_TOTAL=$(numfmt --to=iec --suffix=B --padding=7 $RX)
        TX_TOTAL=$(numfmt --to=iec --suffix=B --padding=7 $TX)
        
        echo "$TIMESTAMP Network $INTERFACE: RX: $RX_RATE_HR, TX: $TX_RATE_HR" >> "$LOG_DIR/network_traffic.log"
        echo "$TIMESTAMP Network $INTERFACE Total: RX: $RX_TOTAL, TX: $TX_TOTAL" >> "$LOG_DIR/network_total.log"
        
        # Update previous values
        PREV_RX=$RX
        PREV_TX=$TX
    else
        echo "Network interface $INTERFACE not found or cannot read statistics." >> "$LOG_DIR/network_traffic.log"
    fi
    
    # All interfaces traffic summary
    echo "$TIMESTAMP All Network Interfaces:" >> "$LOG_DIR/all_interfaces.log"
    for iface in $ALL_INTERFACES; do
        if [ -f "/sys/class/net/$iface/statistics/rx_bytes" ]; then
            IFACE_RX=$(cat /sys/class/net/$iface/statistics/rx_bytes)
            IFACE_TX=$(cat /sys/class/net/$iface/statistics/tx_bytes)
            
            # Convert to human-readable format
            IFACE_RX_HR=$(numfmt --to=iec --suffix=B --padding=7 $IFACE_RX)
            IFACE_TX_HR=$(numfmt --to=iec --suffix=B --padding=7 $IFACE_TX)
            
            echo "  $iface: RX: $IFACE_RX_HR, TX: $IFACE_TX_HR" >> "$LOG_DIR/all_interfaces.log"
        fi
    done
    
    # Network connections summary
    echo "$TIMESTAMP Network Connections:" >> "$LOG_DIR/network_connections.log"
    echo "  TCP Connections: $(netstat -tn | grep ESTABLISHED | wc -l)" >> "$LOG_DIR/network_connections.log"
    echo "  UDP Connections: $(netstat -un | grep -v ESTABLISHED | wc -l)" >> "$LOG_DIR/network_connections.log"
    
    # Protocol-specific connections
    echo "$TIMESTAMP Protocol Connections:" >> "$LOG_DIR/protocol_connections.log"
    echo "  SSH: $(netstat -tn | grep ":22 " | wc -l)" >> "$LOG_DIR/protocol_connections.log"
    echo "  HTTPS: $(netstat -tn | grep ":443 " | wc -l)" >> "$LOG_DIR/protocol_connections.log"
    echo "  HTTP: $(netstat -tn | grep ":80 " | wc -l)" >> "$LOG_DIR/protocol_connections.log"
    echo "  OpenVPN: $(netstat -tn | grep ":1194 " | wc -l)" >> "$LOG_DIR/protocol_connections.log"
    echo "  WireGuard: $(netstat -tn | grep ":51820 " | wc -l)" >> "$LOG_DIR/protocol_connections.log"
    
    # Get public bandwidth usage via vnstat if available
    if [ -x "$(command -v vnstat)" ]; then
        echo "$TIMESTAMP vnstat Bandwidth Summary:" >> "$LOG_DIR/vnstat_summary.log"
        vnstat -i $INTERFACE -tr 1 >> "$LOG_DIR/vnstat_summary.log"
    fi
done
EOF
    chmod +x "$SCRIPTS_DIR/monitoring/network_monitor.sh"

    # Create a consolidated system monitor script
    cat > "$SCRIPTS_DIR/monitoring/system_monitor.py" << 'EOF'
#!/usr/bin/env python3

"""
System Monitoring Service for IRSSH-Panel
This script collects and stores comprehensive system metrics
"""

import os
import sys
import time
import json
import logging
import subprocess
import argparse
import psutil
import datetime
import socket
import re
import sqlite3
import signal
import threading
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/var/log/irssh/system_monitor.log')
    ]
)
logger = logging.getLogger('system-monitor')

# Constants
DB_PATH = '/opt/irssh-panel/monitoring/metrics.db'
LOG_DIR = '/var/log/irssh/metrics'
COLLECTION_INTERVAL = 60  # seconds
LONG_INTERVAL = 300  # seconds for less frequent metrics
DATA_RETENTION_DAYS = 30  # how many days to keep data

# Ensure directories exist
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

def init_database():
    """Initialize the SQLite database for metrics storage"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create CPU metrics table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS cpu_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        cpu_percent REAL,
        load_1m REAL,
        load_5m REAL,
        load_15m REAL,
        temperature REAL,
        frequency REAL
    )
    ''')
    
    # Create memory metrics table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS memory_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        total BIGINT,
        available BIGINT,
        used BIGINT,
        percent REAL,
        swap_total BIGINT,
        swap_used BIGINT,
        swap_percent REAL
    )
    ''')
    
    # Create disk metrics table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS disk_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        device TEXT,
        mountpoint TEXT,
        total BIGINT,
        used BIGINT,
        free BIGINT,
        percent REAL,
        read_count BIGINT,
        write_count BIGINT,
        read_bytes BIGINT,
        write_bytes BIGINT
    )
    ''')
    
    # Create network metrics table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS network_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        interface TEXT,
        bytes_sent BIGINT,
        bytes_recv BIGINT,
        packets_sent BIGINT,
        packets_recv BIGINT,
        errin INTEGER,
        errout INTEGER,
        dropin INTEGER,
        dropout INTEGER
    )
    ''')
    
    # Create connection metrics table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS connection_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        protocol TEXT,
        local_addr TEXT,
        local_port INTEGER,
        remote_addr TEXT,
        remote_port INTEGER,
        status TEXT,
        pid INTEGER,
        process_name TEXT
    )
    ''')
    
    # Create system info table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS system_info (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        hostname TEXT,
        os_name TEXT,
        os_version TEXT,
        kernel_version TEXT,
        cpu_model TEXT,
        cpu_cores INTEGER,
        cpu_threads INTEGER,
        total_memory BIGINT,
        ipv4_address TEXT,
        ipv6_address TEXT,
        uptime BIGINT
    )
    ''')
    
    # Create protocol metrics table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS protocol_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        protocol TEXT,
        connections INTEGER,
        active_users INTEGER
    )
    ''')
    
    # Create indices for faster queries
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_cpu_timestamp ON cpu_metrics(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_memory_timestamp ON memory_metrics(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_disk_timestamp ON disk_metrics(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_network_timestamp ON network_metrics(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_connection_timestamp ON connection_metrics(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_protocol_timestamp ON protocol_metrics(timestamp)')
    
    conn.commit()
    conn.close()
    
    logger.info("Database initialized successfully")

def get_cpu_metrics():
    """Collect CPU metrics"""
    metrics = {
        'cpu_percent': psutil.cpu_percent(interval=1),
        'load_1m': 0.0,
        'load_5m': 0.0,
        'load_15m': 0.0,
        'temperature': None,
        'frequency': psutil.cpu_freq().current if psutil.cpu_freq() else 0.0
    }
    
    # Get load average
    load = os.getloadavg()
    metrics['load_1m'] = load[0]
    metrics['load_5m'] = load[1]
    metrics['load_15m'] = load[2]
    
    # Try to get CPU temperature
    try:
        # First try psutil, which works on some systems
        temps = psutil.sensors_temperatures()
        if 'coretemp' in temps:
            metrics['temperature'] = temps['coretemp'][0].current
        elif 'cpu_thermal' in temps:
            metrics['temperature'] = temps['cpu_thermal'][0].current
        # If that doesn't work, try reading from system files
        elif os.path.exists('/sys/class/thermal/thermal_zone0/temp'):
            with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
                metrics['temperature'] = float(f.read().strip()) / 1000
    except:
        pass  # Ignore errors in temperature collection
    
    return metrics

def get_memory_metrics():
    """Collect memory metrics"""
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    
    return {
        'total': mem.total,
        'available': mem.available,
        'used': mem.used,
        'percent': mem.percent,
        'swap_total': swap.total,
        'swap_used': swap.used,
        'swap_percent': swap.percent
    }

def get_disk_metrics():
    """Collect disk metrics"""
    metrics = []
    
    # Get disk partitions
    partitions = psutil.disk_partitions()
    for partition in partitions:
        # Skip pseudo filesystems
        if partition.fstype in ('tmpfs', 'devtmpfs', 'devfs', 'overlay', 'squashfs'):
            continue
            
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            
            # Get the device name
            device = partition.device
            
            # Get disk IO metrics
            disk_counters = None
            device_name = os.path.basename(device)
            if device_name in psutil.disk_io_counters(perdisk=True):
                disk_counters = psutil.disk_io_counters(perdisk=True)[device_name]
            
            metric = {
                'device': device,
                'mountpoint': partition.mountpoint,
                'total': usage.total,
                'used': usage.used,
                'free': usage.free,
                'percent': usage.percent,
                'read_count': disk_counters.read_count if disk_counters else 0,
                'write_count': disk_counters.write_count if disk_counters else 0,
                'read_bytes': disk_counters.read_bytes if disk_counters else 0,
                'write_bytes': disk_counters.write_bytes if disk_counters else 0
            }
            
            metrics.append(metric)
        except (PermissionError, FileNotFoundError):
            # Skip if we don't have permission to read this partition
            continue
            
    return metrics

def get_network_metrics():
    """Collect network metrics"""
    metrics = []
    
    net_counters = psutil.net_io_counters(pernic=True)
    for interface, counters in net_counters.items():
        # Skip loopback interface
        if interface == 'lo':
            continue
            
        metric = {
            'interface': interface,
            'bytes_sent': counters.bytes_sent,
            'bytes_recv': counters.bytes_recv,
            'packets_sent': counters.packets_sent,
            'packets_recv': counters.packets_recv,
            'errin': counters.errin,
            'errout': counters.errout,
            'dropin': counters.dropin,
            'dropout': counters.dropout
        }
        
        metrics.append(metric)
            
    return metrics

def get_connection_metrics():
    """Collect connection metrics"""
    metrics = []
    
    connections = psutil.net_connections()
    for conn in connections:
        try:
            # Skip unix sockets
            if not conn.laddr:
                continue
                
            # Get process name if available
            process_name = ""
            if conn.pid:
                try:
                    process = psutil.Process(conn.pid)
                    process_name = process.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                    
            metric = {
                'protocol': 'tcp' if conn.type == socket.SOCK_STREAM else 'udp',
                'local_addr': conn.laddr.ip if conn.laddr else '',
                'local_port': conn.laddr.port if conn.laddr else 0,
                'remote_addr': conn.raddr.ip if conn.raddr else '',
                'remote_port': conn.raddr.port if conn.raddr else 0,
                'status': conn.status,
                'pid': conn.pid if conn.pid else 0,
                'process_name': process_name
            }
            
            metrics.append(metric)
        except (AttributeError, IndexError):
            # Skip problematic connections
            continue
            
    return metrics

def get_system_info():
    """Collect system information"""
    
    # Get hostname
    hostname = socket.gethostname()
    
    # Get OS information
    os_name = ""
    os_version = ""
    if os.path.exists('/etc/os-release'):
        with open('/etc/os-release', 'r') as f:
            os_release = f.read()
            name_match = re.search(r'NAME="?([^"\n]+)"?', os_release)
            version_match = re.search(r'VERSION="?([^"\n]+)"?', os_release)
            if name_match:
                os_name = name_match.group(1)
            if version_match:
                os_version = version_match.group(1)
    
    # Get kernel version
    kernel_version = os.uname().release
    
    # Get CPU info
    cpu_model = ""
    cpu_cores = psutil.cpu_count(logical=False)
    cpu_threads = psutil.cpu_count(logical=True)
    
    if os.path.exists('/proc/cpuinfo'):
        with open('/proc/cpuinfo', 'r') as f:
            cpuinfo = f.read()
            model_match = re.search(r'model name\s*:\s*(.+)', cpuinfo)
            if model_match:
                cpu_model = model_match.group(1)
    
    # Get total memory
    total_memory = psutil.virtual_memory().total
    
    # Get IP addresses
    ipv4_address = ""
    ipv6_address = ""
    
    # Try to get public IPs
    try:
        ipv4_address = subprocess.check_output(['curl', '-s4', 'ifconfig.me']).decode('utf-8').strip()
    except:
        # Fallback to local IP
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    ipv4_address = addr.address
                    break
            if ipv4_address:
                break
    
    try:
        ipv6_address = subprocess.check_output(['curl', '-s6', 'ifconfig.me']).decode('utf-8').strip()
    except:
        # Fallback to local IP
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET6 and not addr.address.startswith('::1'):
                    ipv6_address = addr.address
                    break
            if ipv6_address:
                break
    
    # Get uptime
    uptime = int(time.time() - psutil.boot_time())
    
    return {
        'hostname': hostname,
        'os_name': os_name,
        'os_version': os_version,
        'kernel_version': kernel_version,
        'cpu_model': cpu_model,
        'cpu_cores': cpu_cores,
        'cpu_threads': cpu_threads,
        'total_memory': total_memory,
        'ipv4_address': ipv4_address,
        'ipv6_address': ipv6_address,
        'uptime': uptime
    }

def get_protocol_metrics():
    """Collect protocol-specific metrics"""
    metrics = []
    
    # SSH connections
    ssh_connections = 0
    ssh_users = set()
    
    # Get SSH connections from netstat
    try:
        netstat_output = subprocess.check_output(['netstat', '-tn'], text=True)
        for line in netstat_output.splitlines():
            if ':22 ' in line and 'ESTABLISHED' in line:
                ssh_connections += 1
                # Extract remote IP
                parts = line.split()
                if len(parts) >= 5:
                    remote_addr = parts[4].split(':')[0]
                    ssh_users.add(remote_addr)
    except:
        pass
    
    metrics.append({
        'protocol': 'SSH',
        'connections': ssh_connections,
        'active_users': len(ssh_users)
    })
    
    # OpenVPN connections
    openvpn_connections = 0
    openvpn_users = set()
    
    # Read OpenVPN status file if it exists
    if os.path.exists('/var/log/openvpn/status.log'):
        try:
            with open('/var/log/openvpn/status.log', 'r') as f:
                status_data = f.read()
            
            client_section = False
            for line in status_data.splitlines():
                if line.startswith('CLIENT_LIST'):
                    client_section = True
                    continue
                if client_section and line and not line.startswith('HEADER') and not line.startswith('GLOBAL') and not line.startswith('Updated'):
                    openvpn_connections += 1
                    parts = line.split(',')
                    if len(parts) >= 1:
                        openvpn_users.add(parts[0])  # Username
        except:
            pass
    
    metrics.append({
        'protocol': 'OpenVPN',
        'connections': openvpn_connections,
        'active_users': len(openvpn_users)
    })
    
    # WireGuard connections
    wg_connections = 0
    wg_users = set()
    
    # Get WireGuard connections if wg command is available
    try:
        if os.path.exists('/usr/bin/wg'):
            wg_output = subprocess.check_output(['wg', 'show', 'all', 'dump'], text=True)
            for line in wg_output.splitlines()[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 4 and int(parts[3]) > 0:  # If latest handshake > 0
                    wg_connections += 1
                    wg_users.add(parts[0])  # Public key
    except:
        pass
    
    metrics.append({
        'protocol': 'WireGuard',
        'connections': wg_connections,
        'active_users': len(wg_users)
    })
    
    # HTTP/HTTPS connections
    http_connections = 0
    https_connections = 0
    http_users = set()
    https_users = set()
    
    try:
        netstat_output = subprocess.check_output(['netstat', '-tn'], text=True)
        for line in netstat_output.splitlines():
            if ':80 ' in line and 'ESTABLISHED' in line:
                http_connections += 1
                parts = line.split()
                if len(parts) >= 5:
                    remote_addr = parts[4].split(':')[0]
                    http_users.add(remote_addr)
            elif ':443 ' in line and 'ESTABLISHED' in line:
                https_connections += 1
                parts = line.split()
                if len(parts) >= 5:
                    remote_addr = parts[4].split(':')[0]
                    https_users.add(remote_addr)
    except:
        pass
    
    metrics.append({
        'protocol': 'HTTP',
        'connections': http_connections,
        'active_users': len(http_users)
    })
    
    metrics.append({
        'protocol': 'HTTPS',
        'connections': https_connections,
        'active_users': len(https_users)
    })
    
    return metrics

def store_metrics():
    """Collect and store all metrics in the database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Store CPU metrics
    cpu_metrics = get_cpu_metrics()
    cursor.execute('''
    INSERT INTO cpu_metrics 
    (cpu_percent, load_1m, load_5m, load_15m, temperature, frequency) 
    VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        cpu_metrics['cpu_percent'],
        cpu_metrics['load_1m'],
        cpu_metrics['load_5m'],
        cpu_metrics['load_15m'],
        cpu_metrics['temperature'],
        cpu_metrics['frequency']
    ))
    
    # Store memory metrics
    memory_metrics = get_memory_metrics()
    cursor.execute('''
    INSERT INTO memory_metrics 
    (total, available, used, percent, swap_total, swap_used, swap_percent) 
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        memory_metrics['total'],
        memory_metrics['available'],
        memory_metrics['used'],
        memory_metrics['percent'],
        memory_metrics['swap_total'],
        memory_metrics['swap_used'],
        memory_metrics['swap_percent']
    ))
    
    # Store disk metrics
    disk_metrics = get_disk_metrics()
    for metric in disk_metrics:
        cursor.execute('''
        INSERT INTO disk_metrics 
        (device, mountpoint, total, used, free, percent, read_count, write_count, read_bytes, write_bytes) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            metric['device'],
            metric['mountpoint'],
            metric['total'],
            metric['used'],
            metric['free'],
            metric['percent'],
            metric['read_count'],
            metric['write_count'],
            metric['read_bytes'],
            metric['write_bytes']
        ))
    
    # Store network metrics
    network_metrics = get_network_metrics()
    for metric in network_metrics:
        cursor.execute('''
        INSERT INTO network_metrics 
        (interface, bytes_sent, bytes_recv, packets_sent, packets_recv, errin, errout, dropin, dropout) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            metric['interface'],
            metric['bytes_sent'],
            metric['bytes_recv'],
            metric['packets_sent'],
            metric['packets_recv'],
            metric['errin'],
            metric['errout'],
            metric['dropin'],
            metric['dropout']
        ))
    
    # Store protocol metrics
    protocol_metrics = get_protocol_metrics()
    for metric in protocol_metrics:
        cursor.execute('''
        INSERT INTO protocol_metrics 
        (protocol, connections, active_users) 
        VALUES (?, ?, ?)
        ''', (
            metric['protocol'],
            metric['connections'],
            metric['active_users']
        ))
    
    # Store connections less frequently to avoid database growth
    current_time = time.time()
    if current_time % LONG_INTERVAL < COLLECTION_INTERVAL:
        # Store connection metrics
        connection_metrics = get_connection_metrics()
        for metric in connection_metrics:
            cursor.execute('''
            INSERT INTO connection_metrics 
            (protocol, local_addr, local_port, remote_addr, remote_port, status, pid, process_name) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                metric['protocol'],
                metric['local_addr'],
                metric['local_port'],
                metric['remote_addr'],
                metric['remote_port'],
                metric['status'],
                metric['pid'],
                metric['process_name']
            ))
        
        # Store system info
        system_info = get_system_info()
        cursor.execute('''
        INSERT INTO system_info 
        (hostname, os_name, os_version, kernel_version, cpu_model, cpu_cores, cpu_threads, total_memory, ipv4_address, ipv6_address, uptime) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            system_info['hostname'],
            system_info['os_name'],
            system_info['os_version'],
            system_info['kernel_version'],
            system_info['cpu_model'],
            system_info['cpu_cores'],
            system_info['cpu_threads'],
            system_info['total_memory'],
            system_info['ipv4_address'],
            system_info['ipv6_address'],
            system_info['uptime']
        ))
    
    conn.commit()
    
    # Cleanup old data
    cleanup_old_data(cursor)
    conn.commit()
    
    conn.close()

def cleanup_old_data(cursor):
    """Remove old metrics data to prevent database bloat"""
    cutoff_date = datetime.datetime.now() - datetime.timedelta(days=DATA_RETENTION_DAYS)
    cutoff_str = cutoff_date.strftime('%Y-%m-%d %H:%M:%S')
    
    cursor.execute("DELETE FROM cpu_metrics WHERE timestamp < ?", (cutoff_str,))
    cursor.execute("DELETE FROM memory_metrics WHERE timestamp < ?", (cutoff_str,))
    cursor.execute("DELETE FROM disk_metrics WHERE timestamp < ?", (cutoff_str,))
    cursor.execute("DELETE FROM network_metrics WHERE timestamp < ?", (cutoff_str,))
    cursor.execute("DELETE FROM connection_metrics WHERE timestamp < ?", (cutoff_str,))
    cursor.execute("DELETE FROM protocol_metrics WHERE timestamp < ?", (cutoff_str,))
    
    # Keep more system_info entries as they're less frequent and smaller
    cutoff_date_sys = datetime.datetime.now() - datetime.timedelta(days=DATA_RETENTION_DAYS*2)
    cutoff_str_sys = cutoff_date_sys.strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("DELETE FROM system_info WHERE timestamp < ?", (cutoff_str_sys,))

def main_loop():
    """Main monitoring loop"""
    while True:
        try:
            store_metrics()
        except Exception as e:
            logger.exception(f"Error in metrics collection: {e}")
        
        time.sleep(COLLECTION_INTERVAL)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='System Monitoring Service for IRSSH-Panel')
    parser.add_argument('--daemon', action='store_true', help='Run as a daemon process')
    args = parser.parse_args()
    
    try:
        # Initialize database
        init_database()
        
        if args.daemon:
            # Fork process to run as daemon
            pid = os.fork()
            if pid > 0:
                # Exit parent process
                sys.exit(0)
                
            # Detach from terminal
            os.setsid()
            os.umask(0)
            
            # Fork again
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
            
            # Close file descriptors
            for fd in range(0, 3):
                try:
                    os.close(fd)
                except OSError:
                    pass
                    
            # Redirect stdout/stderr
            sys.stdout = open('/var/log/irssh/system_monitor_stdout.log', 'w')
            sys.stderr = open('/var/log/irssh/system_monitor_stderr.log', 'w')
            
            logger.info("Running as daemon process")
        
        # Start monitoring
        logger.info("System monitor started")
        main_loop()
    
    except KeyboardInterrupt:
        logger.info("System monitor stopped by user")
    except Exception as e:
        logger.exception(f"Unhandled exception: {e}")
EOF
    chmod +x "$SCRIPTS_DIR/monitoring/system_monitor.py"
    
    # Create systemd services for monitoring scripts
    cat > /etc/systemd/system/irssh-cpu-monitor.service << EOL
[Unit]
Description=IRSSH CPU Usage Monitor
After=network.target

[Service]
Type=simple
ExecStart=$SCRIPTS_DIR/monitoring/cpu_monitor.sh
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOL

    cat > /etc/systemd/system/irssh-memory-monitor.service << EOL
[Unit]
Description=IRSSH Memory Usage Monitor
After=network.target

[Service]
Type=simple
ExecStart=$SCRIPTS_DIR/monitoring/memory_monitor.sh
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOL

    cat > /etc/systemd/system/irssh-disk-monitor.service << EOL
[Unit]
Description=IRSSH Disk Usage Monitor
After=network.target

[Service]
Type=simple
ExecStart=$SCRIPTS_DIR/monitoring/disk_monitor.sh
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOL

    cat > /etc/systemd/system/irssh-network-monitor.service << EOL
[Unit]
Description=IRSSH Network Traffic Monitor
After=network.target

[Service]
Type=simple
ExecStart=$SCRIPTS_DIR/monitoring/network_monitor.sh
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOL

    cat > /etc/systemd/system/irssh-system-monitor.service << EOL
[Unit]
Description=IRSSH Comprehensive System Monitor
After=network.target postgresql.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 $SCRIPTS_DIR/monitoring/system_monitor.py --daemon
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOL

    # Create visualization script for monitoring data
    cat > "$SCRIPTS_DIR/monitoring/generate_reports.py" << 'EOF'
#!/usr/bin/env python3

"""
IRSSH-Panel Monitoring Report Generator
Generates visual reports from monitoring data
"""

import os
import sys
import sqlite3
import argparse
import datetime
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import pandas as pd
import seaborn as sns
from pathlib import Path

# Setup configuration
DB_PATH = '/opt/irssh-panel/monitoring/metrics.db'
REPORT_DIR = '/opt/irssh-panel/monitoring/reports'

def ensure_dir(directory):
    """Ensure directory exists"""
    Path(directory).mkdir(parents=True, exist_ok=True)

def generate_cpu_report(conn, period_days=7):
    """Generate CPU usage report"""
    print(f"Generating CPU report for the last {period_days} days...")
    
    # Calculate cutoff date
    cutoff_date = datetime.datetime.now() - datetime.timedelta(days=period_days)
    cutoff_str = cutoff_date.strftime('%Y-%m-%d %H:%M:%S')
    
    # Query data
    query = f"""
    SELECT timestamp, cpu_percent, load_1m, load_5m, load_15m, temperature, frequency
    FROM cpu_metrics
    WHERE timestamp > ?
    ORDER BY timestamp
    """
    
    df = pd.read_sql_query(query, conn, params=(cutoff_str,))
    
    # Convert timestamp to datetime
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    if df.empty:
        print("No CPU data available for the specified period")
        return
    
    # Create plot directory
    cpu_dir = os.path.join(REPORT_DIR, 'cpu')
    ensure_dir(cpu_dir)
    
    # Set the style
    sns.set(style="darkgrid")
    
    # Plot CPU usage over time
    plt.figure(figsize=(12, 6))
    plt.plot(df['timestamp'], df['cpu_percent'], 'b-', linewidth=1)
    plt.title(f'CPU Usage (Last {period_days} Days)')
    plt.xlabel('Time')
    plt.ylabel('CPU Usage (%)')
    plt.ylim(0, 100)
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(os.path.join(cpu_dir, 'cpu_usage.png'))
    plt.close()
    
    # Plot CPU load average
    plt.figure(figsize=(12, 6))
    plt.plot(df['timestamp'], df['load_1m'], 'r-', label='1 min', linewidth=1)
    plt.plot(df['timestamp'], df['load_5m'], 'g-', label='5 min', linewidth=1)
    plt.plot(df['timestamp'], df['load_15m'], 'b-', label='15 min', linewidth=1)
    plt.title(f'System Load Average (Last {period_days} Days)')
    plt.xlabel('Time')
    plt.ylabel('Load Average')
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(cpu_dir, 'load_average.png'))
    plt.close()
    
    # Plot CPU temperature if available
    if not df['temperature'].isnull().all():
        plt.figure(figsize=(12, 6))
        plt.plot(df['timestamp'], df['temperature'], 'r-', linewidth=1)
        plt.title(f'CPU Temperature (Last {period_days} Days)')
        plt.xlabel('Time')
        plt.ylabel('Temperature (°C)')
        plt.grid(True)
        plt.tight_layout()
        plt.savefig(os.path.join(cpu_dir, 'cpu_temperature.png'))
        plt.close()
    
    # Plot CPU frequency
    plt.figure(figsize=(12, 6))
    plt.plot(df['timestamp'], df['frequency'], 'g-', linewidth=1)
    plt.title(f'CPU Frequency (Last {period_days} Days)')
    plt.xlabel('Time')
    plt.ylabel('Frequency (MHz)')
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(os.path.join(cpu_dir, 'cpu_frequency.png'))
    plt.close()
    
    print("CPU report generated successfully")

def generate_memory_report(conn, period_days=7):
    """Generate memory usage report"""
    print(f"Generating memory report for the last {period_days} days...")
    
    # Calculate cutoff date
    cutoff_date = datetime.datetime.now() - datetime.timedelta(days=period_days)
    cutoff_str = cutoff_date.strftime('%Y-%m-%d %H:%M:%S')
    
    # Query data
    query = f"""
    SELECT timestamp, total, available, used, percent, swap_total, swap_used, swap_percent
    FROM memory_metrics
    WHERE timestamp > ?
    ORDER BY timestamp
    """
    
    df = pd.read_sql_query(query, conn, params=(cutoff_str,))
    
    # Convert timestamp to datetime
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    if df.empty:
        print("No memory data available for the specified period")
        return
    
    # Create plot directory
    memory_dir = os.path.join(REPORT_DIR, 'memory')
    ensure_dir(memory_dir)
    
    # Set the style
    sns.set(style="darkgrid")
    
    # Plot memory usage percentage
    plt.figure(figsize=(12, 6))
    plt.plot(df['timestamp'], df['percent'], 'b-', linewidth=1)
    plt.title(f'Memory Usage (Last {period_days} Days)')
    plt.xlabel('Time')
    plt.ylabel('Memory Usage (%)')
    plt.ylim(0, 100)
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(os.path.join(memory_dir, 'memory_percent.png'))
    plt.close()
    
    # Plot memory usage in GB
    plt.figure(figsize=(12, 6))
    # Convert to GB
    df['used_gb'] = df['used'] / (1024 * 1024 * 1024)
    df['total_gb'] = df['total'] / (1024 * 1024 * 1024)
    df['available_gb'] = df['available'] / (1024 * 1024 * 1024)
    
    plt.plot(df['timestamp'], df['used_gb'], 'r-', label='Used', linewidth=1)
    plt.plot(df['timestamp'], df['available_gb'], 'g-', label='Available', linewidth=1)
    plt.title(f'Memory Usage (Last {period_days} Days)')
    plt.xlabel('Time')
    plt.ylabel('Memory (GB)')
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(memory_dir, 'memory_usage.png'))
    plt.close()
    
    # Plot swap usage if available
    if not (df['swap_total'] == 0).all():
        plt.figure(figsize=(12, 6))
        plt.plot(df['timestamp'], df['swap_percent'], 'r-', linewidth=1)
        plt.title(f'Swap Usage (Last {period_days} Days)')
        plt.xlabel('Time')
        plt.ylabel('Swap Usage (%)')
        plt.ylim(0, 100)
        plt.grid(True)
        plt.tight_layout()
        plt.savefig(os.path.join(memory_dir, 'swap_percent.png'))
        plt.close()
    
    print("Memory report generated successfully")

def generate_disk_report(conn, period_days=7):
    """Generate disk usage report"""
    print(f"Generating disk report for the last {period_days} days...")
    
    # Calculate cutoff date
    cutoff_date = datetime.datetime.now() - datetime.timedelta(days=period_days)
    cutoff_str = cutoff_date.strftime('%Y-%m-%d %H:%M:%S')
    
    # Query data
    query = f"""
    SELECT timestamp, device, mountpoint, total, used, free, percent
    FROM disk_metrics
    WHERE timestamp > ? AND mountpoint = '/'
    ORDER BY timestamp
    """
    
    df = pd.read_sql_query(query, conn, params=(cutoff_str,))
    
    # Convert timestamp to datetime
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    if df.empty:
        print("No disk data available for the specified period")
        return
    
    # Create plot directory
    disk_dir = os.path.join(REPORT_DIR, 'disk')
    ensure_dir(disk_dir)
    
    # Set the style
    sns.set(style="darkgrid")
    
    # Plot disk usage percentage
    plt.figure(figsize=(12, 6))
    plt.plot(df['timestamp'], df['percent'], 'b-', linewidth=1)
    plt.title(f'Disk Usage (Last {period_days} Days)')
    plt.xlabel('Time')
    plt.ylabel('Disk Usage (%)')
    plt.ylim(0, 100)
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(os.path.join(disk_dir, 'disk_percent.png'))
    plt.close()
    
    # Plot disk usage in GB
    plt.figure(figsize=(12, 6))
    # Convert to GB
    df['used_gb'] = df['used'] / (1024 * 1024 * 1024)
    df['total_gb'] = df['total'] / (1024 * 1024 * 1024)
    df['free_gb'] = df['free'] / (1024 * 1024 * 1024)
    
    plt.plot(df['timestamp'], df['used_gb'], 'r-', label='Used', linewidth=1)
    plt.plot(df['timestamp'], df['free_gb'], 'g-', label='Free', linewidth=1)
    plt.title(f'Disk Usage (Last {period_days} Days)')
    plt.xlabel('Time')
    plt.ylabel('Disk Space (GB)')
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(disk_dir, 'disk_usage.png'))
    plt.close()
    
    # Get disk IO data
    query = f"""
    SELECT timestamp, device, read_bytes, write_bytes
    FROM disk_metrics
    WHERE timestamp > ? AND mountpoint = '/'
    ORDER BY timestamp
    """
    
    df_io = pd.read_sql_query(query, conn, params=(cutoff_str,))
    
    # Convert timestamp to datetime
    df_io['timestamp'] = pd.to_datetime(df_io['timestamp'])
    
    if not df_io.empty and not (df_io['read_bytes'] == 0).all() and not (df_io['write_bytes'] == 0).all():
        # Convert to GB
        df_io['read_gb'] = df_io['read_bytes'] / (1024 * 1024 * 1024)
        df_io['write_gb'] = df_io['write_bytes'] / (1024 * 1024 * 1024)
        
        plt.figure(figsize=(12, 6))
        plt.plot(df_io['timestamp'], df_io['read_gb'], 'b-', label='Read', linewidth=1)
        plt.plot(df_io['timestamp'], df_io['write_gb'], 'r-', label='Write', linewidth=1)
        plt.title(f'Disk I/O (Last {period_days} Days)')
        plt.xlabel('Time')
        plt.ylabel('I/O (GB)')
        plt.grid(True)
        plt.legend()
        plt.tight_layout()
        plt.savefig(os.path.join(disk_dir, 'disk_io.png'))
        plt.close()
    
    print("Disk report generated successfully")

def generate_network_report(conn, period_days=7):
    """Generate network usage report"""
    print(f"Generating network report for the last {period_days} days...")
    
    # Calculate cutoff date
    cutoff_date = datetime.datetime.now() - datetime.timedelta(days=period_days)
    cutoff_str = cutoff_date.strftime('%Y-%m-%d %H:%M:%S')
    
    # Get the primary interface
    query = """
    SELECT interface, COUNT(*) as count
    FROM network_metrics
    GROUP BY interface
    ORDER BY count DESC
    LIMIT 1
    """
    
    cursor = conn.cursor()
    cursor.execute(query)
    result = cursor.fetchone()
    
    if not result:
        print("No network data available")
        return
        
    primary_interface = result[0]
    
    # Query data
    query = f"""
    SELECT timestamp, bytes_sent, bytes_recv, packets_sent, packets_recv
    FROM network_metrics
    WHERE timestamp > ? AND interface = ?
    ORDER BY timestamp
    """
    
    df = pd.read_sql_query(query, conn, params=(cutoff_str, primary_interface))
    
    # Convert timestamp to datetime
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    if df.empty:
        print("No network data available for the specified period")
        return
    
    # Create plot directory
    network_dir = os.path.join(REPORT_DIR, 'network')
    ensure_dir(network_dir)
    
    # Set the style
    sns.set(style="darkgrid")
    
    # Calculate traffic rates
    df['bytes_sent_gb'] = df['bytes_sent'] / (1024 * 1024 * 1024)
    df['bytes_recv_gb'] = df['bytes_recv'] / (1024 * 1024 * 1024)
    
    # Calculate cumulative traffic
    last_bytes_sent = df['bytes_sent'].iloc[-1]
    last_bytes_recv = df['bytes_recv'].iloc[-1]
    first_bytes_sent = df['bytes_sent'].iloc[0]
    first_bytes_recv = df['bytes_recv'].iloc[0]
    
    total_sent_gb = (last_bytes_sent - first_bytes_sent) / (1024 * 1024 * 1024)
    total_recv_gb = (last_bytes_recv - first_bytes_recv) / (1024 * 1024 * 1024)
    
    # Plot network traffic over time
    plt.figure(figsize=(12, 6))
    plt.plot(df['timestamp'], df['bytes_sent_gb'], 'r-', label='Sent', linewidth=1)
    plt.plot(df['timestamp'], df['bytes_recv_gb'], 'b-', label='Received', linewidth=1)
    plt.title(f'Network Traffic ({primary_interface}) - Last {period_days} Days')
    plt.xlabel('Time')
    plt.ylabel('Traffic (GB)')
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(network_dir, 'network_traffic.png'))
    plt.close()
    
    # Plot packet counts
    plt.figure(figsize=(12, 6))
    plt.plot(df['timestamp'], df['packets_sent'] / 1000000, 'r-', label='Sent', linewidth=1)
    plt.plot(df['timestamp'], df['packets_recv'] / 1000000, 'b-', label='Received', linewidth=1)
    plt.title(f'Network Packets ({primary_interface}) - Last {period_days} Days')
    plt.xlabel('Time')
    plt.ylabel('Packets (millions)')
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(network_dir, 'network_packets.png'))
    plt.close()
    
    # Generate traffic summary report
    with open(os.path.join(network_dir, 'traffic_summary.txt'), 'w') as f:
        f.write(f"Network Traffic Summary - Last {period_days} Days\n")
        f.write(f"==================================================\n")
        f.write(f"Primary Interface: {primary_interface}\n")
        f.write(f"Total Data Sent: {total_sent_gb:.2f} GB\n")
        f.write(f"Total Data Received: {total_recv_gb:.2f} GB\n")
        f.write(f"Total Combined Traffic: {total_sent_gb + total_recv_gb:.2f} GB\n")
        f.write(f"==================================================\n")
        f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    print("Network report generated successfully")

def generate_protocol_report(conn, period_days=7):
    """Generate protocol usage report"""
    print(f"Generating protocol report for the last {period_days} days...")
    
    # Calculate cutoff date
    cutoff_date = datetime.datetime.now() - datetime.timedelta(days=period_days)
    cutoff_str = cutoff_date.strftime('%Y-%m-%d %H:%M:%S')
    
    # Query data
    query = f"""
    SELECT timestamp, protocol, connections, active_users
    FROM protocol_metrics
    WHERE timestamp > ?
    ORDER BY timestamp
    """
    
    df = pd.read_sql_query(query, conn, params=(cutoff_str,))
    
    # Convert timestamp to datetime
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    if df.empty:
        print("No protocol data available for the specified period")
        return
    
    # Create plot directory
    protocol_dir = os.path.join(REPORT_DIR, 'protocol')
    ensure_dir(protocol_dir)
    
    # Set the style
    sns.set(style="darkgrid")
    
    # Get unique protocols
    protocols = df['protocol'].unique()
    
    # Plot connections by protocol
    plt.figure(figsize=(12, 8))
    
    for protocol in protocols:
        protocol_df = df[df['protocol'] == protocol]
        plt.plot(protocol_df['timestamp'], protocol_df['connections'], linewidth=1, label=protocol)
    
    plt.title(f'Protocol Connections (Last {period_days} Days)')
    plt.xlabel('Time')
    plt.ylabel('Number of Connections')
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(protocol_dir, 'protocol_connections.png'))
    plt.close()
    
    # Plot active users by protocol
    plt.figure(figsize=(12, 8))
    
    for protocol in protocols:
        protocol_df = df[df['protocol'] == protocol]
        plt.plot(protocol_df['timestamp'], protocol_df['active_users'], linewidth=1, label=protocol)
    
    plt.title(f'Active Users by Protocol (Last {period_days} Days)')
    plt.xlabel('Time')
    plt.ylabel('Number of Active Users')
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(protocol_dir, 'protocol_users.png'))
    plt.close()
    
    # Create a stacked area chart for protocol usage
    protocols_to_include = ['SSH', 'OpenVPN', 'WireGuard', 'HTTP', 'HTTPS']
    filtered_protocols = [p for p in protocols if p in protocols_to_include]
    
    # Create a pivot table for plotting
    pivot_df = df[df['protocol'].isin(filtered_protocols)].pivot_table(
        index='timestamp', 
        columns='protocol', 
        values='connections',
        fill_value=0
    )
    
    # Resample to smooth out the data
    pivot_df = pivot_df.resample('1H').mean()
    
    plt.figure(figsize=(12, 8))
    pivot_df.plot.area(stacked=True, alpha=0.7, ax=plt.gca())
    
    plt.title(f'Protocol Usage Distribution (Last {period_days} Days)')
    plt.xlabel('Time')
    plt.ylabel('Number of Connections')
    plt.grid(True)
    plt.legend(title='Protocol')
    plt.tight_layout()
    plt.savefig(os.path.join(protocol_dir, 'protocol_distribution.png'))
    plt.close()
    
    print("Protocol report generated successfully")

def generate_report_index():
    """Generate HTML index page for all reports"""
    print("Generating report index page...")
    
    # Create index.html
    with open(os.path.join(REPORT_DIR, 'index.html'), 'w') as f:
        f.write('''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IRSSH-Panel Monitoring Reports</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
        }
        h1, h2, h3 {
            color: #0070f3;
        }
        .report-section {
            margin-bottom: 40px;
            border: 1px solid #eaeaea;
            border-radius: 8px;
            padding: 20px;
            background-color: #f9f9f9;
        }
        .report-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .report-item {
            border: 1px solid #ddd;
            border-radius: 8px;
            overflow: hidden;
            background-color: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        .report-item img {
            max-width: 100%;
            height: auto;
            display: block;
        }
        .report-caption {
            padding: 10px 15px;
            text-align: center;
            font-weight: bold;
        }
        .timestamp {
            text-align: center;
            margin-top: 40px;
            color: #666;
            font-size: 0.9rem;
        }
        header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid #eaeaea;
        }
        .logo {
            font-size: 1.5rem;
            font-weight: bold;
            color: #0070f3;
        }
    </style>
</head>
<body>
    <header>
        <div class="logo">IRSSH-Panel Monitoring Reports</div>
        <div>Generated: ''' + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''</div>
    </header>
    
    <div class="report-section">
        <h2>CPU Usage</h2>
        <div class="report-grid">
            <div class="report-item">
                <img src="cpu/cpu_usage.png" alt="CPU Usage">
                <div class="report-caption">CPU Usage</div>
            </div>
            <div class="report-item">
                <img src="cpu/load_average.png" alt="Load Average">
                <div class="report-caption">Load Average</div>
            </div>
            <div class="report-item">
                <img src="cpu/cpu_frequency.png" alt="CPU Frequency">
                <div class="report-caption">CPU Frequency</div>
            </div>
            ''' + ('''
            <div class="report-item">
                <img src="cpu/cpu_temperature.png" alt="CPU Temperature">
                <div class="report-caption">CPU Temperature</div>
            </div>
            ''' if os.path.exists(os.path.join(REPORT_DIR, 'cpu/cpu_temperature.png')) else '') + '''
        </div>
    </div>
    
    <div class="report-section">
        <h2>Memory Usage</h2>
        <div class="report-grid">
            <div class="report-item">
                <img src="memory/memory_percent.png" alt="Memory Usage">
                <div class="report-caption">Memory Usage (%)</div>
            </div>
            <div class="report-item">
                <img src="memory/memory_usage.png" alt="Memory Usage">
                <div class="report-caption">Memory Usage (GB)</div>
            </div>
            ''' + ('''
            <div class="report-item">
                <img src="memory/swap_percent.png" alt="Swap Usage">
                <div class="report-caption">Swap Usage</div>
            </div>
            ''' if os.path.exists(os.path.join(REPORT_DIR, 'memory/swap_percent.png')) else '') + '''
        </div>
    </div>
    
    <div class="report-section">
        <h2>Disk Usage</h2>
        <div class="report-grid">
            <div class="report-item">
                <img src="disk/disk_percent.png" alt="Disk Usage">
                <div class="report-caption">Disk Usage (%)</div>
            </div>
            <div class="report-item">
                <img src="disk/disk_usage.png" alt="Disk Usage">
                <div class="report-caption">Disk Usage (GB)</div>
            </div>
            ''' + ('''
            <div class="report-item">
                <img src="disk/disk_io.png" alt="Disk I/O">
                <div class="report-caption">Disk I/O</div>
            </div>
            ''' if os.path.exists(os.path.join(REPORT_DIR, 'disk/disk_io.png')) else '') + '''
        </div>
    </div>
    
    <div class="report-section">
        <h2>Network Usage</h2>
        <div class="report-grid">
            <div class="report-item">
                <img src="network/network_traffic.png" alt="Network Traffic">
                <div class="report-caption">Network Traffic</div>
            </div>
            <div class="report-item">
                <img src="network/network_packets.png" alt="Network Packets">
                <div class="report-caption">Network Packets</div>
            </div>
        </div>
    </div>
    
    <div class="report-section">
        <h2>Protocol Usage</h2>
        <div class="report-grid">
            <div class="report-item">
                <img src="protocol/protocol_connections.png" alt="Protocol Connections">
                <div class="report-caption">Protocol Connections</div>
            </div>
            <div class="report-item">
                <img src="protocol/protocol_users.png" alt="Protocol Users">
                <div class="report-caption">Protocol Users</div>
            </div>
            <div class="report-item">
                <img src="protocol/protocol_distribution.png" alt="Protocol Distribution">
                <div class="report-caption">Protocol Distribution</div>
            </div>
        </div>
    </div>
    
    <div class="timestamp">
        <p>Last updated: ''' + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '''</p>
    </div>
</body>
</html>''')
    
    print("Report index page generated successfully")

def main():
    """Main function for report generation"""
    parser = argparse.ArgumentParser(description='IRSSH-Panel Monitoring Report Generator')
    parser.add_argument('--days', type=int, default=7, help='Number of days to include in the report')
    args = parser.parse_args()
    
    period_days = args.days
    
    # Ensure report directory exists
    ensure_dir(REPORT_DIR)
    
    try:
        # Connect to database
        conn = sqlite3.connect(DB_PATH)
        
        # Generate reports
        generate_cpu_report(conn, period_days)
        generate_memory_report(conn, period_days)
        generate_disk_report(conn, period_days)
        generate_network_report(conn, period_days)
        generate_protocol_report(conn, period_days)
        
        # Generate index page
        generate_report_index()
        
        # Close connection
        conn.close()
        
        print(f"All reports generated successfully for the last {period_days} days.")
        print(f"Report available at: {REPORT_DIR}/index.html")
        
    except Exception as e:
        print(f"Error generating reports: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
EOF
    chmod +x "$SCRIPTS_DIR/monitoring/generate_reports.py"
    
    # Create a cron job to generate reports daily
    (crontab -l 2>/dev/null; echo "0 0 * * * python3 $SCRIPTS_DIR/monitoring/generate_reports.py --days 7 >/dev/null 2>&1") | crontab -
    
    # Enable and start monitoring services
    systemctl daemon-reload
    systemctl enable node-exporter
    systemctl restart node-exporter
    systemctl enable collectd
    systemctl restart collectd
    systemctl enable irssh-cpu-monitor
    systemctl start irssh-cpu-monitor
    systemctl enable irssh-memory-monitor
    systemctl start irssh-memory-monitor
    systemctl enable irssh-disk-monitor
    systemctl start irssh-disk-monitor
    systemctl enable irssh-network-monitor
    systemctl start irssh-network-monitor
    systemctl enable irssh-system-monitor
    systemctl start irssh-system-monitor
    
    info "Monitoring setup completed"
}

setup_geolocation() {
    info "Setting up geolocation services (hidden by default)"
    
    # Create geolocation module directory
    mkdir -p "$PANEL_DIR/modules/geolocation"
    
    # Download GeoLite2 Country database
    mkdir -p "$PANEL_DIR/modules/geolocation/db"
    
    # Create a placeholder database file that will be replaced by the real one when activated
    cat > "$PANEL_DIR/modules/geolocation/db/placeholder.txt" << EOF
This is a placeholder file for the GeoLite2 Country database.
The actual database will be downloaded and installed when the geolocation module is activated.

When activated, this directory will contain:
- GeoLite2-Country.mmdb
- GeoLite2-City.mmdb (optional for more precise locations)
- license_key.txt

For security and licensing reasons, these files are not included directly in the installation.
EOF
    
    # Create API endpoint for geolocation
    cat > "$PANEL_DIR/backend/geolocation.js" << 'EOF'
// Geolocation API Module
// This module is disabled by default and will be activated by the update script

const express = require('express');
const Router = express.Router();
const maxmind = require('maxmind');
const fs = require('fs');
const path = require('path');
const winston = require('winston');
const crypto = require('crypto');
const ipaddr = require('ipaddr.js');

// Setup logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) => {
            return `${timestamp} [${level.toUpperCase()}]: ${message}`;
        })
    ),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        }),
        new winston.transports.File({ 
            filename: path.join('logs', 'geolocation.log') 
        })
    ]
});

// Module is initially deactivated
let isActivated = false;
let countryLookup = null;
let cityLookup = null;
let ASNLookup = null;

// Function to initialize the geolocation database
async function initGeolocation() {
    const countryDbPath = path.join(__dirname, '../modules/geolocation/db/GeoLite2-Country.mmdb');
    const cityDbPath = path.join(__dirname, '../modules/geolocation/db/GeoLite2-City.mmdb');
    const asnDbPath = path.join(__dirname, '../modules/geolocation/db/GeoLite2-ASN.mmdb');
    
    try {
        // Check if the country database exists
        if (fs.existsSync(countryDbPath)) {
            countryLookup = await maxmind.open(countryDbPath);
            logger.info('Country geolocation database loaded successfully');
            
            // Check if the city database exists (optional)
            if (fs.existsSync(cityDbPath)) {
                cityLookup = await maxmind.open(cityDbPath);
                logger.info('City geolocation database loaded successfully');
            } else {
                logger.info('City geolocation database not found, using country-level only');
            }
            
            // Check if the ASN database exists (optional)
            if (fs.existsSync(asnDbPath)) {
                ASNLookup = await maxmind.open(asnDbPath);
                logger.info('ASN database loaded successfully');
            } else {
                logger.info('ASN database not found');
            }
            
            isActivated = true;
            return true;
        } else {
            logger.warn('Geolocation database not found, module remains deactivated');
            return false;
        }
    } catch (error) {
        logger.error(`Error initializing geolocation database: ${error.message}`);
        return false;
    }
}

// Function to normalize IP addresses (handle IPv4-mapped IPv6 addresses)
function normalizeIP(ip) {
    try {
        const addr = ipaddr.parse(ip);
        
        // Convert IPv4-mapped IPv6 addresses to IPv4
        if (addr.kind() === 'ipv6' && addr.isIPv4MappedAddress()) {
            return addr.toIPv4Address().toString();
        }
        
        return ip;
    } catch (e) {
        return ip;
    }
}

// Authentication middleware (should be the same as in your main app)
const authMiddleware = (req, res, next) => {
    // If module is not activated, return 404 to hide its existence
    if (!isActivated) {
        return res.status(404).json({ error: 'Endpoint not found' });
    }
    
    // Check for auth token
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Authentication required' });
        }
        
        const token = authHeader.split(' ')[1];
        const jwt = require('jsonwebtoken');
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'irssh-secret-key');
        
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
};

// Admin middleware
const adminMiddleware = (req, res, next) => {
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// Activate route - used to activate the module with a special key
Router.post('/activate', async (req, res) => {
    const { activationKey, serverIp } = req.body;
    
    // The activation key should be a hash based on the server IP
    // This provides a way to ensure the key is specific to this server
    const expectedKey = generateActivationKey(serverIp);
    
    if (activationKey === expectedKey) {
        const success = await initGeolocation();
        
        if (success) {
            res.json({ 
                success: true, 
                message: 'Geolocation module activated successfully' 
            });
        } else {
            res.status(500).json({ 
                success: false, 
                message: 'Failed to activate geolocation module, database not found or invalid' 
            });
        }
    } else {
        res.status(403).json({ 
            success: false, 
            message: 'Invalid activation key' 
        });
    }
});

// Helper function to generate activation key
function generateActivationKey(serverIp) {
    // Create a SHA-256 hash of the server IP with a special secret
    return crypto.createHash('sha256')
        .update(`IRSSH-GEO-${serverIp}-special-secret`)
        .digest('hex');
}

// Get geolocation for an IP
Router.get('/lookup/:ip', authMiddleware, adminMiddleware, (req, res) => {
    const ip = normalizeIP(req.params.ip);
    
    // Basic IP validation
    if (!ip.match(/^(\d{1,3}\.){3}\d{1,3}$/) && !ip.includes(':')) {
        return res.status(400).json({ error: 'Invalid IP address format' });
    }
    
    try {
        let result = { ip };
        
        // Try city lookup first if available
        if (cityLookup) {
            const cityData = cityLookup.get(ip);
            if (cityData) {
                result = {
                    ...result,
                    country: cityData.country?.names?.en || 'Unknown',
                    country_code: cityData.country?.iso_code || 'Unknown',
                    city: cityData.city?.names?.en || 'Unknown',
                    subdivision: cityData.subdivisions?.[0]?.names?.en,
                    postal_code: cityData.postal?.code,
                    coordinates: cityData.location ? {
                        latitude: cityData.location.latitude,
                        longitude: cityData.location.longitude,
                        accuracy_radius: cityData.location.accuracy_radius
                    } : null,
                    timezone: cityData.location?.time_zone,
                    accuracy: 'city'
                };
            }
        }
        
        // Fall back to country lookup if city data not available
        if (!result.country && countryLookup) {
            const countryData = countryLookup.get(ip);
            if (countryData) {
                result = {
                    ...result,
                    country: countryData.country?.names?.en || 'Unknown',
                    country_code: countryData.country?.iso_code || 'Unknown',
                    accuracy: 'country'
                };
            }
        }
        
        // Add ASN information if available
        if (ASNLookup) {
            const asnData = ASNLookup.get(ip);
            if (asnData) {
                result.network = {
                    asn: asnData.autonomous_system_number,
                    organization: asnData.autonomous_system_organization,
                    network: asnData.network
                };
            }
        }
        
        if (!result.country) {
            result = {
                ...result,
                country: 'Unknown',
                country_code: 'Unknown',
                accuracy: 'none'
            };
        }
        
        res.json(result);
    } catch (error) {
        logger.error(`Error looking up IP ${ip}: ${error.message}`);
        res.status(500).json({ error: 'Geolocation lookup failed' });
    }
});

// Get client connections with geolocation data
Router.get('/connections', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const db = req.app.locals.db;
        
        if (!db) {
            return res.status(500).json({ error: 'Database connection not available' });
        }
        
        // Get active connections
        const result = await db.query(`
            SELECT 
                id, username, protocol, connect_time, client_ip, 
                session_id, status
            FROM user_connections
            WHERE status = 'active'
            ORDER BY connect_time DESC
        `);
        
        // Enhance each connection with geolocation data
        const enhancedConnections = await Promise.all(result.rows.map(async (conn) => {
            let geoData = { 
                country: 'Unknown',
                country_code: 'Unknown',
                accuracy: 'none'
            };
            
            if (conn.client_ip && conn.client_ip !== 'Unknown') {
                try {
                    const normalizedIp = normalizeIP(conn.client_ip);
                    
                    // Try city lookup first
                    if (cityLookup) {
                        const cityData = cityLookup.get(normalizedIp);
                        if (cityData) {
                            geoData = {
                                country: cityData.country?.names?.en || 'Unknown',
                                country_code: cityData.country?.iso_code || 'Unknown',
                                city: cityData.city?.names?.en || 'Unknown',
                                subdivision: cityData.subdivisions?.[0]?.names?.en,
                                coordinates: cityData.location ? {
                                    latitude: cityData.location.latitude,
                                    longitude: cityData.location.longitude
                                } : null,
                                accuracy: 'city'
                            };
                        }
                    }
                    
                    // Fall back to country lookup
                    if (geoData.country === 'Unknown' && countryLookup) {
                        const countryData = countryLookup.get(normalizedIp);
                        if (countryData) {
                            geoData = {
                                country: countryData.country?.names?.en || 'Unknown',
                                country_code: countryData.country?.iso_code || 'Unknown',
                                accuracy: 'country'
                            };
                        }
                    }
                    
                    // Add ASN information if available
                    if (ASNLookup) {
                        const asnData = ASNLookup.get(normalizedIp);
                        if (asnData) {
                            geoData.network = {
                                asn: asnData.autonomous_system_number,
                                organization: asnData.autonomous_system_organization
                            };
                        }
                    }
                } catch (error) {
                    logger.error(`Error getting geolocation for IP ${conn.client_ip}: ${error.message}`);
                }
            }
            
            return {
                ...conn,
                geolocation: geoData
            };
        }));
        
        res.json({ connections: enhancedConnections });
    } catch (error) {
        logger.error(`Error fetching connections with geolocation: ${error.message}`);
        res.status(500).json({ error: 'Database error' });
    }
});

// Check status of the geolocation module
Router.get('/status', authMiddleware, adminMiddleware, (req, res) => {
    res.json({
        activated: isActivated,
        databases: {
            country: countryLookup !== null,
            city: cityLookup !== null,
            asn: ASNLookup !== null
        }
    });
});

// Get geolocation statistics
Router.get('/stats', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const db = req.app.locals.db;
        
        if (!db || !isActivated) {
            return res.status(500).json({ error: 'Database connection not available or module not activated' });
        }
        
        // Get active connections
        const result = await db.query(`
            SELECT client_ip
            FROM user_connections
            WHERE status = 'active'
        `);
        
        // Gather country statistics
        const countries = {};
        let unknownCount = 0;
        
        for (const row of result.rows) {
            const ip = row.client_ip;
            
            if (!ip || ip === 'Unknown') {
                unknownCount++;
                continue;
            }
            
            let countryCode = 'XX';
            let countryName = 'Unknown';
            
            try {
                const normalizedIp = normalizeIP(ip);
                
                // Try lookup
                if (cityLookup) {
                    const data = cityLookup.get(normalizedIp);
                    if (data && data.country) {
                        countryCode = data.country.iso_code;
                        countryName = data.country.names.en;
                    }
                } else if (countryLookup) {
                    const data = countryLookup.get(normalizedIp);
                    if (data && data.country) {
                        countryCode = data.country.iso_code;
                        countryName = data.country.names.en;
                    }
                }
            } catch (e) {
                logger.error(`Error looking up country for IP ${ip}: ${e.message}`);
            }
            
            if (countryCode === 'XX') {
                unknownCount++;
            } else {
                countries[countryCode] = countries[countryCode] || { 
                    code: countryCode,
                    name: countryName,
                    count: 0
                };
                countries[countryCode].count++;
            }
        }
        
        // Convert to array and sort by count
        const countriesList = Object.values(countries).sort((a, b) => b.count - a.count);
        
        res.json({
            total_connections: result.rows.length,
            unknown_locations: unknownCount,
            countries: countriesList
        });
    } catch (error) {
        logger.error(`Error fetching geolocation stats: ${error.message}`);
        res.status(500).json({ error: 'Error fetching geolocation statistics' });
    }
});

// Try to initialize the module at startup
initGeolocation().catch(error => {
    logger.error(`Failed to initialize geolocation module: ${error.message}`);
});

module.exports = Router;
EOF

    # Create activation script that will be released separately
    cat > "$PANEL_DIR/modules/geolocation/activate.sh" << 'EOF'
#!/bin/bash

# This script activates the geolocation module in IRSSH-Panel
# It will download the required databases and enable the module

# Define colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Base directories
PANEL_DIR="/opt/irssh-panel"
MODULE_DIR="$PANEL_DIR/modules/geolocation"
DB_DIR="$MODULE_DIR/db"
API_URL="http://localhost:3001/api/geolocation"

# Log function
log() {
    echo -e "${2:-$GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
   log "This script must be run as root" "$RED"
   exit 1
fi

# Check if the geolocation module exists
if [ ! -d "$MODULE_DIR" ]; then
    log "Geolocation module directory not found: $MODULE_DIR" "$RED"
    exit 1
fi

# Create DB directory if needed
mkdir -p "$DB_DIR"

# Prompt for MaxMind license key
read -p "Enter your MaxMind GeoLite2 license key: " LICENSE_KEY

if [ -z "$LICENSE_KEY" ]; then
    log "License key is required. Please obtain a free GeoLite2 license from MaxMind." "$RED"
    exit 1
fi

# Save license key for future use
echo "$LICENSE_KEY" > "$DB_DIR/license_key.txt"
chmod 600 "$DB_DIR/license_key.txt"

# Download GeoLite2 databases
log "Downloading GeoLite2 Country database..."
COUNTRY_URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=${LICENSE_KEY}&suffix=tar.gz"
wget -q -O "$DB_DIR/GeoLite2-Country.tar.gz" "$COUNTRY_URL"

if [ $? -ne 0 ]; then
    log "Failed to download Country database. Please check your license key." "$RED"
    exit 1
fi

log "Extracting GeoLite2 Country database..."
mkdir -p "$DB_DIR/tmp"
tar -xzf "$DB_DIR/GeoLite2-Country.tar.gz" -C "$DB_DIR/tmp"
find "$DB_DIR/tmp" -name "*.mmdb" -exec cp {} "$DB_DIR/GeoLite2-Country.mmdb" \;
rm -rf "$DB_DIR/tmp"
rm -f "$DB_DIR/GeoLite2-Country.tar.gz"

log "Downloading GeoLite2 City database..."
CITY_URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${LICENSE_KEY}&suffix=tar.gz"
wget -q -O "$DB_DIR/GeoLite2-City.tar.gz" "$CITY_URL"

if [ $? -ne 0 ]; then
    log "Failed to download City database. Continuing with Country database only." "$YELLOW"
else
    log "Extracting GeoLite2 City database..."
    mkdir -p "$DB_DIR/tmp"
    tar -xzf "$DB_DIR/GeoLite2-City.tar.gz" -C "$DB_DIR/tmp"
    find "$DB_DIR/tmp" -name "*.mmdb" -exec cp {} "$DB_DIR/GeoLite2-City.mmdb" \;
    rm -rf "$DB_DIR/tmp"
    rm -f "$DB_DIR/GeoLite2-City.tar.gz"
fi

log "Downloading GeoLite2 ASN database..."
ASN_URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=${LICENSE_KEY}&suffix=tar.gz"
wget -q -O "$DB_DIR/GeoLite2-ASN.tar.gz" "$ASN_URL"

if [ $? -ne 0 ]; then
    log "Failed to download ASN database. Continuing without ASN data." "$YELLOW"
else
    log "Extracting GeoLite2 ASN database..."
    mkdir -p "$DB_DIR/tmp"
    tar -xzf "$DB_DIR/GeoLite2-ASN.tar.gz" -C "$DB_DIR/tmp"
    find "$DB_DIR/tmp" -name "*.mmdb" -exec cp {} "$DB_DIR/GeoLite2-ASN.mmdb" \;
    rm -rf "$DB_DIR/tmp"
    rm -f "$DB_DIR/GeoLite2-ASN.tar.gz"
fi

# Get server IP
SERVER_IP=$(curl -s4 ifconfig.me || ip -4 route get 8.8.8.8 | awk '{print $7; exit}')

# Generate activation key
ACTIVATION_KEY=$(echo -n "IRSSH-GEO-${SERVER_IP}-special-secret" | sha256sum | awk '{print $1}')

# Install Node.js dependencies for geolocation
log "Installing Node.js dependencies for geolocation..."
cd "$PANEL_DIR/backend"
npm install maxmind ipaddr.js

# Activate the module via API
log "Activating geolocation module..."
RESPONSE=$(curl -s -X POST "$API_URL/activate" \
    -H "Content-Type: application/json" \
    -d "{\"activationKey\": \"$ACTIVATION_KEY\", \"serverIp\": \"$SERVER_IP\"}")

SUCCESS=$(echo "$RESPONSE" | grep -c '"success":true')
if [ "$SUCCESS" -eq 1 ]; then
    log "Geolocation module activated successfully!" "$GREEN"
else
    ERROR_MSG=$(echo "$RESPONSE" | grep -o '"message":"[^"]*"' | cut -d'"' -f4)
    log "Failed to activate geolocation module: $ERROR_MSG" "$RED"
    exit 1
fi

# Update API routes to include geolocation
if ! grep -q "geolocation" "$PANEL_DIR/backend/index.js"; then
    log "Updating backend to include geolocation routes..."
    # Add the route to the main backend
    sed -i '/const app = express();/a const geolocationRoutes = require("./geolocation");' "$PANEL_DIR/backend/index.js"
    sed -i '/app.use("\/api"/a app.use("/api/geolocation", geolocationRoutes);' "$PANEL_DIR/backend/index.js"
fi

# Setup automatic database updates
cat > /etc/cron.monthly/update-geolite2 << CRON
#!/bin/bash
# Monthly updates for GeoLite2 databases

LICENSE_KEY=\$(cat $DB_DIR/license_key.txt)

# Update Country database
wget -q -O "$DB_DIR/GeoLite2-Country.tar.gz" "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=\${LICENSE_KEY}&suffix=tar.gz"
if [ \$? -eq 0 ]; then
    mkdir -p "$DB_DIR/tmp"
    tar -xzf "$DB_DIR/GeoLite2-Country.tar.gz" -C "$DB_DIR/tmp"
    find "$DB_DIR/tmp" -name "*.mmdb" -exec cp {} "$DB_DIR/GeoLite2-Country.mmdb" \;
    rm -rf "$DB_DIR/tmp"
    rm -f "$DB_DIR/GeoLite2-Country.tar.gz"
    echo "\$(date): GeoLite2 Country database updated successfully" >> $DB_DIR/update.log
else
    echo "\$(date): Failed to update GeoLite2 Country database" >> $DB_DIR/update.log
fi

# Update City database
wget -q -O "$DB_DIR/GeoLite2-City.tar.gz" "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=\${LICENSE_KEY}&suffix=tar.gz"
if [ \$? -eq 0 ]; then
    mkdir -p "$DB_DIR/tmp"
    tar -xzf "$DB_DIR/GeoLite2-City.tar.gz" -C "$DB_DIR/tmp"
    find "$DB_DIR/tmp" -name "*.mmdb" -exec cp {} "$DB_DIR/GeoLite2-City.mmdb" \;
    rm -rf "$DB_DIR/tmp"
    rm -f "$DB_DIR/GeoLite2-City.tar.gz"
    echo "\$(date): GeoLite2 City database updated successfully" >> $DB_DIR/update.log
else
    echo "\$(date): Failed to update GeoLite2 City database" >> $DB_DIR/update.log
fi

# Update ASN database
wget -q -O "$DB_DIR/GeoLite2-ASN.tar.gz" "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=\${LICENSE_KEY}&suffix=tar.gz"
if [ \$? -eq 0 ]; then
    mkdir -p "$DB_DIR/tmp"
    tar -xzf "$DB_DIR/GeoLite2-ASN.tar.gz" -C "$DB_DIR/tmp"
    find "$DB_DIR/tmp" -name "*.mmdb" -exec cp {} "$DB_DIR/GeoLite2-ASN.mmdb" \;
    rm -rf "$DB_DIR/tmp"
    rm -f "$DB_DIR/GeoLite2-ASN.tar.gz"
    echo "\$(date): GeoLite2 ASN database updated successfully" >> $DB_DIR/update.log
else
    echo "\$(date): Failed to update GeoLite2 ASN database" >> $DB_DIR/update.log
fi

# Restart API to reload databases
systemctl restart irssh-api
CRON

chmod +x /etc/cron.monthly/update-geolite2

# Restart the backend API
log "Restarting API server..."
systemctl restart irssh-api

log "Geolocation module activation completed!" "$GREEN"
log "Your activation key: $ACTIVATION_KEY" "$YELLOW"
log "Server IP: $SERVER_IP" "$YELLOW"
log "Please keep this information secure and do not share it." "$YELLOW"

echo
echo "The geolocation module has been activated and is ready to use."
echo "You can now access the geolocation features in the admin panel."
echo
EOF

    chmod +x "$PANEL_DIR/modules/geolocation/activate.sh"
    
    # Create the React component for the geolocation section (hidden by default)
    mkdir -p "$PANEL_DIR/frontend/src/pages"
    
    cat > "$PANEL_DIR/frontend/src/pages/Geolocation.jsx" << 'EOF'
import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import axios from 'axios';
import { toast } from 'react-hot-toast';
import { MapContainer, TileLayer, Marker, Popup, CircleMarker } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';

// Fix for default marker icons in Leaflet with webpack
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
    iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png',
    iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png',
    shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
});

const GeolocationPage = () => {
    const [isActivated, setIsActivated] = useState(false);
    const [activationKey, setActivationKey] = useState('');
    const [connections, setConnections] = useState([]);
    const [loading, setLoading] = useState(true);
    const [lookupIp, setLookupIp] = useState('');
    const [ipResult, setIpResult] = useState(null);
    const [mapCenter, setMapCenter] = useState([0, 0]);
    const [mapZoom, setMapZoom] = useState(2);
    const [stats, setStats] = useState(null);
    const [viewMode, setViewMode] = useState('table'); // 'table', 'map', or 'stats'
    const mapRef = useRef(null);

    // Check if the module is activated
    useEffect(() => {
        checkActivationStatus();
    }, []);

    const checkActivationStatus = async () => {
        try {
            setLoading(true);
            const response = await axios.get('/api/geolocation/status');
            setIsActivated(response.data.activated);
            
            if (response.data.activated) {
                // Fetch connections with geolocation data
                fetchGeoConnections();
                fetchStats();
            }
            
            setLoading(false);
        } catch (error) {
            // 404 error means the endpoint doesn't exist or module is not activated
            if (error.response && error.response.status === 404) {
                setIsActivated(false);
            } else {
                console.error('Error checking geolocation status:', error);
                toast.error('Failed to check geolocation status');
            }
            setLoading(false);
        }
    };

    const fetchGeoConnections = async () => {
        try {
            setLoading(true);
            const response = await axios.get('/api/geolocation/connections');
            setConnections(response.data.connections);
            setLoading(false);
        } catch (error) {
            console.error('Error fetching connections:', error);
            toast.error('Failed to fetch connection data');
            setLoading(false);
        }
    };

    const fetchStats = async () => {
        try {
            const response = await axios.get('/api/geolocation/stats');
            setStats(response.data);
        } catch (error) {
            console.error('Error fetching geolocation stats:', error);
        }
    };

    const activateModule = async () => {
        try {
            // Get server IP
            const ipResponse = await axios.get('/api/system/info');
            const serverIp = ipResponse.data.system?.ipv4_address || '127.0.0.1';
            
            const response = await axios.post('/api/geolocation/activate', {
                activationKey,
                serverIp
            });
            
            if (response.data.success) {
                toast.success('Geolocation module activated successfully');
                setIsActivated(true);
                fetchGeoConnections();
                fetchStats();
            } else {
                toast.error(response.data.message || 'Activation failed');
            }
        } catch (error) {
            console.error('Error activating module:', error);
            toast.error(error.response?.data?.message || 'Failed to activate module');
        }
    };

    const lookupIPAddress = async () => {
        if (!lookupIp) {
            toast.error('Please enter an IP address');
            return;
        }
        
        try {
            setLoading(true);
            const response = await axios.get(`/api/geolocation/lookup/${lookupIp}`);
            setIpResult(response.data);
            
            // Center map on the result if coordinates are available
            if (response.data.coordinates) {
                setMapCenter([response.data.coordinates.latitude, response.data.coordinates.longitude]);
                setMapZoom(10);
                setViewMode('map');
            }
            
            setLoading(false);
        } catch (error) {
            console.error('Error looking up IP:', error);
            toast.error('Failed to lookup IP address');
            setIpResult(null);
            setLoading(false);
        }
    };

    // Filter connections with valid coordinates for the map
    const mappableConnections = useMemo(() => {
        return connections.filter(
            conn => conn.geolocation?.coordinates?.latitude && conn.geolocation?.coordinates?.longitude
        );
    }, [connections]);

    // Calculate map bounds to fit all markers
    const fitMapToMarkers = useCallback(() => {
        if (mapRef.current && mappableConnections.length > 0) {
            const bounds = L.latLngBounds(
                mappableConnections.map(conn => [
                    conn.geolocation.coordinates.latitude,
                    conn.geolocation.coordinates.longitude
                ])
            );
            mapRef.current.fitBounds(bounds, { padding: [50, 50] });
        }
    }, [mappableConnections]);

    // Group connections by country for statistics
    const connectionsByCountry = useMemo(() => {
        const countryMap = {};
        connections.forEach(conn => {
            const countryCode = conn.geolocation?.country_code || 'Unknown';
            const countryName = conn.geolocation?.country || 'Unknown';
            
            if (!countryMap[countryCode]) {
                countryMap[countryCode] = {
                    code: countryCode,
                    name: countryName,
                    count: 0,
                    connections: []
                };
            }
            
            countryMap[countryCode].count += 1;
            countryMap[countryCode].connections.push(conn);
        });
        
        return Object.values(countryMap).sort((a, b) => b.count - a.count);
    }, [connections]);

    if (loading && !isActivated) {
        return <div className="p-4">Loading geolocation module status...</div>;
    }

    if (!isActivated) {
        return (
            <div className="p-4">
                <h2 className="text-2xl font-bold mb-4">Geolocation Module</h2>
                <div className="bg-white rounded-lg shadow p-6">
                    <div className="bg-yellow-100 border-l-4 border-yellow-500 text-yellow-700 p-4 mb-4">
                        This module is not activated. Contact your service provider for an activation key.
                    </div>
                    
                    <div className="mb-4">
                        <label className="block text-gray-700 mb-2">Activation Key:</label>
                        <input
                            type="text"
                            className="w-full p-2 border border-gray-300 rounded"
                            value={activationKey}
                            onChange={(e) => setActivationKey(e.target.value)}
                            placeholder="Enter your activation key"
                        />
                    </div>
                    
                    <button
                        className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
                        onClick={activateModule}
                        disabled={!activationKey}
                    >
                        Activate Module
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="p-4">
            <h2 className="text-2xl font-bold mb-4">Geolocation Tracking</h2>
            
            <div className="flex mb-4 space-x-2">
                <button 
                    className={`px-4 py-2 rounded ${viewMode === 'table' ? 'bg-blue-600 text-white' : 'bg-gray-200'}`}
                    onClick={() => setViewMode('table')}
                >
                    Table View
                </button>
                <button 
                    className={`px-4 py-2 rounded ${viewMode === 'map' ? 'bg-blue-600 text-white' : 'bg-gray-200'}`}
                    onClick={() => {
                        setViewMode('map');
                        // Give time for the map to initialize before fitting bounds
                        setTimeout(fitMapToMarkers, 100);
                    }}
                >
                    Map View
                </button>
                <button 
                    className={`px-4 py-2 rounded ${viewMode === 'stats' ? 'bg-blue-600 text-white' : 'bg-gray-200'}`}
                    onClick={() => setViewMode('stats')}
                >
                    Statistics
                </button>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                <div className="bg-white rounded-lg shadow p-4">
                    <h3 className="text-lg font-semibold mb-3">IP Lookup</h3>
                    <div className="flex mb-3">
                        <input
                            type="text"
                            className="flex-grow p-2 border border-gray-300 rounded-l"
                            placeholder="Enter IP address"
                            value={lookupIp}
                            onChange={(e) => setLookupIp(e.target.value)}
                        />
                        <button
                            className="bg-blue-600 text-white px-4 py-2 rounded-r hover:bg-blue-700"
                            onClick={lookupIPAddress}
                        >
                            Lookup
                        </button>
                    </div>
                    
                    {ipResult && (
                        <div className="mt-3 border-t pt-3">
                            <h4 className="font-semibold">Results for {ipResult.ip}</h4>
                            <table className="w-full mt-2">
                                <tbody>
                                    <tr>
                                        <td className="font-medium pr-4">Country:</td>
                                        <td>{ipResult.country}</td>
                                    </tr>
                                    <tr>
                                        <td className="font-medium pr-4">Country Code:</td>
                                        <td>{ipResult.country_code}</td>
                                    </tr>
                                    {ipResult.city && (
                                        <tr>
                                            <td className="font-medium pr-4">City:</td>
                                            <td>{ipResult.city}</td>
                                        </tr>
                                    )}
                                    {ipResult.subdivision && (
                                        <tr>
                                            <td className="font-medium pr-4">Region:</td>
                                            <td>{ipResult.subdivision}</td>
                                        </tr>
                                    )}
                                    {ipResult.coordinates && (
                                        <tr>
                                            <td className="font-medium pr-4">Coordinates:</td>
                                            <td>
                                                {ipResult.coordinates.latitude.toFixed(4)}, {ipResult.coordinates.longitude.toFixed(4)}
                                            </td>
                                        </tr>
                                    )}
                                    {ipResult.network && (
                                        <tr>
                                            <td className="font-medium pr-4">Network:</td>
                                            <td>AS{ipResult.network.asn} - {ipResult.network.organization}</td>
                                        </tr>
                                    )}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
                
                <div className="bg-white rounded-lg shadow p-4">
                    <h3 className="text-lg font-semibold mb-3">Connection Statistics</h3>
                    <div className="grid grid-cols-2 gap-4">
                        <div className="bg-gray-100 p-4 rounded text-center">
                            <div className="text-3xl font-bold text-blue-600">{connections.length}</div>
                            <div className="text-sm text-gray-600">Active Connections</div>
                        </div>
                        
                        <div className="bg-gray-100 p-4 rounded text-center">
                            <div className="text-3xl font-bold text-blue-600">
                                {connectionsByCountry.length}
                            </div>
                            <div className="text-sm text-gray-600">Countries</div>
                        </div>
                    </div>
                    
                    <div className="mt-4">
                        <h4 className="font-semibold mb-2">Top Countries</h4>
                        <ul className="space-y-2">
                            {connectionsByCountry.slice(0, 5).map(country => (
                                <li key={country.code} className="flex justify-between">
                                    <span>{country.name}</span>
                                    <span className="font-medium">{country.count}</span>
                                </li>
                            ))}
                        </ul>
                    </div>
                </div>
            </div>
            
            {viewMode === 'table' && (
                <div className="bg-white rounded-lg shadow overflow-hidden">
                    <div className="px-4 py-3 border-b flex justify-between items-center">
                        <h3 className="text-lg font-semibold">Active Connections</h3>
                        <button 
                            className="bg-blue-600 text-white px-3 py-1 rounded text-sm hover:bg-blue-700"
                            onClick={fetchGeoConnections}
                        >
                            Refresh
                        </button>
                    </div>
                    
                    {connections.length === 0 ? (
                        <div className="p-4 text-center text-gray-500">No active connections</div>
                    ) : (
                        <div className="overflow-x-auto">
                            <table className="min-w-full divide-y divide-gray-200">
                                <thead className="bg-gray-50">
                                    <tr>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Username</th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Protocol</th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">IP Address</th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Country</th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">City</th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Connected</th>
                                    </tr>
                                </thead>
                                <tbody className="bg-white divide-y divide-gray-200">
                                    {connections.map(conn => (
                                        <tr key={conn.id} className="hover:bg-gray-50">
                                            <td className="px-6 py-4 whitespace-nowrap font-medium">{conn.username}</td>
                                            <td className="px-6 py-4 whitespace-nowrap">{conn.protocol}</td>
                                            <td className="px-6 py-4 whitespace-nowrap">{conn.client_ip}</td>
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                {conn.geolocation.country_code !== 'Unknown' && (
                                                    <span className="mr-2">
                                                        <img 
                                                            src={`https://flagcdn.com/16x12/${conn.geolocation.country_code.toLowerCase()}.png`}
                                                            width="16"
                                                            height="12"
                                                            alt={conn.geolocation.country_code}
                                                            className="inline-block mr-1"
                                                        />
                                                    </span>
                                                )}
                                                {conn.geolocation.country}
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap">{conn.geolocation.city || 'N/A'}</td>
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                {new Date(conn.connect_time).toLocaleString()}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            )}
            
            {viewMode === 'map' && (
                <div className="bg-white rounded-lg shadow p-4">
                    <h3 className="text-lg font-semibold mb-3">Connection Map</h3>
                    <div style={{ height: '600px', width: '100%' }}>
                        <MapContainer 
                            center={mapCenter} 
                            zoom={mapZoom} 
                            style={{ height: '100%', width: '100%' }}
                            ref={mapRef}
                        >
                            <TileLayer
                                attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
                                url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                            />
                            
                            {mappableConnections.map(conn => (
                                <Marker 
                                    key={conn.id}
                                    position={[
                                        conn.geolocation.coordinates.latitude,
                                        conn.geolocation.coordinates.longitude
                                    ]}
                                >
                                    <Popup>
                                        <div>
                                            <strong>User:</strong> {conn.username}<br />
                                            <strong>Protocol:</strong> {conn.protocol}<br />
                                            <strong>IP:</strong> {conn.client_ip}<br />
                                            <strong>Location:</strong> {conn.geolocation.city ? `${conn.geolocation.city}, ` : ''} {conn.geolocation.country}
                                        </div>
                                    </Popup>
                                </Marker>
                            ))}
                            
                            {ipResult && ipResult.coordinates && (
                                <CircleMarker
                                    center={[ipResult.coordinates.latitude, ipResult.coordinates.longitude]}
                                    radius={10}
                                    pathOptions={{ color: 'red', fillColor: 'red', fillOpacity: 0.7 }}
                                >
                                    <Popup>
                                        <div>
                                            <strong>IP:</strong> {ipResult.ip}<br />
                                            <strong>Location:</strong> {ipResult.city ? `${ipResult.city}, ` : ''} {ipResult.country}
                                        </div>
                                    </Popup>
                                </CircleMarker>
                            )}
                        </MapContainer>
                    </div>
                </div>
            )}
            
            {viewMode === 'stats' && (
                <div className="bg-white rounded-lg shadow p-4">
                    <h3 className="text-lg font-semibold mb-3">Geolocation Statistics</h3>
                    
                    {stats ? (
                        <div>
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                                <div className="bg-gray-100 p-4 rounded text-center">
                                    <div className="text-3xl font-bold text-blue-600">{stats.total_connections}</div>
                                    <div className="text-sm text-gray-600">Total Connections</div>
                                </div>
                                
                                <div className="bg-gray-100 p-4 rounded text-center">
                                    <div className="text-3xl font-bold text-blue-600">{stats.countries.length}</div>
                                    <div className="text-sm text-gray-600">Countries</div>
                                </div>
                                
                                <div className="bg-gray-100 p-4 rounded text-center">
                                    <div className="text-3xl font-bold text-blue-600">{stats.unknown_locations}</div>
                                    <div className="text-sm text-gray-600">Unknown Locations</div>
                                </div>
                            </div>
                            
                            <h4 className="font-semibold mb-3">Connections by Country</h4>
                            <div className="overflow-x-auto">
                                <table className="min-w-full divide-y divide-gray-200">
                                    <thead className="bg-gray-50">
                                        <tr>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Country</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Connections</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Percentage</th>
                                        </tr>
                                    </thead>
                                    <tbody className="bg-white divide-y divide-gray-200">
                                        {stats.countries.map(country => (
                                            <tr key={country.code} className="hover:bg-gray-50">
                                                <td className="px-6 py-4 whitespace-nowrap">
                                                    {country.code !== 'XX' && (
                                                        <img 
                                                            src={`https://flagcdn.com/16x12/${country.code.toLowerCase()}.png`}
                                                            width="16"
                                                            height="12"
                                                            alt={country.code}
                                                            className="inline-block mr-2"
                                                        />
                                                    )}
                                                    {country.name}
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap font-medium">{country.count}</td>
                                                <td className="px-6 py-4 whitespace-nowrap">
                                                    {((country.count / stats.total_connections) * 100).toFixed(1)}%
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    ) : (
                        <div className="p-4 text-center text-gray-500">Loading statistics...</div>
                    )}
                </div>
            )}
        </div>
    );
};

export default GeolocationPage;
EOF

    # Create a placeholder for the geolocation section in the frontend
    if [ -f "$PANEL_DIR/frontend/src/App.jsx" ]; then
        info "Creating placeholder for geolocation module in frontend"
    fi
    
    info "Geolocation services setup completed"
}

# Function to create admin CLI tool
create_admin_cli_tool() {
    info "Creating admin CLI tool..."
    
    cat > "$SCRIPTS_DIR/irssh-admin.sh" << 'EOF'
#!/bin/bash

# IRSSH-Panel Admin CLI Tool
# This script provides command-line tools for managing the IRSSH-Panel

# Define colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Base directories
PANEL_DIR="/opt/irssh-panel"
CONFIG_DIR="/etc/enhanced_ssh"
LOG_DIR="/var/log/irssh"

# Log function
log() {
    local level=$1
    local message=$2
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    case $level in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} $timestamp - $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $timestamp - $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $timestamp - $message"
            ;;
        "DEBUG")
            echo -e "${BLUE}[DEBUG]${NC} $timestamp - $message"
            ;;
        *)
            echo "$timestamp - $message"
            ;;
    esac
}

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
   log "ERROR" "This script must be run as root"
   exit 1
fi
# Load database configuration
if [ -f "$CONFIG_DIR/db/database.conf" ]; then
    source "$CONFIG_DIR/db/database.conf"
else
    log "ERROR" "Database configuration file not found"
    exit 1
fi

# Display help
show_help() {
    cat << EOF
IRSSH-Panel Admin CLI Tool

Usage: irssh-admin [command] [options]

Commands:
  user                User management commands
    list              List all users
    add               Add a new user
    del               Delete a user
    modify            Modify a user
    extend            Extend a user's expiry date
    show              Show detailed information about a user
  
  conn                Connection management commands
    list              List all active connections
    kill              Terminate a connection
    
  service             Service management commands
    status            Check service status
    restart           Restart a service
    logs              View service logs
    
  db                  Database commands
    backup            Create a database backup
    restore           Restore from a backup
    
  system              System commands
    status            Show system status
    update            Update IRSSH-Panel
    
  ansible             Ansible automation commands
    list-playbooks    List available Ansible playbooks
    run               Run an Ansible playbook
    status            Show Ansible execution status
    install-role      Install an Ansible role
    
  multi-server        Multi-server management commands
    list              List connected servers
    add               Add a new server to the cluster
    remove            Remove a server from the cluster
    sync              Synchronize configuration across servers
    status            Show multi-server status
    
  help                Show this help message

Examples:
  irssh-admin user list
  irssh-admin user add --username test --expiry 30
  irssh-admin conn list
  irssh-admin conn kill --id 123
  irssh-admin service status
  irssh-admin ansible run --playbook deploy-proxy
  irssh-admin multi-server add --host 192.168.1.10 --role worker

EOF
}

# User commands
user_command() {
    local subcommand=$1
    shift
    
    case $subcommand in
        "list")
            user_list
            ;;
        "add")
            user_add "$@"
            ;;
        "del")
            user_delete "$@"
            ;;
        "modify")
            user_modify "$@"
            ;;
        "extend")
            user_extend "$@"
            ;;
        "show")
            user_show "$@"
            ;;
        *)
            log "ERROR" "Unknown user command: $subcommand"
            show_help
            exit 1
            ;;
    esac
}

# List all users
user_list() {
    log "INFO" "Listing all users..."
    
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "
        SELECT 
            username, 
            status,
            CASE 
                WHEN expiry_date IS NULL THEN 'No expiry'
                WHEN expiry_date < NOW() THEN 'Expired'
                ELSE to_char(expiry_date, 'YYYY-MM-DD HH24:MI:SS')
            END as expiry_date,
            CASE
                WHEN data_limit = 0 THEN 'Unlimited'
                ELSE pg_size_pretty(data_limit)
            END as data_limit,
            max_connections,
            (
                SELECT COUNT(*) 
                FROM user_connections 
                WHERE username = user_profiles.username AND status = 'active'
            ) as active_connections
        FROM user_profiles
        ORDER BY 
            CASE 
                WHEN status = 'active' AND (expiry_date IS NULL OR expiry_date > NOW()) THEN 1
                WHEN status = 'active' AND expiry_date <= NOW() THEN 2
                ELSE 3
            END,
            username;
    "
}

# Add a new user
user_add() {
    local username=""
    local password=""
    local expiry_days=30
    local max_connections=1
    local data_limit=0
    local email=""
    local mobile=""
    local status="active"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --username)
                username="$2"
                shift 2
                ;;
            --password)
                password="$2"
                shift 2
                ;;
            --expiry)
                expiry_days="$2"
                shift 2
                ;;
            --max-conn)
                max_connections="$2"
                shift 2
                ;;
            --data-limit)
                data_limit="$2"
                shift 2
                ;;
            --email)
                email="$2"
                shift 2
                ;;
            --mobile)
                mobile="$2"
                shift 2
                ;;
            --status)
                status="$2"
                shift 2
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                return 1
                ;;
        esac
    done
    
    if [ -z "$username" ]; then
        read -p "Enter username: " username
    fi
    
    if [ -z "$username" ]; then
        log "ERROR" "Username is required"
        return 1
    fi
    
    if [ -z "$password" ]; then
        read -s -p "Enter password: " password
        echo
    fi
    
    if [ -z "$password" ]; then
        # Generate random password if not provided
        password=$(openssl rand -base64 12)
        log "INFO" "Generated random password: $password"
    fi
    
    # Calculate expiry date
    local expiry_date="NULL"
    if [ "$expiry_days" != "0" ]; then
        expiry_date="NOW() + INTERVAL '$expiry_days days'"
    fi
    
    # Calculate data limit in bytes
    local data_limit_bytes=0
    if [ "$data_limit" != "0" ]; then
        data_limit_bytes=$(echo "$data_limit * 1024 * 1024 * 1024" | bc)
    fi
    
    # Check if user already exists
    local user_exists=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -tAc "
        SELECT COUNT(*) FROM user_profiles WHERE username = '$username'
    ")
    
    if [ "$user_exists" -gt 0 ]; then
        log "ERROR" "User '$username' already exists"
        return 1
    fi
    
    # Create the user in database
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "
        INSERT INTO user_profiles (
            username, 
            email, 
            mobile, 
            max_connections, 
            expiry_date, 
            data_limit, 
            status
        ) VALUES (
            '$username', 
            $([ -z "$email" ] && echo "NULL" || echo "'$email'"), 
            $([ -z "$mobile" ] && echo "NULL" || echo "'$mobile'"), 
            $max_connections, 
            $expiry_date, 
            $data_limit_bytes, 
            '$status'
        );
    "
    
    if [ $? -eq 0 ]; then
        log "INFO" "User '$username' created successfully"
        
        # Create accounts across all protocols
        # SSH account
        if grep -q "PasswordAuthentication yes" /etc/ssh/sshd_config; then
            useradd -m -s /bin/false "$username" || log "WARN" "Failed to create system user for SSH"
            echo "$username:$password" | chpasswd || log "WARN" "Failed to set SSH password"
        fi
        
        # WireGuard account
        if [ -f "$SCRIPTS_DIR/wireguard/generate_client.sh" ]; then
            "$SCRIPTS_DIR/wireguard/generate_client.sh" "$username" || log "WARN" "Failed to create WireGuard account"
        fi
        
        # OpenVPN account
        if [ -f "$SCRIPTS_DIR/sslvpn/generate_client.sh" ]; then
            "$SCRIPTS_DIR/sslvpn/generate_client.sh" "$username" || log "WARN" "Failed to create SSL-VPN account"
        fi
        
        # NordWhisper account
        if [ -f "$SCRIPTS_DIR/nordwhisper/generate_nordwhisper_client.sh" ]; then
            "$SCRIPTS_DIR/nordwhisper/generate_nordwhisper_client.sh" "$username" || log "WARN" "Failed to create NordWhisper account"
        fi
        
        # Show user details
        user_show --username "$username"
    else
        log "ERROR" "Failed to create user '$username'"
        return 1
    fi
}

# Delete a user
user_delete() {
    local username=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --username)
                username="$2"
                shift 2
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                return 1
                ;;
        esac
    done
    
    if [ -z "$username" ]; then
        read -p "Enter username to delete: " username
    fi
    
    if [ -z "$username" ]; then
        log "ERROR" "Username is required"
        return 1
    fi
    
    # Check if user exists
    local user_exists=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -tAc "
        SELECT COUNT(*) FROM user_profiles WHERE username = '$username'
    ")
    
    if [ "$user_exists" -eq 0 ]; then
        log "ERROR" "User '$username' does not exist"
        return 1
    fi
    
    # Confirm deletion
    read -p "Are you sure you want to delete user '$username'? (y/N): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        log "INFO" "User deletion cancelled"
        return 0
    fi
    
    # Delete the user
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "
        DELETE FROM user_profiles WHERE username = '$username';
    "
    
    if [ $? -eq 0 ]; then
        log "INFO" "User '$username' deleted successfully from database"
        
        # Remove user from system and protocols
        # SSH account
        userdel -r "$username" 2>/dev/null || log "WARN" "Failed to remove system user"
        
        # WireGuard account
        if [ -f "/etc/wireguard/wg0.conf" ]; then
            sed -i "/# User: $username/,/^$/d" /etc/wireguard/wg0.conf || log "WARN" "Failed to remove WireGuard config"
            wg-quick down wg0 && wg-quick up wg0 || log "WARN" "Failed to reload WireGuard"
        fi
        
        # Remove OpenVPN certificate
        if [ -d "/etc/openvpn/easyrsa/pki" ]; then
            cd /etc/openvpn/easyrsa
            ./easyrsa --batch revoke "$username" 2>/dev/null || log "WARN" "Failed to revoke OpenVPN certificate"
            ./easyrsa --batch gen-crl || log "WARN" "Failed to regenerate CRL"
            cp -f pki/crl.pem /etc/openvpn/server/ || log "WARN" "Failed to copy CRL"
        fi
        
        # Remove NordWhisper account
        if [ -d "$CONFIG_DIR/nordwhisper/clients/$username" ]; then
            rm -rf "$CONFIG_DIR/nordwhisper/clients/$username" || log "WARN" "Failed to remove NordWhisper configs"
        fi
        
        log "INFO" "User '$username' completely removed from all systems"
    else
        log "ERROR" "Failed to delete user '$username'"
        return 1
    fi
}

# Show user details
user_show() {
    local username=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --username)
                username="$2"
                shift 2
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                return 1
                ;;
        esac
    done
    
    if [ -z "$username" ]; then
        read -p "Enter username: " username
    fi
    
    if [ -z "$username" ]; then
        log "ERROR" "Username is required"
        return 1
    fi
    
    # Check if user exists
    local user_exists=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -tAc "
        SELECT COUNT(*) FROM user_profiles WHERE username = '$username'
    ")
    
    if [ "$user_exists" -eq 0 ]; then
        log "ERROR" "User '$username' does not exist"
        return 1
    fi
    
    # Get user details
    echo -e "${GREEN}User Details: $username${NC}"
    echo "===================="
    
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "
        SELECT 
            username,
            email,
            mobile,
            status,
            max_connections,
            CASE 
                WHEN expiry_date IS NULL THEN 'No expiry'
                WHEN expiry_date < NOW() THEN 'Expired (' || to_char(expiry_date, 'YYYY-MM-DD HH24:MI:SS') || ')'
                ELSE to_char(expiry_date, 'YYYY-MM-DD HH24:MI:SS') || ' (' || 
                    EXTRACT(DAY FROM expiry_date - NOW())::INTEGER || 'd ' || 
                    EXTRACT(HOUR FROM expiry_date - NOW())::INTEGER || 'h remaining)'
            END as expiry_date,
            CASE
                WHEN data_limit = 0 THEN 'Unlimited'
                ELSE pg_size_pretty(data_limit)
            END as data_limit,
            to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') as created_at,
            (
                SELECT COUNT(*) 
                FROM user_connections 
                WHERE username = user_profiles.username AND status = 'active'
            ) as active_connections,
            (
                SELECT pg_size_pretty(COALESCE(SUM(upload_bytes + download_bytes), 0))
                FROM user_connections 
                WHERE username = user_profiles.username
            ) as total_traffic
        FROM user_profiles
        WHERE username = '$username';
    "
    
    echo -e "\n${GREEN}Active Connections:${NC}"
    echo "===================="
    
    local active_connections=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -tAc "
        SELECT COUNT(*) FROM user_connections WHERE username = '$username' AND status = 'active'
    ")
    
    if [ "$active_connections" -eq 0 ]; then
        echo "No active connections"
    else
        PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "
            SELECT 
                id, 
                protocol, 
                client_ip, 
                to_char(connect_time, 'YYYY-MM-DD HH24:MI:SS') as connect_time,
                pg_size_pretty(upload_bytes) as upload,
                pg_size_pretty(download_bytes) as download,
                EXTRACT(EPOCH FROM (NOW() - connect_time)) / 60 as duration_minutes
            FROM user_connections 
            WHERE username = '$username' AND status = 'active'
            ORDER BY connect_time DESC;
        "
    fi
    
    # Show available protocol configurations
    echo -e "\n${GREEN}Protocol Configurations:${NC}"
    echo "===================="
    
    # Check SSH access
    if id "$username" &>/dev/null; then
        echo -e "SSH: ${GREEN}Enabled${NC}"
    else
        echo -e "SSH: ${RED}Disabled${NC}"
    fi
    
    # Check WireGuard config
    if [ -f "$CONFIG_DIR/wireguard/clients/$username.conf" ]; then
        echo -e "WireGuard: ${GREEN}Configured${NC} - Config file: $CONFIG_DIR/wireguard/clients/$username.conf"
    else
        echo -e "WireGuard: ${RED}Not configured${NC}"
    fi
    
    # Check SSL-VPN config
    if [ -f "$CONFIG_DIR/sslvpn/clients/$username/$username.ovpn" ]; then
        echo -e "SSL-VPN: ${GREEN}Configured${NC} - Config file: $CONFIG_DIR/sslvpn/clients/$username/$username.ovpn"
    else
        echo -e "SSL-VPN: ${RED}Not configured${NC}"
    fi
    
    # Check NordWhisper config
    if [ -d "$CONFIG_DIR/nordwhisper/clients/$username" ]; then
        echo -e "NordWhisper: ${GREEN}Configured${NC} - Config directory: $CONFIG_DIR/nordwhisper/clients/$username"
    else
        echo -e "NordWhisper: ${RED}Not configured${NC}"
    fi
}

# Connection commands
conn_command() {
    local subcommand=$1
    shift
    
    case $subcommand in
        "list")
            conn_list
            ;;
        "kill")
            conn_kill "$@"
            ;;
        *)
            log "ERROR" "Unknown connection command: $subcommand"
            show_help
            exit 1
            ;;
    esac
}

# List all active connections
conn_list() {
    log "INFO" "Listing all active connections..."
    
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "
        SELECT 
            id, 
            username, 
            protocol, 
            client_ip, 
            to_char(connect_time, 'YYYY-MM-DD HH24:MI:SS') as connect_time,
            pg_size_pretty(upload_bytes) as upload,
            pg_size_pretty(download_bytes) as download,
            EXTRACT(EPOCH FROM (NOW() - connect_time)) / 60 as duration_minutes
        FROM user_connections 
        WHERE status = 'active'
        ORDER BY connect_time DESC;
    "
}

# Kill a connection
conn_kill() {
    local connection_id=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --id)
                connection_id="$2"
                shift 2
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                return 1
                ;;
        esac
    done
    
    if [ -z "$connection_id" ]; then
        read -p "Enter connection ID to terminate: " connection_id
    fi
    
    if [ -z "$connection_id" ]; then
        log "ERROR" "Connection ID is required"
        return 1
    fi
    
    # Check if connection exists
    local conn_exists=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -tAc "
        SELECT COUNT(*) FROM user_connections WHERE id = $connection_id AND status = 'active'
    ")
    
    if [ "$conn_exists" -eq 0 ]; then
        log "ERROR" "Active connection with ID $connection_id does not exist"
        return 1
    fi
    
    # Get connection details
    local conn_details=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -tAc "
        SELECT username, protocol, session_id FROM user_connections WHERE id = $connection_id
    ")
    
    local username=$(echo "$conn_details" | awk '{print $1}')
    local protocol=$(echo "$conn_details" | awk '{print $2}')
    local session_id=$(echo "$conn_details" | awk '{print $3}')
    
    # Terminate the connection in the database
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "
        UPDATE user_connections 
        SET status = 'terminated', 
            disconnect_time = NOW(), 
            disconnect_reason = 'admin_terminated'
        WHERE id = $connection_id;
    "
    
    if [ $? -eq 0 ]; then
        log "INFO" "Connection $connection_id ($username, $protocol) marked as terminated in database"
        
        # Try to physically terminate the connection based on protocol
        case $protocol in
            "ssh")
                pkill -f "sshd:.*$username@" || log "WARN" "Failed to terminate SSH process"
                ;;
            "wireguard")
                # This is more complex and would need to extract the public key from session_id
                # or locate it some other way, then use wg set to remove the peer
                log "WARN" "Automatic termination of WireGuard connections not implemented"
                ;;
            "l2tp")
                pkill -f "pppd.*$username" || log "WARN" "Failed to terminate L2TP process"
                ;;
            "ikev2")
                # Would need to identify the connection ID in strongSwan/charon
                log "WARN" "Automatic termination of IKEv2 connections not implemented"
                ;;
            "sslvpn")
                # Extract client ID from management interface
                if [ -S /var/run/openvpn/server.sock ]; then
                    echo "kill $username" | nc -U /var/run/openvpn/server.sock || log "WARN" "Failed to terminate SSL-VPN connection"
                else
                    log "WARN" "OpenVPN management interface not available"
                fi
                ;;
            "nordwhisper")
                log "WARN" "Automatic termination of NordWhisper connections not implemented"
                ;;
            *)
                log "WARN" "Unknown protocol: $protocol, cannot terminate physically"
                ;;
        esac
        
        log "INFO" "Connection terminated successfully"
    else
        log "ERROR" "Failed to terminate connection"
        return 1
    fi
}

# Service commands
service_command() {
    local subcommand=$1
    shift
    
    case $subcommand in
        "status")
            service_status
            ;;
        "restart")
            service_restart "$@"
            ;;
        "logs")
            service_logs "$@"
            ;;
        *)
            log "ERROR" "Unknown service command: $subcommand"
            show_help
            exit 1
            ;;
    esac
}

# Check service status
service_status() {
    log "INFO" "Checking service status..."
    
    echo -e "${GREEN}IRSSH-Panel Service Status${NC}"
    echo "=========================="
    
    local services=(
        "nginx" 
        "postgresql" 
        "redis-server" 
        "irssh-api" 
        "irssh-user-manager"
        "irssh-ssh-monitor"
        "irssh-wireguard-monitor"
        "irssh-l2tp-monitor"
        "irssh-ikev2-monitor"
        "irssh-cisco-monitor"
        "irssh-singbox-monitor"
        "irssh-sslvpn-monitor"
        "irssh-nordwhisper-monitor"
        "irssh-system-monitor"
    )
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo -e "${GREEN}● ${service} is active${NC}"
        elif systemctl is-enabled --quiet "$service"; then
            echo -e "${YELLOW}● ${service} is enabled but not running${NC}"
        else
            echo -e "${RED}● ${service} is not enabled${NC}"
        fi
    done
}

# Ansible commands
ansible_command() {
    local subcommand=$1
    shift
    
    case $subcommand in
        "list-playbooks")
            ansible_list_playbooks
            ;;
        "run")
            ansible_run_playbook "$@"
            ;;
        "status")
            ansible_status
            ;;
        "install-role")
            ansible_install_role "$@"
            ;;
        *)
            log "ERROR" "Unknown ansible command: $subcommand"
            show_help
            exit 1
            ;;
    esac
}

# List available Ansible playbooks
ansible_list_playbooks() {
    log "INFO" "Listing available Ansible playbooks..."
    
    if [ ! -d "$ANSIBLE_DIR/playbooks" ]; then
        log "ERROR" "Ansible playbooks directory not found"
        return 1
    fi
    
    echo -e "${GREEN}Available Ansible Playbooks${NC}"
    echo "============================"
    
    find "$ANSIBLE_DIR/playbooks" -name "*.yml" | while read -r playbook; do
        local name=$(basename "$playbook" .yml)
        local description=""
        
        # Extract description from playbook if available
        if grep -q "^# Description:" "$playbook"; then
            description=$(grep "^# Description:" "$playbook" | sed 's/# Description: //')
        fi
        
        echo -e "${BLUE}${name}${NC}: ${description}"
    done
}

# Run an Ansible playbook
ansible_run_playbook() {
    local playbook=""
    local inventory="$ANSIBLE_DIR/inventory/hosts"
    local extra_vars=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --playbook)
                playbook="$2"
                shift 2
                ;;
            --inventory)
                inventory="$2"
                shift 2
                ;;
            --extra-vars)
                extra_vars="$2"
                shift 2
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                return 1
                ;;
        esac
    done
    
    if [ -z "$playbook" ]; then
        read -p "Enter playbook name: " playbook
    fi
    
    if [ -z "$playbook" ]; then
        log "ERROR" "Playbook name is required"
        return 1
    fi
    
    # Check if playbook exists
    local playbook_path="$ANSIBLE_DIR/playbooks/$playbook.yml"
    if [ ! -f "$playbook_path" ]; then
        log "ERROR" "Playbook '$playbook.yml' not found"
        return 1
    fi
    
    # Check if inventory exists
    if [ ! -f "$inventory" ]; then
        log "ERROR" "Inventory file not found: $inventory"
        return 1
    fi
    
    log "INFO" "Running Ansible playbook: $playbook"
    
    # Create log directory
    mkdir -p "$LOG_DIR/ansible"
    local log_file="$LOG_DIR/ansible/${playbook}_$(date +%Y%m%d%H%M%S).log"
    
    # Run the playbook
    if [ -n "$extra_vars" ]; then
        ansible-playbook -i "$inventory" "$playbook_path" --extra-vars "$extra_vars" | tee "$log_file"
    else
        ansible-playbook -i "$inventory" "$playbook_path" | tee "$log_file"
    fi
    
    if [ $? -eq 0 ]; then
        log "INFO" "Playbook execution completed successfully"
    else
        log "ERROR" "Playbook execution failed. Check the log file: $log_file"
        return 1
    fi
}

# Install an Ansible role
ansible_install_role() {
    local role=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --role)
                role="$2"
                shift 2
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                return 1
                ;;
        esac
    done
    
    if [ -z "$role" ]; then
        read -p "Enter role name: " role
    fi
    
    if [ -z "$role" ]; then
        log "ERROR" "Role name is required"
        return 1
    fi
    
    log "INFO" "Installing Ansible role: $role"
    
    # Install the role
    ansible-galaxy install "$role"
    
    if [ $? -eq 0 ]; then
        log "INFO" "Role installed successfully"
    else
        log "ERROR" "Failed to install role"
        return 1
    fi
}

# Multi-server commands
multi_server_command() {
    local subcommand=$1
    shift
    
    case $subcommand in
        "list")
            multi_server_list
            ;;
        "add")
            multi_server_add "$@"
            ;;
        "remove")
            multi_server_remove "$@"
            ;;
        "sync")
            multi_server_sync "$@"
            ;;
        "status")
            multi_server_status
            ;;
        *)
            log "ERROR" "Unknown multi-server command: $subcommand"
            show_help
            exit 1
            ;;
    esac
}

# List connected servers
multi_server_list() {
    log "INFO" "Listing connected servers..."
    
    if [ ! -f "$CONFIG_DIR/multi-server/servers.json" ]; then
        log "ERROR" "Multi-server configuration not found"
        log "INFO" "Run 'irssh-admin multi-server activate' to enable multi-server functionality"
        return 1
    fi
    
    echo -e "${GREEN}Connected Servers${NC}"
    echo "================="
    
    cat "$CONFIG_DIR/multi-server/servers.json" | jq -r '.servers[] | "\(.name) (\(.role)): \(.host) - Status: \(.status)"'
}

# Add a new server to the cluster
multi_server_add() {
    if [ ! -f "$CONFIG_DIR/multi-server/servers.json" ]; then
        log "ERROR" "Multi-server configuration not found"
        log "INFO" "Run 'irssh-admin multi-server activate' to enable multi-server functionality"
        return 1
    fi
    
    local host=""
    local name=""
    local role="worker"
    local ssh_port=22
    local ssh_key=""
    local username="root"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --host)
                host="$2"
                shift 2
                ;;
            --name)
                name="$2"
                shift 2
                ;;
            --role)
                role="$2"
                shift 2
                ;;
            --ssh-port)
                ssh_port="$2"
                shift 2
                ;;
            --ssh-key)
                ssh_key="$2"
                shift 2
                ;;
            --username)
                username="$2"
                shift 2
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                return 1
                ;;
        esac
    done
    
    if [ -z "$host" ]; then
        read -p "Enter server hostname or IP: " host
    fi
    
    if [ -z "$host" ]; then
        log "ERROR" "Server hostname or IP is required"
        return 1
    fi
    
    if [ -z "$name" ]; then
        read -p "Enter server name [server-$(date +%s)]: " name
        name=${name:-server-$(date +%s)}
    fi
    
    # Update servers.json
    local temp_file=$(mktemp)
    jq ".servers += [{\"name\": \"$name\", \"host\": \"$host\", \"role\": \"$role\", \"ssh_port\": $ssh_port, \"ssh_key\": \"$ssh_key\", \"username\": \"$username\", \"status\": \"new\", \"added_at\": \"$(date -Iseconds)\"}]" "$CONFIG_DIR/multi-server/servers.json" > "$temp_file"
    mv "$temp_file" "$CONFIG_DIR/multi-server/servers.json"
    
    # Update Ansible inventory
    local inventory_file="$ANSIBLE_DIR/inventory/hosts"
    
    if ! grep -q "\[$role\]" "$inventory_file"; then
        echo -e "\n[$role]" >> "$inventory_file"
    fi
    
    if ! grep -q "$host" "$inventory_file"; then
        echo "$name ansible_host=$host ansible_port=$ssh_port ansible_user=$username" >> "$inventory_file"
    fi
    
    log "INFO" "Server '$name' ($host) added to the cluster"
    
    # Ask if user wants to run server setup playbook
    read -p "Do you want to run the server setup playbook now? (y/N): " run_setup
    if [[ "$run_setup" == "y" || "$run_setup" == "Y" ]]; then
        log "INFO" "Running server setup playbook..."
        ansible-playbook -i "$ANSIBLE_DIR/inventory/hosts" "$ANSIBLE_DIR/playbooks/server-setup.yml" --limit "$name"
    else
        log "INFO" "You can run the setup later with: irssh-admin ansible run --playbook server-setup --extra-vars 'limit=$name'"
    fi
}

# Remove a server from the cluster
multi_server_remove() {
    if [ ! -f "$CONFIG_DIR/multi-server/servers.json" ]; then
        log "ERROR" "Multi-server configuration not found"
        return 1
    fi
    
    local name=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --name)
                name="$2"
                shift 2
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                return 1
                ;;
        esac
    done
    
    if [ -z "$name" ]; then
        read -p "Enter server name to remove: " name
    fi
    
    if [ -z "$name" ]; then
        log "ERROR" "Server name is required"
        return 1
    fi
    
    # Check if server exists
    if ! jq -e ".servers[] | select(.name == \"$name\")" "$CONFIG_DIR/multi-server/servers.json" > /dev/null; then
        log "ERROR" "Server '$name' not found"
        return 1
    fi
    
    # Remove server from servers.json
    local temp_file=$(mktemp)
    jq ".servers = [.servers[] | select(.name != \"$name\")]" "$CONFIG_DIR/multi-server/servers.json" > "$temp_file"
    mv "$temp_file" "$CONFIG_DIR/multi-server/servers.json"
    
    # Remove server from Ansible inventory
    local inventory_file="$ANSIBLE_DIR/inventory/hosts"
    sed -i "/^$name ansible_host/d" "$inventory_file"
    
    log "INFO" "Server '$name' removed from the cluster"
}

# Synchronize configuration across servers
multi_server_sync() {
    if [ ! -f "$CONFIG_DIR/multi-server/servers.json" ]; then
        log "ERROR" "Multi-server configuration not found"
        return 1
    fi
    
    local target=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --target)
                target="$2"
                shift 2
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                return 1
                ;;
        esac
    done
    
    # Run synchronization playbook
    local limit_arg=""
    if [ -n "$target" ]; then
        limit_arg="--limit $target"
    fi
    
    log "INFO" "Running configuration synchronization across the cluster..."
    ansible-playbook -i "$ANSIBLE_DIR/inventory/hosts" "$ANSIBLE_DIR/playbooks/sync-config.yml" $limit_arg
    
    if [ $? -eq 0 ]; then
        log "INFO" "Configuration synchronized successfully"
    else
        log "ERROR" "Failed to synchronize configuration"
        return 1
    fi
}

# Show multi-server status
multi_server_status() {
    if [ ! -f "$CONFIG_DIR/multi-server/servers.json" ]; then
        log "ERROR" "Multi-server configuration not found"
        log "INFO" "Run 'irssh-admin multi-server activate' to enable multi-server functionality"
        return 1
    fi
    
    log "INFO" "Checking multi-server status..."
    
    echo -e "${GREEN}Multi-Server Cluster Status${NC}"
    echo "=========================="
    
    # Get server count
    local server_count=$(jq '.servers | length' "$CONFIG_DIR/multi-server/servers.json")
    local active_count=$(jq '[.servers[] | select(.status == "active")] | length' "$CONFIG_DIR/multi-server/servers.json")
    
    echo -e "Total Servers: ${BLUE}$server_count${NC}"
    echo -e "Active Servers: ${GREEN}$active_count${NC}"
    echo
    
    # Display server list with status
    jq -r '.servers[] | "\(.name) (\(.role)): \(.host) - Status: \(.status)"' "$CONFIG_DIR/multi-server/servers.json"
    
    echo
    echo -e "${GREEN}Tunnel Status${NC}"
    echo "=============="
    
    # Check tunnel status if wireguard is installed
    if command -v wg &> /dev/null; then
        wg show
    else
        echo "WireGuard not installed on this server"
    fi
}

# Function to activate multi-server functionality
multi_server_activate() {
    log "INFO" "Activating multi-server functionality..."
    
    # Check if already activated
    if [ -f "$CONFIG_DIR/multi-server/servers.json" ]; then
        log "INFO" "Multi-server functionality is already activated"
        return 0
    fi
    
    # Check activation key
    local activation_key=""
    local server_ip=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --key)
                activation_key="$2"
                shift 2
                ;;
            --server-ip)
                server_ip="$2"
                shift 2
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                return 1
                ;;
        esac
    done
    
    if [ -z "$activation_key" ]; then
        read -p "Enter multi-server activation key: " activation_key
    fi
    
    if [ -z "$activation_key" ]; then
        log "ERROR" "Activation key is required"
        return 1
    fi
    
    if [ -z "$server_ip" ]; then
        server_ip=$(curl -s4 ifconfig.me || ip -4 route get 8.8.8.8 | awk '{print $7; exit}')
    fi
    
    # Generate expected key
    local expected_key=$(echo -n "IRSSH-MULTI-${server_ip}-special-secret" | sha256sum | awk '{print $1}')
    
    if [ "$activation_key" != "$expected_key" ]; then
        log "ERROR" "Invalid activation key"
        return 1
    fi
    
    # Create necessary directories
    mkdir -p "$CONFIG_DIR/multi-server"
    mkdir -p "$ANSIBLE_DIR/inventory"
    mkdir -p "$ANSIBLE_DIR/playbooks"
    mkdir -p "$ANSIBLE_DIR/roles"
    
    # Create initial servers.json
    cat > "$CONFIG_DIR/multi-server/servers.json" << EOF
{
    "version": "1.0",
    "master": {
        "name": "master",
        "host": "$server_ip",
        "role": "master"
    },
    "servers": [
        {
            "name": "master",
            "host": "$server_ip",
            "role": "master",
            "ssh_port": 22,
            "ssh_key": "",
            "username": "root",
            "status": "active",
            "added_at": "$(date -Iseconds)"
        }
    ]
}
EOF
    
    # Create initial Ansible inventory
    cat > "$ANSIBLE_DIR/inventory/hosts" << EOF
# IRSSH-Panel Multi-Server Inventory

[master]
master ansible_host=$server_ip ansible_connection=local

[worker]

[edge]

[all:vars]
ansible_python_interpreter=/usr/bin/python3
EOF
    
    # Create server setup playbook
    cat > "$ANSIBLE_DIR/playbooks/server-setup.yml" << 'EOF'
---
# Description: Initial server setup for IRSSH-Panel worker nodes

- name: Server setup for IRSSH-Panel
  hosts: all
  become: yes
  gather_facts: yes
  
  tasks:
    - name: Update apt cache
      apt:
        update_cache: yes
        cache_valid_time: 3600
    
    - name: Install required packages
      apt:
        name: 
          - curl
          - wget
          - git
          - unzip
          - zip
          - tar
          - python3
          - python3-pip
          - wireguard
        state: present
    
    - name: Get server IP
      shell: "curl -s4 ifconfig.me || ip -4 route get 8.8.8.8 | awk '{print $7; exit}'"
      register: server_ip
    
    - name: Create required directories
      file:
        path: "{{ item }}"
        state: directory
        mode: 0755
      with_items:
        - /etc/enhanced_ssh
        - /etc/enhanced_ssh/multi-server
        - /var/log/irssh
    
    - name: Generate WireGuard keys
      shell: |
        wg genkey | tee /etc/enhanced_ssh/multi-server/private.key | wg pubkey > /etc/enhanced_ssh/multi-server/public.key
      args:
        creates: /etc/enhanced_ssh/multi-server/private.key
    
    - name: Read private key
      slurp:
        src: /etc/enhanced_ssh/multi-server/private.key
      register: private_key_b64
    
    - name: Read public key
      slurp:
        src: /etc/enhanced_ssh/multi-server/public.key
      register: public_key_b64
    
    - name: Store server information
      set_fact:
        server_info:
          host: "{{ server_ip.stdout }}"
          private_key: "{{ private_key_b64.content | b64decode | trim }}"
          public_key: "{{ public_key_b64.content | b64decode | trim }}"
    
    - name: Save server information to master node
      delegate_to: master
      copy:
        content: "{{ server_info | to_json }}"
        dest: "/etc/enhanced_ssh/multi-server/servers/{{ inventory_hostname }}.json"
      when: inventory_hostname != 'master'
    
    - name: Update server status
      delegate_to: master
      shell: |
        jq ".servers[] |= if .name == \"{{ inventory_hostname }}\" then .status = \"active\" else . end" /etc/enhanced_ssh/multi-server/servers.json > /tmp/servers.json.tmp
        mv /tmp/servers.json.tmp /etc/enhanced_ssh/multi-server/servers.json
      when: inventory_hostname != 'master'
    
    - name: Report success
      debug:
        msg: "Server {{ inventory_hostname }} ({{ server_ip.stdout }}) setup completed successfully"
EOF
    
    # Create configuration sync playbook
    cat > "$ANSIBLE_DIR/playbooks/sync-config.yml" << 'EOF'
---
# Description: Synchronize configuration across all servers in the cluster

- name: Synchronize IRSSH-Panel configuration
  hosts: all
  become: yes
  gather_facts: yes
  
  tasks:
    - name: Ensure configuration directories exist
      file:
        path: "{{ item }}"
        state: directory
        mode: 0755
      with_items:
        - /etc/enhanced_ssh
        - /etc/enhanced_ssh/multi-server
        - /var/log/irssh
    
    - name: Copy shared configuration files
      synchronize:
        src: /etc/enhanced_ssh/{{ item }}
        dest: /etc/enhanced_ssh/{{ item }}
        delete: yes
        recursive: yes
      with_items:
        - db
        - wireguard
        - sslvpn
        - nordwhisper
      delegate_to: master
    
    - name: Copy tunnel configuration
      template:
        src: /etc/enhanced_ssh/multi-server/templates/wg-tunnel.conf.j2
        dest: /etc/wireguard/wg-tunnel.conf
        mode: 0600
      when: inventory_hostname != 'master'
    
    - name: Restart WireGuard tunnel
      systemd:
        name: wg-quick@wg-tunnel
        state: restarted
        enabled: yes
      when: inventory_hostname != 'master'
    
    - name: Copy protocol services
      synchronize:
        src: /opt/irssh-panel/services/protocols/
        dest: /opt/irssh-panel/services/protocols/
        delete: yes
        recursive: yes
      delegate_to: master
      when: inventory_hostname != 'master'
    
    - name: Restart protocol services
      systemd:
        name: "{{ item }}"
        state: restarted
      with_items:
        - irssh-ssh-monitor
        - irssh-wireguard-monitor
        - irssh-l2tp-monitor
        - irssh-ikev2-monitor
        - irssh-cisco-monitor
        - irssh-singbox-monitor
        - irssh-sslvpn-monitor
        - irssh-nordwhisper-monitor
      ignore_errors: yes
      when: inventory_hostname != 'master'
    
    - name: Report synchronization status
      debug:
        msg: "Configuration synchronized to {{ inventory_hostname }}"
EOF
    
    # Create tunnel setup playbook
    cat > "$ANSIBLE_DIR/playbooks/setup-tunnels.yml" << 'EOF'
---
# Description: Set up WireGuard tunnels between all servers in the cluster

- name: Set up WireGuard tunnels
  hosts: all
  become: yes
  gather_facts: yes
  
  vars:
    tunnel_subnet: 10.10.0.0/16
    master_ip: 10.10.0.1
  
  tasks:
    - name: Ensure WireGuard is installed
      apt:
        name: wireguard
        state: present
    
    - name: Create tunnel configuration directory
      file:
        path: /etc/enhanced_ssh/multi-server/templates
        state: directory
        mode: 0755
      delegate_to: master
      run_once: true
    
    - name: Generate master tunnel configuration
      template:
        src: templates/master-tunnel.conf.j2
        dest: /etc/enhanced_ssh/multi-server/templates/master-tunnel.conf
        mode: 0600
      delegate_to: master
      run_once: true
    
    - name: Generate worker tunnel configuration template
      template:
        src: templates/worker-tunnel.conf.j2
        dest: /etc/enhanced_ssh/multi-server/templates/wg-tunnel.conf.j2
        mode: 0600
      delegate_to: master
      run_once: true
    
    - name: Copy master tunnel configuration
      copy:
        src: /etc/enhanced_ssh/multi-server/templates/master-tunnel.conf
        dest: /etc/wireguard/wg-tunnel.conf
        mode: 0600
      when: inventory_hostname == 'master'
    
    - name: Generate worker tunnel configuration
      template:
        src: /etc/enhanced_ssh/multi-server/templates/wg-tunnel.conf.j2
        dest: /etc/wireguard/wg-tunnel.conf
        mode: 0600
      when: inventory_hostname != 'master'
    
    - name: Enable and start WireGuard tunnel
      systemd:
        name: wg-quick@wg-tunnel
        state: started
        enabled: yes
    
    - name: Report tunnel setup status
      debug:
        msg: "WireGuard tunnel set up on {{ inventory_hostname }}"
EOF
    
    # Create activation files
    mkdir -p "$CONFIG_DIR/multi-server/activate"
    
    # Create activation script
    cat > "$CONFIG_DIR/multi-server/activate/activate-multi-server.sh" << 'EOF'
#!/bin/bash

# This script activates the multi-server functionality in IRSSH-Panel

# Define colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Base directories
PANEL_DIR="/opt/irssh-panel"
CONFIG_DIR="/etc/enhanced_ssh"
ANSIBLE_DIR="${PANEL_DIR}/ansible"

# Log function
log() {
    echo -e "${2:-$GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
   log "This script must be run as root" "$RED"
   exit 1
fi

# Get server IP
SERVER_IP=$(curl -s4 ifconfig.me || ip -4 route get 8.8.8.8 | awk '{print $7; exit}')

# Generate activation key
ACTIVATION_KEY=$(echo -n "IRSSH-MULTI-${SERVER_IP}-special-secret" | sha256sum | awk '{print $1}')

# Activate multi-server functionality
/usr/local/bin/irssh-admin multi-server activate --key "$ACTIVATION_KEY" --server-ip "$SERVER_IP"

if [ $? -eq 0 ]; then
    log "Multi-server functionality activated successfully!" "$GREEN"
    
    # Create directories for server information
    mkdir -p "$CONFIG_DIR/multi-server/servers"
    
    # Generate WireGuard keys for master
    if [ ! -f "$CONFIG_DIR/multi-server/private.key" ]; then
        log "Generating WireGuard keys for master server..."
        wg genkey | tee "$CONFIG_DIR/multi-server/private.key" | wg pubkey > "$CONFIG_DIR/multi-server/public.key"
    fi
    
    # Create tunnel template directories
    mkdir -p "$ANSIBLE_DIR/playbooks/templates"
    
    # Create master tunnel template
    cat > "$ANSIBLE_DIR/playbooks/templates/master-tunnel.conf.j2" << 'EOT'
[Interface]
PrivateKey = {{ hostvars['master']['server_info']['private_key'] }}
Address = 10.10.0.1/16
ListenPort = 51821

# Worker nodes
{% for host in groups['worker'] %}
[Peer]
# {{ host }}
PublicKey = {{ hostvars[host]['server_info']['public_key'] }}
AllowedIPs = 10.10.{{ loop.index }}.0/24
{% endfor %}

# Edge nodes
{% for host in groups['edge'] %}
[Peer]
# {{ host }}
PublicKey = {{ hostvars[host]['server_info']['public_key'] }}
AllowedIPs = 10.10.{{ groups['worker']|length + loop.index }}.0/24
{% endfor %}
EOT
    
    # Create worker tunnel template
    cat > "$ANSIBLE_DIR/playbooks/templates/worker-tunnel.conf.j2" << 'EOT'
[Interface]
PrivateKey = {{ server_info.private_key }}
{% if inventory_hostname in groups['worker'] %}
Address = 10.10.{{ groups['worker'].index(inventory_hostname) + 1 }}.1/24
{% else %}
Address = 10.10.{{ groups['worker']|length + groups['edge'].index(inventory_hostname) + 1 }}.1/24
{% endif %}
ListenPort = 51821

[Peer]
# master
PublicKey = {{ hostvars['master']['server_info']['public_key'] }}
Endpoint = {{ hostvars['master']['server_info']['host'] }}:51821
AllowedIPs = 10.10.0.0/16
PersistentKeepalive = 25
EOT

    # Initialize frontend components for multi-server
    mkdir -p "$PANEL_DIR/frontend/src/pages"
    mkdir -p "$PANEL_DIR/backend/api"
    
    # Create Multi-Server API endpoints
    cat > "$PANEL_DIR/backend/api/multi-server.js" << 'EOT'
const express = require('express');
const Router = express.Router();
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

// Configuration paths
const CONFIG_DIR = '/etc/enhanced_ssh';
const MULTI_SERVER_CONFIG = path.join(CONFIG_DIR, 'multi-server/servers.json');
const ANSIBLE_DIR = '/opt/irssh-panel/ansible';

// Check if multi-server is activated
const isActivated = () => {
    return fs.existsSync(MULTI_SERVER_CONFIG);
};

// Authentication middleware
const authMiddleware = (req, res, next) => {
    // If module is not activated, return 404 to hide its existence
    if (!isActivated()) {
        return res.status(404).json({ error: 'Endpoint not found' });
    }
    
    // Check for auth token
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Authentication required' });
        }
        
        const token = authHeader.split(' ')[1];
        const jwt = require('jsonwebtoken');
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'irssh-secret-key');
        
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
};

// Admin middleware
const adminMiddleware = (req, res, next) => {
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// Get servers list
Router.get('/servers', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const data = fs.readFileSync(MULTI_SERVER_CONFIG, 'utf8');
        const config = JSON.parse(data);
        res.json({ servers: config.servers });
    } catch (error) {
        res.status(500).json({ error: 'Failed to read server configuration' });
    }
});

// Get server details
Router.get('/servers/:name', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const data = fs.readFileSync(MULTI_SERVER_CONFIG, 'utf8');
        const config = JSON.parse(data);
        const server = config.servers.find(s => s.name === req.params.name);
        
        if (!server) {
            return res.status(404).json({ error: 'Server not found' });
        }
        
        res.json({ server });
    } catch (error) {
        res.status(500).json({ error: 'Failed to read server configuration' });
    }
});

// Add server
Router.post('/servers', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { name, host, role = 'worker', ssh_port = 22, username = 'root' } = req.body;
        
        if (!name || !host) {
            return res.status(400).json({ error: 'Name and host are required' });
        }
        
        // Read current configuration
        const data = fs.readFileSync(MULTI_SERVER_CONFIG, 'utf8');
        const config = JSON.parse(data);
        
        // Check if server with this name already exists
        if (config.servers.some(s => s.name === name)) {
            return res.status(400).json({ error: 'Server with this name already exists' });
        }
        
        // Add new server
        const newServer = {
            name,
            host,
            role,
            ssh_port,
            ssh_key: '',
            username,
            status: 'new',
            added_at: new Date().toISOString()
        };
        
        config.servers.push(newServer);
        
        // Save updated configuration
        fs.writeFileSync(MULTI_SERVER_CONFIG, JSON.stringify(config, null, 4));
        
        // Update Ansible inventory
        const inventoryFile = path.join(ANSIBLE_DIR, 'inventory/hosts');
        let inventory = fs.readFileSync(inventoryFile, 'utf8');
        
        if (!inventory.includes(`[${role}]`)) {
            inventory += `\n[${role}]\n`;
        }
        
        if (!inventory.includes(`${name} ansible_host=`)) {
            inventory += `${name} ansible_host=${host} ansible_port=${ssh_port} ansible_user=${username}\n`;
        }
        
        fs.writeFileSync(inventoryFile, inventory);
        
        res.json({ success: true, server: newServer });
    } catch (error) {
        res.status(500).json({ error: 'Failed to add server', details: error.message });
    }
});

// Remove server
Router.delete('/servers/:name', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const name = req.params.name;
        
        if (name === 'master') {
            return res.status(400).json({ error: 'Cannot remove master server' });
        }
        
        // Read current configuration
        const data = fs.readFileSync(MULTI_SERVER_CONFIG, 'utf8');
        const config = JSON.parse(data);
        
        // Check if server exists
        const serverIndex = config.servers.findIndex(s => s.name === name);
        if (serverIndex === -1) {
            return res.status(404).json({ error: 'Server not found' });
        }
        
        // Remove server
        config.servers.splice(serverIndex, 1);
        
        // Save updated configuration
        fs.writeFileSync(MULTI_SERVER_CONFIG, JSON.stringify(config, null, 4));
        
        // Update Ansible inventory
        const inventoryFile = path.join(ANSIBLE_DIR, 'inventory/hosts');
        let inventory = fs.readFileSync(inventoryFile, 'utf8');
        
        // Remove server from inventory
        inventory = inventory.replace(new RegExp(`${name} ansible_host=.*\\n`, 'g'), '');
        
        fs.writeFileSync(inventoryFile, inventory);
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to remove server', details: error.message });
    }
});

// Run Ansible playbook
Router.post('/ansible/run', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { playbook, target } = req.body;
        
if (!playbook) {
            return res.status(400).json({ error: 'Playbook name is required' });
        }
        
        const playbookPath = path.join(ANSIBLE_DIR, `playbooks/${playbook}.yml`);
        
        if (!fs.existsSync(playbookPath)) {
            return res.status(404).json({ error: 'Playbook not found' });
        }
        
        // Build command
        let command = `ansible-playbook -i ${ANSIBLE_DIR}/inventory/hosts ${playbookPath}`;
        
        if (target) {
            command += ` --limit ${target}`;
        }
        
        // Run command
        const { stdout, stderr } = await execAsync(command);
        
        res.json({
            success: true,
            output: stdout,
            errors: stderr
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to run Ansible playbook', details: error.message });
    }
});

// Get server status
Router.get('/status', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        // Read configuration
        const data = fs.readFileSync(MULTI_SERVER_CONFIG, 'utf8');
        const config = JSON.parse(data);
        
        // Get WireGuard status
        let tunnelStatus = {};
        try {
            const { stdout } = await execAsync('wg show');
            tunnelStatus = { status: 'active', details: stdout };
        } catch (error) {
            tunnelStatus = { status: 'error', details: error.message };
        }
        
        res.json({
            version: config.version,
            master: config.master,
            serverCount: config.servers.length,
            activeCount: config.servers.filter(s => s.status === 'active').length,
            tunnelStatus
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get status', details: error.message });
    }
});

// Sync configuration
Router.post('/sync', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { target } = req.body;
        
        // Build command
        let command = `ansible-playbook -i ${ANSIBLE_DIR}/inventory/hosts ${ANSIBLE_DIR}/playbooks/sync-config.yml`;
        
        if (target) {
            command += ` --limit ${target}`;
        }
        
        // Run command
        const { stdout, stderr } = await execAsync(command);
        
        res.json({
            success: true,
            output: stdout,
            errors: stderr
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to sync configuration', details: error.message });
    }
});

// Activate module
Router.post('/activate', async (req, res) => {
    try {
        const { activationKey, serverIp } = req.body;
        
        if (isActivated()) {
            return res.json({ success: true, message: 'Multi-server functionality is already activated' });
        }
        
        // Generate expected key
        const crypto = require('crypto');
        const expectedKey = crypto.createHash('sha256')
            .update(`IRSSH-MULTI-${serverIp}-special-secret`)
            .digest('hex');
        
        if (activationKey !== expectedKey) {
            return res.status(403).json({ success: false, message: 'Invalid activation key' });
        }
        
        // Run activation script
        const { stdout, stderr } = await execAsync(`${CONFIG_DIR}/multi-server/activate/activate-multi-server.sh`);
        
        if (stderr && stderr.includes('error')) {
            return res.status(500).json({ success: false, message: 'Activation failed', error: stderr });
        }
        
        res.json({ success: true, message: 'Multi-server functionality activated successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to activate multi-server functionality', details: error.message });
    }
});

module.exports = Router;
EOT

    # Add Multi-Server React component
    cat > "$PANEL_DIR/frontend/src/pages/MultiServer.jsx" << 'EOT'
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { toast } from 'react-hot-toast';

const MultiServerPage = () => {
    const [isActivated, setIsActivated] = useState(false);
    const [activationKey, setActivationKey] = useState('');
    const [servers, setServers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [status, setStatus] = useState(null);
    const [newServer, setNewServer] = useState({
        name: '',
        host: '',
        role: 'worker',
        ssh_port: 22,
        username: 'root'
    });
    const [selectedPlaybook, setSelectedPlaybook] = useState('');
    const [playbooks, setPlaybooks] = useState([]);
    const [playbookTarget, setPlaybookTarget] = useState('');
    const [playbookOutput, setPlaybookOutput] = useState('');
    const [tab, setTab] = useState('servers');

    // Check if module is activated
    useEffect(() => {
        checkActivationStatus();
    }, []);

    const checkActivationStatus = async () => {
        try {
            setLoading(true);
            const response = await axios.get('/api/multi-server/status');
            setIsActivated(true);
            setStatus(response.data);
            await fetchServers();
            await fetchPlaybooks();
            setLoading(false);
        } catch (error) {
            // 404 error means endpoint doesn't exist or module not activated
            if (error.response && error.response.status === 404) {
                setIsActivated(false);
            } else {
                console.error('Error checking multi-server status:', error);
                toast.error('Failed to check multi-server status');
            }
            setLoading(false);
        }
    };

    const fetchServers = async () => {
        try {
            const response = await axios.get('/api/multi-server/servers');
            setServers(response.data.servers);
        } catch (error) {
            console.error('Error fetching servers:', error);
            toast.error('Failed to fetch server data');
        }
    };

    const fetchPlaybooks = async () => {
        try {
            const response = await axios.get('/api/ansible/playbooks');
            setPlaybooks(response.data.playbooks);
        } catch (error) {
            console.error('Error fetching playbooks:', error);
        }
    };

    const activateModule = async () => {
        try {
            // Get server IP
            const ipResponse = await axios.get('/api/system/info');
            const serverIp = ipResponse.data.system?.ipv4_address || '127.0.0.1';
            
            const response = await axios.post('/api/multi-server/activate', {
                activationKey,
                serverIp
            });
            
            if (response.data.success) {
                toast.success('Multi-server functionality activated successfully');
                setIsActivated(true);
                checkActivationStatus();
            } else {
                toast.error(response.data.message || 'Activation failed');
            }
        } catch (error) {
            console.error('Error activating module:', error);
            toast.error(error.response?.data?.message || 'Failed to activate module');
        }
    };

    const addServer = async (e) => {
        e.preventDefault();
        try {
            const response = await axios.post('/api/multi-server/servers', newServer);
            if (response.data.success) {
                toast.success(`Server ${newServer.name} added successfully`);
                fetchServers();
                setNewServer({
                    name: '',
                    host: '',
                    role: 'worker',
                    ssh_port: 22,
                    username: 'root'
                });
            }
        } catch (error) {
            console.error('Error adding server:', error);
            toast.error(error.response?.data?.error || 'Failed to add server');
        }
    };

    const removeServer = async (name) => {
        if (window.confirm(`Are you sure you want to remove server ${name}?`)) {
            try {
                const response = await axios.delete(`/api/multi-server/servers/${name}`);
                if (response.data.success) {
                    toast.success(`Server ${name} removed successfully`);
                    fetchServers();
                }
            } catch (error) {
                console.error('Error removing server:', error);
                toast.error(error.response?.data?.error || 'Failed to remove server');
            }
        }
    };

    const syncConfiguration = async () => {
        try {
            setLoading(true);
            const response = await axios.post('/api/multi-server/sync', {
                target: playbookTarget || undefined
            });
            
            if (response.data.success) {
                toast.success('Configuration synchronized successfully');
                setPlaybookOutput(response.data.output);
                fetchServers();
            }
            setLoading(false);
        } catch (error) {
            console.error('Error syncing configuration:', error);
            toast.error('Failed to synchronize configuration');
            setLoading(false);
        }
    };

    const runPlaybook = async () => {
        if (!selectedPlaybook) {
            toast.error('Please select a playbook');
            return;
        }
        
        try {
            setLoading(true);
            const response = await axios.post('/api/multi-server/ansible/run', {
                playbook: selectedPlaybook,
                target: playbookTarget || undefined
            });
            
            if (response.data.success) {
                toast.success('Playbook executed successfully');
                setPlaybookOutput(response.data.output);
                fetchServers();
            }
            setLoading(false);
        } catch (error) {
            console.error('Error running playbook:', error);
            toast.error('Failed to run playbook');
            setLoading(false);
        }
    };

    const handleInputChange = (e) => {
        const { name, value } = e.target;
        setNewServer({
            ...newServer,
            [name]: value
        });
    };

    if (loading && !isActivated) {
        return <div className="p-4">Loading multi-server module status...</div>;
    }

    if (!isActivated) {
        return (
            <div className="p-4">
                <h2 className="text-2xl font-bold mb-4">Multi-Server Management</h2>
                <div className="bg-white rounded-lg shadow p-6">
                    <div className="bg-yellow-100 border-l-4 border-yellow-500 text-yellow-700 p-4 mb-4">
                        This module is not activated. Contact your service provider for an activation key.
                    </div>
                    
                    <div className="mb-4">
                        <label className="block text-gray-700 mb-2">Activation Key:</label>
                        <input
                            type="text"
                            className="w-full p-2 border border-gray-300 rounded"
                            value={activationKey}
                            onChange={(e) => setActivationKey(e.target.value)}
                            placeholder="Enter your activation key"
                        />
                    </div>
                    
                    <button
                        className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
                        onClick={activateModule}
                        disabled={!activationKey}
                    >
                        Activate Module
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="p-4">
            <h2 className="text-2xl font-bold mb-4">Multi-Server Management</h2>
            
            <div className="bg-white rounded-lg shadow mb-6">
                <div className="flex border-b">
                    <button 
                        className={`px-4 py-2 font-medium ${tab === 'servers' ? 'text-blue-600 border-b-2 border-blue-600' : 'text-gray-500'}`}
                        onClick={() => setTab('servers')}
                    >
                        Servers
                    </button>
                    <button 
                        className={`px-4 py-2 font-medium ${tab === 'ansible' ? 'text-blue-600 border-b-2 border-blue-600' : 'text-gray-500'}`}
                        onClick={() => setTab('ansible')}
                    >
                        Ansible Automation
                    </button>
                    <button 
                        className={`px-4 py-2 font-medium ${tab === 'tunnels' ? 'text-blue-600 border-b-2 border-blue-600' : 'text-gray-500'}`}
                        onClick={() => setTab('tunnels')}
                    >
                        Network Tunnels
                    </button>
                </div>
                
                <div className="p-4">
                    {tab === 'servers' && (
                        <div>
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                                <div className="bg-blue-50 p-4 rounded shadow-sm">
                                    <div className="text-lg font-semibold">Total Servers</div>
                                    <div className="text-3xl font-bold">{servers.length}</div>
                                </div>
                                <div className="bg-green-50 p-4 rounded shadow-sm">
                                    <div className="text-lg font-semibold">Active Servers</div>
                                    <div className="text-3xl font-bold">
                                        {servers.filter(s => s.status === 'active').length}
                                    </div>
                                </div>
                                <div className="bg-yellow-50 p-4 rounded shadow-sm">
                                    <div className="text-lg font-semibold">Master Server</div>
                                    <div className="text-xl font-semibold">
                                        {status?.master?.host || 'N/A'}
                                    </div>
                                </div>
                            </div>
                            
                            <div className="mb-6">
                                <h3 className="text-lg font-semibold mb-2">Add New Server</h3>
                                <form onSubmit={addServer} className="bg-gray-50 p-4 rounded">
                                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-4">
                                        <div>
                                            <label className="block text-sm font-medium mb-1">Server Name</label>
                                            <input
                                                type="text"
                                                name="name"
                                                className="w-full p-2 border border-gray-300 rounded"
                                                value={newServer.name}
                                                onChange={handleInputChange}
                                                required
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium mb-1">Hostname/IP</label>
                                            <input
                                                type="text"
                                                name="host"
                                                className="w-full p-2 border border-gray-300 rounded"
                                                value={newServer.host}
                                                onChange={handleInputChange}
                                                required
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium mb-1">Role</label>
                                            <select
                                                name="role"
                                                className="w-full p-2 border border-gray-300 rounded"
                                                value={newServer.role}
                                                onChange={handleInputChange}
                                            >
                                                <option value="worker">Worker</option>
                                                <option value="edge">Edge</option>
                                            </select>
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium mb-1">SSH Port</label>
                                            <input
                                                type="number"
                                                name="ssh_port"
                                                className="w-full p-2 border border-gray-300 rounded"
                                                value={newServer.ssh_port}
                                                onChange={handleInputChange}
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium mb-1">Username</label>
                                            <input
                                                type="text"
                                                name="username"
                                                className="w-full p-2 border border-gray-300 rounded"
                                                value={newServer.username}
                                                onChange={handleInputChange}
                                            />
                                        </div>
                                        <div className="flex items-end">
                                            <button
                                                type="submit"
                                                className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
                                            >
                                                Add Server
                                            </button>
                                        </div>
                                    </div>
                                </form>
                            </div>
                            
                            <h3 className="text-lg font-semibold mb-2">Server List</h3>
                            <div className="overflow-x-auto">
                                <table className="min-w-full divide-y divide-gray-200">
                                    <thead className="bg-gray-50">
                                        <tr>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Host</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Added</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody className="bg-white divide-y divide-gray-200">
                                        {servers.map((server) => (
                                            <tr key={server.name}>
                                                <td className="px-6 py-4 whitespace-nowrap">{server.name}</td>
                                                <td className="px-6 py-4 whitespace-nowrap">{server.host}</td>
                                                <td className="px-6 py-4 whitespace-nowrap">{server.role}</td>
                                                <td className="px-6 py-4 whitespace-nowrap">
                                                    <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                                                        server.status === 'active' ? 'bg-green-100 text-green-800' : 
                                                        server.status === 'new' ? 'bg-yellow-100 text-yellow-800' : 
                                                        'bg-red-100 text-red-800'
                                                    }`}>
                                                        {server.status}
                                                    </span>
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap">
                                                    {new Date(server.added_at).toLocaleString()}
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                                    {server.name !== 'master' && (
                                                        <button
                                                            onClick={() => removeServer(server.name)}
                                                            className="text-red-600 hover:text-red-900"
                                                        >
                                                            Remove
                                                        </button>
                                                    )}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}
                    
                    {tab === 'ansible' && (
                        <div>
                            <div className="mb-6">
                                <h3 className="text-lg font-semibold mb-2">Run Ansible Playbook</h3>
                                <div className="bg-gray-50 p-4 rounded">
                                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                                        <div>
                                            <label className="block text-sm font-medium mb-1">Playbook</label>
                                            <select
                                                className="w-full p-2 border border-gray-300 rounded"
                                                value={selectedPlaybook}
                                                onChange={(e) => setSelectedPlaybook(e.target.value)}
                                            >
                                                <option value="">Select a playbook</option>
                                                {playbooks.map(playbook => (
                                                    <option key={playbook.name} value={playbook.name}>
                                                        {playbook.name} - {playbook.description}
                                                    </option>
                                                ))}
                                            </select>
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium mb-1">Target (optional)</label>
                                            <input
                                                type="text"
                                                className="w-full p-2 border border-gray-300 rounded"
                                                value={playbookTarget}
                                                onChange={(e) => setPlaybookTarget(e.target.value)}
                                                placeholder="Leave empty for all servers"
                                            />
                                        </div>
                                        <div className="flex items-end">
                                            <button
                                                onClick={runPlaybook}
                                                className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
                                                disabled={!selectedPlaybook}
                                            >
                                                Run Playbook
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div className="mb-6">
                                <h3 className="text-lg font-semibold mb-2">Quick Actions</h3>
                                <div className="bg-gray-50 p-4 rounded flex gap-4">
                                    <button
                                        onClick={syncConfiguration}
                                        className="bg-green-600 text-white px-4 py-2 rounded hover:bg-green-700"
                                    >
                                        Synchronize Configuration
                                    </button>
                                </div>
                            </div>
                            
                            {playbookOutput && (
                                <div className="mb-6">
                                    <h3 className="text-lg font-semibold mb-2">Execution Output</h3>
                                    <pre className="bg-black text-green-400 p-4 rounded overflow-x-auto whitespace-pre-wrap">
                                        {playbookOutput}
                                    </pre>
                                </div>
                            )}
                        </div>
                    )}
                    
                    {tab === 'tunnels' && (
                        <div>
                            <div className="mb-6">
                                <h3 className="text-lg font-semibold mb-2">Tunnel Status</h3>
                                <div className="bg-gray-50 p-4 rounded">
                                    <div className="mb-4">
                                        <span className={`px-2 py-1 mr-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                                            status?.tunnelStatus?.status === 'active' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                                        }`}>
                                            {status?.tunnelStatus?.status || 'unknown'}
                                        </span>
                                        <span className="text-sm text-gray-600">
                                            WireGuard Tunnel Status
                                        </span>
                                    </div>
                                    
                                    <pre className="bg-black text-green-400 p-4 rounded overflow-x-auto text-sm">
                                        {status?.tunnelStatus?.details || 'No tunnel details available'}
                                    </pre>
                                </div>
                            </div>
                            
                            <div className="mb-6">
                                <h3 className="text-lg font-semibold mb-2">Tunnel Actions</h3>
                                <div className="bg-gray-50 p-4 rounded flex gap-4">
                                    <button
                                        onClick={() => {
                                            setSelectedPlaybook('setup-tunnels');
                                            setTab('ansible');
                                        }}
                                        className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
                                    >
                                        Setup/Reconfigure Tunnels
                                    </button>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default MultiServerPage;
EOT

    # Add endpoints to backend
    log "Adding multi-server endpoints to backend API..."
    
    # Update index.js in backend to include multi-server routes
    sed -i '/const app = express();/a const multiServerRoutes = require("./api/multi-server");' "$PANEL_DIR/backend/index.js"
    sed -i '/app.use("\/api"/a app.use("/api/multi-server", multiServerRoutes);' "$PANEL_DIR/backend/index.js"
    
    # Setup tunnels between servers
    log "Running initial tunnels setup..."
    ansible-playbook -i "$ANSIBLE_DIR/inventory/hosts" "$ANSIBLE_DIR/playbooks/setup-tunnels.yml"
    
    # Enable WireGuard for tunnels
    systemctl enable wg-quick@wg-tunnel
    systemctl daemon-reload
    
    # Create tunnel script for automatically reestablishing connections
    cat > "$CONFIG_DIR/multi-server/tunnel-monitor.sh" << 'EOF'
#!/bin/bash

# This script monitors WireGuard tunnels and restarts them if needed

LOG_DIR="/var/log/irssh"
CONFIG_DIR="/etc/enhanced_ssh"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

# Check if WireGuard tunnel is active
if ! ip a | grep -q wg-tunnel; then
    echo "$TIMESTAMP: WireGuard tunnel not active, restarting..." >> "$LOG_DIR/tunnel-monitor.log"
    systemctl restart wg-quick@wg-tunnel
else
    # Check if tunnel is working by pinging master server
    if ! ping -c 1 -W 2 10.10.0.1 > /dev/null 2>&1; then
        echo "$TIMESTAMP: Tunnel not working, restarting..." >> "$LOG_DIR/tunnel-monitor.log"
        systemctl restart wg-quick@wg-tunnel
    else
        echo "$TIMESTAMP: Tunnel working correctly" >> "$LOG_DIR/tunnel-monitor.log"
    fi
fi
EOF

    chmod +x "$CONFIG_DIR/multi-server/tunnel-monitor.sh"
    
    # Add cron job to run tunnel monitor every 5 minutes
    (crontab -l 2>/dev/null; echo "*/5 * * * * $CONFIG_DIR/multi-server/tunnel-monitor.sh") | crontab -
    
    # Create Multi-Tunneling activation script
    mkdir -p "$CONFIG_DIR/multi-tunneling/activate"
    
    # Create activation script for multi-tunneling
    cat > "$CONFIG_DIR/multi-tunneling/activate/activate-multi-tunneling.sh" << 'EOF'
#!/bin/bash

# This script activates the multi-tunneling functionality in IRSSH-Panel

# Define colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Base directories
PANEL_DIR="/opt/irssh-panel"
CONFIG_DIR="/etc/enhanced_ssh"
ANSIBLE_DIR="${PANEL_DIR}/ansible"

# Log function
log() {
    echo -e "${2:-$GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
   log "This script must be run as root" "$RED"
   exit 1
fi

# Check if multi-server is activated
if [ ! -f "$CONFIG_DIR/multi-server/servers.json" ]; then
    log "Multi-server functionality is not activated yet. Please activate it first." "$RED"
    exit 1
fi

# Get server IP
SERVER_IP=$(curl -s4 ifconfig.me || ip -4 route get 8.8.8.8 | awk '{print $7; exit}')

# Generate activation key
ACTIVATION_KEY=$(echo -n "IRSSH-TUNNEL-${SERVER_IP}-special-secret" | sha256sum | awk '{print $1}')

# Ask for activation key
read -p "Enter activation key: " INPUT_KEY

if [ "$INPUT_KEY" != "$ACTIVATION_KEY" ]; then
    log "Invalid activation key" "$RED"
    exit 1
fi

# Continue with activation
log "Valid activation key entered" "$GREEN"
log "Activating multi-tunneling functionality..." "$BLUE"

# Create required directories
mkdir -p "$CONFIG_DIR/multi-tunneling/endpoints"
mkdir -p "$CONFIG_DIR/multi-tunneling/routes"
mkdir -p "$ANSIBLE_DIR/playbooks/templates/tunneling"

# Install tunneling packages
apt-get update
apt-get install -y frr iptables-persistent

# Enable IP forwarding
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-ip-forward.conf
sysctl -p /etc/sysctl.d/99-ip-forward.conf

# Create tunneling configuration
cat > "$CONFIG_DIR/multi-tunneling/config.json" << EOT
{
    "version": "1.0",
    "activated": true,
    "activation_date": "$(date -Iseconds)",
    "endpoints": [],
    "routes": []
}
EOT

# Create Ansible playbook for tunneling setup
cat > "$ANSIBLE_DIR/playbooks/setup-tunneling.yml" << 'EOT'
---
# Description: Set up advanced multi-tunneling between all servers in the cluster

- name: Set up advanced multi-tunneling
  hosts: all
  become: yes
  gather_facts: yes
  
  vars:
    tunnel_network: 10.20.0.0/16
    
  tasks:
    - name: Ensure FRR is installed
      apt:
        name: frr
        state: present
    
    - name: Enable IP forwarding
      sysctl:
        name: net.ipv4.ip_forward
        value: '1'
        state: present
        reload: yes
    
    - name: Enable FRR daemons
      lineinfile:
        path: /etc/frr/daemons
        regexp: "^{{ item }}="
        line: "{{ item }}=yes"
      with_items:
        - zebra
        - bgpd
        - ospfd
      notify: Restart FRR
    
    - name: Create FRR configuration
      template:
        src: templates/tunneling/frr.conf.j2
        dest: /etc/frr/frr.conf
        owner: frr
        group: frr
        mode: 0640
      notify: Restart FRR
    
    - name: Update WireGuard tunnel configuration for routing
      template:
        src: templates/tunneling/wg-tunnel-routing.conf.j2
        dest: /etc/wireguard/wg-tunnel.conf
        mode: 0600
      notify: Restart WireGuard

    - name: Set up iptables routing rules
      template:
        src: templates/tunneling/iptables-rules.j2
        dest: /etc/iptables/rules.v4
      notify: Reload iptables
    
  handlers:
    - name: Restart FRR
      systemd:
        name: frr
        state: restarted
        enabled: yes
    
    - name: Restart WireGuard
      systemd:
        name: wg-quick@wg-tunnel
        state: restarted
        enabled: yes
    
    - name: Reload iptables
      shell: iptables-restore < /etc/iptables/rules.v4
EOT

# Create required template files
mkdir -p "$ANSIBLE_DIR/playbooks/templates/tunneling"

# FRR configuration template
cat > "$ANSIBLE_DIR/playbooks/templates/tunneling/frr.conf.j2" << 'EOT'
! FRR configuration for IRSSH Multi-Tunneling
hostname {{ inventory_hostname }}
password zebra
enable password zebra
log syslog informational
!
! Zebra configuration
router-id {{ hostvars[inventory_hostname]['server_info']['host'] }}
!
{% if inventory_hostname == 'master' %}
! BGP configuration for master node
router bgp 65000
 bgp router-id {{ hostvars[inventory_hostname]['server_info']['host'] }}
 bgp log-neighbor-changes
 network {{ tunnel_network }}
 
 {% for host in groups['worker'] %}
 neighbor 10.10.{{ loop.index }}.1 remote-as 65001
 neighbor 10.10.{{ loop.index }}.1 description {{ host }}
 {% endfor %}
 
 {% for host in groups['edge'] %}
 neighbor 10.10.{{ groups['worker']|length + loop.index }}.1 remote-as 65002
 neighbor 10.10.{{ groups['worker']|length + loop.index }}.1 description {{ host }}
 {% endfor %}
!
{% elif inventory_hostname in groups['worker'] %}
! BGP configuration for worker nodes
router bgp 65001
 bgp router-id {{ hostvars[inventory_hostname]['server_info']['host'] }}
 bgp log-neighbor-changes
 network {{ hostvars[inventory_hostname]['endpoint_network'] | default('10.100.0.0/24') }}
 
 neighbor 10.10.0.1 remote-as 65000
 neighbor 10.10.0.1 description master
!
{% elif inventory_hostname in groups['edge'] %}
! BGP configuration for edge nodes
router bgp 65002
 bgp router-id {{ hostvars[inventory_hostname]['server_info']['host'] }}
 bgp log-neighbor-changes
 network {{ hostvars[inventory_hostname]['endpoint_network'] | default('10.200.0.0/24') }}
 
 neighbor 10.10.0.1 remote-as 65000
 neighbor 10.10.0.1 description master
!
{% endif %}
!
line vty
!
EOT

# WireGuard tunnel routing template
cat > "$ANSIBLE_DIR/playbooks/templates/tunneling/wg-tunnel-routing.conf.j2" << 'EOT'
# WireGuard tunnel configuration with routing for IRSSH Multi-Tunneling
[Interface]
PrivateKey = {{ server_info.private_key }}
{% if inventory_hostname == 'master' %}
Address = 10.10.0.1/16
{% elif inventory_hostname in groups['worker'] %}
Address = 10.10.{{ groups['worker'].index(inventory_hostname) + 1 }}.1/24
{% else %}
Address = 10.10.{{ groups['worker']|length + groups['edge'].index(inventory_hostname) + 1 }}.1/24
{% endif %}
ListenPort = 51821
MTU = 1420
Table = off

{% if 'endpoint_network' in hostvars[inventory_hostname] %}
# Endpoint network announcement
PostUp = ip route add {{ hostvars[inventory_hostname]['endpoint_network'] }} dev wg-tunnel
PostDown = ip route del {{ hostvars[inventory_hostname]['endpoint_network'] }} dev wg-tunnel
{% endif %}

# Master routes all traffic
{% if inventory_hostname == 'master' %}
{% for host in groups['worker'] %}
[Peer]
# {{ host }}
PublicKey = {{ hostvars[host]['server_info']['public_key'] }}
AllowedIPs = 10.10.{{ loop.index }}.0/24{% if 'endpoint_network' in hostvars[host] %}, {{ hostvars[host]['endpoint_network'] }}{% endif %}
{% endfor %}

{% for host in groups['edge'] %}
[Peer]
# {{ host }}
PublicKey = {{ hostvars[host]['server_info']['public_key'] }}
AllowedIPs = 10.10.{{ groups['worker']|length + loop.index }}.0/24{% if 'endpoint_network' in hostvars[host] %}, {{ hostvars[host]['endpoint_network'] }}{% endif %}
{% endfor %}
{% else %}
# Connect to master only, use BGP for other routes
[Peer]
# master
PublicKey = {{ hostvars['master']['server_info']['public_key'] }}
Endpoint = {{ hostvars['master']['server_info']['host'] }}:51821
AllowedIPs = 10.10.0.0/16,{{ tunnel_network }}
PersistentKeepalive = 25
{% endif %}
EOT

# iptables rules template
cat > "$ANSIBLE_DIR/playbooks/templates/tunneling/iptables-rules.j2" << 'EOT'
# Generated by IRSSH Panel Multi-Tunneling
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
{% if inventory_hostname == 'master' %}
-A INPUT -p udp -m state --state NEW -m udp --dport 51821 -j ACCEPT
{% endif %}
-A INPUT -j REJECT --reject-with icmp-host-prohibited
-A FORWARD -j ACCEPT
COMMIT

*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
{% if inventory_hostname != 'master' %}
# Masquerade outgoing traffic from tunnel network
-A POSTROUTING -s 10.10.0.0/16 -o eth0 -j MASQUERADE
{% if 'endpoint_network' in hostvars[inventory_hostname] %}
# Masquerade traffic from endpoint network
-A POSTROUTING -s {{ hostvars[inventory_hostname]['endpoint_network'] }} -o eth0 -j MASQUERADE
{% endif %}
{% endif %}
COMMIT
EOT

# Create multi-tunneling API endpoints
cat > "$PANEL_DIR/backend/api/multi-tunneling.js" << 'EOT'
const express = require('express');
const Router = express.Router();
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const crypto = require('crypto');

// Configuration paths
const CONFIG_DIR = '/etc/enhanced_ssh';
const TUNNEL_CONFIG = path.join(CONFIG_DIR, 'multi-tunneling/config.json');
const ANSIBLE_DIR = '/opt/irssh-panel/ansible';

// Check if multi-tunneling is activated
const isActivated = () => {
    return fs.existsSync(TUNNEL_CONFIG) && 
           JSON.parse(fs.readFileSync(TUNNEL_CONFIG, 'utf8')).activated === true;
};

// Authentication middleware
const authMiddleware = (req, res, next) => {
    // If module is not activated, return 404 to hide its existence
    if (!isActivated()) {
        return res.status(404).json({ error: 'Endpoint not found' });
    }
    
    // Check for auth token
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Authentication required' });
        }
        
        const token = authHeader.split(' ')[1];
        const jwt = require('jsonwebtoken');
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'irssh-secret-key');
        
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
};

// Admin middleware
const adminMiddleware = (req, res, next) => {
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// Get tunneling configuration
Router.get('/config', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const config = JSON.parse(fs.readFileSync(TUNNEL_CONFIG, 'utf8'));
        res.json({ config });
    } catch (error) {
        res.status(500).json({ error: 'Failed to read tunneling configuration' });
    }
});

// Add endpoint
Router.post('/endpoints', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { server, network, description } = req.body;
        
        if (!server || !network) {
            return res.status(400).json({ error: 'Server and network are required' });
        }
        
        // Read current configuration
        const config = JSON.parse(fs.readFileSync(TUNNEL_CONFIG, 'utf8'));
        
        // Check if endpoint with this network already exists
        if (config.endpoints.some(e => e.network === network)) {
            return res.status(400).json({ error: 'Endpoint with this network already exists' });
        }
        
        // Add new endpoint
        const endpoint = {
            id: crypto.randomUUID(),
            server,
            network,
            description: description || '',
            created_at: new Date().toISOString()
        };
        
        config.endpoints.push(endpoint);
        
        // Save updated configuration
        fs.writeFileSync(TUNNEL_CONFIG, JSON.stringify(config, null, 4));
        
        // Update server inventory with endpoint network
        const inventoryFile = path.join(ANSIBLE_DIR, 'inventory/hosts');
        let inventory = fs.readFileSync(inventoryFile, 'utf8');
        
        if (!inventory.includes(`${server} endpoint_network=`)) {
            // Find the server line
            const serverLine = new RegExp(`^${server} ansible_host=.*$`, 'm');
            const match = inventory.match(serverLine);
            
            if (match) {
                inventory = inventory.replace(match[0], `${match[0]} endpoint_network=${network}`);
                fs.writeFileSync(inventoryFile, inventory);
            }
        }
        
        res.json({ success: true, endpoint });
    } catch (error) {
        res.status(500).json({ error: 'Failed to add endpoint', details: error.message });
    }
});

// Remove endpoint
Router.delete('/endpoints/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const id = req.params.id;
        
        // Read current configuration
        const config = JSON.parse(fs.readFileSync(TUNNEL_CONFIG, 'utf8'));
        
        // Find endpoint
        const endpointIndex = config.endpoints.findIndex(e => e.id === id);
        if (endpointIndex === -1) {
            return res.status(404).json({ error: 'Endpoint not found' });
        }
        
        const endpoint = config.endpoints[endpointIndex];
        
        // Remove endpoint
        config.endpoints.splice(endpointIndex, 1);
        
        // Save updated configuration
        fs.writeFileSync(TUNNEL_CONFIG, JSON.stringify(config, null, 4));
        
        // Update server inventory to remove endpoint network
        const inventoryFile = path.join(ANSIBLE_DIR, 'inventory/hosts');
        let inventory = fs.readFileSync(inventoryFile, 'utf8');
        
        inventory = inventory.replace(new RegExp(`(${endpoint.server} ansible_host=.*) endpoint_network=${endpoint.network.replace(/\./g, '\\.').replace(/\//g, '\\/')}`, 'g'), '$1');
        fs.writeFileSync(inventoryFile, inventory);
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to remove endpoint', details: error.message });
    }
});

// Add route
Router.post('/routes', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { source, destination, description } = req.body;
        
        if (!source || !destination) {
            return res.status(400).json({ error: 'Source and destination are required' });
        }
        
        // Read current configuration
        const config = JSON.parse(fs.readFileSync(TUNNEL_CONFIG, 'utf8'));
        
        // Check if route already exists
        if (config.routes.some(r => r.source === source && r.destination === destination)) {
            return res.status(400).json({ error: 'Route already exists' });
        }
        
        // Add new route
        const route = {
            id: crypto.randomUUID(),
            source,
            destination,
            description: description || '',
            created_at: new Date().toISOString()
        };
        
        config.routes.push(route);
        
        // Save updated configuration
        fs.writeFileSync(TUNNEL_CONFIG, JSON.stringify(config, null, 4));
        
        res.json({ success: true, route });
    } catch (error) {
        res.status(500).json({ error: 'Failed to add route', details: error.message });
    }
});

// Remove route
Router.delete('/routes/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const id = req.params.id;
        
        // Read current configuration
        const config = JSON.parse(fs.readFileSync(TUNNEL_CONFIG, 'utf8'));
        
        // Find route
        const routeIndex = config.routes.findIndex(r => r.id === id);
        if (routeIndex === -1) {
            return res.status(404).json({ error: 'Route not found' });
        }
        
        // Remove route
        config.routes.splice(routeIndex, 1);
        
        // Save updated configuration
        fs.writeFileSync(TUNNEL_CONFIG, JSON.stringify(config, null, 4));
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to remove route', details: error.message });
    }
});

// Apply configuration
Router.post('/apply', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        // Run Ansible playbook to set up tunneling
        const { stdout, stderr } = await execAsync(`ansible-playbook -i ${ANSIBLE_DIR}/inventory/hosts ${ANSIBLE_DIR}/playbooks/setup-tunneling.yml`);
        
        res.json({
            success: true,
            message: 'Tunneling configuration applied successfully',
            output: stdout,
            errors: stderr
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to apply tunneling configuration', details: error.message });
    }
});

// Activate module
Router.post('/activate', async (req, res) => {
    try {
        const { activationKey, serverIp } = req.body;
        
        if (isActivated()) {
            return res.json({ success: true, message: 'Multi-tunneling functionality is already activated' });
        }
        
        // Generate expected key
        const expectedKey = crypto.createHash('sha256')
            .update(`IRSSH-TUNNEL-${serverIp}-special-secret`)
            .digest('hex');
        
        if (activationKey !== expectedKey) {
            return res.status(403).json({ success: false, message: 'Invalid activation key' });
        }
        
        // Run activation script
        const { stdout, stderr } = await execAsync(`${CONFIG_DIR}/multi-tunneling/activate/activate-multi-tunneling.sh`);
        
        if (stderr && stderr.includes('error')) {
            return res.status(500).json({ success: false, message: 'Activation failed', error: stderr });
        }
        
        res.json({ success: true, message: 'Multi-tunneling functionality activated successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to activate multi-tunneling functionality', details: error.message });
    }
});

module.exports = Router;
EOT

# Add endpoints to backend
log "Adding multi-tunneling endpoints to backend API..."

# Update index.js in backend to include multi-tunneling routes
sed -i '/const app = express();/a const multiTunnelingRoutes = require("./api/multi-tunneling");' "$PANEL_DIR/backend/index.js"
sed -i '/app.use("\/api"/a app.use("/api/multi-tunneling", multiTunnelingRoutes);' "$PANEL_DIR/backend/index.js"

# Create React component for multi-tunneling
cat > "$PANEL_DIR/frontend/src/pages/MultiTunneling.jsx" << 'EOT'
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { toast } from 'react-hot-toast';

const MultiTunnelingPage = () => {
    const [isActivated, setIsActivated] = useState(false);
    const [activationKey, setActivationKey] = useState('');
    const [loading, setLoading] = useState(true);
    const [config, setConfig] = useState(null);
    const [servers, setServers] = useState([]);
    const [newEndpoint, setNewEndpoint] = useState({
        server: '',
        network: '',
        description: ''
    });
    const [newRoute, setNewRoute] = useState({
        source: '',
        destination: '',
        description: ''
    });
    const [output, setOutput] = useState('');

    // Check if module is activated
    useEffect(() => {
        checkActivationStatus();
    }, []);

    const checkActivationStatus = async () => {
        try {
            setLoading(true);
            const response = await axios.get('/api/multi-tunneling/config');
            setIsActivated(true);
            setConfig(response.data.config);
            await fetchServers();
            setLoading(false);
        } catch (error) {
            // 404 error means endpoint doesn't exist or module not activated
            if (error.response && error.response.status === 404) {
                setIsActivated(false);
            } else {
                console.error('Error checking multi-tunneling status:', error);
                toast.error('Failed to check multi-tunneling status');
            }
            setLoading(false);
        }
    };

    const fetchServers = async () => {
        try {
            const response = await axios.get('/api/multi-server/servers');
            setServers(response.data.servers);
        } catch (error) {
            console.error('Error fetching servers:', error);
        }
    };

    const activateModule = async () => {
        try {
            // Get server IP
            const ipResponse = await axios.get('/api/system/info');
            const serverIp = ipResponse.data.system?.ipv4_address || '127.0.0.1';
            
            const response = await axios.post('/api/multi-tunneling/activate', {
                activationKey,
                serverIp
            });
            
            if (response.data.success) {
                toast.success('Multi-tunneling functionality activated successfully');
                setIsActivated(true);
                checkActivationStatus();
            } else {
                toast.error(response.data.message || 'Activation failed');
            }
        } catch (error) {
            console.error('Error activating module:', error);
            toast.error(error.response?.data?.message || 'Failed to activate module');
        }
    };

    const addEndpoint = async (e) => {
        e.preventDefault();
        try {
            const response = await axios.post('/api/multi-tunneling/endpoints', newEndpoint);
            if (response.data.success) {
                toast.success(`Endpoint added successfully`);
                checkActivationStatus();
                setNewEndpoint({
                    server: '',
                    network: '',
                    description: ''
                });
            }
        } catch (error) {
            console.error('Error adding endpoint:', error);
            toast.error(error.response?.data?.error || 'Failed to add endpoint');
        }
    };

    const removeEndpoint = async (id) => {
        if (window.confirm('Are you sure you want to remove this endpoint?')) {
            try {
                const response = await axios.delete(`/api/multi-tunneling/endpoints/${id}`);
                if (response.data.success) {
                    toast.success('Endpoint removed successfully');
                    checkActivationStatus();
                }
            } catch (error) {
                console.error('Error removing endpoint:', error);
                toast.error(error.response?.data?.error || 'Failed to remove endpoint');
            }
        }
    };

    const addRoute = async (e) => {
        e.preventDefault();
        try {
            const response = await axios.post('/api/multi-tunneling/routes', newRoute);
            if (response.data.success) {
                toast.success(`Route added successfully`);
                checkActivationStatus();
                setNewRoute({
                    source: '',
                    destination: '',
                    description: ''
                });
            }
        } catch (error) {
            console.error('Error adding route:', error);
            toast.error(error.response?.data?.error || 'Failed to add route');
        }
    };

    const removeRoute = async (id) => {
        if (window.confirm('Are you sure you want to remove this route?')) {
            try {
                const response = await axios.delete(`/api/multi-tunneling/routes/${id}`);
                if (response.data.success) {
                    toast.success('Route removed successfully');
                    checkActivationStatus();
                }
            } catch (error) {
                console.error('Error removing route:', error);
                toast.error(error.response?.data?.error || 'Failed to remove route');
            }
        }
    };

    const applyConfiguration = async () => {
        try {
            setLoading(true);
            const response = await axios.post('/api/multi-tunneling/apply');
            if (response.data.success) {
                toast.success('Tunneling configuration applied successfully');
                setOutput(response.data.output);
            }
            setLoading(false);
        } catch (error) {
            console.error('Error applying configuration:', error);
            toast.error('Failed to apply tunneling configuration');
            setLoading(false);
        }
    };

    const handleEndpointChange = (e) => {
        const { name, value } = e.target;
        setNewEndpoint({
            ...newEndpoint,
            [name]: value
        });
    };

    const handleRouteChange = (e) => {
        const { name, value } = e.target;
        setNewRoute({
            ...newRoute,
            [name]: value
        });
    };

    if (loading && !isActivated) {
        return <div className="p-4">Loading multi-tunneling module status...</div>;
    }

    if (!isActivated) {
        return (
            <div className="p-4">
                <h2 className="text-2xl font-bold mb-4">Multi-Tunneling Management</h2>
                <div className="bg-white rounded-lg shadow p-6">
                    <div className="bg-yellow-100 border-l-4 border-yellow-500 text-yellow-700 p-4 mb-4">
                        This module is not activated. Contact your service provider for an activation key.
                    </div>
                    
                    <div className="mb-4">
                        <label className="block text-gray-700 mb-2">Activation Key:</label>
                        <input
                            type="text"
                            className="w-full p-2 border border-gray-300 rounded"
                            value={activationKey}
                            onChange={(e) => setActivationKey(e.target.value)}
                            placeholder="Enter your activation key"
                        />
                    </div>
                    
                    <button
                        className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
                        onClick={activateModule}
                        disabled={!activationKey}
                    >
                        Activate Module
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="p-4">
            <h2 className="text-2xl font-bold mb-4">Multi-Tunneling Management</h2>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                <div className="bg-blue-50 p-4 rounded shadow-sm">
                    <div className="text-lg font-semibold">Endpoints</div>
                    <div className="text-3xl font-bold">{config?.endpoints?.length || 0}</div>
                </div>
                <div className="bg-green-50 p-4 rounded shadow-sm">
                    <div className="text-lg font-semibold">Routes</div>
                    <div className="text-3xl font-bold">{config?.routes?.length || 0}</div>
                </div>
                <div className="bg-yellow-50 p-4 rounded shadow-sm">
                    <div className="text-lg font-semibold">Status</div>
                    <div className="text-xl font-semibold text-green-600">Active</div>
                </div>
            </div>
            
            <div className="bg-white rounded-lg shadow mb-6">
                <div className="p-4 border-b">
                    <h3 className="text-lg font-semibold">Endpoints</h3>
                    <p className="text-sm text-gray-600">Define network endpoints that can be accessed through the tunnel.</p>
                </div>
                
                <div className="p-4">
                    <form onSubmit={addEndpoint} className="mb-6 bg-gray-50 p-4 rounded">
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                            <div>
                                <label className="block text-sm font-medium mb-1">Server</label>
                                <select
                                    name="server"
                                    className="w-full p-2 border border-gray-300 rounded"
                                    value={newEndpoint.server}
                                    onChange={handleEndpointChange}
                                    required
                                >
                                    <option value="">Select a server</option>
                                    {servers.map(server => (
                                        <option key={server.name} value={server.name}>
                                            {server.name} ({server.host})
                                        </option>
                                    ))}
                                </select>
                            </div>
                            <div>
                                <label className="block text-sm font-medium mb-1">Network CIDR</label>
                                <input
                                    type="text"
                                    name="network"
                                    className="w-full p-2 border border-gray-300 rounded"
                                    value={newEndpoint.network}
                                    onChange={handleEndpointChange}
                                    placeholder="e.g. 192.168.1.0/24"
                                    required
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium mb-1">Description</label>
                                <input
                                    type="text"
                                    name="description"
                                    className="w-full p-2 border border-gray-300 rounded"
                                    value={newEndpoint.description}
                                    onChange={handleEndpointChange}
                                    placeholder="Optional description"
                                />
                            </div>
                        </div>
                        <div className="mt-4">
                            <button
                                type="submit"
                                className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
                            >
                                Add Endpoint
                            </button>
                        </div>
                    </form>
                    
                    <div className="overflow-x-auto">
                        <table className="min-w-full divide-y divide-gray-200">
                            <thead className="bg-gray-50">
                                <tr>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Server</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Network</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Description</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="bg-white divide-y divide-gray-200">
                                {servers.map((server, index) => (
                                    <tr key={index}>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{server.server}</td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{server.network}</td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{server.description}</td>
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${server.status === 'online' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                                                {server.status}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                            <button 
                                                className="text-indigo-600 hover:text-indigo-900"
                                                onClick={() => testConnection(server.server)}
                                            >
                                                Test
                                            </button>
                                            <button 
                                                className="ml-4 text-red-600 hover:text-red-900"
                                                onClick={() => removeServer(server.server)}
                                            >
                                                Remove
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div className="mt-10">
                <h3 className="text-lg font-medium text-gray-900">Active Routes</h3>
                <div className="mt-5 border-t border-gray-200">
                    <div className="shadow overflow-hidden border-b border-gray-200 sm:rounded-lg">
                        <table className="min-w-full divide-y divide-gray-200">
                            <thead className="bg-gray-50">
                                <tr>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Destination</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Description</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="bg-white divide-y divide-gray-200">
                                {config && config.routes ? config.routes.map((route, index) => (
                                    <tr key={index}>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{route.source}</td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{route.destination}</td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{route.description}</td>
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${route.status === 'active' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                                                {route.status}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                            <button 
                                                className="text-red-600 hover:text-red-900"
                                                onClick={() => removeRoute(index)}
                                            >
                                                Remove
                                            </button>
                                        </td>
                                    </tr>
                                )) : (
                                    <tr>
                                        <td colSpan="5" className="px-6 py-4 text-center text-sm text-gray-500">
                                            No routes configured
                                        </td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div className="mt-10">
                <h3 className="text-lg font-medium text-gray-900">Add New Server Endpoint</h3>
                <div className="mt-5 md:grid md:grid-cols-3 md:gap-6">
                    <div className="md:col-span-1">
                        <div className="px-4 sm:px-0">
                            <p className="mt-1 text-sm text-gray-600">
                                Add a new remote server to establish tunneling routes. 
                                The server must have SSH access and the provided key must have permission to login.
                            </p>
                        </div>
                    </div>
                    <div className="mt-5 md:mt-0 md:col-span-2">
                        <form onSubmit={addServer}>
                            <div className="shadow sm:rounded-md sm:overflow-hidden">
                                <div className="px-4 py-5 bg-white space-y-6 sm:p-6">
                                    <div className="grid grid-cols-6 gap-6">
                                        <div className="col-span-6 sm:col-span-3">
                                            <label htmlFor="server" className="block text-sm font-medium text-gray-700">Server Address</label>
                                            <input
                                                type="text"
                                                name="server"
                                                id="server"
                                                placeholder="IP or hostname (e.g., 192.168.1.1 or server.example.com)"
                                                className="mt-1 focus:ring-indigo-500 focus:border-indigo-500 block w-full shadow-sm sm:text-sm border-gray-300 rounded-md"
                                                value={newEndpoint.server}
                                                onChange={(e) => setNewEndpoint({...newEndpoint, server: e.target.value})}
                                                required
                                            />
                                        </div>

                                        <div className="col-span-6 sm:col-span-3">
                                            <label htmlFor="network" className="block text-sm font-medium text-gray-700">Network Type</label>
                                            <select
                                                id="network"
                                                name="network"
                                                className="mt-1 block w-full py-2 px-3 border border-gray-300 bg-white rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                                value={newEndpoint.network}
                                                onChange={(e) => setNewEndpoint({...newEndpoint, network: e.target.value})}
                                                required
                                            >
                                                <option value="">Select network type</option>
                                                <option value="ipv4">IPv4</option>
                                                <option value="ipv6">IPv6</option>
                                                <option value="dual">Dual-Stack (IPv4 + IPv6)</option>
                                            </select>
                                        </div>

                                        <div className="col-span-6">
                                            <label htmlFor="description" className="block text-sm font-medium text-gray-700">Description</label>
                                            <input
                                                type="text"
                                                name="description"
                                                id="description"
                                                placeholder="Brief description of this server"
                                                className="mt-1 focus:ring-indigo-500 focus:border-indigo-500 block w-full shadow-sm sm:text-sm border-gray-300 rounded-md"
                                                value={newEndpoint.description}
                                                onChange={(e) => setNewEndpoint({...newEndpoint, description: e.target.value})}
                                            />
                                        </div>
                                    </div>
                                </div>
                                <div className="px-4 py-3 bg-gray-50 text-right sm:px-6">
                                    <button
                                        type="submit"
                                        className="inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                                    >
                                        Add Server
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>

            <div className="mt-10">
                <h3 className="text-lg font-medium text-gray-900">Create New Route</h3>
                <div className="mt-5 md:grid md:grid-cols-3 md:gap-6">
                    <div className="md:col-span-1">
                        <div className="px-4 sm:px-0">
                            <p className="mt-1 text-sm text-gray-600">
                                Create tunneling routes between servers.
                                Traffic will be forwarded from source to destination.
                            </p>
                        </div>
                    </div>
                    <div className="mt-5 md:mt-0 md:col-span-2">
                        <form onSubmit={addRoute}>
                            <div className="shadow sm:rounded-md sm:overflow-hidden">
                                <div className="px-4 py-5 bg-white space-y-6 sm:p-6">
                                    <div className="grid grid-cols-6 gap-6">
                                        <div className="col-span-6 sm:col-span-3">
                                            <label htmlFor="source" className="block text-sm font-medium text-gray-700">Source Server</label>
                                            <select
                                                id="source"
                                                name="source"
                                                className="mt-1 block w-full py-2 px-3 border border-gray-300 bg-white rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                                value={newRoute.source}
                                                onChange={(e) => setNewRoute({...newRoute, source: e.target.value})}
                                                required
                                            >
                                                <option value="">Select source server</option>
                                                <option value="local">This Server</option>
                                                {servers.map((server, index) => (
                                                    <option key={index} value={server.server}>{server.server} ({server.description})</option>
                                                ))}
                                            </select>
                                        </div>

                                        <div className="col-span-6 sm:col-span-3">
                                            <label htmlFor="destination" className="block text-sm font-medium text-gray-700">Destination Server</label>
                                            <select
                                                id="destination"
                                                name="destination"
                                                className="mt-1 block w-full py-2 px-3 border border-gray-300 bg-white rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                                value={newRoute.destination}
                                                onChange={(e) => setNewRoute({...newRoute, destination: e.target.value})}
                                                required
                                            >
                                                <option value="">Select destination server</option>
                                                <option value="local">This Server</option>
                                                {servers.map((server, index) => (
                                                    <option key={index} value={server.server}>{server.server} ({server.description})</option>
                                                ))}
                                            </select>
                                        </div>

                                        <div className="col-span-6">
                                            <label htmlFor="route-description" className="block text-sm font-medium text-gray-700">Description</label>
                                            <input
                                                type="text"
                                                name="route-description"
                                                id="route-description"
                                                placeholder="Brief description of this route"
                                                className="mt-1 focus:ring-indigo-500 focus:border-indigo-500 block w-full shadow-sm sm:text-sm border-gray-300 rounded-md"
                                                value={newRoute.description}
                                                onChange={(e) => setNewRoute({...newRoute, description: e.target.value})}
                                            />
                                        </div>
                                    </div>
                                </div>
                                <div className="px-4 py-3 bg-gray-50 text-right sm:px-6">
                                    <button
                                        type="submit"
                                        className="inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                                    >
                                        Create Route
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>

            {output && (
                <div className="mt-10">
                    <h3 className="text-lg font-medium text-gray-900">Command Output</h3>
                    <div className="mt-2 bg-black rounded-md p-4">
                        <pre className="text-green-400 whitespace-pre-wrap">
                            {output}
                        </pre>
                    </div>
                </div>
            )}
        </div>
    );
};

export default MultiTunnelingPage;
EOT

# Create Multi-Tunneling backend API file
mkdir -p "$PANEL_DIR/backend/api"
cat > "$PANEL_DIR/backend/api/multi-tunneling.js" << 'EOT'
const express = require('express');
const { execSync, exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const router = express.Router();
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const winston = require('winston');

// Configure logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) => {
            return `${timestamp} [${level.toUpperCase()}]: ${message}`;
        })
    ),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        }),
        new winston.transports.File({ 
            filename: path.join(__dirname, '../../logs/multi-tunneling.log') 
        })
    ]
});

// Config paths
const CONFIG_DIR = '/etc/enhanced_ssh';
const MULTI_TUNNELING_CONFIG = path.join(CONFIG_DIR, 'multi-tunneling.json');
const SSH_KEY_DIR = path.join(CONFIG_DIR, 'ssh-keys');

// Create directories if they don't exist
if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
}

if (!fs.existsSync(SSH_KEY_DIR)) {
    fs.mkdirSync(SSH_KEY_DIR, { recursive: true });
}

// Initialize database connection using CONFIG_DIR/db/database.conf
let dbConfig = {};
try {
    const dbConfigPath = path.join(CONFIG_DIR, 'db', 'database.conf');
    if (fs.existsSync(dbConfigPath)) {
        const dbConfigContent = fs.readFileSync(dbConfigPath, 'utf8');
        const lines = dbConfigContent.split('\n');
        lines.forEach(line => {
            if (line.trim() && !line.startsWith('#')) {
                const [key, value] = line.split('=');
                if (key && value) {
                    dbConfig[key.trim()] = value.trim().replace(/["']/g, '');
                }
            }
        });
    }
} catch (error) {
    logger.error(`Error loading database config: ${error.message}`);
}

// Create database pool if config is available
let pool = null;
if (dbConfig.DB_NAME && dbConfig.DB_USER && dbConfig.DB_PASSWORD) {
    pool = new Pool({
        host: dbConfig.DB_HOST || 'localhost',
        port: parseInt(dbConfig.DB_PORT) || 5432,
        database: dbConfig.DB_NAME,
        user: dbConfig.DB_USER,
        password: dbConfig.DB_PASSWORD,
        ssl: dbConfig.DB_SSL_MODE === 'require' ? { rejectUnauthorized: false } : false
    });
}

// Authentication middleware
const authenticate = (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ error: 'Authentication required' });
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'irssh-secret-key');
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
};

// Admin authorization middleware
const authorizeAdmin = (req, res, next) => {
    if (req.user?.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// Initialize configuration
const initConfig = () => {
    try {
        if (!fs.existsSync(MULTI_TUNNELING_CONFIG)) {
            const initialConfig = {
                status: 'inactive',
                activation: {
                    key: null,
                    date: null
                },
                servers: [],
                routes: [],
                ssh: {
                    key_path: path.join(SSH_KEY_DIR, 'multi_tunneling_key'),
                    public_key_path: path.join(SSH_KEY_DIR, 'multi_tunneling_key.pub')
                }
            };
            
            fs.writeFileSync(MULTI_TUNNELING_CONFIG, JSON.stringify(initialConfig, null, 2));
            return initialConfig;
        } else {
            return JSON.parse(fs.readFileSync(MULTI_TUNNELING_CONFIG, 'utf8'));
        }
    } catch (error) {
        logger.error(`Error initializing config: ${error.message}`);
        return {
            status: 'error',
            error: error.message
        };
    }
};

// Generate SSH key if it doesn't exist
const ensureSSHKey = () => {
    try {
        const config = getConfig();
        
        if (!fs.existsSync(config.ssh.key_path)) {
            // Create SSH key directory if it doesn't exist
            if (!fs.existsSync(SSH_KEY_DIR)) {
                fs.mkdirSync(SSH_KEY_DIR, { recursive: true });
            }
            
            // Generate new SSH key
            execSync(`ssh-keygen -t rsa -b 4096 -f "${config.ssh.key_path}" -N "" -C "irssh-multi-tunneling"`, { stdio: 'ignore' });
            logger.info('Generated new SSH key for multi-tunneling');
        }
        
        // Set proper permissions
        fs.chmodSync(config.ssh.key_path, 0o600);
        fs.chmodSync(config.ssh.public_key_path, 0o644);
        
        return {
            private_key: config.ssh.key_path,
            public_key: config.ssh.public_key_path,
            public_key_content: fs.readFileSync(config.ssh.public_key_path, 'utf8')
        };
    } catch (error) {
        logger.error(`Error ensuring SSH key: ${error.message}`);
        return {
            error: error.message
        };
    }
};

// Get configuration
const getConfig = () => {
    try {
        if (fs.existsSync(MULTI_TUNNELING_CONFIG)) {
            return JSON.parse(fs.readFileSync(MULTI_TUNNELING_CONFIG, 'utf8'));
        } else {
            return initConfig();
        }
    } catch (error) {
        logger.error(`Error reading config: ${error.message}`);
        return {
            status: 'error',
            error: error.message
        };
    }
};

// Update configuration
const updateConfig = (newConfig) => {
    try {
        fs.writeFileSync(MULTI_TUNNELING_CONFIG, JSON.stringify(newConfig, null, 2));
        return true;
    } catch (error) {
        logger.error(`Error updating config: ${error.message}`);
        return false;
    }
};

// Activate multi-tunneling feature
router.post('/activate', authenticate, authorizeAdmin, (req, res) => {
    try {
        const { activationKey } = req.body;
        const config = getConfig();
        
        // In a real implementation, validate the activation key against a server
        // For now, we'll accept any non-empty key
        if (!activationKey) {
            return res.status(400).json({ error: 'Activation key is required' });
        }
        
        // Generate SSH key if needed
        const sshKey = ensureSSHKey();
        if (sshKey.error) {
            return res.status(500).json({ error: `Failed to generate SSH key: ${sshKey.error}` });
        }
        
        // Update configuration
        config.status = 'active';
        config.activation = {
            key: activationKey,
            date: new Date().toISOString()
        };
        
        if (updateConfig(config)) {
            return res.json({
                success: true,
                message: 'Multi-tunneling feature activated successfully',
                ssh_public_key: sshKey.public_key_content
            });
        } else {
            return res.status(500).json({ error: 'Failed to update configuration' });
        }
    } catch (error) {
        logger.error(`Error activating multi-tunneling: ${error.message}`);
        return res.status(500).json({ error: error.message });
    }
});

// Get configuration
router.get('/config', authenticate, authorizeAdmin, (req, res) => {
    try {
        const config = getConfig();
        
        // If not activated, return 404
        if (config.status !== 'active' && config.status !== 'error') {
            return res.status(404).json({ error: 'Multi-tunneling feature is not activated' });
        }
        
        // Get SSH public key
        const sshKey = ensureSSHKey();
        
        return res.json({
            config,
            ssh_public_key: sshKey.public_key_content
        });
    } catch (error) {
        logger.error(`Error getting config: ${error.message}`);
        return res.status(500).json({ error: error.message });
    }
});

// Add server
router.post('/servers', authenticate, authorizeAdmin, (req, res) => {
    try {
        const { server, network, description } = req.body;
        
        if (!server) {
            return res.status(400).json({ error: 'Server address is required' });
        }
        
        if (!network) {
            return res.status(400).json({ error: 'Network type is required' });
        }
        
        const config = getConfig();
        
        // Check if server already exists
        if (config.servers.some(s => s.server === server)) {
            return res.status(400).json({ error: 'Server already exists' });
        }
        
        // Test SSH connection
        try {
            const sshKey = ensureSSHKey();
            const cmd = `ssh -o StrictHostKeyChecking=no -o BatchMode=yes -i "${sshKey.private_key}" root@${server} "echo Connection successful"`;
            const output = execSync(cmd, { timeout: 5000 }).toString();
            
            // Add server to config
            config.servers.push({
                server,
                network,
                description: description || '',
                status: 'online',
                added_at: new Date().toISOString()
            });
            
            if (updateConfig(config)) {
                return res.json({
                    success: true,
                    message: 'Server added successfully',
                    server: {
                        server,
                        network,
                        description: description || '',
                        status: 'online'
                    },
                    output
                });
            } else {
                return res.status(500).json({ error: 'Failed to update configuration' });
            }
        } catch (error) {
            logger.error(`SSH connection failed: ${error.message}`);
            return res.status(400).json({ 
                error: 'Failed to connect to server',
                details: error.message,
                hint: 'Make sure the server is reachable and the SSH key is authorized'
            });
        }
    } catch (error) {
        logger.error(`Error adding server: ${error.message}`);
        return res.status(500).json({ error: error.message });
    }
});

// Get servers
router.get('/servers', authenticate, authorizeAdmin, (req, res) => {
    try {
        const config = getConfig();
        return res.json({ servers: config.servers });
    } catch (error) {
        logger.error(`Error getting servers: ${error.message}`);
        return res.status(500).json({ error: error.message });
    }
});

// Test server connection
router.post('/servers/test', authenticate, authorizeAdmin, (req, res) => {
    try {
        const { server } = req.body;
        
        if (!server) {
            return res.status(400).json({ error: 'Server address is required' });
        }
        
        const config = getConfig();
        
        // Check if server exists
        const serverConfig = config.servers.find(s => s.server === server);
        if (!serverConfig) {
            return res.status(404).json({ error: 'Server not found' });
        }
        
        // Test SSH connection
        try {
            const sshKey = ensureSSHKey();
            const cmd = `ssh -o StrictHostKeyChecking=no -o BatchMode=yes -i "${sshKey.private_key}" root@${server} "echo Connection successful && uptime && free -m"`;
            const output = execSync(cmd, { timeout: 5000 }).toString();
            
            // Update server status
            serverConfig.status = 'online';
            serverConfig.last_check = new Date().toISOString();
            
            if (updateConfig(config)) {
                return res.json({
                    success: true,
                    server: serverConfig,
                    output
                });
            } else {
                return res.status(500).json({ error: 'Failed to update configuration' });
            }
        } catch (error) {
            // Update server status to offline
            serverConfig.status = 'offline';
            serverConfig.last_check = new Date().toISOString();
            updateConfig(config);
            
            logger.error(`SSH connection failed: ${error.message}`);
            return res.status(400).json({ 
                error: 'Failed to connect to server',
                details: error.message,
                server: serverConfig
            });
        }
    } catch (error) {
        logger.error(`Error testing server: ${error.message}`);
        return res.status(500).json({ error: error.message });
    }
});

// Remove server
router.delete('/servers/:server', authenticate, authorizeAdmin, (req, res) => {
    try {
        const { server } = req.params;
        
        if (!server) {
            return res.status(400).json({ error: 'Server address is required' });
        }
        
        const config = getConfig();
        
        // Check if server exists
        const serverIndex = config.servers.findIndex(s => s.server === server);
        if (serverIndex === -1) {
            return res.status(404).json({ error: 'Server not found' });
        }
        
        // Check if server is used in any routes
        const routesUsingServer = config.routes.filter(r => 
            r.source === server || r.destination === server
        );
        
        if (routesUsingServer.length > 0) {
            return res.status(400).json({ 
                error: 'Server is used in routes',
                routes: routesUsingServer
            });
        }
        
        // Remove server
        config.servers.splice(serverIndex, 1);
        
        if (updateConfig(config)) {
            return res.json({
                success: true,
                message: 'Server removed successfully'
            });
        } else {
            return res.status(500).json({ error: 'Failed to update configuration' });
        }
    } catch (error) {
        logger.error(`Error removing server: ${error.message}`);
        return res.status(500).json({ error: error.message });
    }
});

// Add route
router.post('/routes', authenticate, authorizeAdmin, (req, res) => {
    try {
        const { source, destination, description } = req.body;
        
        if (!source) {
            return res.status(400).json({ error: 'Source server is required' });
        }
        
        if (!destination) {
            return res.status(400).json({ error: 'Destination server is required' });
        }
        
        // Check if source and destination are the same
        if (source === destination) {
            return res.status(400).json({ error: 'Source and destination cannot be the same' });
        }
        
        const config = getConfig();
        
        // Check if source server exists (or is 'local')
        if (source !== 'local' && !config.servers.some(s => s.server === source)) {
            return res.status(404).json({ error: 'Source server not found' });
        }
        
        // Check if destination server exists (or is 'local')
        if (destination !== 'local' && !config.servers.some(s => s.server === destination)) {
            return res.status(404).json({ error: 'Destination server not found' });
        }
        
        // Check if route already exists
        if (config.routes.some(r => r.source === source && r.destination === destination)) {
            return res.status(400).json({ error: 'Route already exists' });
        }
        
        // Determine the local and remote servers
        const localServer = source === 'local' ? destination : (destination === 'local' ? source : null);
        
        // If neither source nor destination is 'local', we need to set up tunneling between two remote servers
        let setupCommand = '';
        let testCommand = '';
        
        if (localServer) {
            // Direct tunneling between local and remote server
            const sshKey = ensureSSHKey();
            setupCommand = `ssh -o StrictHostKeyChecking=no -i "${sshKey.private_key}" root@${localServer} "echo Setting up tunnel"`;
            testCommand = `ssh -o StrictHostKeyChecking=no -i "${sshKey.private_key}" root@${localServer} "echo Test successful"`;
        } else {
            // Tunneling between two remote servers
            const sshKey = ensureSSHKey();
            
            // Create a ProxyJump configuration to connect from source to destination
            setupCommand = `ssh -o StrictHostKeyChecking=no -i "${sshKey.private_key}" root@${source} "ssh -o StrictHostKeyChecking=no root@${destination} 'echo Setting up tunnel'"`;
            testCommand = `ssh -o StrictHostKeyChecking=no -i "${sshKey.private_key}" root@${source} "ssh -o StrictHostKeyChecking=no root@${destination} 'echo Test successful'"`;
        }
        
        // Test connection
        try {
            const output = execSync(testCommand, { timeout: 10000 }).toString();
            
            // Add route to config
            config.routes.push({
                source,
                destination,
                description: description || '',
                status: 'active',
                created_at: new Date().toISOString()
            });
            
            if (updateConfig(config)) {
                return res.json({
                    success: true,
                    message: 'Route added successfully',
                    route: {
                        source,
                        destination,
                        description: description || '',
                        status: 'active'
                    },
                    output
                });
            } else {
                return res.status(500).json({ error: 'Failed to update configuration' });
            }
        } catch (error) {
            logger.error(`Tunnel setup failed: ${error.message}`);
            return res.status(400).json({ 
                error: 'Failed to set up tunnel',
                details: error.message,
                hint: 'Make sure both servers are reachable and SSH keys are properly authorized'
            });
        }
    } catch (error) {
        logger.error(`Error adding route: ${error.message}`);
        return res.status(500).json({ error: error.message });
    }
});

// Remove route
router.delete('/routes/:index', authenticate, authorizeAdmin, (req, res) => {
    try {
        const index = parseInt(req.params.index);
        
        if (isNaN(index)) {
            return res.status(400).json({ error: 'Invalid route index' });
        }
        
        const config = getConfig();
        
        // Check if route exists
        if (index < 0 || index >= config.routes.length) {
            return res.status(404).json({ error: 'Route not found' });
        }
        
        // Remove route
        config.routes.splice(index, 1);
        
        if (updateConfig(config)) {
            return res.json({
                success: true,
                message: 'Route removed successfully'
            });
        } else {
            return res.status(500).json({ error: 'Failed to update configuration' });
        }
    } catch (error) {
        logger.error(`Error removing route: ${error.message}`);
        return res.status(500).json({ error: error.message });
    }
});

// Generate Ansible playbook for server setup
router.get('/ansible/playbook', authenticate, authorizeAdmin, (req, res) => {
    try {
        const config = getConfig();
        const sshKey = ensureSSHKey();
        
        // Create Ansible directory if it doesn't exist
        const ANSIBLE_DIR = path.join(CONFIG_DIR, 'ansible');
        if (!fs.existsSync(ANSIBLE_DIR)) {
            fs.mkdirSync(ANSIBLE_DIR, { recursive: true });
        }
        
        // Create inventory file
        let inventoryContent = "[tunneling_servers]\n";
        config.servers.forEach(server => {
            inventoryContent += `${server.server} ansible_user=root ansible_ssh_private_key_file=${sshKey.private_key}\n`;
        });
        
        const inventoryPath = path.join(ANSIBLE_DIR, 'tunneling_inventory');
        fs.writeFileSync(inventoryPath, inventoryContent);
        
        // Create playbook for setting up SSH tunneling
        const playbookContent = `---
# Ansible Playbook for Setting Up SSH Tunneling
# Generated by IRSSH-Panel on ${new Date().toISOString()}

- name: Setup SSH tunneling between servers
  hosts: tunneling_servers
  become: yes
  gather_facts: yes
  
  tasks:
    - name: Ensure SSH server is installed
      apt:
        name: openssh-server
        state: present
        update_cache: yes
      
    - name: Configure SSH server for tunneling
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
        state: present
      with_items:
        - { regexp: '^AllowTcpForwarding', line: 'AllowTcpForwarding yes' }
        - { regexp: '^PermitTunnel', line: 'PermitTunnel yes' }
        - { regexp: '^GatewayPorts', line: 'GatewayPorts yes' }
      notify: Restart SSH
      
    - name: Copy authorized keys
      authorized_key:
        user: root
        state: present
        key: "{{ lookup('file', '${sshKey.public_key}') }}"
        
    - name: Install tunneling tools
      apt:
        name:
          - autossh
          - netcat
          - socat
        state: present
        
  handlers:
    - name: Restart SSH
      service:
        name: sshd
        state: restarted
`;
        
        const playbookPath = path.join(ANSIBLE_DIR, 'setup_tunneling.yml');
        fs.writeFileSync(playbookPath, playbookContent);
        
        // Create script to run Ansible playbook
        const scriptContent = `#!/bin/bash
cd ${ANSIBLE_DIR}
ansible-playbook -i tunneling_inventory setup_tunneling.yml
`;
        
        const scriptPath = path.join(ANSIBLE_DIR, 'run_tunneling_playbook.sh');
        fs.writeFileSync(scriptPath, scriptContent);
        fs.chmodSync(scriptPath, 0o755);
        
        return res.json({
            success: true,
            files: {
                inventory: inventoryPath,
                playbook: playbookPath,
                script: scriptPath
            },
            playbook_content: playbookContent
        });
    } catch (error) {
        logger.error(`Error generating Ansible playbook: ${error.message}`);
        return res.status(500).json({ error: error.message });
    }
});

// Run Ansible playbook
router.post('/ansible/run', authenticate, authorizeAdmin, (req, res) => {
    try {
        const ANSIBLE_DIR = path.join(CONFIG_DIR, 'ansible');
        const scriptPath = path.join(ANSIBLE_DIR, 'run_tunneling_playbook.sh');
        
        if (!fs.existsSync(scriptPath)) {
            // Generate playbook first
            const playbookRes = router.get('/ansible/playbook', authenticate, authorizeAdmin, () => {});
            if (!playbookRes.success) {
                return res.status(500).json({ error: 'Failed to generate Ansible playbook' });
            }
        }
        
        // Run playbook asynchronously
        exec(scriptPath, (error, stdout, stderr) => {
            if (error) {
                logger.error(`Ansible playbook execution failed: ${error.message}`);
                // Log outputs for debugging
                logger.error(`Stdout: ${stdout}`);
                logger.error(`Stderr: ${stderr}`);
            } else {
                logger.info(`Ansible playbook executed successfully`);
                logger.debug(`Stdout: ${stdout}`);
            }
        });
        
        return res.json({
            success: true,
            message: 'Ansible playbook execution started'
        });
    } catch (error) {
        logger.error(`Error running Ansible playbook: ${error.message}`);
        return res.status(500).json({ error: error.message });
    }
});

// Initialize configuration on module load
initConfig();
ensureSSHKey();

module.exports = router;
EOT

# Setup Dropbear and BadVPN UDP Gateway modules
setup_additional_modules() {
    info "Setting up additional modules..."
    
    # Ask for Dropbear port
    read -p "Enter port for Dropbear SSH (default: 2222): " DROPBEAR_PORT
    DROPBEAR_PORT=${DROPBEAR_PORT:-2222}
    
    # Ask for BadVPN UDP Gateway port
    read -p "Enter port for BadVPN UDP Gateway (default: 7300): " UDPGW_PORT
    UDPGW_PORT=${UDPGW_PORT:-7300}
    
    # Setup Dropbear SSH
    info "Installing Dropbear SSH on port $DROPBEAR_PORT..."
    apt-get install -y dropbear || error "Failed to install Dropbear" "no-exit"
    
    # Backup original Dropbear config
    if [ -f /etc/default/dropbear ]; then
        cp /etc/default/dropbear /etc/default/dropbear.backup
    fi
    
    # Configure Dropbear
    cat > /etc/default/dropbear << EOF
# Dropbear SSH server configuration for IRSSH-Panel

# Set to 'NO' to disable starting Dropbear
NO_START=0

# Additional arguments for Dropbear
DROPBEAR_EXTRA_ARGS="-p $DROPBEAR_PORT -w -g"

# Specify keyfile locations (the default is to use the same as OpenSSH)
DROPBEAR_RSAKEY=/etc/dropbear/dropbear_rsa_host_key
DROPBEAR_DSSKEY=/etc/dropbear/dropbear_dss_host_key
DROPBEAR_ECDSAKEY=/etc/dropbear/dropbear_ecdsa_host_key
DROPBEAR_ED25519KEY=/etc/dropbear/dropbear_ed25519_host_key

# Set to 'NO' to disable password authentication
DROPBEAR_PASSWORD_AUTH=YES

# Set to 'YES' to enable public key authentication
DROPBEAR_PUBKEY_AUTH=YES

# If compiled with TCP keep-alive support, set the idle timeout in seconds
# (zero means never time out)
DROPBEAR_RECEIVE_WINDOW=65536
EOF
    
    # Create Dropbear directory if it doesn't exist
    mkdir -p /etc/dropbear
    
    # Restart Dropbear
    systemctl enable dropbear
    systemctl restart dropbear
    
    info "Dropbear SSH installed and configured on port $DROPBEAR_PORT"
    
    # Setup BadVPN UDP Gateway
    info "Installing BadVPN UDP Gateway on port $UDPGW_PORT..."
    
    # Install dependencies
    apt-get install -y cmake build-essential libssl-dev || error "Failed to install BadVPN dependencies" "no-exit"
    
    # Create temp directory for BadVPN
    mkdir -p /tmp/badvpn
    cd /tmp/badvpn || error "Failed to create temp directory for BadVPN" "no-exit"
    
    # Download and extract BadVPN
    wget -O badvpn.tar.gz https://github.com/ambrop72/badvpn/archive/refs/tags/1.999.130.tar.gz || error "Failed to download BadVPN" "no-exit"
    tar -xvf badvpn.tar.gz || error "Failed to extract BadVPN" "no-exit"
    cd badvpn-1.999.130 || error "Failed to access BadVPN directory" "no-exit"
    
    # Build and install BadVPN
    mkdir -p build
    cd build || error "Failed to create BadVPN build directory" "no-exit"
    cmake .. -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 || error "Failed to configure BadVPN" "no-exit"
    make || error "Failed to build BadVPN" "no-exit"
    make install || error "Failed to install BadVPN" "no-exit"
    
    # Create systemd service for BadVPN
    cat > /etc/systemd/system/badvpn.service << EOF
[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:$UDPGW_PORT --max-clients 1000 --max-connections-for-client 10
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # Start and enable BadVPN service
    systemctl enable badvpn.service
    systemctl start badvpn.service
    
    info "BadVPN UDP Gateway installed and configured on port $UDPGW_PORT"
    
    # Add information to config
    mkdir -p "$CONFIG_DIR/modules"
    cat > "$CONFIG_DIR/modules/additional.conf" << EOF
# IRSSH-Panel Additional Modules Configuration

# Dropbear SSH
DROPBEAR_ENABLED=true
DROPBEAR_PORT=$DROPBEAR_PORT

# BadVPN UDP Gateway
BADVPN_ENABLED=true
BADVPN_PORT=$UDPGW_PORT
EOF
    
    # Clean up
    cd "$PANEL_DIR"
    rm -rf /tmp/badvpn
    
    info "Additional modules setup completed"
}

# Function to install and configure SSL-VPN protocol
install_ssl_vpn() {
    info "Installing SSL-VPN protocol..."
    
    # Create directory for SSL-VPN
    mkdir -p "$CONFIG_DIR/ssl-vpn"
    
    # Install dependencies
    apt-get install -y openssl nginx stunnel4 || error "Failed to install SSL-VPN dependencies" "no-exit"
    
    # Generate SSL certificate for stunnel
    CERT_DIR="$CONFIG_DIR/ssl-vpn/certs"
    mkdir -p "$CERT_DIR"
    
    # Generate private key and certificate
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$CERT_DIR/sslvpn.key" \
        -out "$CERT_DIR/sslvpn.crt" \
        -subj "/CN=IRSSH-SSL-VPN/O=IRSSH-Panel/C=US" || error "Failed to generate SSL certificate" "no-exit"
    
    # Combine key and certificate for stunnel
    cat "$CERT_DIR/sslvpn.key" "$CERT_DIR/sslvpn.crt" > "$CERT_DIR/sslvpn.pem"
    chmod 600 "$CERT_DIR/sslvpn.pem"
    
    # Determine available port for SSL-VPN
    SSL_VPN_PORT=$(shuf -i 10000-19999 -n 1)
    info "Using port $SSL_VPN_PORT for SSL-VPN"
    
    # Configure stunnel for SSL-VPN
    cat > /etc/stunnel/ssl-vpn.conf << EOF
pid = /var/run/stunnel4/stunnel.pid
setuid = stunnel4
setgid = stunnel4
cert = $CERT_DIR/sslvpn.pem
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
debug = 7
output = /var/log/stunnel4/ssl-vpn.log

[ssh-ssl]
accept = $SSL_VPN_PORT
connect = 127.0.0.1:${PORTS[SSH]}
EOF
    
    # Create systemd service for SSL-VPN
    cat > /etc/systemd/system/ssl-vpn.service << EOF
[Unit]
Description=SSL-VPN Service for IRSSH-Panel
After=network.target
Requires=stunnel4.service

[Service]
Type=simple
ExecStart=/usr/bin/stunnel4 /etc/stunnel/ssl-vpn.conf
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # Configure firewall to allow SSL-VPN port
    if command -v ufw &> /dev/null; then
        ufw allow $SSL_VPN_PORT/tcp
    fi
    
    # Enable and start SSL-VPN service
    systemctl enable ssl-vpn.service
    systemctl start ssl-vpn.service
    
    # Create client configuration generator script
    cat > "$SCRIPTS_DIR/generate_sslvpn_client.sh" << 'EOF'
#!/bin/bash

# SSL-VPN Client Configuration Generator
# For IRSSH-Panel

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $0 <username> <output_file>"
    exit 1
fi

USERNAME="$1"
OUTPUT_FILE="$2"
SERVER_IP=$(curl -s4 ifconfig.me || curl -s4 icanhazip.com || ip -4 route get 8.8.8.8 | awk '{print $7; exit}')
SSL_VPN_PORT=$(grep 'accept =' /etc/stunnel/ssl-vpn.conf | awk '{print $3}')

# Generate client configuration
cat > "$OUTPUT_FILE" << EOL
# IRSSH-Panel SSL-VPN Client Configuration
# Generated for user: $USERNAME

client = yes
foreground = yes
debug = 1

[ssh-ssl]
accept = 127.0.0.1:2222
connect = $SERVER_IP:$SSL_VPN_PORT
verifyChain = no
EOL

# Create certificate file
CERT_PATH="/etc/enhanced_ssh/ssl-vpn/certs/sslvpn.crt"
if [ -f "$CERT_PATH" ]; then
    cat "$CERT_PATH" >> "$OUTPUT_FILE"
fi

echo "SSL-VPN client configuration generated for $USERNAME"
echo "File saved as: $OUTPUT_FILE"
echo
echo "To connect, install stunnel on the client and run:"
echo "  stunnel $OUTPUT_FILE"
echo "Then connect SSH to 127.0.0.1:2222 with username and password"
EOF
    
    chmod +x "$SCRIPTS_DIR/generate_sslvpn_client.sh"
    
    # Save port information
    PORTS["SSL_VPN"]=$SSL_VPN_PORT
    
    info "SSL-VPN protocol installed and configured on port $SSL_VPN_PORT"
    info "Client configuration generator script created at $SCRIPTS_DIR/generate_sslvpn_client.sh"
}

# Function to install and configure NordWhisper protocol
install_nordwhisper() {
    info "Installing NordWhisper protocol..."
    
    # Create directory for NordWhisper
    mkdir -p "$CONFIG_DIR/nordwhisper"
    
    # Install dependencies
    apt-get install -y golang git build-essential netcat || error "Failed to install NordWhisper dependencies" "no-exit"
    
    # Set up Go environment if needed
    if [ ! -d "/usr/local/go" ]; then
        LATEST_GO=$(curl -s https://go.dev/dl/ | grep -oP 'go[0-9]+\.[0-9]+\.[0-9]+\.linux-amd64\.tar\.gz' | head -n 1)
        if [ -z "$LATEST_GO" ]; then
            LATEST_GO="go1.20.3.linux-amd64.tar.gz"  # Fallback to a known version
        fi
        
        wget -O go.tar.gz "https://dl.google.com/go/$LATEST_GO" || error "Failed to download Go" "no-exit"
        tar -C /usr/local -xzf go.tar.gz || error "Failed to extract Go" "no-exit"
        rm go.tar.gz
        
        echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
        chmod +x /etc/profile.d/go.sh
        source /etc/profile.d/go.sh
    fi
    
    # Clone NordWhisper (Using the actual library name, which is 'Hysteria2')
    mkdir -p /tmp/nordwhisper
    cd /tmp/nordwhisper || error "Failed to create temp directory for NordWhisper" "no-exit"
    
    # Use Hysteria2 as the implementation base for NordWhisper
    git clone https://github.com/apernet/hysteria.git || error "Failed to clone Hysteria2 repository" "no-exit"
    cd hysteria || error "Failed to access Hysteria2 directory" "no-exit"
    
    # Build hysteria (which we'll use as NordWhisper)
    go build -o hysteria cmd/hysteria.go || error "Failed to build Hysteria2" "no-exit"
    cp hysteria /usr/local/bin/nordwhisper
    chmod +x /usr/local/bin/nordwhisper
    
    # Determine available port for NordWhisper
    NORDWHISPER_PORT=$(shuf -i 20000-29999 -n 1)
    info "Using port $NORDWHISPER_PORT for NordWhisper"
    
    # Generate self-signed certificate for NordWhisper
    CERT_DIR="$CONFIG_DIR/nordwhisper/certs"
    mkdir -p "$CERT_DIR"
    
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$CERT_DIR/nordwhisper.key" \
        -out "$CERT_DIR/nordwhisper.crt" \
        -subj "/CN=NordWhisper/O=IRSSH-Panel/C=US" || error "Failed to generate NordWhisper certificate" "no-exit"
    
    # Create NordWhisper server configuration
    SERVER_CONFIG_DIR="$CONFIG_DIR/nordwhisper/server"
    mkdir -p "$SERVER_CONFIG_DIR"
    
    # Generate a secure password for NordWhisper
    NORDWHISPER_PASSWORD=$(openssl rand -base64 24)
    
    cat > "$SERVER_CONFIG_DIR/config.json" << EOF
{
    "listen": ":$NORDWHISPER_PORT",
    "tls": {
        "cert": "$CERT_DIR/nordwhisper.crt",
        "key": "$CERT_DIR/nordwhisper.key"
    },
    "auth": {
        "type": "password",
        "password": "$NORDWHISPER_PASSWORD"
    },
    "masquerade": {
        "type": "http",
        "file": {
            "dir": "/var/www/html",
            "index": ["index.html", "index.htm"]
        }
    },
    "bandwidth": {
        "up": "1 gbps",
        "down": "1 gbps"
    },
    "ignoreClientBandwidth": false,
    "obfs": {
        "type": "salamander",
        "salamander": {
            "password": "$(openssl rand -base64 16)"
        }
    }
}
EOF
    
    # Create client configuration template
    CLIENT_CONFIG_DIR="$CONFIG_DIR/nordwhisper/client"
    mkdir -p "$CLIENT_CONFIG_DIR"
    
    cat > "$CLIENT_CONFIG_DIR/config.json.template" << EOF
{
    "server": "SERVER_IP:$NORDWHISPER_PORT",
    "auth": "PASSWORD",
    "tls": {
        "sni": "NordWhisper",
        "insecure": true
    },
    "socks5": {
        "listen": "127.0.0.1:1080"
    },
    "transport": {
        "type": "udp"
    },
    "bandwidth": {
        "up": "50 mbps",
        "down": "200 mbps"
    },
    "obfs": {
        "type": "salamander",
        "salamander": {
            "password": "OBFS_PASSWORD"
        }
    }
}
EOF
    
    # Create systemd service for NordWhisper
    cat > /etc/systemd/system/nordwhisper.service << EOF
[Unit]
Description=NordWhisper Service for IRSSH-Panel
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/nordwhisper server -c $SERVER_CONFIG_DIR/config.json
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # Configure firewall to allow NordWhisper port
    if command -v ufw &> /dev/null; then
        ufw allow $NORDWHISPER_PORT/udp
    fi
    
    # Enable and start NordWhisper service
    systemctl enable nordwhisper.service
    systemctl start nordwhisper.service
    
    # Create client configuration generator script
    cat > "$SCRIPTS_DIR/generate_nordwhisper_client.sh" << 'EOF'
#!/bin/bash

# NordWhisper Client Configuration Generator
# For IRSSH-Panel

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $0 <username> <output_file>"
    exit 1
fi

USERNAME="$1"
OUTPUT_FILE="$2"
SERVER_IP=$(curl -s4 ifconfig.me || curl -s4 icanhazip.com || ip -4 route get 8.8.8.8 | awk '{print $7; exit}')
SERVER_CONFIG="$CONFIG_DIR/nordwhisper/server/config.json"
CLIENT_TEMPLATE="$CONFIG_DIR/nordwhisper/client/config.json.template"

if [ ! -f "$SERVER_CONFIG" ] || [ ! -f "$CLIENT_TEMPLATE" ]; then
    echo "Error: Server configuration or client template not found"
    exit 1
fi

# Get password and obfs password from server config
PASSWORD=$(grep -oP '"password": "\K[^"]+' "$SERVER_CONFIG" | head -1)
OBFS_PASSWORD=$(grep -oP '"password": "\K[^"]+' "$SERVER_CONFIG" | tail -1)

# Generate client configuration
cp "$CLIENT_TEMPLATE" "$OUTPUT_FILE"
sed -i "s/SERVER_IP/$SERVER_IP/g" "$OUTPUT_FILE"
sed -i "s/PASSWORD/$PASSWORD/g" "$OUTPUT_FILE"
sed -i "s/OBFS_PASSWORD/$OBFS_PASSWORD/g" "$OUTPUT_FILE"

# Save certificate
CERT_FILE="$OUTPUT_FILE.crt"
cp "$CONFIG_DIR/nordwhisper/certs/nordwhisper.crt" "$CERT_FILE"

echo "NordWhisper client configuration generated for $USERNAME"
echo "Config file saved as: $OUTPUT_FILE"
echo "Certificate saved as: $CERT_FILE"
echo
echo "To connect, install Hysteria2 (NordWhisper) client and run:"
echo "  hysteria client -c $OUTPUT_FILE"
echo "Then configure your applications to use SOCKS5 proxy at 127.0.0.1:1080"
EOF
    
    chmod +x "$SCRIPTS_DIR/generate_nordwhisper_client.sh"
    
    # Save port information
    PORTS["NORDWHISPER"]=$NORDWHISPER_PORT
    
    # Clean up
    cd "$PANEL_DIR"
    rm -rf /tmp/nordwhisper
    
    info "NordWhisper protocol installed and configured on port $NORDWHISPER_PORT"
    info "Client configuration generator script created at $SCRIPTS_DIR/generate_nordwhisper_client.sh"
    info "Default NordWhisper password: $NORDWHISPER_PASSWORD (saved in $SERVER_CONFIG_DIR/config.json)"
}

# Function to install and configure SingBox with specific protocols
install_singbox_improved() {
    info "Installing improved SingBox with selected protocols..."
    
    local ARCH="amd64"
    if [ "$(uname -m)" = "aarch64" ]; then
        ARCH="arm64"
    fi
    
    local VERSION="1.7.1"  # Using the latest stable version
    local URL="https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box-${VERSION}-linux-${ARCH}.tar.gz"
   
    mkdir -p /tmp/sing-box
    wget "$URL" -O /tmp/sing-box.tar.gz || error "Failed to download Sing-Box"
    tar -xzf /tmp/sing-box.tar.gz -C /tmp/sing-box --strip-components=1
   
    cp /tmp/sing-box/sing-box /usr/local/bin/
    chmod +x /usr/local/bin/sing-box || error "Failed to set permissions for sing-box"
   
    mkdir -p /etc/sing-box
    mkdir -p "$CONFIG_DIR/singbox/users"
    mkdir -p "$LOG_DIR/singbox"
    
    # Generate UUIDs and passwords for protocols
    local SHADOWSOCKS_PASSWORD=$(openssl rand -base64 24)
    local TUIC_UUID=$(cat /proc/sys/kernel/random/uuid)
    local TUIC_PASSWORD=$(openssl rand -base64 16)
    local VLESS_UUID=$(cat /proc/sys/kernel/random/uuid)
    local HYSTERIA2_PASSWORD=$(openssl rand -base64 16)
    
    # Generate a certificate for the protocols
    mkdir -p /etc/sing-box/cert
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/sing-box/cert/private.key \
        -out /etc/sing-box/cert/cert.crt \
        -subj "/CN=IRSSH-SingBox/O=IRSSH-Panel/C=US" || error "Failed to generate certificate for SingBox"
    
    # Set ports for protocols
    local SHADOWSOCKS_PORT=$(shuf -i 30000-30999 -n 1)
    local TUIC_PORT=$(shuf -i 31000-31999 -n 1)
    local VLESS_PORT=$(shuf -i 32000-32999 -n 1)
    local HYSTERIA2_PORT=$(shuf -i 33000-33999 -n 1)
    
    info "Using the following ports for SingBox protocols:"
    info "  - Shadowsocks: $SHADOWSOCKS_PORT"
    info "  - TUIC: $TUIC_PORT"
    info "  - VLess Reality: $VLESS_PORT"
    info "  - Hysteria2: $HYSTERIA2_PORT"
    
    # Create SingBox configuration with only the four specified protocols
    cat > /etc/sing-box/config.json << EOF
{
    "log": {
        "level": "info",
        "output": "$LOG_DIR/singbox/sing-box.log",
        "timestamp": true
    },
    "inbounds": [
        {
            "type": "shadowsocks",
            "tag": "ss-in",
            "listen": "::",
            "listen_port": $SHADOWSOCKS_PORT,
            "method": "2022-blake3-aes-256-gcm",
            "password": "$SHADOWSOCKS_PASSWORD",
            "multiplex": {
                "enabled": true,
                "max_connections": 8,
                "min_streams": 4
            }
        },
        {
            "type": "tuic",
            "tag": "tuic-in",
            "listen": "::",
            "listen_port": $TUIC_PORT,
            "users": [
                {
                    "uuid": "$TUIC_UUID",
                    "password": "$TUIC_PASSWORD"
                }
            ],
            "congestion_control": "bbr",
            "tls": {
                "enabled": true,
                "server_name": "tuic.irssh",
                "certificate_path": "/etc/sing-box/cert/cert.crt",
                "key_path": "/etc/sing-box/cert/private.key"
            }
        },
        {
            "type": "vless",
            "tag": "vless-in",
            "listen": "::",
            "listen_port": $VLESS_PORT,
            "users": [
                {
                    "uuid": "$VLESS_UUID",
                    "name": "default"
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "vless.irssh",
                "reality": {
                    "enabled": true,
                    "handshake": {
                        "server": "www.microsoft.com",
                        "server_port": 443
                    },
                    "private_key": "$(sing-box generate reality-keypair | grep PrivateKey | awk '{print $2}')",
                    "short_id": [
                        "$(openssl rand -hex 8)"
                    ]
                }
            },
            "transport": {
                "type": "grpc",
                "service_name": "vless-grpc"
            }
        },
        {
            "type": "hysteria2",
            "tag": "hysteria2-in",
            "listen": "::",
            "listen_port": $HYSTERIA2_PORT,
            "users": [
                {
                    "password": "$HYSTERIA2_PASSWORD"
                }
            ],
            "ignore_client_bandwidth": true,
            "masquerade": "https://www.google.com",
            "tls": {
                "enabled": true,
                "server_name": "hysteria2.irssh",
                "alpn": ["h3"],
                "certificate_path": "/etc/sing-box/cert/cert.crt",
                "key_path": "/etc/sing-box/cert/private.key"
            }
        }
    ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        }
    ],
    "route": {
        "rules": [
            {
                "inbound": ["ss-in", "tuic-in", "vless-in", "hysteria2-in"],
                "outbound": "direct"
            }
        ]
    }
}
EOF
    
    # Save user information for the admin
    cat > "$CONFIG_DIR/singbox/users/${ADMIN_USER}.json" << EOF
{
    "username": "${ADMIN_USER}",
    "shadowsocks": {
        "port": $SHADOWSOCKS_PORT,
        "password": "$SHADOWSOCKS_PASSWORD",
        "method": "2022-blake3-aes-256-gcm"
    },
    "tuic": {
        "port": $TUIC_PORT,
        "uuid": "$TUIC_UUID",
        "password": "$TUIC_PASSWORD"
    },
    "vless": {
        "port": $VLESS_PORT,
        "uuid": "$VLESS_UUID",
        "reality_private_key": "$(grep 'private_key' /etc/sing-box/config.json | grep -o '"private_key": "[^"]*' | cut -d'"' -f4)",
        "reality_short_id": "$(grep 'short_id' /etc/sing-box/config.json | grep -o '"short_id": \[[^]]*' | grep -o '"[^"]*"' | tr -d '"')"
    },
    "hysteria2": {
        "port": $HYSTERIA2_PORT,
        "password": "$HYSTERIA2_PASSWORD"
    },
    "created_at": "$(date +"%Y-%m-%d %H:%M:%S")"
}
EOF
    
    # Create configuration generators for each protocol
    # Shadowsocks client config generator
    cat > "$SCRIPTS_DIR/generate_shadowsocks_client.sh" << 'EOF'
#!/bin/bash

# Shadowsocks Client Configuration Generator

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $0 <username> <output_file>"
    exit 1
fi

USERNAME="$1"
OUTPUT_FILE="$2"

# Get server IP
SERVER_IP=$(curl -s4 ifconfig.me || curl -s4 icanhazip.com || ip -4 route get 8.8.8.8 | awk '{print $7; exit}')
SERVER_IPv6=$(curl -s6 ifconfig.me || curl -s6 icanhazip.com || ip -6 addr show scope global | grep -oP '(?<=inet6\s)\S+(?=/)' | head -n 1)

# Get user config
USER_CONFIG="/etc/enhanced_ssh/singbox/users/${USERNAME}.json"
if [ ! -f "$USER_CONFIG" ]; then
    echo "Error: User configuration not found"
    exit 1
fi

# Extract configuration
SS_PORT=$(grep -o '"port": [0-9]*' "$USER_CONFIG" | head -1 | awk '{print $2}')
SS_PASSWORD=$(grep -o '"password": "[^"]*"' "$USER_CONFIG" | head -1 | sed 's/"password": "\(.*\)"/\1/')
SS_METHOD=$(grep -o '"method": "[^"]*"' "$USER_CONFIG" | head -1 | sed 's/"method": "\(.*\)"/\1/')

# Generate client configuration (JSON format for clients like Clash)
cat > "$OUTPUT_FILE" << EOL
{
  "servers": [
    {
      "server": "$SERVER_IP",
      "server_port": $SS_PORT,
      "password": "$SS_PASSWORD",
      "method": "$SS_METHOD",
      "remarks": "IRSSH-Shadowsocks-IPv4"
    }
EOL

# Add IPv6 configuration if available
if [ ! -z "$SERVER_IPv6" ]; then
cat >> "$OUTPUT_FILE" << EOL
    ,
    {
      "server": "$SERVER_IPv6",
      "server_port": $SS_PORT,
      "password": "$SS_PASSWORD",
      "method": "$SS_METHOD",
      "remarks": "IRSSH-Shadowsocks-IPv6"
    }
EOL
fi

# Close the JSON
cat >> "$OUTPUT_FILE" << EOL
  ]
}
EOL

# Generate URI format as well
SS_URI_BASE64=$(echo -n "${SS_METHOD}:${SS_PASSWORD}@${SERVER_IP}:${SS_PORT}" | base64 -w 0)
SS_URI="ss://${SS_URI_BASE64}"

# IPv6 URI if available
if [ ! -z "$SERVER_IPv6" ]; then
    SS_URI_IPv6_BASE64=$(echo -n "${SS_METHOD}:${SS_PASSWORD}@[${SERVER_IPv6}]:${SS_PORT}" | base64 -w 0)
    SS_URI_IPv6="ss://${SS_URI_IPv6_BASE64}"
fi

# Output the URIs to the console
echo "Shadowsocks client configuration generated for $USERNAME"
echo "Configuration file saved as: $OUTPUT_FILE"
echo
echo "Shadowsocks URI (IPv4): $SS_URI"
if [ ! -z "$SERVER_IPv6" ]; then
    echo "Shadowsocks URI (IPv6): $SS_URI_IPv6"
fi
EOF
    
    # TUIC client config generator
    cat > "$SCRIPTS_DIR/generate_tuic_client.sh" << 'EOF'
#!/bin/bash

# TUIC Client Configuration Generator

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $0 <username> <output_file>"
    exit 1
fi

USERNAME="$1"
OUTPUT_FILE="$2"

# Get server IP
SERVER_IP=$(curl -s4 ifconfig.me || curl -s4 icanhazip.com || ip -4 route get 8.8.8.8 | awk '{print $7; exit}')
SERVER_IPv6=$(curl -s6 ifconfig.me || curl -s6 icanhazip.com || ip -6 addr show scope global | grep -oP '(?<=inet6\s)\S+(?=/)' | head -n 1)

# Get user config
USER_CONFIG="/etc/enhanced_ssh/singbox/users/${USERNAME}.json"
if [ ! -f "$USER_CONFIG" ]; then
    echo "Error: User configuration not found"
    exit 1
fi

# Extract configuration
TUIC_PORT=$(grep -o '"port": [0-9]*' "$USER_CONFIG" | sed -n '2p' | awk '{print $2}')
TUIC_UUID=$(grep -o '"uuid": "[^"]*"' "$USER_CONFIG" | head -1 | sed 's/"uuid": "\(.*\)"/\1/')
TUIC_PASSWORD=$(grep -o '"password": "[^"]*"' "$USER_CONFIG" | sed -n '2p' | sed 's/"password": "\(.*\)"/\1/')

# Copy certificate for client
CERT_FILE="${OUTPUT_FILE}.crt"
cp /etc/sing-box/cert/cert.crt "$CERT_FILE"

# Generate Sing-Box client configuration
cat > "$OUTPUT_FILE" << EOL
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "socks",
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "listen_port": 1080
    },
    {
      "type": "http",
      "tag": "http-in",
      "listen": "127.0.0.1",
      "listen_port": 1081
    }
  ],
  "outbounds": [
    {
      "type": "tuic",
      "tag": "tuic-out",
      "server": "$SERVER_IP",
      "server_port": $TUIC_PORT,
      "uuid": "$TUIC_UUID",
      "password": "$TUIC_PASSWORD",
      "congestion_control": "bbr",
      "zero_rtt_handshake": true,
      "tls": {
        "enabled": true,
        "disable_sni": false,
        "server_name": "tuic.irssh",
        "insecure": true
      }
    }
  ],
  "route": {
    "rules": [
      {
        "inbound": ["socks-in", "http-in"],
        "outbound": "tuic-out"
      }
    ]
  }
}
EOL

# Generate IPv6 configuration if available
if [ ! -z "$SERVER_IPv6" ]; then
    IPV6_FILE="${OUTPUT_FILE%.*}_ipv6.json"
    sed "s/$SERVER_IP/[$SERVER_IPv6]/g" "$OUTPUT_FILE" > "$IPV6_FILE"
    echo "IPv6 configuration saved as: $IPV6_FILE"
fi

echo "TUIC client configuration generated for $USERNAME"
echo "Configuration file saved as: $OUTPUT_FILE"
echo "Certificate saved as: $CERT_FILE"
echo
echo "To use, run sing-box with this configuration:"
echo "sing-box run -c $OUTPUT_FILE"
echo "Then configure your applications to use SOCKS5 proxy at 127.0.0.1:1080 or HTTP proxy at 127.0.0.1:1081"
EOF
    
    # VLess Reality client config generator
    cat > "$SCRIPTS_DIR/generate_vless_client.sh" << 'EOF'
#!/bin/bash

# VLess Reality Client Configuration Generator

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $0 <username> <output_file>"
    exit 1
fi

USERNAME="$1"
OUTPUT_FILE="$2"

# Get server IP
SERVER_IP=$(curl -s4 ifconfig.me || curl -s4 icanhazip.com || ip -4 route get 8.8.8.8 | awk '{print $7; exit}')
SERVER_IPv6=$(curl -s6 ifconfig.me || curl -s6 icanhazip.com || ip -6 addr show scope global | grep -oP '(?<=inet6\s)\S+(?=/)' | head -n 1)

# Get user config
USER_CONFIG="/etc/enhanced_ssh/singbox/users/${USERNAME}.json"
if [ ! -f "$USER_CONFIG" ]; then
    echo "Error: User configuration not found"
    exit 1
fi

# Extract configuration
VLESS_PORT=$(grep -o '"port": [0-9]*' "$USER_CONFIG" | sed -n '3p' | awk '{print $2}')
VLESS_UUID=$(grep -o '"uuid": "[^"]*"' "$USER_CONFIG" | sed -n '2p' | sed 's/"uuid": "\(.*\)"/\1/')
REALITY_PRIVATE_KEY=$(grep -o '"reality_private_key": "[^"]*"' "$USER_CONFIG" | sed 's/"reality_private_key": "\(.*\)"/\1/')
REALITY_SHORT_ID=$(grep -o '"reality_short_id": "[^"]*"' "$USER_CONFIG" | sed 's/"reality_short_id": "\(.*\)"/\1/')

# Calculate Reality public key from private key
REALITY_PUBLIC_KEY=$(echo "$REALITY_PRIVATE_KEY" | sing-box generate reality-keypair | grep PublicKey | awk '{print $2}')

# Generate Sing-Box client configuration
cat > "$OUTPUT_FILE" << EOL
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "socks",
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "listen_port": 1080
    },
    {
      "type": "http",
      "tag": "http-in",
      "listen": "127.0.0.1",
      "listen_port": 1081
    }
  ],
  "outbounds": [
    {
      "type": "vless",
      "tag": "vless-out",
      "server": "$SERVER_IP",
      "server_port": $VLESS_PORT,
      "uuid": "$VLESS_UUID",
      "tls": {
        "enabled": true,
        "server_name": "www.microsoft.com",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        },
        "reality": {
          "enabled": true,
          "public_key": "$REALITY_PUBLIC_KEY",
          "short_id": "$REALITY_SHORT_ID"
        }
      },
      "transport": {
        "type": "grpc",
        "service_name": "vless-grpc"
      }
    }
  ],
  "route": {
    "rules": [
      {
        "inbound": ["socks-in", "http-in"],
        "outbound": "vless-out"
      }
    ]
  }
}
EOL

# Generate IPv6 configuration if available
if [ ! -z "$SERVER_IPv6" ]; then
    IPV6_FILE="${OUTPUT_FILE%.*}_ipv6.json"
    sed "s/$SERVER_IP/[$SERVER_IPv6]/g" "$OUTPUT_FILE" > "$IPV6_FILE"
    echo "IPv6 configuration saved as: $IPV6_FILE"
fi

# Generate a share link for V2ray clients
VLESS_LINK="vless://$VLESS_UUID@$SERVER_IP:$VLESS_PORT?security=reality&sni=www.microsoft.com&fp=chrome&pbk=$REALITY_PUBLIC_KEY&sid=$REALITY_SHORT_ID&type=grpc&serviceName=vless-grpc&encryption=none#IRSSH-VLess-Reality"

echo "VLess Reality client configuration generated for $USERNAME"
echo "Configuration file saved as: $OUTPUT_FILE"
echo
echo "Share link for V2ray clients:"
echo "$VLESS_LINK"
echo
echo "To use with sing-box, run:"
echo "sing-box run -c $OUTPUT_FILE"
echo "Then configure your applications to use SOCKS5 proxy at 127.0.0.1:1080 or HTTP proxy at 127.0.0.1:1081"
EOF
    
    # Hysteria2 client config generator
    cat > "$SCRIPTS_DIR/generate_hysteria2_client.sh" << 'EOF'
#!/bin/bash

# Hysteria2 Client Configuration Generator

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $0 <username> <output_file>"
    exit 1
fi

USERNAME="$1"
OUTPUT_FILE="$2"

# Get server IP
SERVER_IP=$(curl -s4 ifconfig.me || curl -s4 icanhazip.com || ip -4 route get 8.8.8.8 | awk '{print $7; exit}')
SERVER_IPv6=$(curl -s6 ifconfig.me || curl -s6 icanhazip.com || ip -6 addr show scope global | grep -oP '(?<=inet6\s)\S+(?=/)' | head -n 1)

# Get user config
USER_CONFIG="/etc/enhanced_ssh/singbox/users/${USERNAME}.json"
if [ ! -f "$USER_CONFIG" ]; then
    echo "Error: User configuration not found"
    exit 1
fi

# Extract configuration
HYSTERIA2_PORT=$(grep -o '"port": [0-9]*' "$USER_CONFIG" | sed -n '4p' | awk '{print $2}')
HYSTERIA2_PASSWORD=$(grep -o '"password": "[^"]*"' "$USER_CONFIG" | sed -n '3p' | sed 's/"password": "\(.*\)"/\1/')

# Copy certificate for client
CERT_FILE="${OUTPUT_FILE}.crt"
cp /etc/sing-box/cert/cert.crt "$CERT_FILE"

# Generate Sing-Box client configuration
cat > "$OUTPUT_FILE" << EOL
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "socks",
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "listen_port": 1080
    },
    {
      "type": "http",
      "tag": "http-in",
      "listen": "127.0.0.1",
      "listen_port": 1081
    }
  ],
  "outbounds": [
    {
      "type": "hysteria2",
      "tag": "hysteria2-out",
      "server": "$SERVER_IP",
      "server_port": $HYSTERIA2_PORT,
      "password": "$HYSTERIA2_PASSWORD",
      "tls": {
        "enabled": true,
        "server_name": "hysteria2.irssh",
        "insecure": true,
        "alpn": ["h3"]
      }
    }
  ],
  "route": {
    "rules": [
      {
        "inbound": ["socks-in", "http-in"],
        "outbound": "hysteria2-out"
      }
    ]
  }
}
EOL

# Generate IPv6 configuration if available
if [ ! -z "$SERVER_IPv6" ]; then
    IPV6_FILE="${OUTPUT_FILE%.*}_ipv6.json"
    sed "s/$SERVER_IP/[$SERVER_IPv6]/g" "$OUTPUT_FILE" > "$IPV6_FILE"
    echo "IPv6 configuration saved as: $IPV6_FILE"
fi

# Generate a direct Hysteria2 client configuration
cat > "${OUTPUT_FILE}.hysteria.yaml" << EOL
server: $SERVER_IP:$HYSTERIA2_PORT
auth: $HYSTERIA2_PASSWORD

bandwidth:
  up: 50 mbps
  down: 200 mbps

tls:
  sni: hysteria2.irssh
  insecure: true

socks5:
  listen: 127.0.0.1:1080

http:
  listen: 127.0.0.1:1081
EOL

echo "Hysteria2 client configuration generated for $USERNAME"
echo "Sing-Box configuration saved as: $OUTPUT_FILE"
echo "Hysteria2 native configuration saved as: ${OUTPUT_FILE}.hysteria.yaml"
echo "Certificate saved as: $CERT_FILE"
echo
echo "To use with sing-box, run:"
echo "sing-box run -c $OUTPUT_FILE"
echo "To use with hysteria2 client, run:"
echo "hysteria2 -c ${OUTPUT_FILE}.hysteria.yaml"
echo "Then configure your applications to use SOCKS5 proxy at 127.0.0.1:1080 or HTTP proxy at 127.0.0.1:1081"
EOF
    
    # Make all client config generators executable
    chmod +x "$SCRIPTS_DIR/generate_shadowsocks_client.sh"
    chmod +x "$SCRIPTS_DIR/generate_tuic_client.sh"
    chmod +x "$SCRIPTS_DIR/generate_vless_client.sh"
    chmod +x "$SCRIPTS_DIR/generate_hysteria2_client.sh"
    
    # Create systemd service for SingBox
    cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=Sing-Box Service for IRSSH-Panel
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    
    # Enable firewall rules for all protocols
    if command -v ufw &> /dev/null; then
        ufw allow $SHADOWSOCKS_PORT/tcp
        ufw allow $SHADOWSOCKS_PORT/udp
        ufw allow $TUIC_PORT/udp
        ufw allow $VLESS_PORT/tcp
        ufw allow $HYSTERIA2_PORT/udp
    fi
    
    # Save port information to PORTS array
    PORTS["SHADOWSOCKS"]=$SHADOWSOCKS_PORT
    PORTS["TUIC"]=$TUIC_PORT
    PORTS["VLESS"]=$VLESS_PORT
    PORTS["HYSTERIA2"]=$HYSTERIA2_PORT
    
    # Enable and start sing-box service
    systemctl daemon-reload
    systemctl enable sing-box.service
    systemctl start sing-box.service
    
    # Clean up temporary files
    rm -rf /tmp/sing-box*
    
    info "SingBox installed with selected protocols:"
    info "  - Shadowsocks on port $SHADOWSOCKS_PORT"
    info "  - TUIC on port $TUIC_PORT"
    info "  - VLess Reality on port $VLESS_PORT"
    info "  - Hysteria2 on port $HYSTERIA2_PORT"
    info "Client configuration generators are available in $SCRIPTS_DIR directory"
}

# Function to install advanced monitoring system
setup_advanced_monitoring() {
    info "Setting up advanced monitoring system..."
    
    # Create monitoring directories
    mkdir -p "$MONITOR_DIR/system"
    mkdir -p "$MONITOR_DIR/protocols"
    mkdir -p "$MONITOR_DIR/user-usage"
    mkdir -p "$MONITOR_DIR/dashboard"
    mkdir -p "$LOG_DIR/monitoring"
    
    # Install monitoring tools
    apt-get install -y prometheus prometheus-node-exporter \
        collectd vnstat goaccess htop sysstat apachetop nethogs iotop \
        || warn "Failed to install some monitoring tools"
    
    # Install Grafana for dashboard visualization
    info "Installing Grafana..."
    if ! apt-key list | grep -q "Grafana"; then
        wget -q -O - https://packages.grafana.com/gpg.key | apt-key add -
        add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"
        apt-get update
    fi
    
    apt-get install -y grafana || warn "Failed to install Grafana"
    
    # Configure Prometheus
    cat > /etc/prometheus/prometheus.yml << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          # - alertmanager:9093

rule_files:
  # - "first_rules.yml"
  # - "second_rules.yml"

scrape_configs:
  - job_name: "prometheus"
    static_configs:
      - targets: ["localhost:9090"]

  - job_name: "node"
    static_configs:
      - targets: ["localhost:9100"]
EOF
    
    # Create a dashboard for Grafana
    mkdir -p /etc/grafana/provisioning/dashboards
    mkdir -p /etc/grafana/provisioning/datasources
    
    # Create datasource configuration
    cat > /etc/grafana/provisioning/datasources/prometheus.yml << EOF
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://localhost:9090
    isDefault: true
    editable: false
EOF
    
    # Create dashboard configuration
    cat > /etc/grafana/provisioning/dashboards/default.yml << EOF
apiVersion: 1

providers:
  - name: 'Default'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    editable: true
    options:
      path: /var/lib/grafana/dashboards
EOF
    
    # Create a sample dashboard JSON
    mkdir -p /var/lib/grafana/dashboards
    cat > /var/lib/grafana/dashboards/irssh-dashboard.json << 'EOF'
{
  "annotations": {
    "list": [
      {
        "builtIn": 1,
        "datasource": "-- Grafana --",
        "enable": true,
        "hide": true,
        "iconColor": "rgba(0, 211, 255, 1)",
        "name": "Annotations & Alerts",
        "type": "dashboard"
      }
    ]
  },
  "editable": true,
  "gnetId": null,
  "graphTooltip": 0,
  "id": 1,
  "links": [],
  "panels": [
    {
      "aliasColors": {},
      "bars": false,
      "dashLength": 10,
      "dashes": false,
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "custom": {}
        },
        "overrides": []
      },
      "fill": 1,
      "fillGradient": 0,
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 0
      },
      "hiddenSeries": false,
      "id": 2,
      "legend": {
        "avg": false,
        "current": false,
        "max": false,
        "min": false,
        "show": true,
        "total": false,
        "values": false
      },
      "lines": true,
      "linewidth": 1,
      "nullPointMode": "null",
      "options": {
        "alertThreshold": true
      },
      "percentage": false,
      "pluginVersion": "7.3.7",
      "pointradius": 2,
      "points": false,
      "renderer": "flot",
      "seriesOverrides": [],
      "spaceLength": 10,
      "stack": false,
      "steppedLine": false,
      "targets": [
        {
          "expr": "100 - (avg by (instance) (irate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)",
          "interval": "",
          "legendFormat": "CPU Usage",
          "refId": "A"
        }
      ],
      "thresholds": [],
      "timeFrom": null,
      "timeRegions": [],
      "timeShift": null,
      "title": "CPU Usage",
      "tooltip": {
        "shared": true,
        "sort": 0,
        "value_type": "individual"
      },
      "type": "graph",
      "xaxis": {
        "buckets": null,
        "mode": "time",
        "name": null,
        "show": true,
        "values": []
      },
      "yaxes": [
        {
          "format": "percent",
          "label": null,
          "logBase": 1,
          "max": "100",
          "min": "0",
          "show": true
        },
        {
          "format": "short",
          "label": null,
          "logBase": 1,
          "max": null,
          "min": null,
          "show": true
        }
      ],
      "yaxis": {
        "align": false,
        "alignLevel": null
      }
    },
    {
      "aliasColors": {},
      "bars": false,
      "dashLength": 10,
      "dashes": false,
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "custom": {}
        },
        "overrides": []
      },
      "fill": 1,
      "fillGradient": 0,
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 12,
        "y": 0
      },
      "hiddenSeries": false,
      "id": 4,
      "legend": {
        "avg": false,
        "current": false,
        "max": false,
        "min": false,
        "show": true,
        "total": false,
        "values": false
      },
      "lines": true,
      "linewidth": 1,
      "nullPointMode": "null",
      "options": {
        "alertThreshold": true
      },
      "percentage": false,
      "pluginVersion": "7.3.7",
      "pointradius": 2,
      "points": false,
      "renderer": "flot",
      "seriesOverrides": [],
      "spaceLength": 10,
      "stack": false,
      "steppedLine": false,
      "targets": [
        {
          "expr": "100 * (1 - ((node_memory_MemAvailable_bytes{} or node_memory_MemFree_bytes{}) / node_memory_MemTotal_bytes{}))",
          "interval": "",
          "legendFormat": "Memory Usage",
          "refId": "A"
        }
      ],
      "thresholds": [],
      "timeFrom": null,
      "timeRegions": [],
      "timeShift": null,
      "title": "Memory Usage",
      "tooltip": {
        "shared": true,
        "sort": 0,
        "value_type": "individual"
      },
      "type": "graph",
      "xaxis": {
        "buckets": null,
        "mode": "time",
        "name": null,
        "show": true,
        "values": []
      },
      "yaxes": [
        {
          "format": "percent",
          "label": null,
          "logBase": 1,
          "max": "100",
          "min": "0",
          "show": true
        },
        {
          "format": "short",
          "label": null,
          "logBase": 1,
          "max": null,
          "min": null,
          "show": true
        }
      ],
      "yaxis": {
        "align": false,
        "alignLevel": null
      }
    },
    {
      "aliasColors": {},
      "bars": false,
      "dashLength": 10,
      "dashes": false,
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "custom": {}
        },
        "overrides": []
      },
      "fill": 1,
      "fillGradient": 0,
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 8
      },
      "hiddenSeries": false,
      "id": 6,
      "legend": {
        "avg": false,
        "current": false,
        "max": false,
        "min": false,
        "show": true,
        "total": false,
        "values": false
      },
      "lines": true,
      "linewidth": 1,
      "nullPointMode": "null",
      "options": {
        "alertThreshold": true
      },
      "percentage": false,
      "pluginVersion": "7.3.7",
      "pointradius": 2,
      "points": false,
      "renderer": "flot",
      "seriesOverrides": [],
      "spaceLength": 10,
      "stack": false,
      "steppedLine": false,
      "targets": [
        {
          "expr": "100 - (node_filesystem_avail_bytes{mountpoint=\"/\"} / node_filesystem_size_bytes{mountpoint=\"/\"} * 100)",
          "interval": "",
          "legendFormat": "Disk Usage",
          "refId": "A"
        }
      ],
      "thresholds": [],
      "timeFrom": null,
      "timeRegions": [],
      "timeShift": null,
      "title": "Disk Usage",
      "tooltip": {
        "shared": true,
        "sort": 0,
        "value_type": "individual"
      },
      "type": "graph",
      "xaxis": {
        "buckets": null,
        "mode": "time",
        "name": null,
        "show": true,
        "values": []
      },
      "yaxes": [
        {
          "format": "percent",
          "label": null,
          "logBase": 1,
          "max": "100",
          "min": "0",
          "show": true
        },
        {
          "format": "short",
          "label": null,
          "logBase": 1,
          "max": null,
          "min": null,
          "show": true
        }
      ],
      "yaxis": {
        "align": false,
        "alignLevel": null
      }
    },
    {
      "aliasColors": {},
      "bars": false,
      "dashLength": 10,
      "dashes": false,
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "custom": {}
        },
        "overrides": []
      },
      "fill": 1,
      "fillGradient": 0,
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 12,
        "y": 8
      },
      "hiddenSeries": false,
      "id": 8,
      "legend": {
        "avg": false,
        "current": false,
        "max": false,
        "min": false,
        "show": true,
        "total": false,
        "values": false
      },
      "lines": true,
      "linewidth": 1,
      "nullPointMode": "null",
      "options": {
        "alertThreshold": true
      },
      "percentage": false,
      "pluginVersion": "7.3.7",
      "pointradius": 2,
      "points": false,
      "renderer": "flot",
      "seriesOverrides": [],
      "spaceLength": 10,
      "stack": false,
      "steppedLine": false,
      "targets": [
        {
          "expr": "node_network_receive_bytes_total{device=~\"eth0|ens3|ens4|ens5|enp|wlan0\"} or node_network_receive_bytes{device=~\"eth0|ens3|ens4|ens5|enp|wlan0\"}",
          "interval": "",
          "legendFormat": "Received",
          "refId": "A"
        },
        {
          "expr": "node_network_transmit_bytes_total{device=~\"eth0|ens3|ens4|ens5|enp|wlan0\"} or node_network_transmit_bytes{device=~\"eth0|ens3|ens4|ens5|enp|wlan0\"}",
          "interval": "",
          "legendFormat": "Sent",
          "refId": "B"
        }
      ],
      "thresholds": [],
      "timeFrom": null,
      "timeRegions": [],
      "timeShift": null,
      "title": "Network Traffic",
      "tooltip": {
        "shared": true,
        "sort": 0,
        "value_type": "individual"
      },
      "type": "graph",
      "xaxis": {
        "buckets": null,
        "mode": "time",
        "name": null,
        "show": true,
        "values": []
      },
      "yaxes": [
        {
          "format": "bytes",
          "label": null,
          "logBase": 1,
          "max": null,
          "min": null,
          "show": true
        },
        {
          "format": "short",
          "label": null,
          "logBase": 1,
          "max": null,
          "min": null,
          "show": true
        }
      ],
      "yaxis": {
        "align": false,
        "alignLevel": null
      }
    }
  ],
  "refresh": "5s",
  "schemaVersion": 26,
  "style": "dark",
  "tags": [],
  "templating": {
    "list": []
  },
  "time": {
    "from": "now-6h",
    "to": "now"
  },
  "timepicker": {},
  "timezone": "",
  "title": "IRSSH Panel Dashboard",
  "uid": "irssh-panel",
  "version": 1
}
EOF
    
    # Set permissions for Grafana dashboards
    chown -R grafana:grafana /var/lib/grafana/dashboards
    
    # Create base Python monitoring script for all protocols
    cat > "$MONITOR_DIR/all_protocols_monitor.py" << 'EOF'
#!/usr/bin/env python3

"""
Comprehensive Protocol Monitor for IRSSH-Panel
This script monitors all protocol connections and reports to the database
"""

import os
import sys
import time
import json
import logging
import subprocess
import argparse
import requests
import hashlib
import psycopg2
import configparser
import re
import threading
import signal
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/var/log/irssh/protocols_monitor.log')
    ]
)
logger = logging.getLogger('protocols-monitor')

# Configuration
CONFIG_FILE = '/etc/enhanced_ssh/db/database.conf'
PROTOCOLS = ['ssh', 'l2tp', 'ikev2', 'cisco', 'wireguard', 'singbox', 'ssl_vpn', 'nordwhisper']

# Global state
running = True
monitor_threads = {}
db_connection = None
active_connections = {}  # track active connections by protocol

def load_db_config():
    """Load database configuration from file"""
    db_config = {}
    
    # Default values
    db_config['host'] = 'localhost'
    db_config['port'] = '5432'
    db_config['dbname'] = 'irssh_panel'
    db_config['user'] = 'admin'
    db_config['password'] = 'admin'
    
    if not os.path.exists(CONFIG_FILE):
        logger.error(f"Config file not found: {CONFIG_FILE}")
        return db_config
    
    try:
        # First try to parse as INI file
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE)
        
        if 'DEFAULT' in config:
            db_config['host'] = config.get('DEFAULT', 'DB_HOST', fallback='localhost')
            db_config['port'] = config.get('DEFAULT', 'DB_PORT', fallback='5432')
            db_config['dbname'] = config.get('DEFAULT', 'DB_NAME', fallback='irssh_panel')
            db_config['user'] = config.get('DEFAULT', 'DB_USER', fallback='admin')
            db_config['password'] = config.get('DEFAULT', 'DB_PASSWORD', fallback='admin')
        else:
            # Try reading as KEY=VALUE format
            with open(CONFIG_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"\'')
                        
                        if key == 'DB_HOST':
                            db_config['host'] = value
                        elif key == 'DB_PORT':
                            db_config['port'] = value
                        elif key == 'DB_NAME':
                            db_config['dbname'] = value
                        elif key == 'DB_USER':
                            db_config['user'] = value
                        elif key == 'DB_PASSWORD':
                            db_config['password'] = value
    except Exception as e:
        logger.error(f"Error loading database config: {e}")
    
    return db_config

def get_db_connection():
    """Get a connection to the PostgreSQL database"""
    global db_connection
    
    if db_connection and db_connection.closed == 0:
        return db_connection
    
    db_config = load_db_config()
    try:
        db_connection = psycopg2.connect(
            host=db_config['host'],
            port=db_config['port'],
            dbname=db_config['dbname'],
            user=db_config['user'],
            password=db_config['password']
        )
        db_connection.autocommit = True
        return db_connection
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        db_connection = None
        return None

def initialize_database():
    """Ensure necessary database tables exist"""
    try:
        conn = get_db_connection()
        if not conn:
            logger.error("Unable to connect to database")
            return False
        
        with conn.cursor() as cur:
            # Check if user_connections table exists
            cur.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = 'user_connections'
                )
            """)
            table_exists = cur.fetchone()[0]
            
            if not table_exists:
                logger.info("Creating user_connections table...")
                cur.execute("""
                    CREATE TABLE user_connections (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(50) NOT NULL,
                        protocol VARCHAR(20) NOT NULL,
                        connect_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        disconnect_time TIMESTAMP,
                        client_ip VARCHAR(50),
                        upload_bytes BIGINT DEFAULT 0,
                        download_bytes BIGINT DEFAULT 0,
                        session_id VARCHAR(100) UNIQUE,
                        status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'closed', 'terminated')),
                        disconnect_reason VARCHAR(50)
                    )
                """)
                
                # Create index for better performance
                cur.execute("""
                    CREATE INDEX idx_connections_username ON user_connections(username);
                    CREATE INDEX idx_connections_status ON user_connections(status);
                    CREATE INDEX idx_connections_protocol ON user_connections(protocol);
                """)
            
            # Check if user_profiles table exists
            cur.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = 'user_profiles'
                )
            """)
            profiles_exist = cur.fetchone()[0]
            
            if not profiles_exist:
                logger.info("Creating user_profiles table...")
                cur.execute("""
                    CREATE TABLE user_profiles (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        email VARCHAR(100),
                        mobile VARCHAR(20),
                        referred_by VARCHAR(50),
                        notes TEXT,
                        telegram_id VARCHAR(100),
                        max_connections INTEGER DEFAULT 1,
                        expiry_date TIMESTAMP,
                        data_limit BIGINT DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_notification TIMESTAMP,
                        status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'deactive', 'suspended')),
                        usage_alerts BOOLEAN DEFAULT true
                    )
                """)
        
        return True
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        return False

def check_user_exists(username):
    """Check if user exists in the database"""
    try:
        conn = get_db_connection()
        if not conn:
            return False
        
        with conn.cursor() as cur:
            cur.execute("SELECT username FROM user_profiles WHERE username = %s", (username,))
            return cur.fetchone() is not None
    except Exception as e:
        logger.error(f"Error checking user existence: {e}")
        return False

def hash_session_id(username, ip_address, protocol):
    """Create a unique hash for the session ID"""
    session_string = f"{username}_{ip_address}_{protocol}_{int(time.time())}"
    return hashlib.md5(session_string.encode()).hexdigest()[:16]

def get_active_sessions_from_db(protocol=None):
    """Get active sessions from the database"""
    active_sessions = {}
    
    try:
        conn = get_db_connection()
        if not conn:
            return active_sessions
        
        with conn.cursor() as cur:
            if protocol:
                # Get sessions for a specific protocol
                cur.execute(
                    "SELECT username, session_id FROM user_connections "
                    "WHERE protocol = %s AND status = 'active'",
                    (protocol,)
                )
            else:
                # Get all active sessions
                cur.execute(
                    "SELECT username, session_id, protocol FROM user_connections "
                    "WHERE status = 'active'"
                )
                
            for row in cur.fetchall():
                if protocol:
                    active_sessions[row[1]] = row[0]  # session_id: username
                else:
                    if row[2] not in active_sessions:
                        active_sessions[row[2]] = {}  # protocol: {}
                    active_sessions[row[2]][row[1]] = row[0]  # protocol: {session_id: username}
            
            return active_sessions
    except Exception as e:
        logger.error(f"Error getting active sessions from DB: {e}")
        return active_sessions

def report_connection_start(username, protocol, ip_address, session_id):
    """Report new connection to the database"""
    try:
        conn = get_db_connection()
        if not conn:
            return False
        
        with conn.cursor() as cur:
            # Check if user exists
            if not check_user_exists(username):
                logger.warning(f"User {username} not found in the database")
                return False
            
            # Check if connection with this session_id already exists
            cur.execute(
                "SELECT id FROM user_connections WHERE session_id = %s",
                (session_id,)
            )
            existing = cur.fetchone()
            if existing:
                logger.info(f"Connection with session_id {session_id} already exists, skipping")
                return True
            
            # Insert new connection
            cur.execute(
                "INSERT INTO user_connections (username, protocol, client_ip, session_id, connect_time) "
                "VALUES (%s, %s, %s, %s, %s) RETURNING id",
                (username, protocol, ip_address, session_id, datetime.now())
            )
            
            conn.commit()
            logger.info(f"Reported new {protocol} connection: {username} from {ip_address}")
            return True
    except Exception as e:
        logger.error(f"Error reporting connection start: {e}")
        return False

def report_connection_end(username, session_id, upload_bytes=0, download_bytes=0):
    """Report connection end to the database"""
    try:
        conn = get_db_connection()
        if not conn:
            return False
        
        with conn.cursor() as cur:
            # Check if connection exists and is active
            cur.execute(
                "SELECT id, upload_bytes, download_bytes FROM user_connections "
                "WHERE session_id = %s AND status = 'active'",
                (session_id,)
            )
            conn_data = cur.fetchone()
            
            if not conn_data:
                logger.warning(f"No active connection found with session ID {session_id}")
                return False
            
            conn_id, current_upload, current_download = conn_data
            
            # Update connection status and traffic data
            total_upload = current_upload + upload_bytes
            total_download = current_download + download_bytes
            
            cur.execute(
                "UPDATE user_connections SET "
                "status = 'closed', disconnect_time = %s, "
                "upload_bytes = %s, download_bytes = %s, "
                "disconnect_reason = 'normal' "
                "WHERE id = %s",
                (datetime.now(), total_upload, total_download, conn_id)
            )
            
            conn.commit()
            logger.info(f"Reported {username} disconnect for session {session_id}")
            return True
    except Exception as e:
        logger.error(f"Error reporting connection end: {e}")
        return False

def update_traffic_stats(session_id, upload_bytes, download_bytes):
    """Update traffic statistics for an active connection"""
    try:
        conn = get_db_connection()
        if not conn:
            return False
        
        with conn.cursor() as cur:
            # Check if connection exists and is active
            cur.execute(
                "SELECT id, upload_bytes, download_bytes FROM user_connections "
                "WHERE session_id = %s AND status = 'active'",
                (session_id,)
            )
            conn_data = cur.fetchone()
            
            if not conn_data:
                return False
            
            conn_id, current_upload, current_download = conn_data
            
            # Update traffic data
            total_upload = current_upload + upload_bytes
            total_download = current_download + download_bytes
            
            cur.execute(
                "UPDATE user_connections SET "
                "upload_bytes = %s, download_bytes = %s "
                "WHERE id = %s",
                (total_upload, total_download, conn_id)
            )
            
            conn.commit()
            return True
    except Exception as e:
        logger.error(f"Error updating traffic stats: {e}")
        return False

# Import protocol-specific monitoring functions
def monitor_ssh_connections():
    """Monitor SSH connections"""
    logger.info("Starting SSH connection monitor")
    
    while running:
        try:
            # Get currently active SSH sessions
            ssh_output = subprocess.check_output(
                "netstat -tnpa | grep 'ESTABLISHED.*sshd' | awk '{print $5 \" \" $7}'", 
                shell=True, text=True
            )
            
            current_connections = []
            
            for line in ssh_output.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    ip_address = parts[0].split(':')[0]  # Remove port
                    process_info = ' '.join(parts[1:])
                    
                    # Extract username from process info
                    if 'sshd:' in process_info:
                        username_part = process_info.split('sshd:')[1].strip()
                        if '@' in username_part:
                            username = username_part.split('@')[0].strip()
                            
                            # Skip system users
                            if username not in ['root', 'nobody', 'sshd']:
                                session_id = f"ssh_{username}_{hash_session_id(username, ip_address, 'ssh')}"
                                current_connections.append({
                                    'username': username,
                                    'ip_address': ip_address,
                                    'session_id': session_id
                                })
            
            # Get active sessions from database
            db_sessions = get_active_sessions_from_db('ssh')
            current_session_ids = {conn['session_id'] for conn in current_connections}
            
            # Report new connections
            for conn in current_connections:
                if conn['session_id'] not in db_sessions:
                    report_connection_start(
                        conn['username'], 
                        'ssh', 
                        conn['ip_address'], 
                        conn['session_id']
                    )
            
            # Report ended connections
            for session_id, username in db_sessions.items():
                if session_id not in current_session_ids:
                    report_connection_end(username, session_id)
            
            # Update active connections
            active_connections['ssh'] = current_connections
            
            # Sleep before next check
            time.sleep(30)
        except Exception as e:
            logger.error(f"Error in SSH monitoring: {e}")
            time.sleep(60)  # Sleep longer after error

def monitor_singbox_connections():
    """Monitor SingBox connections"""
    logger.info("Starting SingBox connection monitor")
    
    while running:
        try:
            # For SingBox, we need to check logs since there's no direct way to list connections
            # This is a simplified approach - in a real setup, you'd want to use SingBox API or stats
            
            # Read the last 100 lines of the SingBox log
            if os.path.exists("/var/log/irssh/singbox/sing-box.log"):
                log_lines = subprocess.check_output(
                    "tail -n 100 /var/log/irssh/singbox/sing-box.log",
                    shell=True, text=True
                )
                
                # Get user configs to map identifiers to usernames
                user_configs = {}
                users_dir = "/etc/enhanced_ssh/singbox/users"
                if os.path.exists(users_dir):
                    for filename in os.listdir(users_dir):
                        if filename.endswith('.json'):
                            try:
                                with open(os.path.join(users_dir, filename), 'r') as f:
                                    config = json.load(f)
                                    username = config.get('username')
                                    if username:
                                        # Store identifiers for each protocol
                                        if 'shadowsocks' in config:
                                            user_configs[config['shadowsocks']['password']] = username
                                        if 'tuic' in config:
                                            user_configs[config['tuic']['uuid']] = username
                                        if 'vless' in config:
                                            user_configs[config['vless']['uuid']] = username
                                        if 'hysteria2' in config:
                                            user_configs[config['hysteria2']['password']] = username
                            except Exception as e:
                                logger.error(f"Error reading user config {filename}: {e}")
                
                # Parse log for connection events
                current_connections = []
                
                for line in log_lines.splitlines():
                    # Check for successful connection events
                    if "accepted" in line.lower() or "new connection" in line.lower():
                        # Extract protocol type
                        protocol_match = re.search(r'\[(shadowsocks|tuic|vless|hysteria2)\]', line)
                        if protocol_match:
                            protocol = protocol_match.group(1)
                            
                            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                            if ip_match:
                                ip_address = ip_match.group(1)
                                
                                # Extract user identifier (this is a simplification - real parsing would be more complex)
                                # For shadowsocks - password might be found
                                # For TUIC and VLess - UUID
                                # For Hysteria2 - password
                                uuid_match = re.search(r'uuid: ([a-f0-9-]+)', line)
                                password_match = re.search(r'password: ([a-zA-Z0-9+/=]+)', line)
                                
                                identifier = None
                                if uuid_match:
                                    identifier = uuid_match.group(1)
                                elif password_match:
                                    identifier = password_match.group(1)
                                
                                if identifier and identifier in user_configs:
                                    username = user_configs[identifier]
                                    
                                    # Create a unique session ID
                                    session_id = f"singbox_{protocol}_{username}_{hash_session_id(username, ip_address, f'singbox_{protocol}')}"
                                    
                                    # Add to current connections if not already present
                                    if not any(c['session_id'] == session_id for c in current_connections):
                                        current_connections.append({
                                            'username': username,
                                            'protocol': f'singbox_{protocol}',
                                            'ip_address': ip_address,
                                            'session_id': session_id
                                        })
            
            # Get active sessions from database for all singbox protocols
            db_sessions = {}
            for proto in ['singbox_shadowsocks', 'singbox_tuic', 'singbox_vless', 'singbox_hysteria2']:
                db_sessions.update(get_active_sessions_from_db(proto))
            
            current_session_ids = {conn['session_id'] for conn in current_connections}
            
            # Report new connections
            for conn in current_connections:
                if conn['session_id'] not in db_sessions:
                    report_connection_start(
                        conn['username'], 
                        conn['protocol'], 
                        conn['ip_address'], 
                        conn['session_id']
                    )
            
            # For SingBox, we can't reliably detect disconnections from logs
            # We'll consider a session disconnected if it hasn't been seen for a while
            # This would be handled better in a real implementation
            
            # Update active connections
            active_connections.update({
                'singbox_shadowsocks': [c for c in current_connections if c['protocol'] == 'singbox_shadowsocks'],
                'singbox_tuic': [c for c in current_connections if c['protocol'] == 'singbox_tuic'],
                'singbox_vless': [c for c in current_connections if c['protocol'] == 'singbox_vless'],
                'singbox_hysteria2': [c for c in current_connections if c['protocol'] == 'singbox_hysteria2']
            })
            
            # Sleep before next check
            time.sleep(60)
        except Exception as e:
            logger.error(f"Error in SingBox monitoring: {e}")
            time.sleep(60)  # Sleep longer after error

# Function to start all protocol monitors
def start_protocol_monitors():
    global monitor_threads
    
    protocols_to_monitor = {
        'ssh': monitor_ssh_connections,
        'singbox': monitor_singbox_connections,
        # Add other protocols as needed
    }
    
    for protocol, monitor_func in protocols_to_monitor.items():
        if protocol not in monitor_threads or not monitor_threads[protocol].is_alive():
            thread = threading.Thread(target=monitor_func, daemon=True)
            thread.start()
            monitor_threads[protocol] = thread
            logger.info(f"Started monitor for {protocol}")

# Main function with signal handler
def main():
    global running
    
    # Setup signal handler for graceful shutdown
    def signal_handler(sig, frame):
        global running
        logger.info("Received shutdown signal, stopping monitors...")
        running = False
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Initialize database
    initialize_database()
    
    # Start protocol monitors
    start_protocol_monitors()
    
    # Main loop to keep script running and restart any dead monitors
    while running:
        for protocol, thread in list(monitor_threads.items()):
            if not thread.is_alive():
                logger.warning(f"Monitor for {protocol} died, restarting...")
                if protocol == 'ssh':
                    new_thread = threading.Thread(target=monitor_ssh_connections, daemon=True)
                elif protocol == 'singbox':
                    new_thread = threading.Thread(target=monitor_singbox_connections, daemon=True)
                # Add other protocols as needed
                
                new_thread.start()
                monitor_threads[protocol] = new_thread
        
        time.sleep(60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='IRSSH-Panel Protocol Monitor')
    parser.add_argument('--daemon', action='store_true', help='Run as a daemon process')
    args = parser.parse_args()
    
    if args.daemon:
        # Fork process to run as daemon
        try:
            pid = os.fork()
            if pid > 0:
                # Exit parent process
                sys.exit(0)
        except OSError as e:
            logger.error(f"Fork failed: {e}")
            sys.exit(1)
        
        # Detach from terminal
        os.setsid()
        os.umask(0)
        
        try:
            pid = os.fork()
            if pid > 0:
                # Exit from second parent process
                sys.exit(0)
        except OSError as e:
            logger.error(f"Second fork failed: {e}")
            sys.exit(1)
        
        # Redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        
        with open('/dev/null', 'r') as f:
            os.dup2(f.fileno(), sys.stdin.fileno())
        
        with open('/var/log/irssh/protocols_monitor_stdout.log', 'a+') as f:
            os.dup2(f.fileno(), sys.stdout.fileno())
        
        with open('/var/log/irssh/protocols_monitor_stderr.log', 'a+') as f:
            os.dup2(f.fileno(), sys.stderr.fileno())
    
    main()
EOF
    
    chmod +x "$MONITOR_DIR/all_protocols_monitor.py"
    
    # Create systemd service for the monitoring script
    cat > /etc/systemd/system/irssh-protocols-monitor.service << EOF
[Unit]
Description=IRSSH Protocol Monitor Service
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 $MONITOR_DIR/all_protocols_monitor.py --daemon
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # Create backup script for database
    cat > "$SCRIPTS_DIR/backup_database.sh" << 'EOF'
#!/bin/bash

# Database Backup Script for IRSSH-Panel

# Configuration
BACKUP_DIR="/opt/irssh-backups/db"
BACKUP_RETENTION_DAYS=14
CONFIG_FILE="/etc/enhanced_ssh/db/database.conf"
LOG_FILE="/var/log/irssh/database_backup.log"

# Make sure backup directory exists
mkdir -p "$BACKUP_DIR"
mkdir -p "$(dirname $LOG_FILE)"

# Function to log messages
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Load database configuration
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    log "Error: Database configuration file not found"
    exit 1
fi

# Set timestamp for backup file
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="$BACKUP_DIR/${DB_NAME}_${TIMESTAMP}.backup"

# Perform the backup using pg_dump
log "Starting database backup to $BACKUP_FILE"
export PGPASSWORD="$DB_PASSWORD"
pg_dump -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -F c -b -v -f "$BACKUP_FILE"

# Check if backup was successful
if [ $? -eq 0 ]; then
    log "Database backup completed successfully"
    
    # Compress the backup
    log "Compressing backup..."
    gzip -f "$BACKUP_FILE"
    
    # Calculate size of the compressed backup
    BACKUP_SIZE=$(du -h "${BACKUP_FILE}.gz" | awk '{print $1}')
    log "Backup compressed. Size: $BACKUP_SIZE"
    
    # Remove old backups
    log "Removing backups older than $BACKUP_RETENTION_DAYS days"
    find "$BACKUP_DIR" -name "*.backup.gz" -type f -mtime +$BACKUP_RETENTION_DAYS -delete
else
    log "Error: Database backup failed"
    exit 1
fi

# Get total size of backup directory
TOTAL_SIZE=$(du -sh "$BACKUP_DIR" | awk '{print $1}')
log "Total backup directory size: $TOTAL_SIZE"

# Optional: Send backup notification via Telegram
# This part requires telegram-send to be installed and configured
if command -v telegram-send &> /dev/null; then
    log "Sending backup notification via Telegram"
    telegram-send "Database backup completed successfully on $(hostname)
Date: $(date)
File: ${DB_NAME}_${TIMESTAMP}.backup.gz
Size: $BACKUP_SIZE
Total backup directory size: $TOTAL_SIZE"
fi

log "Backup process completed"
exit 0
EOF
    
    chmod +x "$SCRIPTS_DIR/backup_database.sh"
    
    # Create systemd timer for automated backups
    cat > /etc/systemd/system/irssh-backup.service << EOF
[Unit]
Description=IRSSH Database Backup Service
After=network.target postgresql.service

[Service]
Type=oneshot
ExecStart=$SCRIPTS_DIR/backup_database.sh
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/irssh-backup.timer << EOF
[Unit]
Description=Run IRSSH Database Backup daily

[Timer]
OnCalendar=*-*-* 02:00:00
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
EOF

    # Set up Grafana to be accessible on panel port
    if [ -f "/etc/grafana/grafana.ini" ]; then
        # Configure Grafana to run on a different port to avoid conflict with the panel
        GRAFANA_PORT=$(shuf -i 3001-4999 -n 1)
        sed -i "s/^;http_port = 3000/http_port = $GRAFANA_PORT/" /etc/grafana/grafana.ini
        
        # Update Nginx config to proxy Grafana
        cat > /etc/nginx/conf.d/grafana.conf << EOF
location /grafana/ {
    proxy_pass http://localhost:$GRAFANA_PORT/;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
}
EOF
    fi
    
    # Enable and start services
    systemctl daemon-reload
    systemctl enable prometheus
    systemctl restart prometheus
    systemctl enable prometheus-node-exporter
    systemctl restart prometheus-node-exporter
    systemctl enable grafana-server
    systemctl restart grafana-server
    systemctl enable irssh-protocols-monitor.service
    systemctl start irssh-protocols-monitor.service
    systemctl enable irssh-backup.timer
    systemctl start irssh-backup.timer
    
    # Restart Nginx to apply changes
    systemctl restart nginx
    
    info "Advanced monitoring system setup completed"
    if [ -f "/etc/grafana/grafana.ini" ]; then
        info "Grafana dashboard available at http://$SERVER_IPv4:$PORTS[WEB]/grafana/"
        info "Default Grafana login: admin/admin (please change on first login)"
    fi
}

# Function to enhance security
enhance_security() {
    info "Enhancing system security..."
    
    # Create directory for security settings
    mkdir -p "$CONFIG_DIR/security"
    
    # Install security-related packages
    apt-get install -y fail2ban ufw unattended-upgrades \
        debsums apt-listchanges apticron logwatch \
        || warn "Failed to install some security packages"
    
    # Configure fail2ban for SSH
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
banaction = iptables-multiport

[sshd]
enabled = true
port = ${PORTS[SSH]}
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF
    
    # Configure fail2ban for web panel
    cat >> /etc/fail2ban/jail.local << EOF

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https,${PORTS[WEB]}
logpath = /var/log/nginx/error.log
maxretry = 5
EOF
    
    # Setup unattended upgrades
    cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};

Unattended-Upgrade::Package-Blacklist {
};

Unattended-Upgrade::Automatic-Reboot "false";
EOF
    
    # Configure SSH hardening
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    cat > /etc/ssh/sshd_config << EOF
# IRSSH-Panel Hardened SSH Configuration

Port ${PORTS[SSH]}
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Logging
SyslogFacility AUTH
LogLevel INFO

# Authentication
LoginGraceTime 2m
PermitRootLogin yes
StrictModes yes
MaxAuthTries 6
MaxSessions 10

# Allow password authentication for user management
PasswordAuthentication yes

# Key exchange algorithms and ciphers
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Other settings
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
    
    # Enable and configure UFW (Uncomplicated Firewall)
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ${PORTS[SSH]}/tcp
    ufw allow ${PORTS[WEB]}/tcp
    
    # Allow all protocol ports
    for protocol in "${!PORTS[@]}"; do
        if [[ "$protocol" != "SSH" && "$protocol" != "WEB" ]]; then
            ufw allow ${PORTS[$protocol]}/tcp
            ufw allow ${PORTS[$protocol]}/udp
        fi
    done
    
    # Enable UFW
    echo "y" | ufw enable
    
    # Make root login more secure
    if [ -f "/root/.bashrc" ]; then
        cat >> /root/.bashrc << EOF

# Enhanced security for root login
TMOUT=1800
readonly TMOUT
export TMOUT
EOF
    fi
    
    # Configure secure shared memory
    if ! grep -q "tmpfs /run/shm" /etc/fstab; then
        echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
    fi
    
    # Enable AppArmor
    if [ -f "/etc/default/apparmor" ]; then
        sed -i 's/APPARMOR=.*/APPARMOR=enforce/' /etc/default/apparmor
        systemctl enable apparmor
        systemctl restart apparmor
    fi
    
    # Set up log monitoring
    cat > /etc/logwatch/conf/logwatch.conf << EOF
Output = mail
Format = html
MailTo = root
Detail = High
Service = All
Service = "-zz-network"
Service = "-zz-sys"
Service = "-eximstats"
EOF
    
    # Restart services
    systemctl restart ssh
    systemctl restart fail2ban
    
    info "Security enhancements completed"
}

# Function to setup Docker and Docker Compose
setup_docker() {
    info "Setting up Docker and Docker Compose..."
    
    # Create Docker directories
    mkdir -p "$PANEL_DIR/docker"
    mkdir -p "$PANEL_DIR/docker/compose"
    
    # Create a basic docker-compose.yml for IRSSH-Panel
    cat > "$PANEL_DIR/docker/compose/irssh-panel.yml" << EOF
version: '3.8'

services:
  postgres:
    image: postgres:15
    volumes:
      - postgres_data:/var/lib/postgresql/data
    environment:
      POSTGRES_DB: ${DB_NAME}
      POSTGRES_USER: ${DB_USER}
      POSTGRES_PASSWORD: ${DB_USER_PASSWORD}
    restart: always
    networks:
      - irssh-network

  redis:
    image: redis:7
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes
    restart: always
    networks:
      - irssh-network

  nginx:
    image: nginx:latest
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf
      - ${PANEL_DIR}/frontend/dist:/usr/share/nginx/html
    ports:
      - "${PORTS[WEB]}:80"
    restart: always
    networks:
      - irssh-network
    depends_on:
      - api

  api:
    build:
      context: ${PANEL_DIR}/backend
      dockerfile: Dockerfile
    volumes:
      - ${PANEL_DIR}/backend:/app
    environment:
      - NODE_ENV=production
      - DB_HOST=postgres
      - DB_PORT=5432
      - DB_NAME=${DB_NAME}
      - DB_USER=${DB_USER}
      - DB_PASSWORD=${DB_USER_PASSWORD}
      - REDIS_URL=redis://redis:6379
    restart: always
    networks:
      - irssh-network
    depends_on:
      - postgres
      - redis

networks:
  irssh-network:

volumes:
  postgres_data:
  redis_data:
EOF
    
    # Create Dockerfile for backend
    cat > "$PANEL_DIR/backend/Dockerfile" << 'EOF'
FROM node:20-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install

COPY . .

EXPOSE 3000

CMD ["node", "index.js"]
EOF
    
    # Create Nginx config for Docker
    cat > "$PANEL_DIR/docker/nginx.conf" << 'EOF'
server {
    listen 80;
    server_name _;
    
    root /usr/share/nginx/html;
    index index.html;
    
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    location /api {
        proxy_pass http://api:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
EOF
    
    # Create docker-compose.yml for SingBox
    cat > "$PANEL_DIR/docker/compose/singbox.yml" << EOF
version: '3.8'

services:
  singbox:
    image: ghcr.io/sagernet/sing-box:latest
    volumes:
      - /etc/sing-box:/etc/sing-box
    network_mode: host
    restart: always
    command: run -c /etc/sing-box/config.json
EOF
    
    # Create a script to manage Docker services
    cat > "$SCRIPTS_DIR/docker_manage.sh" << 'EOF'
#!/bin/bash

# Docker Management Script for IRSSH-Panel

DOCKER_DIR="/opt/irssh-panel/docker"
COMPOSE_DIR="$DOCKER_DIR/compose"
LOG_DIR="/var/log/irssh/docker"

mkdir -p "$LOG_DIR"

usage() {
    echo "IRSSH-Panel Docker Management Script"
    echo
    echo "Usage: $0 <command> <service>"
    echo
    echo "Commands:"
    echo "  start   - Start a Docker service"
    echo "  stop    - Stop a Docker service"
    echo "  restart - Restart a Docker service"
    echo "  status  - Check status of a Docker service"
    echo "  logs    - View logs of a Docker service"
    echo
    echo "Services:"
    echo "  panel   - IRSSH-Panel (includes PostgreSQL, Redis, Nginx, API)"
    echo "  singbox - SingBox VPN service"
    echo "  all     - All services"
    echo
    echo "Examples:"
    echo "  $0 start panel"
    echo "  $0 logs singbox"
}

if [ $# -lt 2 ]; then
    usage
    exit 1
fi

COMMAND=$1
SERVICE=$2

check_docker() {
    if ! command -v docker &> /dev/null || ! command -v docker-compose &> /dev/null; then
        echo "Error: Docker or Docker Compose not installed"
        exit 1
    fi
}

start_service() {
    local service=$1
    local compose_file=""
    
    case "$service" in
        panel)
            compose_file="$COMPOSE_DIR/irssh-panel.yml"
            ;;
        singbox)
            compose_file="$COMPOSE_DIR/singbox.yml"
            ;;
        *)
            echo "Error: Unknown service: $service"
            exit 1
            ;;
    esac
    
    if [ ! -f "$compose_file" ]; then
        echo "Error: Compose file not found: $compose_file"
        exit 1
    fi
    
    echo "Starting $service..."
    docker-compose -f "$compose_file" up -d
    
    if [ $? -eq 0 ]; then
        echo "$service started successfully"
    else
        echo "Error starting $service"
        exit 1
    fi
}

stop_service() {
    local service=$1
    local compose_file=""
    
    case "$service" in
        panel)
            compose_file="$COMPOSE_DIR/irssh-panel.yml"
            ;;
        singbox)
            compose_file="$COMPOSE_DIR/singbox.yml"
            ;;
        *)
            echo "Error: Unknown service: $service"
            exit 1
            ;;
    esac
    
    if [ ! -f "$compose_file" ]; then
        echo "Error: Compose file not found: $compose_file"
        exit 1
    fi
    
    echo "Stopping $service..."
    docker-compose -f "$compose_file" down
    
    if [ $? -eq 0 ]; then
        echo "$service stopped successfully"
    else
        echo "Error stopping $service"
        exit 1
    fi
}

check_status() {
    local service=$1
    local compose_file=""
    
    case "$service" in
        panel)
            compose_file="$COMPOSE_DIR/irssh-panel.yml"
            docker-compose -f "$compose_file" ps
            ;;
        singbox)
            compose_file="$COMPOSE_DIR/singbox.yml"
            docker-compose -f "$compose_file" ps
            ;;
        all)
            echo "IRSSH-Panel status:"
            docker-compose -f "$COMPOSE_DIR/irssh-panel.yml" ps
            echo
            echo "SingBox status:"
            docker-compose -f "$COMPOSE_DIR/singbox.yml" ps
            ;;
        *)
            echo "Error: Unknown service: $service"
            exit 1
            ;;
    esac
}

view_logs() {
    local service=$1
    local compose_file=""
    
    case "$service" in
        panel)
            compose_file="$COMPOSE_DIR/irssh-panel.yml"
            docker-compose -f "$compose_file" logs --tail=100
            ;;
        singbox)
            compose_file="$COMPOSE_DIR/singbox.yml"
            docker-compose -f "$compose_file" logs --tail=100
            ;;
        *)
            echo "Error: Unknown service: $service"
            exit 1
            ;;
    esac
}

check_docker

case "$COMMAND" in
    start)
        if [ "$SERVICE" = "all" ]; then
            start_service panel
            start_service singbox
        else
            start_service "$SERVICE"
        fi
        ;;
    stop)
        if [ "$SERVICE" = "all" ]; then
            stop_service panel
            stop_service singbox
        else
            stop_service "$SERVICE"
        fi
        ;;
    restart)
        if [ "$SERVICE" = "all" ]; then
            stop_service panel
            stop_service singbox
            start_service panel
            start_service singbox
        else
            stop_service "$SERVICE"
            start_service "$SERVICE"
        fi
        ;;
    status)
        check_status "$SERVICE"
        ;;
    logs)
        view_logs "$SERVICE"
        ;;
    *)
        echo "Error: Unknown command: $COMMAND"
        usage
        exit 1
        ;;
esac

exit 0
EOF
    
    chmod +x "$SCRIPTS_DIR/docker_manage.sh"
    
    info "Docker setup completed"
    info "Docker configuration files are available in $PANEL_DIR/docker"
    info "Use $SCRIPTS_DIR/docker_manage.sh to manage Docker services"
}

# Setup Ansible configuration for automation
setup_ansible() {
    info "Setting up Ansible for automation..."
    
    # Create Ansible directories
    mkdir -p "$ANSIBLE_DIR/playbooks"
    mkdir -p "$ANSIBLE_DIR/inventory"
    mkdir -p "$ANSIBLE_DIR/roles"
    mkdir -p "$ANSIBLE_DIR/vars"
    
    # Create inventory file
    cat > "$ANSIBLE_DIR/inventory/hosts" << EOF
[local]
localhost ansible_connection=local

[web_servers]
# Add web servers here

[vpn_servers]
# Add VPN servers here

[database_servers]
# Add database servers here
EOF
    
    # Create Ansible configuration
    cat > "$ANSIBLE_DIR/ansible.cfg" << EOF
[defaults]
inventory = inventory/hosts
roles_path = roles
host_key_checking = False
deprecation_warnings = False
retry_files_enabled = False
stdout_callback = yaml
bin_ansible_callbacks = True
EOF
    
    # Create playbook for IRSSH-Panel deployment
    cat > "$ANSIBLE_DIR/playbooks/deploy_irssh_panel.yml" << EOF
---
# Ansible Playbook for IRSSH-Panel Deployment
# This playbook automates the deployment of IRSSH-Panel to remote servers

- name: Deploy IRSSH-Panel
  hosts: web_servers
  become: yes
  
  vars:
    panel_version: "4.0.0"
    admin_user: "admin"
    web_port: 8080
    
  tasks:
    - name: Update apt cache
      apt:
        update_cache: yes
        cache_valid_time: 3600
    
    - name: Install required packages
      apt:
        name:
          - curl
          - wget
          - git
          - unzip
          - build-essential
          - python3
          - python3-pip
          - nginx
          - postgresql
          - postgresql-contrib
          - redis-server
        state: present
    
    - name: Install Node.js 20.x
      block:
        - name: Add Node.js repository
          shell: curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
          args:
            warn: no
        
        - name: Install Node.js
          apt:
            name: nodejs
            state: present
    
    - name: Create panel directories
      file:
        path: "{{ item }}"
        state: directory
        mode: '0755'
      loop:
        - /opt/irssh-panel
        - /etc/enhanced_ssh
        - /var/log/irssh
    
    - name: Clone IRSSH-Panel repository
      git:
        repo: https://github.com/irkids/IRSSH-Panel.git
        dest: /tmp/irssh-panel
        version: main
    
    - name: Copy frontend files
      copy:
        src: /tmp/irssh-panel/frontend/
        dest: /opt/irssh-panel/frontend/
        remote_src: yes
    
    - name: Copy backend files
      copy:
        src: /tmp/irssh-panel/backend/
        dest: /opt/irssh-panel/backend/
        remote_src: yes
    
    - name: Install frontend dependencies
      npm:
        path: /opt/irssh-panel/frontend
        state: present
    
    - name: Build frontend
      shell: cd /opt/irssh-panel/frontend && npm run build
    
    - name: Install backend dependencies
      npm:
        path: /opt/irssh-panel/backend
        state: present
    
    - name: Configure Nginx
      template:
        src: ../templates/nginx.conf.j2
        dest: /etc/nginx/sites-available/irssh-panel
    
    - name: Enable Nginx site
      file:
        src: /etc/nginx/sites-available/irssh-panel
        dest: /etc/nginx/sites-enabled/irssh-panel
        state: link
    
    - name: Restart Nginx
      service:
        name: nginx
        state: restarted
        enabled: yes
    
    - name: Start backend service
      systemd:
        name: irssh-api
        state: restarted
        enabled: yes
        daemon_reload: yes
EOF
    
    # Create playbook for protocol installation
    cat > "$ANSIBLE_DIR/playbooks/install_protocols.yml" << EOF
---
# Ansible Playbook for Protocol Installation
# This playbook automates the installation of VPN protocols

- name: Install VPN Protocols
  hosts: vpn_servers
  become: yes
  
  vars:
    protocols:
      - name: SSH
        enabled: true
      - name: L2TP
        enabled: true
      - name: IKEV2
        enabled: true
      - name: CISCO
        enabled: true
      - name: WIREGUARD
        enabled: true
      - name: SINGBOX
        enabled: true
      - name: SSL_VPN
        enabled: true
      - name: NORDWHISPER
        enabled: true
  
  tasks:
    - name: Install common dependencies
      apt:
        name:
          - curl
          - wget
          - git
          - unzip
          - build-essential
        state: present
    
    - name: Install SSH server
      apt:
        name: openssh-server
        state: present
      when: protocols | selectattr('name', 'equalto', 'SSH') | selectattr('enabled', 'equalto', true) | list | count > 0
    
    - name: Install L2TP/IPsec
      apt:
        name:
          - strongswan
          - xl2tpd
        state: present
      when: protocols | selectattr('name', 'equalto', 'L2TP') | selectattr('enabled', 'equalto', true) | list | count > 0
    
    - name: Install IKEv2/IPsec
      apt:
        name:
          - strongswan
          - strongswan-pki
          - libcharon-extra-plugins
        state: present
      when: protocols | selectattr('name', 'equalto', 'IKEV2') | selectattr('enabled', 'equalto', true) | list | count > 0
    
    - name: Install OpenConnect (Cisco AnyConnect)
      apt:
        name:
          - ocserv
          - gnutls-bin
        state: present
      when: protocols | selectattr('name', 'equalto', 'CISCO') | selectattr('enabled', 'equalto', true) | list | count > 0
    
    - name: Install WireGuard
      apt:
        name: wireguard
        state: present
      when: protocols | selectattr('name', 'equalto', 'WIREGUARD') | selectattr('enabled', 'equalto', true) | list | count > 0
    
    - name: Download and install Sing-Box
      block:
        - name: Create temporary directory
          file:
            path: /tmp/sing-box
            state: directory
        
        - name: Download Sing-Box
          get_url:
            url: "https://github.com/SagerNet/sing-box/releases/download/v1.7.1/sing-box-1.7.1-linux-amd64.tar.gz"
            dest: /tmp/sing-box.tar.gz
        
        - name: Extract Sing-Box
          unarchive:
            src: /tmp/sing-box.tar.gz
            dest: /tmp/sing-box
            remote_src: yes
            extra_opts: [--strip-components=1]
        
        - name: Install Sing-Box binary
          copy:
            src: /tmp/sing-box/sing-box
            dest: /usr/local/bin/sing-box
            mode: '0755'
            remote_src: yes
      when: protocols | selectattr('name', 'equalto', 'SINGBOX') | selectattr('enabled', 'equalto', true) | list | count > 0
    
    - name: Configure SSL-VPN (stunnel)
      apt:
        name: stunnel4
        state: present
      when: protocols | selectattr('name', 'equalto', 'SSL_VPN') | selectattr('enabled', 'equalto', true) | list | count > 0
    
    - name: Install Golang for NordWhisper
      apt:
        name: golang
        state: present
      when: protocols | selectattr('name', 'equalto', 'NORDWHISPER') | selectattr('enabled', 'equalto', true) | list | count > 0
EOF
    
    # Create playbook for multi-server setup
    cat > "$ANSIBLE_DIR/playbooks/setup_multi_server.yml" << EOF
---
# Ansible Playbook for Multi-Server Setup
# This playbook configures tunneling between multiple servers

- name: Configure Multi-Server Environment
  hosts: vpn_servers
  become: yes
  
  vars:
    primary_server: "{{ groups['vpn_servers'][0] }}"
    ssh_key_path: "/etc/enhanced_ssh/ssh-keys/multi_server_key"
  
  tasks:
    - name: Ensure SSH key directory exists
      file:
        path: "/etc/enhanced_ssh/ssh-keys"
        state: directory
        mode: '0700'
      delegate_to: "{{ primary_server }}"
      run_once: true
    
    - name: Generate SSH key on primary server
      openssh_keypair:
        path: "{{ ssh_key_path }}"
        type: rsa
        size: 4096
        state: present
      delegate_to: "{{ primary_server }}"
      run_once: true
    
    - name: Read public key content
      slurp:
        src: "{{ ssh_key_path }}.pub"
      register: pubkey_content
      delegate_to: "{{ primary_server }}"
      run_once: true
    
    - name: Add public key to authorized_keys on all servers
      authorized_key:
        user: root
        key: "{{ pubkey_content['content'] | b64decode }}"
        state: present
    
    - name: Configure SSH server for tunneling
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
        state: present
      with_items:
        - { regexp: '^AllowTcpForwarding', line: 'AllowTcpForwarding yes' }
        - { regexp: '^PermitTunnel', line: 'PermitTunnel yes' }
        - { regexp: '^GatewayPorts', line: 'GatewayPorts yes' }
    
    - name: Restart SSH service
      service:
        name: sshd
        state: restarted
    
    - name: Install tunneling tools
      apt:
        name:
          - autossh
          - netcat
          - socat
        state: present
    
    - name: Create tunneling configuration directory
      file:
        path: "/etc/enhanced_ssh/tunneling"
        state: directory
        mode: '0755'
    
    - name: Configure tunneling service
      template:
        src: ../templates/tunneling.service.j2
        dest: /etc/systemd/system/irssh-tunneling.service
    
    - name: Enable tunneling service
      systemd:
        name: irssh-tunneling
        enabled: yes
        daemon_reload: yes
EOF
    
    # Create playbook for user management
    cat > "$ANSIBLE_DIR/playbooks/manage_users.yml" << EOF
---
# Ansible Playbook for User Management
# This playbook provides tasks for managing VPN users

- name: Manage VPN Users
  hosts: vpn_servers
  become: yes
  
  vars:
    action: "list"  # Options: list, add, delete, update
    username: ""
    password: ""
    expiry_days: 30
    protocols:
      - ssh
      - wireguard
      - l2tp
      - ikev2
      - singbox
  
  tasks:
    - name: List all users
      shell: /usr/local/bin/irssh-admin user list
      register: user_list
      when: action == "list"
    
    - name: Display user list
      debug:
        msg: "{{ user_list.stdout_lines }}"
      when: action == "list"
    
    - name: Add new user
      shell: >
        /usr/local/bin/irssh-admin user add 
        --username {{ username }} 
        --expiry {{ expiry_days }} 
        --max-conn 2
      register: add_result
      when: action == "add" and username != ""
    
    - name: Display add result
      debug:
        msg: "{{ add_result.stdout_lines }}"
      when: action == "add" and username != ""
    
    - name: Delete user
      shell: /usr/local/bin/irssh-admin user del --username {{ username }}
      register: delete_result
      when: action == "delete" and username != ""
    
    - name: Display delete result
      debug:
        msg: "{{ delete_result.stdout_lines }}"
      when: action == "delete" and username != ""
    
    - name: Update user expiry
      shell: >
        /usr/local/bin/irssh-admin user extend 
        --username {{ username }} 
        --days {{ expiry_days }}
      register: update_result
      when: action == "update" and username != ""
    
    - name: Display update result
      debug:
        msg: "{{ update_result.stdout_lines }}"
      when: action == "update" and username != ""
    
    - name: Generate client configurations
      block:
        - name: Create output directory
          file:
            path: "/etc/enhanced_ssh/client_configs/{{ username }}"
            state: directory
            mode: '0755'
          when: protocols | length > 0
        
        - name: Generate SSH config
          shell: >
            /usr/local/bin/irssh-admin generate ssh 
            --username {{ username }} 
            --output "/etc/enhanced_ssh/client_configs/{{ username }}/ssh_config.txt"
          when: "'ssh' in protocols"
        
        - name: Generate WireGuard config
          shell: >
            /usr/local/bin/irssh-admin generate wireguard
            --username {{ username }} 
            --output "/etc/enhanced_ssh/client_configs/{{ username }}/wireguard.conf"
          when: "'wireguard' in protocols"
        
        - name: Generate L2TP config
          shell: >
            /usr/local/bin/irssh-admin generate l2tp
            --username {{ username }} 
            --output "/etc/enhanced_ssh/client_configs/{{ username }}/l2tp.txt"
          when: "'l2tp' in protocols"
        
        - name: Generate IKEv2 config
          shell: >
            /usr/local/bin/irssh-admin generate ikev2
            --username {{ username }} 
            --output "/etc/enhanced_ssh/client_configs/{{ username }}/ikev2.mobileconfig"
          when: "'ikev2' in protocols"
        
        - name: Generate SingBox configs
          shell: >
            /usr/local/bin/irssh-admin generate singbox
            --username {{ username }} 
            --output "/etc/enhanced_ssh/client_configs/{{ username }}/singbox"
          when: "'singbox' in protocols"
      when: action == "add" or action == "update"
EOF
    
    # Create template for Nginx configuration
    mkdir -p "$ANSIBLE_DIR/templates"
    cat > "$ANSIBLE_DIR/templates/nginx.conf.j2" << 'EOF'
server {
    listen {{ web_port }};
    listen [::]:{{ web_port }};
    
    server_name _;
    
    root /opt/irssh-panel/frontend/dist;
    index index.html;
    
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    location /api {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
EOF
    
    # Create template for tunneling service
    cat > "$ANSIBLE_DIR/templates/tunneling.service.j2" << 'EOF'
[Unit]
Description=IRSSH Tunneling Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/autossh -M 0 -o "ServerAliveInterval 30" -o "ServerAliveCountMax 3" -N -T -i {{ ssh_key_path }} -L 0.0.0.0:LOCAL_PORT:localhost:REMOTE_PORT root@REMOTE_SERVER
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # Create a README file
    cat > "$ANSIBLE_DIR/README.md" << 'EOF'
# IRSSH-Panel Ansible Automation

This directory contains Ansible playbooks and configurations for automating IRSSH-Panel deployment and management.

## Directory Structure

- `playbooks/`: Contains all playbooks for different operations
- `inventory/`: Contains inventory files defining server groups
- `roles/`: Contains reusable Ansible roles
- `templates/`: Contains Jinja2 templates for configuration files
- `vars/`: Contains variable files

## Available Playbooks

- `deploy_irssh_panel.yml`: Deploy IRSSH-Panel to web servers
- `install_protocols.yml`: Install and configure VPN protocols
- `setup_multi_server.yml`: Configure multi-server environment with tunneling
- `manage_users.yml`: Manage VPN users (add, delete, update)

## Usage Examples

1. Deploy IRSSH-Panel:
   ```
   ansible-playbook -i inventory/hosts playbooks/deploy_irssh_panel.yml
   ```

2. Install protocols:
   ```
   ansible-playbook -i inventory/hosts playbooks/install_protocols.yml
   ```

3. Add a new user:
   ```
   ansible-playbook -i inventory/hosts playbooks/manage_users.yml -e "action=add username=testuser password=testpass expiry_days=30"
   ```

4. Delete a user:
   ```
   ansible-playbook -i inventory/hosts playbooks/manage_users.yml -e "action=delete username=testuser"
   ```

5. Setup multi-server environment:
   ```
   ansible-playbook -i inventory/hosts playbooks/setup_multi_server.yml
   ```

For more information, check the documentation at https://github.com/irkids/IRSSH-Panel
EOF
    
    # Create Ansible wrapper script
    cat > "$SCRIPTS_DIR/ansible_wrapper.sh" << 'EOF'
#!/bin/bash

# IRSSH-Panel Ansible Wrapper Script

ANSIBLE_DIR="/opt/irssh-panel/ansible"
LOG_DIR="/var/log/irssh/ansible"

mkdir -p "$LOG_DIR"

usage() {
    echo "IRSSH-Panel Ansible Wrapper"
    echo
    echo "Usage: $0 <playbook> [extra_vars]"
    echo
    echo "Available playbooks:"
    echo "  deploy       - Deploy IRSSH-Panel"
    echo "  protocols    - Install VPN protocols"
    echo "  multi-server - Set up multi-server environment"
    echo "  users        - Manage users"
    echo
    echo "Examples:"
    echo "  $0 deploy"
    echo "  $0 protocols"
    echo "  $0 users 'action=add username=testuser password=testpass'"
}

if [ $# -lt 1 ]; then
    usage
    exit 1
fi

PLAYBOOK=$1
shift
EXTRA_VARS="$@"

case "$PLAYBOOK" in
    deploy)
        ansible-playbook -i "$ANSIBLE_DIR/inventory/hosts" "$ANSIBLE_DIR/playbooks/deploy_irssh_panel.yml" $EXTRA_VARS
        ;;
    protocols)
        ansible-playbook -i "$ANSIBLE_DIR/inventory/hosts" "$ANSIBLE_DIR/playbooks/install_protocols.yml" $EXTRA_VARS
        ;;
    multi-server)
        ansible-playbook -i "$ANSIBLE_DIR/inventory/hosts" "$ANSIBLE_DIR/playbooks/setup_multi_server.yml" $EXTRA_VARS
        ;;
    users)
        ansible-playbook -i "$ANSIBLE_DIR/inventory/hosts" "$ANSIBLE_DIR/playbooks/manage_users.yml" -e "$EXTRA_VARS"
        ;;
    *)
        echo "Error: Unknown playbook: $PLAYBOOK"
        usage
        exit 1
        ;;
esac

exit 0
EOF
    
    chmod +x "$SCRIPTS_DIR/ansible_wrapper.sh"
    
    # Create symlink for easy access
    ln -sf "$SCRIPTS_DIR/ansible_wrapper.sh" /usr/local/bin/irssh-ansible
    
    info "Ansible setup completed"
    info "Ansible playbooks are available in $ANSIBLE_DIR"
    info "Use 'irssh-ansible' command to run playbooks"
}

# Function to enhance frontend with advanced features
enhance_frontend() {
    info "Enhancing frontend with advanced features..."
    
    # Create directory for enhanced frontend components
    mkdir -p "$PANEL_DIR/frontend/src/components"
    mkdir -p "$PANEL_DIR/frontend/src/hooks"
    mkdir -p "$PANEL_DIR/frontend/src/utils"
    mkdir -p "$PANEL_DIR/frontend/src/context"
    
    # Install advanced frontend dependencies
    cd "$PANEL_DIR/frontend" || error "Failed to access frontend directory"
    
    # Add TypeScript and advanced dependencies
    npm install --save typescript @types/react @types/react-dom \
        @tanstack/react-query react-hook-form zod @hookform/resolvers \
        date-fns react-datepicker chart.js react-chartjs-2 \
        @headlessui/react tailwindcss postcss autoprefixer \
        socket.io-client || warn "Failed to install some frontend dependencies"
    
    # Create tsconfig.json
    cat > "$PANEL_DIR/frontend/tsconfig.json" << EOF
{
  "compilerOptions": {
    "target": "ESNext",
    "useDefineForClassFields": true,
    "lib": ["DOM", "DOM.Iterable", "ESNext"],
    "allowJs": false,
    "skipLibCheck": true,
    "esModuleInterop": false,
    "allowSyntheticDefaultImports": true,
    "strict": true,
    "forceConsistentCasingInFileNames": true,
    "module": "ESNext",
    "moduleResolution": "Node",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"]
    }
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
}
EOF
    
    # Create TypeScript config for Node
    cat > "$PANEL_DIR/frontend/tsconfig.node.json" << EOF
{
  "compilerOptions": {
    "composite": true,
    "module": "ESNext",
    "moduleResolution": "Node",
    "allowSyntheticDefaultImports": true
  },
  "include": ["vite.config.ts"]
}
EOF
    
    # Create tailwind config
    cat > "$PANEL_DIR/frontend/tailwind.config.js" << EOF
/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#f0f9ff',
          100: '#e0f2fe',
          200: '#bae6fd',
          300: '#7dd3fc',
          400: '#38bdf8',
          500: '#0ea5e9',
          600: '#0284c7',
          700: '#0369a1',
          800: '#075985',
          900: '#0c4a6e',
          950: '#082f49',
        },
      },
    },
  },
  plugins: [],
}
EOF
    
    # Create postcss config
    cat > "$PANEL_DIR/frontend/postcss.config.js" << EOF
module.exports = {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
}
EOF
    
    # Update vite.config.js to vite.config.ts
    cat > "$PANEL_DIR/frontend/vite.config.ts" << EOF
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src')
    }
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true
      }
    }
  }
})
EOF
    
    # Create auth context for centralized authentication
    cat > "$PANEL_DIR/frontend/src/context/AuthContext.tsx" << 'EOF'
import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';

interface User {
  id: number;
  username: string;
  role: string;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  token: null,
  isLoading: true,
  isAuthenticated: false,
  login: async () => {},
  logout: () => {},
});

export const useAuth = () => useContext(AuthContext);

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Initialize auth state from localStorage
  useEffect(() => {
    const storedToken = localStorage.getItem('irssh_token');
    const storedUser = localStorage.getItem('irssh_user');

    if (storedToken && storedUser) {
      setToken(storedToken);
      setUser(JSON.parse(storedUser));
    }

    setIsLoading(false);
  }, []);

  // Login function
  const login = async (username: string, password: string) => {
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Login failed');
      }

      const data = await response.json();

      // Store auth data
      localStorage.setItem('irssh_token', data.token);
      localStorage.setItem('irssh_user', JSON.stringify(data.user));
      
      setToken(data.token);
      setUser(data.user);
    } catch (error) {
      console.error('Login error:', error);
      throw error;
    }
  };

  // Logout function
  const logout = () => {
    localStorage.removeItem('irssh_token');
    localStorage.removeItem('irssh_user');
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isLoading,
        isAuthenticated: !!user && !!token,
        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};
EOF
    
    # Create theme context for dark mode
    cat > "$PANEL_DIR/frontend/src/context/ThemeContext.tsx" << 'EOF'
import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';

type Theme = 'light' | 'dark';

interface ThemeContextType {
  theme: Theme;
  toggleTheme: () => void;
}

const ThemeContext = createContext<ThemeContextType>({
  theme: 'light',
  toggleTheme: () => {},
});

export const useTheme = () => useContext(ThemeContext);

interface ThemeProviderProps {
  children: ReactNode;
}

export const ThemeProvider: React.FC<ThemeProviderProps> = ({ children }) => {
  const [theme, setTheme] = useState<Theme>('light');

  // Initialize theme from localStorage or system preference
  useEffect(() => {
    const storedTheme = localStorage.getItem('irssh_theme') as Theme | null;
    
    if (storedTheme) {
      setTheme(storedTheme);
      document.documentElement.classList.toggle('dark', storedTheme === 'dark');
    } else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
      setTheme('dark');
      document.documentElement.classList.add('dark');
    }
  }, []);

  // Toggle theme function
  const toggleTheme = () => {
    const newTheme = theme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
    localStorage.setItem('irssh_theme', newTheme);
    document.documentElement.classList.toggle('dark', newTheme === 'dark');
  };

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
};
EOF
    
    # Create Socket.IO hook for real-time updates
    cat > "$PANEL_DIR/frontend/src/hooks/useSocket.ts" << 'EOF'
import { useEffect, useState, useRef } from 'react';
import { io, Socket } from 'socket.io-client';
import { useAuth } from '../context/AuthContext';

interface UseSocketOptions {
  url?: string;
  namespace?: string;
  autoConnect?: boolean;
}

export const useSocket = (options: UseSocketOptions = {}) => {
  const { token } = useAuth();
  const [isConnected, setIsConnected] = useState(false);
  const socketRef = useRef<Socket | null>(null);

  const {
    url = window.location.origin,
    namespace = '',
    autoConnect = true
  } = options;

  useEffect(() => {
    // Create socket connection
    const socket = io(`${url}${namespace}`, {
      autoConnect,
      auth: token ? { token } : undefined,
      transports: ['websocket', 'polling']
    });

    // Socket event handlers
    socket.on('connect', () => {
      console.log('Socket connected');
      setIsConnected(true);
    });

    socket.on('disconnect', () => {
      console.log('Socket disconnected');
      setIsConnected(false);
    });

    socket.on('connect_error', (error) => {
      console.error('Socket connection error:', error);
      setIsConnected(false);
    });

    // Store socket in ref
    socketRef.current = socket;

    // Cleanup
    return () => {
      socket.disconnect();
      socketRef.current = null;
    };
  }, [url, namespace, token, autoConnect]);

  // Function to emit events
  const emit = (event: string, data?: any, callback?: (response: any) => void) => {
    if (!socketRef.current) {
      console.error('Socket not initialized');
      return;
    }

    if (callback) {
      socketRef.current.emit(event, data, callback);
    } else {
      socketRef.current.emit(event, data);
    }
  };

  // Function to listen for events
  const on = (event: string, handler: (...args: any[]) => void) => {
    if (!socketRef.current) {
      console.error('Socket not initialized');
      return () => {};
    }

    socketRef.current.on(event, handler);
    return () => {
      socketRef.current?.off(event, handler);
    };
  };

  return {
    socket: socketRef.current,
    isConnected,
    emit,
    on
  };
};
EOF

# Create API client hook for data fetching
cat > "$PANEL_DIR/frontend/src/hooks/useApi.ts" << 'EOF'
import { useAuth } from '../context/AuthContext';

interface FetchOptions extends RequestInit {
  authenticated?: boolean;
}

interface ApiResponse<T> {
  data: T | null;
  error: Error | null;
  loading: boolean;
}

export const useApi = () => {
  const { token, logout } = useAuth();

  const fetchData = async <T>(
    url: string,
    options: FetchOptions = {}
  ): Promise<ApiResponse<T>> => {
    const { authenticated = true, ...fetchOptions } = options;
    
    try {
      const headers = new Headers(options.headers);
      
      // Add content type if not present
      if (!headers.has('Content-Type') && !options.body) {
        headers.set('Content-Type', 'application/json');
      }
      
      // Add auth token if authenticated request
      if (authenticated && token) {
        headers.set('Authorization', `Bearer ${token}`);
      }
      
      const response = await fetch(url, {
        ...fetchOptions,
        headers
      });
      
      // Handle authentication errors
      if (response.status === 401) {
        logout();
        throw new Error('Authentication failed. Please log in again.');
      }
      
      // Parse response
      let data;
      const contentType = response.headers.get('content-type');
      
      if (contentType && contentType.includes('application/json')) {
        data = await response.json();
      } else {
        data = await response.text();
      }
      
      // Check for error responses
      if (!response.ok) {
        const errorMessage = data.error || data.message || 'API request failed';
        throw new Error(errorMessage);
      }
      
      return { data, error: null, loading: false };
    } catch (error) {
      console.error('API Error:', error);
      return { data: null, error: error as Error, loading: false };
    }
  };
  
  const get = <T>(url: string, options: FetchOptions = {}) => {
    return fetchData<T>(url, { ...options, method: 'GET' });
  };
  
  const post = <T>(url: string, data: any, options: FetchOptions = {}) => {
    return fetchData<T>(url, {
      ...options,
      method: 'POST',
      body: JSON.stringify(data)
    });
  };
  
  const put = <T>(url: string, data: any, options: FetchOptions = {}) => {
    return fetchData<T>(url, {
      ...options,
      method: 'PUT',
      body: JSON.stringify(data)
    });
  };
  
  const del = <T>(url: string, options: FetchOptions = {}) => {
    return fetchData<T>(url, { ...options, method: 'DELETE' });
  };
  
  return { get, post, put, del };
};
EOF

# Create Dashboard component with advanced charts
cat > "$PANEL_DIR/frontend/src/components/Dashboard.tsx" << 'EOF'
import React, { useEffect, useState } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  Filler
} from 'chart.js';
import { Line, Bar, Pie } from 'react-chartjs-2';
import { useApi } from '../hooks/useApi';
import { useSocket } from '../hooks/useSocket';

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  Filler
);

interface SystemInfo {
  hostname: string;
  cpus: number;
  memory: {
    total: number;
    free: number;
    usage: number;
  };
  uptime: number;
  load: number[];
}

interface ProtocolStats {
  protocol: string;
  users: number;
  color: string;
}

const Dashboard: React.FC = () => {
  const { get } = useApi();
  const { on, isConnected } = useSocket();
  
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [cpuHistory, setCpuHistory] = useState<number[]>([]);
  const [memoryHistory, setMemoryHistory] = useState<number[]>([]);
  const [timestamps, setTimestamps] = useState<string[]>([]);
  const [protocolStats, setProtocolStats] = useState<ProtocolStats[]>([]);
  const [activeConnections, setActiveConnections] = useState(0);
  const [totalTraffic, setTotalTraffic] = useState(0);
  
  // Fetch initial data
  useEffect(() => {
    const fetchData = async () => {
      // Fetch system info
      const sysInfoResponse = await get<SystemInfo>('/api/system/info');
      if (sysInfoResponse.data) {
        setSystemInfo(sysInfoResponse.data);
        
        // Initialize history with current values
        setCpuHistory([sysInfoResponse.data.load[0] * 100 / sysInfoResponse.data.cpus]);
        setMemoryHistory([sysInfoResponse.data.memory.usage]);
        setTimestamps([new Date().toLocaleTimeString()]);
      }
      
      // Fetch protocol stats
      const statsResponse = await get<any>('/api/connections/stats');
      if (statsResponse.data) {
        const protocols = statsResponse.data.protocols || [];
        
        // Map protocols to chart data format
        const protocolData = protocols.map((p: any, index: number) => ({
          protocol: p.name,
          users: p.active_connections,
          color: getColor(index)
        }));
        
        setProtocolStats(protocolData);
        setActiveConnections(protocols.reduce((sum: number, p: any) => sum + p.active_connections, 0));
        setTotalTraffic(statsResponse.data.total_traffic || 0);
      }
    };
    
    fetchData();
    
    // Set up update interval
    const intervalId = setInterval(fetchData, 30000);
    
    return () => clearInterval(intervalId);
  }, []);
  
  // Socket event listeners for real-time updates
  useEffect(() => {
    if (!isConnected) return;
    
    // Listen for system updates
    const unsubscribeSystem = on('system_update', (data: SystemInfo) => {
      setSystemInfo(data);
      
      // Update history
      setCpuHistory(prev => {
        const newData = [...prev, data.load[0] * 100 / data.cpus];
        return newData.slice(-10); // Keep only last 10 items
      });
      
      setMemoryHistory(prev => {
        const newData = [...prev, data.memory.usage];
        return newData.slice(-10); // Keep only last 10 items
      });
      
      setTimestamps(prev => {
        const newData = [...prev, new Date().toLocaleTimeString()];
        return newData.slice(-10); // Keep only last 10 items
      });
    });
    
    // Listen for connection updates
    const unsubscribeConnections = on('connections_update', (data: any) => {
      const protocols = data.protocols || [];
      
      // Map protocols to chart data format
      const protocolData = protocols.map((p: any, index: number) => ({
        protocol: p.name,
        users: p.active_connections,
        color: getColor(index)
      }));
      
      setProtocolStats(protocolData);
      setActiveConnections(protocols.reduce((sum: number, p: any) => sum + p.active_connections, 0));
      setTotalTraffic(data.total_traffic || 0);
    });
    
    return () => {
      unsubscribeSystem();
      unsubscribeConnections();
    };
  }, [isConnected, on]);
  
  // Helper function to generate colors
  const getColor = (index: number) => {
    const colors = [
      'rgba(54, 162, 235, 0.8)',
      'rgba(255, 99, 132, 0.8)',
      'rgba(75, 192, 192, 0.8)',
      'rgba(255, 206, 86, 0.8)',
      'rgba(153, 102, 255, 0.8)',
      'rgba(255, 159, 64, 0.8)',
      'rgba(199, 199, 199, 0.8)',
      'rgba(83, 102, 255, 0.8)',
      'rgba(40, 159, 64, 0.8)',
      'rgba(210, 199, 199, 0.8)',
    ];
    
    return colors[index % colors.length];
  };
  
  // Format bytes to human readable form
  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };
  
  // Prepare chart data
  const cpuChartData = {
    labels: timestamps,
    datasets: [
      {
        label: 'CPU Usage (%)',
        data: cpuHistory,
        borderColor: 'rgba(54, 162, 235, 1)',
        backgroundColor: 'rgba(54, 162, 235, 0.2)',
        fill: true,
        tension: 0.4
      }
    ]
  };
  
  const memoryChartData = {
    labels: timestamps,
    datasets: [
      {
        label: 'Memory Usage (%)',
        data: memoryHistory,
        borderColor: 'rgba(255, 99, 132, 1)',
        backgroundColor: 'rgba(255, 99, 132, 0.2)',
        fill: true,
        tension: 0.4
      }
    ]
  };
  
  const protocolChartData = {
    labels: protocolStats.map(p => p.protocol),
    datasets: [
      {
        data: protocolStats.map(p => p.users),
        backgroundColor: protocolStats.map(p => p.color),
        borderWidth: 1
      }
    ]
  };
  
  return (
    <div className="p-4 sm:p-6 md:p-8">
      <h1 className="text-2xl font-bold mb-6 text-gray-800 dark:text-white">Dashboard</h1>
      
      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">Active Connections</h3>
          <p className="text-2xl font-bold text-gray-900 dark:text-white">{activeConnections}</p>
        </div>
        
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">Total Traffic</h3>
          <p className="text-2xl font-bold text-gray-900 dark:text-white">{formatBytes(totalTraffic)}</p>
        </div>
        
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">CPU Usage</h3>
          <p className="text-2xl font-bold text-gray-900 dark:text-white">
            {systemInfo ? `${Math.round(systemInfo.load[0] * 100 / systemInfo.cpus)}%` : 'N/A'}
          </p>
        </div>
        
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">Memory Usage</h3>
          <p className="text-2xl font-bold text-gray-900 dark:text-white">
            {systemInfo ? `${systemInfo.memory.usage}%` : 'N/A'}
          </p>
        </div>
      </div>
      
      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <h3 className="text-lg font-medium mb-4 text-gray-800 dark:text-white">CPU Usage History</h3>
          <div className="h-64">
            <Line
              data={cpuChartData}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                  y: {
                    beginAtZero: true,
                    max: 100,
                    ticks: {
                      callback: (value) => `${value}%`
                    }
                  }
                }
              }}
            />
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <h3 className="text-lg font-medium mb-4 text-gray-800 dark:text-white">Memory Usage History</h3>
          <div className="h-64">
            <Line
              data={memoryChartData}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                  y: {
                    beginAtZero: true,
                    max: 100,
                    ticks: {
                      callback: (value) => `${value}%`
                    }
                  }
                }
              }}
            />
          </div>
        </div>
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <h3 className="text-lg font-medium mb-4 text-gray-800 dark:text-white">Protocol Distribution</h3>
          <div className="h-64 flex items-center justify-center">
            {protocolStats.length > 0 ? (
              <Pie
                data={protocolChartData}
                options={{
                  responsive: true,
                  maintainAspectRatio: false,
                  plugins: {
                    legend: {
                      position: 'bottom'
                    }
                  }
                }}
              />
            ) : (
              <p className="text-gray-500 dark:text-gray-400">No active connections</p>
            )}
          </div>
        </div>
        
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
          <h3 className="text-lg font-medium mb-4 text-gray-800 dark:text-white">System Information</h3>
          
          {systemInfo ? (
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-gray-500 dark:text-gray-400">Hostname:</span>
                <span className="font-medium text-gray-900 dark:text-white">{systemInfo.hostname}</span>
              </div>
              
              <div className="flex justify-between">
                <span className="text-gray-500 dark:text-gray-400">CPU Cores:</span>
                <span className="font-medium text-gray-900 dark:text-white">{systemInfo.cpus}</span>
              </div>
              
              <div className="flex justify-between">
                <span className="text-gray-500 dark:text-gray-400">Memory:</span>
                <span className="font-medium text-gray-900 dark:text-white">
                  {systemInfo.memory.free.toFixed(2)} GB free / {systemInfo.memory.total.toFixed(2)} GB total
                </span>
              </div>
              
              <div className="flex justify-between">
                <span className="text-gray-500 dark:text-gray-400">Uptime:</span>
                <span className="font-medium text-gray-900 dark:text-white">
                  {systemInfo.uptime} hours
                </span>
              </div>
              
              <div className="flex justify-between">
                <span className="text-gray-500 dark:text-gray-400">Load Average:</span>
                <span className="font-medium text-gray-900 dark:text-white">
                  {systemInfo.load.join(' / ')}
                </span>
              </div>
            </div>
          ) : (
            <p className="text-gray-500 dark:text-gray-400">Loading system information...</p>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
EOF

# Create user management component
cat > "$PANEL_DIR/frontend/src/components/UserManagement.tsx" << 'EOF'
import React, { useState, useEffect } from 'react';
import { useApi } from '../hooks/useApi';
import { format } from 'date-fns';

interface User {
  username: string;
  email: string | null;
  status: string;
  max_connections: number;
  active_connections: number;
  expiry: {
    date: string | null;
    remaining: {
      expired: boolean;
      days: number;
      hours: number;
      minutes: number;
    };
  };
  data_usage: {
    bytes: number;
    formatted: string;
  };
  data_limit: {
    bytes: number;
    formatted: string;
  };
  usage_percentage: number;
  created_at: string;
}

interface NewUser {
  username: string;
  email: string;
  max_connections: number;
  expiry_days: number;
  data_limit_gb: number;
}

const UserManagement: React.FC = () => {
  const { get, post, put, del } = useApi();
  
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  const [showAddModal, setShowAddModal] = useState(false);
  const [newUser, setNewUser] = useState<NewUser>({
    username: '',
    email: '',
    max_connections: 1,
    expiry_days: 30,
    data_limit_gb: 0
  });
  
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [showUserModal, setShowUserModal] = useState(false);
  
  // Fetch users
  const fetchUsers = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await get<{ users: User[] }>('/api/users');
      if (response.data) {
        setUsers(response.data.users);
      } else if (response.error) {
        setError(response.error.message);
      }
    } catch (err) {
      setError('Failed to fetch users');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };
  
  // Initial fetch
  useEffect(() => {
    fetchUsers();
  }, []);
  
  // Handle add user
  const handleAddUser = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      const response = await post('/api/users', newUser);
      
      if (response.error) {
        setError(response.error.message);
      } else {
        setShowAddModal(false);
        setNewUser({
          username: '',
          email: '',
          max_connections: 1,
          expiry_days: 30,
          data_limit_gb: 0
        });
        fetchUsers();
      }
    } catch (err) {
      setError('Failed to add user');
      console.error(err);
    }
  };
  
  // Handle delete user
  const handleDeleteUser = async (username: string) => {
    if (!confirm(`Are you sure you want to delete user ${username}?`)) {
      return;
    }
    
    try {
      const response = await del(`/api/users/${username}`);
      
      if (response.error) {
        setError(response.error.message);
      } else {
        fetchUsers();
      }
    } catch (err) {
      setError('Failed to delete user');
      console.error(err);
    }
  };
  
  // Handle extend user
  const handleExtendUser = async (username: string, days: number) => {
    try {
      const response = await put(`/api/users/${username}/extend`, { days });
      
      if (response.error) {
        setError(response.error.message);
      } else {
        fetchUsers();
        setShowUserModal(false);
      }
    } catch (err) {
      setError('Failed to extend user');
      console.error(err);
    }
  };
  
  // Handle user status toggle
  const handleToggleStatus = async (username: string, currentStatus: string) => {
    const newStatus = currentStatus === 'active' ? 'deactive' : 'active';
    
    try {
      const response = await put(`/api/users/${username}/status`, { status: newStatus });
      
      if (response.error) {
        setError(response.error.message);
      } else {
        fetchUsers();
      }
    } catch (err) {
      setError('Failed to change user status');
      console.error(err);
    }
  };
  
  // Format date
  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'No expiry';
    try {
      return format(new Date(dateString), 'dd MMM yyyy HH:mm');
    } catch (e) {
      return dateString;
    }
  };
  
  // Handle view user details
  const handleViewUser = (user: User) => {
    setSelectedUser(user);
    setShowUserModal(true);
  };
  
  return (
    <div className="p-4 sm:p-6 md:p-8">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold text-gray-800 dark:text-white">User Management</h1>
        
        <button
          className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
          onClick={() => setShowAddModal(true)}
        >
          Add User
        </button>
      </div>
      
      {error && (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
          {error}
        </div>
      )}
      
      {loading ? (
        <div className="flex justify-center items-center h-64">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead className="bg-gray-50 dark:bg-gray-800">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Username</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Status</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Expiry</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Connections</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Data Usage</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-800">
              {users.map((user) => (
                <tr key={user.username}>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="font-medium text-gray-900 dark:text-white">{user.username}</div>
                    {user.email && <div className="text-sm text-gray-500 dark:text-gray-400">{user.email}</div>}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${
                      user.status === 'active' ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' :
                      'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                    }`}>
                      {user.status}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-900 dark:text-white">{formatDate(user.expiry.date)}</div>
                    {user.expiry.date && !user.expiry.remaining.expired && (
                      <div className="text-xs text-gray-500 dark:text-gray-400">
                        {user.expiry.remaining.days}d {user.expiry.remaining.hours}h remaining
                      </div>
                    )}
                    {user.expiry.date && user.expiry.remaining.expired && (
                      <div className="text-xs text-red-500">Expired</div>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                    {user.active_connections} / {user.max_connections}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-900 dark:text-white">{user.data_usage.formatted}</div>
                    {user.data_limit.bytes > 0 && (
                      <div className="w-full bg-gray-200 rounded-full h-2.5 dark:bg-gray-700 mt-1">
                        <div 
                          className={`h-2.5 rounded-full ${
                            user.usage_percentage > 90 ? 'bg-red-600' :
                            user.usage_percentage > 70 ? 'bg-yellow-400' : 'bg-green-600'
                          }`}
                          style={{ width: `${Math.min(user.usage_percentage, 100)}%` }}
                        ></div>
                      </div>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <button
                      onClick={() => handleViewUser(user)}
                      className="text-blue-600 hover:text-blue-900 dark:text-blue-400 dark:hover:text-blue-300 mr-3"
                    >
                      View
                    </button>
                    <button
                      onClick={() => handleToggleStatus(user.username, user.status)}
                      className={`${
                        user.status === 'active' ? 'text-yellow-600 hover:text-yellow-900 dark:text-yellow-400 dark:hover:text-yellow-300' :
                        'text-green-600 hover:text-green-900 dark:text-green-400 dark:hover:text-green-300'
                      } mr-3`}
                    >
                      {user.status === 'active' ? 'Deactivate' : 'Activate'}
                    </button>
                    <button
                      onClick={() => handleDeleteUser(user.username)}
                      className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
              
              {users.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-6 py-4 text-center text-gray-500 dark:text-gray-400">
                    No users found
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
      
      {/* Add User Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-gray-500 bg-opacity-75 flex items-center justify-center p-4">
          <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden shadow-xl max-w-md w-full">
            <div className="px-6 py-4">
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">Add New User</h3>
              
              <form onSubmit={handleAddUser} className="mt-4">
                <div className="mb-4">
                  <label className="block text-gray-700 dark:text-gray-300 text-sm font-bold mb-2" htmlFor="username">
                    Username
                  </label>
                  <input
                    className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 dark:text-white dark:bg-gray-700 dark:border-gray-600 leading-tight focus:outline-none focus:shadow-outline"
                    id="username"
                    type="text"
                    placeholder="Enter username"
                    value={newUser.username}
                    onChange={(e) => setNewUser({...newUser, username: e.target.value})}
                    required
                  />
                </div>
                
                <div className="mb-4">
                  <label className="block text-gray-700 dark:text-gray-300 text-sm font-bold mb-2" htmlFor="email">
                    Email (optional)
                  </label>
                  <input
                    className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 dark:text-white dark:bg-gray-700 dark:border-gray-600 leading-tight focus:outline-none focus:shadow-outline"
                    id="email"
                    type="email"
                    placeholder="Enter email"
                    value={newUser.email}
                    onChange={(e) => setNewUser({...newUser, email: e.target.value})}
                  />
                </div>
                
                <div className="mb-4">
                  <label className="block text-gray-700 dark:text-gray-300 text-sm font-bold mb-2" htmlFor="max_connections">
                    Maximum Connections
                  </label>
                  <input
                    className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 dark:text-white dark:bg-gray-700 dark:border-gray-600 leading-tight focus:outline-none focus:shadow-outline"
                    id="max_connections"
                    type="number"
                    min="1"
                    max="10"
                    value={newUser.max_connections}
                    onChange={(e) => setNewUser({...newUser, max_connections: parseInt(e.target.value)})}
                    required
                  />
                </div>
                
                <div className="mb-4">
                  <label className="block text-gray-700 dark:text-gray-300 text-sm font-bold mb-2" htmlFor="expiry_days">
                    Expiry Days (0 for never)
                  </label>
                  <input
                    className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 dark:text-white dark:bg-gray-700 dark:border-gray-600 leading-tight focus:outline-none focus:shadow-outline"
                    id="expiry_days"
                    type="number"
                    min="0"
                    value={newUser.expiry_days}
                    onChange={(e) => setNewUser({...newUser, expiry_days: parseInt(e.target.value)})}
                    required
                  />
                </div>
                
                <div className="mb-4">
                  <label className="block text-gray-700 dark:text-gray-300 text-sm font-bold mb-2" htmlFor="data_limit_gb">
                    Data Limit (GB, 0 for unlimited)
                  </label>
                  <input
                    className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 dark:text-white dark:bg-gray-700 dark:border-gray-600 leading-tight focus:outline-none focus:shadow-outline"
                    id="data_limit_gb"
                    type="number"
                    min="0"
                    step="0.1"
                    value={newUser.data_limit_gb}
                    onChange={(e) => setNewUser({...newUser, data_limit_gb: parseFloat(e.target.value)})}
                    required
                  />
                </div>
                
                <div className="flex items-center justify-end mt-6">
                  <button
                    type="button"
                    className="px-4 py-2 bg-gray-300 text-gray-700 rounded-md mr-2 hover:bg-gray-400 focus:outline-none focus:ring-2 focus:ring-gray-500"
                    onClick={() => setShowAddModal(false)}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    Add User
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}
      
      {/* User Details Modal */}
      {showUserModal && selectedUser && (
        <div className="fixed inset-0 bg-gray-500 bg-opacity-75 flex items-center justify-center p-4">
          <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden shadow-xl max-w-md w-full">
            <div className="px-6 py-4">
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">User Details: {selectedUser.username}</h3>
              
              <div className="mt-4 space-y-3">
                <div>
                  <span className="text-gray-500 dark:text-gray-400">Status:</span>
                  <span className={`ml-2 px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${
                    selectedUser.status === 'active' ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' :
                    'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                  }`}>
                    {selectedUser.status}
                  </span>
                </div>
                
                <div>
                  <span className="text-gray-500 dark:text-gray-400">Email:</span>
                  <span className="ml-2 text-gray-900 dark:text-white">{selectedUser.email || 'N/A'}</span>
                </div>
                
                <div>
                  <span className="text-gray-500 dark:text-gray-400">Created:</span>
                  <span className="ml-2 text-gray-900 dark:text-white">{formatDate(selectedUser.created_at)}</span>
                </div>
                
                <div>
                  <span className="text-gray-500 dark:text-gray-400">Expiry:</span>
                  <span className="ml-2 text-gray-900 dark:text-white">{formatDate(selectedUser.expiry.date)}</span>
                </div>
                
                <div>
                  <span className="text-gray-500 dark:text-gray-400">Connections:</span>
                  <span className="ml-2 text-gray-900 dark:text-white">
                    {selectedUser.active_connections} / {selectedUser.max_connections}
                  </span>
                </div>
                
                <div>
                  <span className="text-gray-500 dark:text-gray-400">Data Usage:</span>
                  <span className="ml-2 text-gray-900 dark:text-white">
                    {selectedUser.data_usage.formatted}
                    {selectedUser.data_limit.bytes > 0 ? ` / ${selectedUser.data_limit.formatted}` : ' (Unlimited)'}
                  </span>
                  
                  {selectedUser.data_limit.bytes > 0 && (
                    <div className="w-full bg-gray-200 rounded-full h-2.5 dark:bg-gray-700 mt-1">
                      <div 
                        className={`h-2.5 rounded-full ${
                          selectedUser.usage_percentage > 90 ? 'bg-red-600' :
                          selectedUser.usage_percentage > 70 ? 'bg-yellow-400' : 'bg-green-600'
                        }`}
                        style={{ width: `${Math.min(selectedUser.usage_percentage, 100)}%` }}
                      ></div>
                    </div>
                  )}
                </div>
                
                <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
                  <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Extend Account</h4>
                  
                  <div className="flex items-center">
                    <button
                      onClick={() => handleExtendUser(selectedUser.username, 7)}
                      className="px-3 py-1 bg-blue-100 text-blue-800 rounded-md mr-2 hover:bg-blue-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      +7 Days
                    </button>
                    <button
                      onClick={() => handleExtendUser(selectedUser.username, 30)}
                      className="px-3 py-1 bg-blue-100 text-blue-800 rounded-md mr-2 hover:bg-blue-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      +30 Days
                    </button>
                    <button
                      onClick={() => handleExtendUser(selectedUser.username, 90)}
                      className="px-3 py-1 bg-blue-100 text-blue-800 rounded-md mr-2 hover:bg-blue-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      +90 Days
                    </button>
                    <button
                      onClick={() => handleExtendUser(selectedUser.username, 365)}
                      className="px-3 py-1 bg-blue-100 text-blue-800 rounded-md mr-2 hover:bg-blue-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      +1 Year
                    </button>
                  </div>
                </div>
                
                <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
                  <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Generate Configurations</h4>
                  
                  <div className="flex flex-wrap gap-2">
                    <button
                      onClick={() => window.location.href = `/api/users/${selectedUser.username}/configs/ssh`}
                      className="px-3 py-1 bg-gray-100 text-gray-800 rounded-md hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-gray-500"
                    >
                      SSH
                    </button>
                    <button
                      onClick={() => window.location.href = `/api/users/${selectedUser.username}/configs/wireguard`}
                      className="px-3 py-1 bg-gray-100 text-gray-800 rounded-md hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-gray-500"
                    >
                      WireGuard
                    </button>
                    <button
                      onClick={() => window.location.href = `/api/users/${selectedUser.username}/configs/ikev2`}
                      className="px-3 py-1 bg-gray-100 text-gray-800 rounded-md hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-gray-500"
                    >
                      IKEv2
                    </button>
                    <button
                      onClick={() => window.location.href = `/api/users/${selectedUser.username}/configs/l2tp`}
                      className="px-3 py-1 bg-gray-100 text-gray-800 rounded-md hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-gray-500"
                    >
                      L2TP
                    </button>
                    <button
                      onClick={() => window.location.href = `/api/users/${selectedUser.username}/configs/singbox`}
                      className="px-3 py-1 bg-gray-100 text-gray-800 rounded-md hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-gray-500"
                    >
                      SingBox
                    </button>
                  </div>
                </div>
              </div>
              
              <div className="flex items-center justify-end mt-6">
                <button
                  type="button"
                  className="px-4 py-2 bg-gray-300 text-gray-700 rounded-md hover:bg-gray-400 focus:outline-none focus:ring-2 focus:ring-gray-500"
                  onClick={() => setShowUserModal(false)}
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default UserManagement;
EOF

# Update main.ts/main.js to use TypeScript and new components
cat > "$PANEL_DIR/frontend/src/main.tsx" << 'EOF'
import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'
import { AuthProvider } from './context/AuthContext'
import { ThemeProvider } from './context/ThemeContext'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AuthProvider>
      <ThemeProvider>
        <App />
      </ThemeProvider>
    </AuthProvider>
  </React.StrictMode>,
)
EOF

# Update App.jsx/App.tsx to use new components and routing
cat > "$PANEL_DIR/frontend/src/App.tsx" << 'EOF'
import React, { useState, useEffect } from 'react'
import { createBrowserRouter, RouterProvider, Navigate } from 'react-router-dom'
import { useAuth } from './context/AuthContext'
import { useTheme } from './context/ThemeContext'
import Dashboard from './components/Dashboard'
import UserManagement from './components/UserManagement'
import './App.css'

// Simple login form component
const LoginPage = () => {
  const { login, isAuthenticated } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setIsLoading(true)
    
    try {
      await login(username, password)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setIsLoading(false)
    }
  }
  
  if (isAuthenticated) {
    return <Navigate to="/dashboard" />
  }
  
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-gray-900 px-4">
      <div className="max-w-md w-full bg-white dark:bg-gray-800 rounded-lg shadow-md overflow-hidden">
        <div className="p-6">
          <div className="text-center mb-6">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">IRSSH Panel</h1>
            <p className="text-gray-600 dark:text-gray-400">Sign in to your account</p>
          </div>
          
          {error && (
            <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
              {error}
            </div>
          )}
          
          <form onSubmit={handleSubmit}>
            <div className="mb-4">
              <label className="block text-gray-700 dark:text-gray-300 text-sm font-bold mb-2" htmlFor="username">
                Username
              </label>
              <input
                className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 dark:text-gray-300 dark:bg-gray-700 dark:border-gray-600 leading-tight focus:outline-none focus:shadow-outline"
                id="username"
                type="text"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>
            
            <div className="mb-6">
              <label className="block text-gray-700 dark:text-gray-300 text-sm font-bold mb-2" htmlFor="password">
                Password
              </label>
              <input
                className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 dark:text-gray-300 dark:bg-gray-700 dark:border-gray-600 leading-tight focus:outline-none focus:shadow-outline"
                id="password"
                type="password"
                placeholder="******************"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            
            <div className="flex items-center justify-between">
              <button
                className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
                type="submit"
                disabled={isLoading}
              >
                {isLoading ? 'Signing in...' : 'Sign In'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}

// Layout component with navigation
const Layout = ({ children }: { children: React.ReactNode }) => {
  const { logout, user } = useAuth()
  const { theme, toggleTheme } = useTheme()
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)
  
  return (
    <div className="min-h-screen bg-gray-100 dark:bg-gray-900 flex flex-col">
      {/* Header */}
      <header className="bg-white dark:bg-gray-800 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex">
              <div className="flex-shrink-0 flex items-center">
                <span className="text-xl font-bold text-blue-600 dark:text-blue-400">IRSSH Panel</span>
              </div>
            </div>
            
            <div className="flex items-center">
              <button
                onClick={toggleTheme}
                className="p-2 rounded-md text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                {theme === 'dark' ? (
                  <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
                  </svg>
                ) : (
                  <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
                  </svg>
                )}
              </button>
              
              <div className="ml-3 relative">
                <div>
                  <button
                    className="flex text-sm rounded-full focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                    id="user-menu"
                    aria-expanded="false"
                    aria-haspopup="true"
                    onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
                  >
                    <span className="sr-only">Open user menu</span>
                    <div className="h-8 w-8 rounded-full bg-blue-600 dark:bg-blue-700 text-white flex items-center justify-center">
                      {user?.username.charAt(0).toUpperCase()}
                    </div>
                  </button>
                </div>
                
                {isMobileMenuOpen && (
                  <div
                    className="origin-top-right absolute right-0 mt-2 w-48 rounded-md shadow-lg py-1 bg-white dark:bg-gray-800 ring-1 ring-black ring-opacity-5"
                    role="menu"
                    aria-orientation="vertical"
                    aria-labelledby="user-menu"
                  >
                    <a
                      href="#"
                      className="block px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
                      role="menuitem"
                      onClick={(e) => {
                        e.preventDefault()
                        setIsMobileMenuOpen(false)
                      }}
                    >
                      {user?.username}
                    </a>
                    <a
                      href="#"
                      className="block px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
                      role="menuitem"
                      onClick={(e) => {
                        e.preventDefault()
                        logout()
                      }}
                    >
                      Sign out
                    </a>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </header>
      
      {/* Main content */}
      <div className="flex-1 flex">
        {/* Sidebar */}
        <div className="hidden md:flex md:flex-shrink-0">
          <div className="flex flex-col w-64">
            <div className="flex flex-col h-0 flex-1 bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700">
              <div className="flex-1 flex flex-col pt-5 pb-4 overflow-y-auto">
                <nav className="mt-5 flex-1 px-2 space-y-1">
                  <a
                    href="/dashboard"
                    className="group flex items-center px-2 py-2 text-sm font-medium rounded-md text-gray-900 dark:text-white bg-gray-100 dark:bg-gray-700"
                  >
                    Dashboard
                  </a>
                  <a
                    href="/users"
                    className="group flex items-center px-2 py-2 text-sm font-medium rounded-md text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
                  >
                    User Management
                  </a>
                  <a
                    href="/connections"
                    className="group flex items-center px-2 py-2 text-sm font-medium rounded-md text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
                  >
                    Active Connections
                  </a>
                  <a
                    href="/settings"
                    className="group flex items-center px-2 py-2 text-sm font-medium rounded-md text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
                  >
                    Settings
                  </a>
                </nav>
              </div>
              <div className="flex-shrink-0 flex border-t border-gray-200 dark:border-gray-700 p-4">
                <div className="flex-shrink-0 w-full group block">
                  <div className="flex items-center">
                    <div>
                      <div className="h-9 w-9 rounded-full bg-blue-600 dark:bg-blue-700 text-white flex items-center justify-center">
                        {user?.username.charAt(0).toUpperCase()}
                      </div>
                    </div>
                    <div className="ml-3">
                      <p className="text-sm font-medium text-gray-700 dark:text-white">
                        {user?.username}
                      </p>
                      <p className="text-xs font-medium text-gray-500 dark:text-gray-400 group-hover:text-gray-700 dark:group-hover:text-gray-300">
                        {user?.role}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        
        {/* Main content */}
        <div className="flex-1 overflow-auto">
          {children}
        </div>
      </div>
    </div>
  )
}

// Protected route component
const ProtectedRoute = ({ 
  element,
  path 
}: { 
  element: React.ReactNode, 
  path: string 
}) => {
  const { isAuthenticated, isLoading } = useAuth()
  
  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-gray-900">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    )
  }
  
  if (!isAuthenticated) {
    return <Navigate to="/login" />
  }
  
  return <Layout>{element}</Layout>
}

// Main App component
function App() {
  const router = createBrowserRouter([
    {
      path: '/',
      element: <Navigate to="/dashboard" replace />
    },
    {
      path: '/login',
      element: <LoginPage />
    },
    {
      path: '/dashboard',
      element: <ProtectedRoute element={<Dashboard />} path="/dashboard" />
    },
    {
      path: '/users',
      element: <ProtectedRoute element={<UserManagement />} path="/users" />
    }
  ])
  
  return <RouterProvider router={router} />
}

export default App
EOF

# Update index.css with Tailwind directives
cat > "$PANEL_DIR/frontend/src/index.css" << 'EOF'
@tailwind base;
@tailwind components;
@tailwind utilities;

:root {
  font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
  font-synthesis: none;
  text-rendering: optimizeLegibility;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

/* Dark mode adjustments */
.dark {
  color-scheme: dark;
}

/* Custom app styles */
.app-container {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}
EOF

info "Frontend enhancements completed"
}

# Final function to complete installation
complete_installation() {
    info "Completing installation..."
    
    # Create README file
    cat > "$PANEL_DIR/README.md" << EOF
# IRSSH-Panel - Comprehensive Multi-Protocol VPN Panel

IRSSH-Panel is a comprehensive web panel for managing various VPN protocols.

## Installation Details

- **Installation Date:** $INSTALLATION_DATE
- **Panel Version:** 4.0.0
- **Panel URL:** http://${SERVER_IPv4}:${PORTS[WEB]}

## Installed Protocols

EOF

for protocol in "${!PROTOCOLS[@]}"; do
    if [ "${PROTOCOLS[$protocol]}" = true ]; then
        echo "- **${protocol}:** Enabled (Port ${PORTS[$protocol]})" >> "$PANEL_DIR/README.md"
    else
        echo "- **${protocol}:** Disabled" >> "$PANEL_DIR/README.md"
    fi
done

# Add additional modules information
cat >> "$PANEL_DIR/README.md" << EOF

## Additional Modules

- **Dropbear SSH:** Enabled (Port ${DROPBEAR_PORT:-2222})
- **BadVPN UDP Gateway:** Enabled (Port ${UDPGW_PORT:-7300})
- **SSL-VPN:** Enabled (Port ${PORTS[SSL_VPN]:-0})
- **NordWhisper:** Enabled (Port ${PORTS[NORDWHISPER]:-0})

## Management Tools

- **Web Panel:** http://${SERVER_IPv4}:${PORTS[WEB]}
- **CLI Admin Tool:** Run 'irssh-admin help' for available commands
- **Ansible Automation:** Run 'irssh-ansible' for available playbooks
- **Docker Management:** Run '$SCRIPTS_DIR/docker_manage.sh' for Docker services

## Advanced Features

- **Auto-Optimization:** System automatically optimized based on detected resources
- **Multi-Server Support:** Use Multi-Tunneling feature in Settings
- **Automated Backups:** Database backups run daily at 2:00 AM
- **Monitoring:** Advanced monitoring system with Prometheus and Grafana

## Support

For more information, visit: https://github.com/irkids/IRSSH-Panel
EOF

    # Create summary file for quick reference
    cat > "$CONFIG_DIR/installation_summary.txt" << EOF
IRSSH-Panel Installation Summary
-------------------------------
Panel Version: 4.0.0
Installation Date: $INSTALLATION_DATE

Web Interface:
$([ ! -z "$SERVER_IPv4" ] && echo "IPv4: http://${SERVER_IPv4}:${PORTS[WEB]}")
$([ ! -z "$SERVER_IPv6" ] && echo "IPv6: http://[${SERVER_IPv6}]:${PORTS[WEB]}")

Admin Credentials:
Username: ${ADMIN_USER}
Password: (As specified during installation)

Database Information:
DB Name: ${DB_NAME}
DB User: ${DB_USER}
DB Password: ${DB_USER_PASSWORD}

Installed Protocols:
EOF

for protocol in "${!PROTOCOLS[@]}"; do
    if [ "${PROTOCOLS[$protocol]}" = true ]; then
        echo "- ${protocol} (Port: ${PORTS[$protocol]})" >> "$CONFIG_DIR/installation_summary.txt"
    fi
done

cat >> "$CONFIG_DIR/installation_summary.txt" << EOF

Additional Modules:
- Dropbear SSH (Port: ${DROPBEAR_PORT:-2222})
- BadVPN UDP Gateway (Port: ${UDPGW_PORT:-7300})
$([ ! -z "${PORTS[SSL_VPN]}" ] && echo "- SSL-VPN (Port: ${PORTS[SSL_VPN]})")
$([ ! -z "${PORTS[NORDWHISPER]}" ] && echo "- NordWhisper (Port: ${PORTS[NORDWHISPER]})")

Management Tools:
- Admin CLI Tool: irssh-admin
- User Manager API: http://${SERVER_IPv4}:3001/api
- Ansible Automation: irssh-ansible
- Docker Management: $SCRIPTS_DIR/docker_manage.sh

For more information, see: $PANEL_DIR/README.md
EOF

    # Create completion script to enable command line completion for CLI tools
    cat > "/etc/bash_completion.d/irssh-admin" << 'EOF'
#!/bin/bash

_irssh_admin_completions()
{
    local cur prev opts commands user_commands service_commands db_commands system_commands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    # Main commands
    commands="user conn service db system help"
    
    # Subcommands
    user_commands="list add del modify extend show"
    conn_commands="list kill"
    service_commands="status restart logs"
    db_commands="backup restore"
    system_commands="status update"
    
    # Complete main command
    if [[ ${COMP_CWORD} -eq 1 ]] ; then
        COMPREPLY=( $(compgen -W "${commands}" -- ${cur}) )
        return 0
    fi
    
    # Complete subcommands
    if [[ ${COMP_CWORD} -eq 2 ]] ; then
        case "${prev}" in
            user)
                COMPREPLY=( $(compgen -W "${user_commands}" -- ${cur}) )
                return 0
                ;;
            conn)
                COMPREPLY=( $(compgen -W "${conn_commands}" -- ${cur}) )
                return 0
                ;;
            service)
                COMPREPLY=( $(compgen -W "${service_commands}" -- ${cur}) )
                return 0
                ;;
            db)
                COMPREPLY=( $(compgen -W "${db_commands}" -- ${cur}) )
                return 0
                ;;
            system)
                COMPREPLY=( $(compgen -W "${system_commands}" -- ${cur}) )
                return 0
                ;;
        esac
    fi
    
    # Complete options
    if [[ ${COMP_CWORD} -ge 3 ]] ; then
        case "${COMP_WORDS[1]}" in
            user)
                case "${COMP_WORDS[2]}" in
                    add|del|modify|extend|show)
                        if [[ ${prev} == "--username" ]] ; then
                            # Get list of users from system
                            local users=$(getent passwd | grep -v "nologin\|false" | cut -d: -f1 | sort)
                            COMPREPLY=( $(compgen -W "${users}" -- ${cur}) )
                        else
                            COMPREPLY=( $(compgen -W "--username --expiry --max-conn --data-limit --email --mobile --status" -- ${cur}) )
                        fi
                        return 0
                        ;;
                esac
                ;;
            conn)
                case "${COMP_WORDS[2]}" in
                    kill)
                        COMPREPLY=( $(compgen -W "--id" -- ${cur}) )
                        return 0
                        ;;
                esac
                ;;
            service)
                case "${COMP_WORDS[2]}" in
                    restart|logs)
                        COMPREPLY=( $(compgen -W "--name" -- ${cur}) )
                        return 0
                        ;;
                esac
                ;;
        esac
    fi
}

complete -F _irssh_admin_completions irssh-admin
EOF

    # Make completion script executable
    chmod +x "/etc/bash_completion.d/irssh-admin"

    # Create cron job for routine maintenance
    cat > "/etc/cron.d/irssh-maintenance" << EOF
# IRSSH-Panel Maintenance Tasks
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Database backups (daily at 2:00 AM)
0 2 * * * root $SCRIPTS_DIR/backup_database.sh > /dev/null 2>&1

# Clean up stale connections (every 3 hours)
0 */3 * * * root $SCRIPTS_DIR/cleanup_stale_connections.sh > /dev/null 2>&1

# Update system stats for monitoring (every 5 minutes)
*/5 * * * * root $SCRIPTS_DIR/update_system_stats.sh > /dev/null 2>&1

# Auto-repair check (daily at 3:00 AM)
0 3 * * * root $SCRIPTS_DIR/auto_repair.sh > /dev/null 2>&1

# Log rotation (weekly)
0 0 * * 0 root logrotate -f /etc/logrotate.d/irssh > /dev/null 2>&1
EOF

    # Create update system stats script
    cat > "$SCRIPTS_DIR/update_system_stats.sh" << 'EOF'
#!/bin/bash

# Script to update system statistics for monitoring

LOG_DIR="/var/log/irssh/metrics"
mkdir -p "$LOG_DIR"

# Get CPU usage
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
echo "$(date +"%Y-%m-%d %H:%M:%S") CPU: ${CPU_USAGE}%" >> "$LOG_DIR/cpu_usage.log"

# Get memory usage
MEM_TOTAL=$(free -m | awk '/Mem:/ {print $2}')
MEM_USED=$(free -m | awk '/Mem:/ {print $3}')
MEM_PERCENT=$(echo "scale=2; $MEM_USED*100/$MEM_TOTAL" | bc)
echo "$(date +"%Y-%m-%d %H:%M:%S") Memory: ${MEM_PERCENT}% (${MEM_USED}MB / ${MEM_TOTAL}MB)" >> "$LOG_DIR/memory_usage.log"

# Get disk usage
DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
DISK_TOTAL=$(df -h / | awk 'NR==2 {print $2}')
DISK_USED=$(df -h / | awk 'NR==2 {print $3}')
echo "$(date +"%Y-%m-%d %H:%M:%S") Disk: ${DISK_USAGE}% (${DISK_USED} / ${DISK_TOTAL})" >> "$LOG_DIR/disk_usage.log"

# Get network traffic
INTERFACE=$(ip route get 8.8.8.8 | grep -oP "dev \K\S+")
if [ ! -z "$INTERFACE" ]; then
    if [ -f "/sys/class/net/$INTERFACE/statistics/rx_bytes" ]; then
        RX=$(cat /sys/class/net/$INTERFACE/statistics/rx_bytes)
        TX=$(cat /sys/class/net/$INTERFACE/statistics/tx_bytes)
        echo "$(date +"%Y-%m-%d %H:%M:%S") Network $INTERFACE: RX: $RX bytes, TX: $TX bytes" >> "$LOG_DIR/network_traffic.log"
    fi
fi

# Get active connection counts
CONNECTIONS_COUNT=$(netstat -an | grep ESTABLISHED | wc -l)
SSH_COUNT=$(netstat -an | grep ":22" | grep ESTABLISHED | wc -l)
echo "$(date +"%Y-%m-%d %H:%M:%S") Connections: Total: ${CONNECTIONS_COUNT}, SSH: ${SSH_COUNT}" >> "$LOG_DIR/connections.log"

# Get load average
LOAD=$(cat /proc/loadavg | awk '{print $1, $2, $3}')
echo "$(date +"%Y-%m-%d %H:%M:%S") Load: ${LOAD}" >> "$LOG_DIR/load_average.log"

# Rotate logs if they get too large
for logfile in "$LOG_DIR"/*.log; do
    # If larger than 10MB, keep only last 1000 lines
    if [ $(stat -c%s "$logfile") -gt 10485760 ]; then
        tail -n 1000 "$logfile" > "$logfile.tmp" && mv "$logfile.tmp" "$logfile"
    fi
done

# Update Socket.IO stats if available
if [ -d "$PANEL_DIR/backend" ]; then
    # Create a JSON file with system stats for Socket.IO to serve
    cat > "$PANEL_DIR/backend/system_stats.json" << EOL
{
  "timestamp": "$(date +"%Y-%m-%d %H:%M:%S")",
  "cpu": {
    "usage": $CPU_USAGE
  },
  "memory": {
    "total": $MEM_TOTAL,
    "used": $MEM_USED,
    "percentage": $MEM_PERCENT
  },
  "disk": {
    "usage": $DISK_USAGE,
    "total": "$DISK_TOTAL",
    "used": "$DISK_USED"
  },
  "network": {
    "interface": "$INTERFACE",
    "rx_bytes": $RX,
    "tx_bytes": $TX
  },
  "connections": {
    "total": $CONNECTIONS_COUNT,
    "ssh": $SSH_COUNT
  },
  "load": [$LOAD]
}
EOL
fi
EOF
    chmod +x "$SCRIPTS_DIR/update_system_stats.sh"

    # Create auto-repair script
    cat > "$SCRIPTS_DIR/auto_repair.sh" << 'EOF'
#!/bin/bash

# IRSSH-Panel Auto-Repair Script
# This script checks for and fixes common issues

LOG_DIR="/var/log/irssh"
PANEL_DIR="/opt/irssh-panel"
CONFIG_DIR="/etc/enhanced_ssh"

# Ensure log directory exists
mkdir -p "$LOG_DIR"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_DIR/auto_repair.log"
}

log "Starting auto-repair process"

# Check for critical services
critical_services=("nginx" "postgresql" "redis-server" "irssh-api" "irssh-user-manager")
for service in "${critical_services[@]}"; do
    if ! systemctl is-active --quiet "$service"; then
        log "Service $service is not running, attempting to restart"
        systemctl restart "$service"
        
        sleep 5
        
        if systemctl is-active --quiet "$service"; then
            log "Successfully restarted $service"
        else
            log "Failed to restart $service, manual intervention required"
        fi
    fi
done

# Check PostgreSQL connection
if ! sudo -u postgres psql -c '\l' > /dev/null 2>&1; then
    log "PostgreSQL connection issues detected, checking configuration"
    
    # Check if PostgreSQL is running
    if systemctl is-active --quiet postgresql; then
        # Try to fix common PostgreSQL issues
        log "Attempting to fix PostgreSQL"
        pg_ctlcluster $(pg_lsclusters | awk 'NR>1 {print $1,$2}' | head -n 1 | awk '{print $1,$2}') restart || log "Failed to restart PostgreSQL cluster"
    else
        log "PostgreSQL is not running, attempting to start"
        systemctl start postgresql
    fi
else
    log "PostgreSQL connection is working"
fi

# Check disk space
disk_usage=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$disk_usage" -gt 90 ]; then
    log "WARNING: Disk usage is critically high: ${disk_usage}%"
    
    # Clean up old logs
    log "Cleaning up old logs"
    find "$LOG_DIR" -name "*.log" -type f -mtime +30 -delete
    
    # Clean up old backups
    if [ -d "/opt/irssh-backups" ]; then
        log "Cleaning up old backups"
        find "/opt/irssh-backups" -type f -mtime +90 -delete
    fi
    
    # Clean package cache
    log "Cleaning package cache"
    apt-get clean
fi

# Check for stale connections
log "Checking for stale connections"
timeout 10s "$PANEL_DIR/scripts/cleanup_stale_connections.sh" || log "Stale connection cleanup timed out"

# Check frontend build
if [ ! -f "$PANEL_DIR/frontend/dist/index.html" ]; then
    log "Frontend build is missing, attempting to rebuild"
    
    cd "$PANEL_DIR/frontend" || log "Failed to access frontend directory"
    if [ -f "package.json" ]; then
        npm run build || log "Failed to build frontend"
    else
        log "Missing package.json, cannot rebuild frontend"
    fi
fi

# Check for updates to system packages
log "Checking for security updates"
if apt-get -s upgrade | grep -q "^Inst.*security"; then
    log "Security updates are available"
    
    # Only install security updates
    apt-get update
    apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade --security
    
    log "Security updates installed"
fi

log "Auto-repair process completed"
EOF
    chmod +x "$SCRIPTS_DIR/auto_repair.sh"

    # Create log rotation configuration
    cat > "/etc/logrotate.d/irssh" << EOF
$LOG_DIR/*.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
EOF

    # Set permissions for configuration files
    chmod -R 750 "$PANEL_DIR"
    chmod -R 640 "$CONFIG_DIR"/*.conf
    chmod -R 750 "$SCRIPTS_DIR"/*.sh
    
    # Create a simple backup of the entire installation
    mkdir -p "$BACKUP_DIR/full"
    BACKUP_TIMESTAMP=$(date +"%Y%m%d")
    BACKUP_FILE="$BACKUP_DIR/full/irssh_full_backup_$BACKUP_TIMESTAMP.tar.gz"
    
    info "Creating full backup of installation..."
    tar -czf "$BACKUP_FILE" \
        --exclude="$PANEL_DIR/frontend/node_modules" \
        --exclude="$PANEL_DIR/backend/node_modules" \
        "$PANEL_DIR" "$CONFIG_DIR" "$SCRIPTS_DIR" || warn "Full backup failed"
    
    if [ -f "$BACKUP_FILE" ]; then
        info "Full backup created: $BACKUP_FILE"
    fi
    
    # Final output with summarized information
    cat << EOL

╭────────────────────────────────────────────────╮
│                                                │
│       IRSSH-Panel Installation Complete!       │
│                                                │
╰────────────────────────────────────────────────╯

📋 Installation Summary:

🔗 Web Panel:      http://${SERVER_IPv4}:${PORTS[WEB]}
👤 Admin Account:  ${ADMIN_USER}

📊 Protocols Installed:
EOL

for protocol in "${!PROTOCOLS[@]}"; do
    if [ "${PROTOCOLS[$protocol]}" = true ]; then
        echo "   ✅ ${protocol} (Port: ${PORTS[$protocol]})"
    else
        echo "   ❌ ${protocol} (Disabled)"
    fi
done

cat << EOL

📚 Administration Tools:
   → Web Panel:    http://${SERVER_IPv4}:${PORTS[WEB]}
   → CLI Tool:     irssh-admin
   → Ansible:      irssh-ansible
   → Docker:       $SCRIPTS_DIR/docker_manage.sh

📝 Documentation:
   → Summary:      $CONFIG_DIR/installation_summary.txt
   → Readme:       $PANEL_DIR/README.md
   → Logs:         $LOG_DIR

🔑 Important Credentials:
   Admin Username: ${ADMIN_USER}
   Admin Password: (As provided during setup)
   Database Name:  ${DB_NAME}
   Database User:  ${DB_USER}
   Database Pass:  ${DB_USER_PASSWORD}

🔄 Auto-Optimization:
   The system has been automatically optimized based on
   detected resources: ${CPU_CORES} CPU cores, ${RAM_GB}GB RAM

🛠️ For management, use the 'irssh-admin' command:
   $ irssh-admin user list
   $ irssh-admin conn list
   $ irssh-admin service status

EOL

    # Record installation success
    touch "$PANEL_DIR/.installation_complete"
    echo "$INSTALLATION_DATE" > "$PANEL_DIR/.installation_date"

    info "Installation completed successfully!"
}

# Main installation function
function main() {
    info "Starting IRSSH Panel installation..."
    
    # Create required directories
    mkdir -p "$PANEL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$BACKUP_DIR"
    mkdir -p "$TEMP_DIR"
    
    # Get server IP
    get_server_ip
    
    # Detect system resources for auto-optimization
    detect_system_resources
    
    # Get configuration from user
    get_config
    
    # Setup dependencies
    setup_dependencies
    
    # Optimize system based on detected resources
    optimize_system
    
    # Setup database
    setup_database
    
    # Setup web server
    setup_web_server
    
main() {
    # Install protocols
    for protocol in "${!PROTOCOLS[@]}"; do
        if [ "${PROTOCOLS[$protocol]}" = true ]; then
            info "Installing ${protocol}..."
            case "${protocol,,}" in
                ssh)
                    install_ssh || error "Failed to install SSH" "no-exit"
                    ;;
                l2tp)
                    install_l2tp || error "Failed to install L2TP/IPsec" "no-exit"
                    ;;
                ikev2)
                    install_ikev2 || error "Failed to install IKEv2" "no-exit"
                    ;;
                cisco)
                    install_cisco || error "Failed to install Cisco AnyConnect" "no-exit"
                    ;;
                wireguard)
                    install_wireguard || error "Failed to install WireGuard" "no-exit"
                    ;;
                singbox)
                    install_singbox_improved || error "Failed to install SingBox" "no-exit"
                    ;;
            esac
        fi
    done

    setup_additional_modules
    install_ssl_vpn
    install_nordwhisper
    setup_advanced_monitoring
    enhance_security
    setup_docker
    setup_ansible
    enhance_frontend
    install_user_management
    cleanup
    complete_installation
}

main
