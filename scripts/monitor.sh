# /opt/irssh-panel/scripts/monitor.sh
#!/bin/bash

LOG_DIR="/var/log/irssh/metrics"
mkdir -p "$LOG_DIR"

monitor_ssh() {
    CONNECTIONS=$(netstat -tn | grep ":${SSH_PORT}" | grep ESTABLISHED | wc -l)
    echo "ssh_active_connections $CONNECTIONS" > "$LOG_DIR/ssh.prom"
}

monitor_l2tp() {
    CONNECTIONS=$(netstat -an | grep ":${L2TP_PORT}" | grep ESTABLISHED | wc -l)
    echo "l2tp_active_connections $CONNECTIONS" > "$LOG_DIR/l2tp.prom"
}

monitor_wireguard() {
    CONNECTIONS=$(wg show wg0 | grep "latest handshake" | wc -l)
    echo "wireguard_active_connections $CONNECTIONS" > "$LOG_DIR/wireguard.prom"
}

monitor_system() {
    CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}')
    MEM_USAGE=$(free -m | awk '/Mem:/ {print $3}')
    DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    
    cat > "$LOG_DIR/system.prom" << EOL
system_cpu_usage $CPU_USAGE
system_memory_usage $MEM_USAGE
system_disk_usage $DISK_USAGE
EOL
}

# Run all monitors
monitor_ssh
monitor_l2tp
monitor_wireguard
monitor_system
