# monitoring.sh
#!/bin/bash

# Colors and logging configuration
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'
LOG_FILE="/var/log/irssh/monitoring.log"

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" | tee -a "$LOG_FILE"
}

# System metrics collection
collect_metrics() {
    # CPU Usage
    CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
    
    # Memory Usage
    MEM_TOTAL=$(free -m | awk 'NR==2{print $2}')
    MEM_USED=$(free -m | awk 'NR==2{print $3}')
    MEM_USAGE=$((MEM_USED * 100 / MEM_TOTAL))
    
    # Disk Usage
    DISK_USAGE=$(df -h / | awk 'NR==2{print $5}' | tr -d '%')
    
    # Network Connections
    TOTAL_CONN=$(netstat -an | grep ESTABLISHED | wc -l)
    
    # Save metrics
    echo "$(date +'%Y-%m-%d %H:%M:%S'),${CPU_USAGE},${MEM_USAGE},${DISK_USAGE},${TOTAL_CONN}" >> /var/log/irssh/metrics.csv
}

# Protocol monitoring
check_protocols() {
    local protocols=("ssh" "l2tp" "ikev2" "wireguard" "singbox")
    
    for protocol in "${protocols[@]}"; do
        if ! pgrep -f "$protocol" > /dev/null; then
            error "Protocol $protocol is down!"
            # Attempt restart
            systemctl restart "$protocol" 2>/dev/null || true
        fi
    }
}

# Main monitoring loop
main() {
    while true; do
        collect_metrics
        check_protocols
        sleep 60
    done
}

main "$@"
