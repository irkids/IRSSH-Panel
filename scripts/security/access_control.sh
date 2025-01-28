# access_control.sh
#!/bin/bash

# Configuration
CONFIG_FILE="/opt/irssh-panel/config/access_control.conf"
WHITELIST_FILE="/opt/irssh-panel/config/ip_whitelist.txt"
BLACKLIST_FILE="/opt/irssh-panel/config/ip_blacklist.txt"
LOG_FILE="/var/log/irssh/access_control.log"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" | tee -a "$LOG_FILE"
}

# IP Management
add_to_whitelist() {
    local ip=$1
    if ! grep -q "^$ip$" "$WHITELIST_FILE"; then
        echo "$ip" >> "$WHITELIST_FILE"
        iptables -I INPUT -s "$ip" -j ACCEPT
        log "Added $ip to whitelist"
    fi
}

add_to_blacklist() {
    local ip=$1
    if ! grep -q "^$ip$" "$BLACKLIST_FILE"; then
        echo "$ip" >> "$BLACKLIST_FILE"
        iptables -I INPUT -s "$ip" -j DROP
        log "Added $ip to blacklist"
    fi
}

# Rate limiting
setup_rate_limiting() {
    # Create rate limiting chain
    iptables -N RATE_LIMIT 2>/dev/null || true
    
    # Limit connections per IP
    iptables -A RATE_LIMIT -m state --state NEW -m limit --limit 30/minute --limit-burst 5 -j ACCEPT
    iptables -A RATE_LIMIT -j DROP
    
    # Apply to HTTP/HTTPS
    iptables -A INPUT -p tcp --dport 80 -j RATE_LIMIT
    iptables -A INPUT -p tcp --dport 443 -j RATE_LIMIT
}

# Protocol access control
manage_protocol_access() {
    local protocol=$1
    local port=$2
    local allow=$3
    
    if [ "$allow" = true ]; then
        iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
        log "Enabled access to $protocol on port $port"
    else
        iptables -A INPUT -p tcp --dport "$port" -j DROP
        log "Disabled access to $protocol on port $port"
    fi
}

# Initialize
init() {
    # Create files if not exist
    touch "$WHITELIST_FILE" "$BLACKLIST_FILE"
    
    # Reset iptables
    iptables -F
    iptables -X
    
    # Default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    
    setup_rate_limiting
    
    log "Access control initialized"
}

# Main
case "$1" in
    init)
        init
        ;;
    whitelist)
        add_to_whitelist "$2"
        ;;
    blacklist)
        add_to_blacklist "$2"
        ;;
    protocol)
        manage_protocol_access "$2" "$3" "$4"
        ;;
    *)
        echo "Usage: $0 {init|whitelist|blacklist|protocol}"
        exit 1
        ;;
esac
