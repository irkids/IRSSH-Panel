# ssl_manager.sh
#!/bin/bash

# Configuration
DOMAIN=""
EMAIL=""
SSL_DIR="/etc/letsencrypt/live"
NGINX_CONF="/etc/nginx/sites-available/irssh-panel"
LOG_FILE="/var/log/irssh/ssl_manager.log"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

check_requirements() {
    if ! command -v certbot &> /dev/null; then
        apt-get update
        apt-get install -y certbot python3-certbot-nginx
    fi
}

setup_ssl() {
    local domain=$1
    local email=$2
    
    log "Setting up SSL for $domain"
    
    # Obtain certificate
    certbot --nginx \
        -d "$domain" \
        --non-interactive \
        --agree-tos \
        --email "$email" \
        --redirect \
        --keep-until-expiring \
        --expand || error "Failed to obtain SSL certificate"
        
    # Configure strong SSL settings
    cat > /etc/nginx/conf.d/ssl.conf << EOL
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
add_header Strict-Transport-Security "max-age=63072000" always;
EOL
    
    # Reload Nginx
    systemctl reload nginx
    
    log "SSL setup completed for $domain"
}

renew_certificates() {
    log "Checking for certificate renewals"
    certbot renew --quiet
    systemctl reload nginx
}

check_certificate() {
    local domain=$1
    local cert_file="$SSL_DIR/$domain/cert.pem"
    
    if [ ! -f "$cert_file" ]; then
        error "No certificate found for $domain"
    fi
    
    # Check expiration
    local expires
    expires=$(openssl x509 -enddate -noout -in "$cert_file" | cut -d= -f2)
    local expires_epoch
    expires_epoch=$(date -d "$expires" +%s)
    local now_epoch
    now_epoch=$(date +%s)
    local days_left
    days_left=$(( (expires_epoch - now_epoch) / 86400 ))
    
    if [ "$days_left" -lt 30 ]; then
        log "Certificate for $domain expires in $days_left days. Attempting renewal."
        renew_certificates
    else
        log "Certificate for $domain is valid for $days_left more days"
    fi
}

case "$1" in
    setup)
        if [ -z "$2" ] || [ -z "$3" ]; then
            error "Usage: $0 setup <domain> <email>"
        fi
        check_requirements
        setup_ssl "$2" "$3"
        ;;
    renew)
        renew_certificates
        ;;
    check)
        if [ -z "$2" ]; then
            error "Usage: $0 check <domain>"
        fi
        check_certificate "$2"
        ;;
    *)
        echo "Usage: $0 {setup|renew|check} [domain] [email]"
        exit 1
        ;;
esac
