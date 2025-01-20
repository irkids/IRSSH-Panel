#!/bin/bash

# Configuration
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"

# Create a test HTML file
mkdir -p "$FRONTEND_DIR/build"
cat > "$FRONTEND_DIR/build/index.html" << 'EOL'
<!DOCTYPE html>
<html>
<head>
    <title>IRSSH Panel Test</title>
</head>
<body>
    <h1>IRSSH Panel Test Page</h1>
    <p>If you can see this, Nginx is working correctly.</p>
    <hr>
    <div id="api-status">Checking API status...</div>

    <script>
        fetch('http://77.239.124.50:8000/api/health')
            .then(response => response.json())
            .then(data => {
                document.getElementById('api-status').textContent = 'API Status: ' + JSON.stringify(data);
            })
            .catch(error => {
                document.getElementById('api-status').textContent = 'API Error: ' + error;
            });
    </script>
</body>
</html>
EOL

# Create minimal Nginx configuration
cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen 8675;
    server_name _;

    access_log /var/log/nginx/irssh-access.log;
    error_log /var/log/nginx/irssh-error.log;

    root $FRONTEND_DIR/build;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8000/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOL

# Remove default site if it exists
rm -f /etc/nginx/sites-enabled/default

# Enable our site
ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/

# Test and restart Nginx
nginx -t && systemctl restart nginx

# Show test URLs
echo
echo "Please test these URLs:"
echo "1. http://77.239.124.50:8675 (Panel test page)"
echo "2. http://77.239.124.50:8000/api/health (Direct API access)"
echo
echo "Also check these logs for errors:"
echo "nginx -t"
echo "tail -f /var/log/nginx/irssh-error.log"
echo "tail -f /var/log/nginx/irssh-access.log"
