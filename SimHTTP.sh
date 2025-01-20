#!/bin/bash

# Configuration
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"

# Get server IP
SERVER_IP=$(curl -s ifconfig.me || ip route get 1 | awk '{print $7;exit}')

# Update Nginx config
cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen 80;
    server_name $SERVER_IP;

    root $FRONTEND_DIR/build;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location /api {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
    }
}
EOL

# Remove default and enable our config
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/

# Create a simple React app
cd $FRONTEND_DIR

# Update App.js
cat > src/App.js << 'EOL'
import React from 'react';

function App() {
  return (
    <div style={{ padding: '20px' }}>
      <h1>Welcome to IRSSH Panel</h1>
      <p>Panel is running correctly.</p>
    </div>
  );
}

export default App;
EOL

# Build React app
npm run build

# Restart services
systemctl restart nginx
supervisorctl restart irssh-panel

echo "Done! Try accessing http://$SERVER_IP"
