#!/bin/bash

# Configuration
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"

# Create index.html
cat > "$FRONTEND_DIR/public/index.html" << 'EOL'
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>IRSSH Panel</title>
  </head>
  <body>
    <div id="root"></div>
  </body>
</html>
EOL

# Create App.js
cat > "$FRONTEND_DIR/src/App.js" << 'EOL'
import React, { useState, useEffect } from 'react';

function App() {
  const [apiStatus, setApiStatus] = useState('Loading...');

  useEffect(() => {
    fetch('/api/health')
      .then(response => response.json())
      .then(data => {
        setApiStatus(data.status);
      })
      .catch(error => {
        setApiStatus('Error connecting to API');
        console.error('Error:', error);
      });
  }, []);

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif'
    }}>
      <h1 style={{ marginBottom: '20px' }}>IRSSH Panel</h1>
      <div style={{
        padding: '20px',
        borderRadius: '8px',
        backgroundColor: '#f5f5f5',
        boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
      }}>
        <p>API Status: <strong>{apiStatus}</strong></p>
      </div>
    </div>
  );
}

export default App;
EOL

# Create index.js
cat > "$FRONTEND_DIR/src/index.js" << 'EOL'
import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';

const container = document.getElementById('root');
const root = createRoot(container);
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
EOL

# Update package.json
cat > "$FRONTEND_DIR/package.json" << 'EOL'
{
  "name": "irssh-panel",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-scripts": "5.0.1"
  },
  "scripts": {
    "start": "react-scripts start",
    "build": "react-scripts build",
    "test": "react-scripts test",
    "eject": "react-scripts eject"
  },
  "eslintConfig": {
    "extends": [
      "react-app"
    ]
  },
  "browserslist": {
    "production": [
      ">0.2%",
      "not dead",
      "not op_mini all"
    ],
    "development": [
      "last 1 chrome version",
      "last 1 firefox version",
      "last 1 safari version"
    ]
  }
}
EOL

# Install dependencies and build
cd "$FRONTEND_DIR"
npm install
npm run build

# Update nginx configuration
cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen 8675;
    server_name _;

    root $FRONTEND_DIR/build;
    index index.html;

    # Important: try_files directive for React Router
    location / {
        try_files \$uri \$uri/ /index.html;
        add_header Cache-Control "no-cache";
    }

    location /api {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Disable caching for service worker
    location /static {
        expires 1y;
        add_header Cache-Control "public, no-transform";
    }
}
EOL

# Test nginx configuration and restart
nginx -t && systemctl restart nginx

echo "Frontend has been rebuilt!"
echo "Please access the panel at: http://YOUR-IP:8675"
echo "You should see a simple page showing the API status."
