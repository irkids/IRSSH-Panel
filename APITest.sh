#!/bin/bash

PANEL_DIR="/opt/irssh-panel"
BACKEND_DIR="$PANEL_DIR/backend"
VENV_DIR="$PANEL_DIR/venv"

# Create a simple test API
cat > "$BACKEND_DIR/app/main.py" << 'EOL'
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "API is working"}

@app.get("/api/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/api/test")
async def test():
    return {"message": "Test endpoint working"}
EOL

# Update supervisor config
cat > /etc/supervisor/conf.d/irssh-panel.conf << EOL
[program:irssh-panel]
directory=$BACKEND_DIR
command=$VENV_DIR/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
user=root
autostart=true
autorestart=true
stdout_logfile=/var/log/irssh/uvicorn.out.log
stderr_logfile=/var/log/irssh/uvicorn.err.log
environment=PYTHONPATH="$BACKEND_DIR"
EOL

# Update Nginx configuration
cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen 8675;
    server_name _;

    root $PANEL_DIR/frontend/build;
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
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # Add CORS headers
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;
    }
}
EOL

# Restart services
supervisorctl reread
supervisorctl update
supervisorctl restart irssh-panel
nginx -t && systemctl restart nginx

echo "API should now be accessible at:"
echo "1. http://YOUR-IP:8000/"
echo "2. http://YOUR-IP:8000/api/health"
echo "3. http://YOUR-IP:8000/api/test"
echo
echo "Panel should be accessible at:"
echo "http://YOUR-IP:8675"
echo
echo "Please test these endpoints and provide the results."
