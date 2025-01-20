#!/bin/bash

# Configuration
PANEL_DIR="/opt/irssh-panel"
BACKEND_DIR="$PANEL_DIR/backend"
VENV_DIR="$PANEL_DIR/venv"

# Create main.py
mkdir -p "$BACKEND_DIR/app"
cat > "$BACKEND_DIR/app/main.py" << 'EOL'
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/api/version")
async def version():
    return {"version": "1.0.0"}
EOL

# Update supervisor configuration
cat > /etc/supervisor/conf.d/irssh-panel.conf << EOL
[program:irssh-panel]
directory=$BACKEND_DIR
command=$VENV_DIR/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
user=root
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/irssh/uvicorn.log
EOL

# Ensure the log directory exists
mkdir -p /var/log/irssh

# Install required packages
source $VENV_DIR/bin/activate
pip install fastapi uvicorn

# Restart services
supervisorctl reread
supervisorctl update
supervisorctl restart irssh-panel

# Wait a moment for the service to start
sleep 5

# Test the API
echo "Testing API..."
curl http://localhost:8000/api/health
