#!/bin/bash

# Configuration
PANEL_DIR="/opt/irssh-panel"
BACKEND_DIR="$PANEL_DIR/backend"
VENV_DIR="$PANEL_DIR/venv"

# Create debug endpoint
cat > "$BACKEND_DIR/app/main.py" << 'EOL'
from fastapi import FastAPI, Form, Request
from fastapi.middleware.cors import CORSMiddleware
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = FastAPI()

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

@app.post("/api/auth/token")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    logger.debug(f"Login attempt - Username: {username}")
    
    # Log request headers
    logger.debug("Request headers:")
    for k, v in request.headers.items():
        logger.debug(f"{k}: {v}")
    
    # For testing, accept any login with password "test123"
    if password == "test123":
        return {
            "access_token": "test_token",
            "token_type": "bearer",
            "username": username
        }
    
    logger.debug("Invalid password")
    return {"detail": "Invalid username or password"}
EOL

# Create test login page
cat > "$FRONTEND_DIR/src/components/Auth/Login.js" << 'EOL'
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      console.log('Attempting login...');
      
      const formData = new FormData();
      formData.append('username', username);
      formData.append('password', password);
      
      console.log('Making API request...');
      const response = await axios.post('/api/auth/token', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      
      console.log('API Response:', response.data);
      
      if (response.data.access_token) {
        localStorage.setItem('token', response.data.access_token);
        localStorage.setItem('username', response.data.username);
        navigate('/dashboard');
      }
    } catch (error) {
      console.error('Login error:', error);
      setError('Invalid username or password');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full p-8 bg-white shadow rounded">
        <h2 className="text-center text-3xl font-bold mb-6">Sign in to IRSSH Panel</h2>
        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <input
              type="text"
              placeholder="Username"
              className="w-full p-2 border rounded"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>
          <div className="mb-4">
            <input
              type="password"
              placeholder="Password"
              className="w-full p-2 border rounded"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          {error && (
            <div className="text-red-500 text-sm mb-4 text-center">
              {error}
            </div>
          )}
          <button
            type="submit"
            className="w-full bg-blue-500 text-white p-2 rounded hover:bg-blue-600"
          >
            Sign in
          </button>
        </form>
      </div>
    </div>
  );
}
EOL

# Build frontend
cd "$FRONTEND_DIR"
npm run build

# Restart services
supervisorctl restart irssh-panel

echo "Debug version installed."
echo "Try logging in with any username and password 'test123'"
echo "Check the logs with: tail -f /var/log/irssh/uvicorn.log"
