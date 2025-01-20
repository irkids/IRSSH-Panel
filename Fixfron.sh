#!/bin/bash

# Configuration
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"

# Ensure frontend directory exists
mkdir -p "$FRONTEND_DIR/src/components/Auth"

# Update main FastAPI app with debug logging
cat > "$BACKEND_DIR/app/main.py" << 'EOL'
from fastapi import FastAPI, Form, Request
from fastapi.middleware.cors import CORSMiddleware
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='/var/log/irssh/auth.log'
)
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
    logger.info("Health check endpoint called")
    return {"status": "healthy"}

@app.post("/api/auth/token")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    logger.info(f"Login attempt for user: {username}")
    
    if username == "admin" and password == "test123":
        logger.info("Login successful")
        return {
            "access_token": "test_token",
            "token_type": "bearer",
            "username": username
        }
    
    logger.warning("Login failed")
    return {"detail": "Invalid username or password"}
EOL

# Create React components directory
mkdir -p "$FRONTEND_DIR/src/components/Auth"

# Create Login component
cat > "$FRONTEND_DIR/src/components/Auth/Login.js" << 'EOL'
import React, { useState } from 'react';

function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    console.log('Login attempt:', { username });

    try {
      const formData = new FormData();
      formData.append('username', username);
      formData.append('password', password);

      const response = await fetch('/api/auth/token', {
        method: 'POST',
        body: formData,
      });

      const data = await response.json();
      console.log('API Response:', data);

      if (data.access_token) {
        localStorage.setItem('token', data.access_token);
        localStorage.setItem('username', data.username);
        window.location.href = '/dashboard';
      } else {
        setError('Invalid username or password');
      }
    } catch (error) {
      console.error('Login error:', error);
      setError('Login failed. Please try again.');
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      backgroundColor: '#f3f4f6'
    }}>
      <div style={{
        width: '100%',
        maxWidth: '400px',
        padding: '20px',
        backgroundColor: 'white',
        borderRadius: '8px',
        boxShadow: '0 2px 4px rgba(0, 0, 0, 0.1)'
      }}>
        <h2 style={{
          textAlign: 'center',
          fontSize: '24px',
          fontWeight: 'bold',
          marginBottom: '20px'
        }}>Sign in to IRSSH Panel</h2>
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '15px' }}>
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              style={{
                width: '100%',
                padding: '10px',
                border: '1px solid #ddd',
                borderRadius: '4px'
              }}
            />
          </div>
          <div style={{ marginBottom: '15px' }}>
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={{
                width: '100%',
                padding: '10px',
                border: '1px solid #ddd',
                borderRadius: '4px'
              }}
            />
          </div>
          {error && (
            <div style={{
              color: '#dc2626',
              textAlign: 'center',
              marginBottom: '15px',
              fontSize: '14px'
            }}>
              {error}
            </div>
          )}
          <button
            type="submit"
            style={{
              width: '100%',
              padding: '10px',
              backgroundColor: '#2563eb',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer'
            }}
          >
            Sign in
          </button>
        </form>
      </div>
    </div>
  );
}

export default Login;
EOL

# Create App.js
cat > "$FRONTEND_DIR/src/App.js" << 'EOL'
import React from 'react';
import Login from './components/Auth/Login';

function App() {
  return <Login />;
}

export default App;
EOL

# Update index.js
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

# Create authentication log file
touch /var/log/irssh/auth.log
chmod 644 /var/log/irssh/auth.log

# Build frontend
cd "$FRONTEND_DIR"
npm install
npm run build

# Restart services
supervisorctl restart irssh-panel

echo
echo "Authentication system has been updated!"
echo "Try logging in with:"
echo "Username: admin"
echo "Password: test123"
echo
echo "Check the authentication logs with:"
echo "tail -f /var/log/irssh/auth.log"
