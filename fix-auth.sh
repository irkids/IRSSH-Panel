#!/bin/bash

# Configuration
PANEL_DIR="/opt/irssh-panel"
BACKEND_DIR="$PANEL_DIR/backend"
FRONTEND_DIR="$PANEL_DIR/frontend"
VENV_DIR="$PANEL_DIR/venv"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Logging
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
    exit 1
}

# Create database initialization script
log "Creating database initialization..."
cat > "$BACKEND_DIR/app/core/database.py" << 'EOL'
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = "sqlite:///./irssh_panel.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
EOL

# Fix supervisor configuration
log "Fixing supervisor configuration..."
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

# Create admin user script
log "Creating admin user setup script..."
cat > "$BACKEND_DIR/create_admin.py" << EOL
from app.models.user import User
from app.core.database import SessionLocal, engine, Base
from app.core.security import get_password_hash

def create_admin_user(username: str, password: str):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    
    # Check if admin exists
    admin = db.query(User).filter(User.username == username).first()
    if admin:
        print("Admin user already exists")
        return
    
    # Create admin user
    admin = User(
        username=username,
        hashed_password=get_password_hash(password),
        is_active=True,
        is_admin=True
    )
    
    db.add(admin)
    db.commit()
    print("Admin user created successfully")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python create_admin.py <username> <password>")
        sys.exit(1)
    
    username = sys.argv[1]
    password = sys.argv[2]
    create_admin_user(username, password)
EOL

# Fix npm vulnerabilities
log "Fixing npm vulnerabilities..."
cd "$FRONTEND_DIR"
npm audit fix --force

# Create admin user
log "Creating admin user..."
read -p "Enter admin username (default: admin): " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}

read -s -p "Enter admin password (default: random): " ADMIN_PASS
echo
if [[ -z "$ADMIN_PASS" ]]; then
    ADMIN_PASS=$(openssl rand -base64 12)
    echo "Generated admin password: $ADMIN_PASS"
fi

# Activate virtual environment and create admin
source "$VENV_DIR/bin/activate"
python "$BACKEND_DIR/create_admin.py" "$ADMIN_USER" "$ADMIN_PASS"

# Restart services
log "Restarting services..."
supervisorctl reread
supervisorctl update
supervisorctl restart irssh-panel

# Wait for service to start
sleep 5

# Test service
log "Testing service..."
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/api/health)
if [ "$response" = "200" ]; then
    log "Service is running correctly"
else
    error "Service is not responding correctly"
fi

echo
echo "Authentication system has been fixed!"
echo "Your admin credentials:"
echo "Username: $ADMIN_USER"
echo "Password: $ADMIN_PASS"
echo
echo "Please test the login at: http://YOUR-IP:8675"
echo "API is running at: http://localhost:8000"
