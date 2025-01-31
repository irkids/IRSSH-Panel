#!/bin/bash

# IRSSH Panel - اصلاح‌شده و نهایی
# نسخه: 3.4.4

# تنظیمات دایرکتوری‌ها
PANEL_DIR="/opt/irssh-panel"
FRONTEND_DIR="$PANEL_DIR/frontend"
BACKEND_DIR="$PANEL_DIR/backend"
CONFIG_DIR="$PANEL_DIR/config"
LOG_DIR="/var/log/irssh"

# متغیرهای پایگاه داده
DB_NAME="irssh_panel"
DB_USER="irssh_admin"
DB_PASS=$(openssl rand -base64 32)
ADMIN_PASS=$(openssl rand -base64 16)
JWT_SECRET=$(openssl rand -base64 32)

# متغیر دامنه
DOMAIN="${DOMAIN:-localhost}"

# ثبت لاگ‌ها
log() {
    echo -e "\033[0;32m[$(date +'%Y-%m-%d %H:%M:%S')]\033[0m $1"
}

error() {
    echo -e "\033[0;31m[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:\033[0m $1"
    exit 1
}

# نصب وابستگی‌ها
install_dependencies() {
    log "نصب وابستگی‌های سیستم..."
    apt update
    apt install -y python3 python3-pip python3-venv nginx nodejs postgresql
}

# تنظیم بک‌اند Python
setup_python_backend() {
    log "ایجاد محیط مجازی پایتون..."
    python3 -m venv "$PANEL_DIR/venv"
    source "$PANEL_DIR/venv/bin/activate"
    pip install fastapi uvicorn sqlalchemy psycopg2-binary passlib cryptography

    log "ایجاد فایل `main.py` برای FastAPI..."
    cat > "$BACKEND_DIR/app/main.py" << EOL
from fastapi import FastAPI
app = FastAPI()

@app.get("/")
def read_root():
    return {"status": "IRSSH Panel Ready"}
EOL
}

# تنظیم دیتابیس PostgreSQL
setup_database() {
    log "راه‌اندازی پایگاه داده..."
    systemctl start postgresql
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"
}

# تنظیم Nginx
setup_nginx() {
    log "پیکربندی Nginx..."

    cat > /etc/nginx/sites-available/irssh-panel << EOL
server {
    listen 80;
    server_name ${DOMAIN};

    root ${FRONTEND_DIR}/build;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location /api {
        proxy_pass http://localhost:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOL

    ln -sf /etc/nginx/sites-available/irssh-panel /etc/nginx/sites-enabled/
    nginx -t || error "تنظیمات Nginx نامعتبر است."
    systemctl restart nginx
}

# بررسی و نصب Node.js و رفع خطای `npm audit`
setup_frontend() {
    log "نصب وابستگی‌های فرانت‌اند..."
    cd "$FRONTEND_DIR"
    npm install
    npm audit fix --force
    npm run build
}

# تست و بررسی سرویس‌ها
verify_services() {
    log "بررسی وضعیت سرویس‌ها..."
    systemctl status nginx postgresql | grep Active || error "یک یا چند سرویس اجرا نشده است!"
    curl -s "http://localhost" > /dev/null || error "وب‌سرور در دسترس نیست."
}

# اجرای تمام مراحل نصب
main() {
    install_dependencies
    setup_python_backend
    setup_database
    setup_nginx
    setup_frontend
    verify_services
    log "✅ نصب با موفقیت انجام شد!"
}

main "$@"
