#!/bin/bash

# بررسی و نصب pip در صورت نیاز
if ! command -v pip3 &> /dev/null
then
    echo "pip3 پیدا نشد. در حال نصب pip3..."
    sudo apt update
    sudo apt install -y python3-pip
fi

# ایجاد و فعال‌سازی محیط مجازی
if [ ! -d "venv" ]; then
    echo "در حال ایجاد محیط مجازی..."
    python3 -m venv venv
fi

source venv/bin/activate

# نصب پیش‌نیازها
echo "در حال نصب پیش‌نیازها..."
pip install --upgrade pip
pip install flask flask_sqlalchemy werkzeug

# بررسی فایل اسکریپت Python
SCRIPT_NAME="login_modulel.py"
if [ ! -f "$SCRIPT_NAME" ]; then
    echo "فایل $SCRIPT_NAME یافت نشد."
    deactivate
    exit 1
fi

# اجرای اسکریپت
echo "در حال اجرای اسکریپت Python..."
python3 $SCRIPT_NAME

# غیرفعال‌سازی محیط مجازی
deactivate
