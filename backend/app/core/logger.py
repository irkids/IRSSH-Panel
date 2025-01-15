# app/core/logger.py

import logging
import sys
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from app.core.config import settings

# Create logs directory if it doesn't exist
os.makedirs(settings.LOG_DIR, exist_ok=True)

# Configure logging format
log_format = logging.Formatter(
    '[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s'
)

# Create logger instance
logger = logging.getLogger('irssh_panel')
logger.setLevel(settings.LOG_LEVEL)

# File handler for all logs
file_handler = RotatingFileHandler(
    filename=os.path.join(settings.LOG_DIR, 'irssh-panel.log'),
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5,
    encoding='utf-8'
)
file_handler.setFormatter(log_format)
logger.addHandler(file_handler)

# Error file handler
error_handler = RotatingFileHandler(
    filename=os.path.join(settings.LOG_DIR, 'error.log'),
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5,
    encoding='utf-8'
)
error_handler.setFormatter(log_format)
error_handler.setLevel(logging.ERROR)
logger.addHandler(error_handler)

# Console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(log_format)
logger.addHandler(console_handler)

# Protocol-specific loggers
def get_protocol_logger(protocol_name: str):
    protocol_logger = logging.getLogger(f'irssh_panel.{protocol_name}')
    protocol_logger.setLevel(settings.LOG_LEVEL)

    # Protocol-specific file handler
    handler = TimedRotatingFileHandler(
        filename=os.path.join(settings.LOG_DIR, f'{protocol_name}.log'),
        when='midnight',
        interval=1,
        backupCount=7,
        encoding='utf-8'
    )
    handler.setFormatter(log_format)
    protocol_logger.addHandler(handler)

    return protocol_logger

# Audit logging
audit_format = logging.Formatter(
    '%(asctime)s - %(message)s'
)

audit_logger = logging.getLogger('irssh_panel.audit')
audit_logger.setLevel(logging.INFO)

audit_handler = TimedRotatingFileHandler(
    filename=os.path.join(settings.LOG_DIR, 'audit.log'),
    when='midnight',
    interval=1,
    backupCount=30,  # Keep 30 days of audit logs
    encoding='utf-8'
)
audit_handler.setFormatter(audit_format)
audit_logger.addHandler(audit_handler)

def log_audit(
    action: str, 
    user_id: int = None, 
    ip_address: str = None, 
    details: dict = None
):
    """Log an audit event"""
    message = {
        'action': action,
        'user_id': user_id,
        'ip_address': ip_address,
        'timestamp': datetime.utcnow().isoformat(),
        'details': details or {}
    }
    audit_logger.info(message)

class RequestLogger:
    """Middleware for logging HTTP requests"""
    async def __call__(self, request, call_next):
        start_time = datetime.utcnow()
        response = await call_next(request)
        duration = (datetime.utcnow() - start_time).total_seconds()

        # Log request details
        logger.info(
            f"Request: {request.method} {request.url.path} "
            f"Status: {response.status_code} "
            f"Duration: {duration:.3f}s "
            f"IP: {request.client.host}"
        )

        return response

def setup_logging_middleware(app):
    """Setup request logging middleware"""
    app.middleware('http')(RequestLogger())
