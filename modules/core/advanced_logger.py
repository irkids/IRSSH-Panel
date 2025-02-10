#!/usr/bin/env python3

import os
import sys
import logging
import logging.handlers
from typing import Optional, Dict, Any
from datetime import datetime
from pathlib import Path
import json
import threading
from concurrent.futures import ThreadPoolExecutor

class AdvancedLogger:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
            return cls._instance

    def __init__(self, 
                 log_dir: str = "/var/log/irssh",
                 app_name: str = "irssh",
                 log_level: str = "INFO",
                 max_size: int = 10485760,  # 10MB
                 backup_count: int = 5):
        if not hasattr(self, 'initialized'):
            self.log_dir = Path(log_dir)
            self.app_name = app_name
            self.log_level = getattr(logging, log_level.upper())
            self.max_size = max_size
            self.backup_count = backup_count
            self.loggers: Dict[str, logging.Logger] = {}
            self.executor = ThreadPoolExecutor(max_workers=2)
            
            self._setup_log_directory()
            self._configure_base_logger()
            self.initialized = True

    def _setup_log_directory(self) -> None:
        """Create logging directory with proper permissions"""
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(str(self.log_dir), 0o755)
        except Exception as e:
            sys.stderr.write(f"Failed to create log directory: {e}\n")
            raise

    def _configure_base_logger(self) -> None:
        """Configure the base logging setup"""
        try:
            # Main log file
            main_log = self.log_dir / f"{self.app_name}.log"
            
            # Create formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )

            # File handler with rotation
            file_handler = logging.handlers.RotatingFileHandler(
                main_log,
                maxBytes=self.max_size,
                backupCount=self.backup_count
            )
            file_handler.setFormatter(formatter)

            # Stream handler for console output
            stream_handler = logging.StreamHandler(sys.stdout)
            stream_handler.setFormatter(formatter)

            # Configure root logger
            root_logger = logging.getLogger()
            root_logger.setLevel(self.log_level)
            root_logger.addHandler(file_handler)
            root_logger.addHandler(stream_handler)

            # Create error log specifically for exceptions
            error_handler = logging.handlers.RotatingFileHandler(
                self.log_dir / f"{self.app_name}_error.log",
                maxBytes=self.max_size,
                backupCount=self.backup_count
            )
            error_handler.setFormatter(formatter)
            error_handler.setLevel(logging.ERROR)
            root_logger.addHandler(error_handler)

        except Exception as e:
            sys.stderr.write(f"Failed to configure logging: {e}\n")
            raise

    def get_logger(self, name: str) -> logging.Logger:
        """Get or create a logger for a specific component"""
        if name not in self.loggers:
            logger = logging.getLogger(name)
            logger.setLevel(self.log_level)
            self.loggers[name] = logger
        return self.loggers[name]

    def log_exception(self, exc: Exception, context: Optional[Dict[str, Any]] = None) -> None:
        """Log an exception with additional context"""
        def _log_exception():
            error_logger = self.get_logger('error')
            error_msg = {
                'timestamp': datetime.utcnow().isoformat(),
                'exception_type': exc.__class__.__name__,
                'exception_message': str(exc),
                'traceback': self._format_traceback(exc),
                'context': context or {}
            }
            error_logger.error(json.dumps(error_msg))

        self.executor.submit(_log_exception)

    @staticmethod
    def _format_traceback(exc: Exception) -> str:
        """Format exception traceback"""
        import traceback
        return ''.join(traceback.format_exception(type(exc), exc, exc.__traceback__))

    def rotate_logs(self) -> None:
        """Manually trigger log rotation"""
        for handler in logging.getLogger().handlers:
            if isinstance(handler, logging.handlers.RotatingFileHandler):
                handler.doRollover()

    def cleanup_old_logs(self, days: int = 30) -> None:
        """Clean up log files older than specified days"""
        def _cleanup():
            try:
                from datetime import timedelta
                cutoff = datetime.now() - timedelta(days=days)
                
                for log_file in self.log_dir.glob("*.log.*"):
                    if log_file.stat().st_mtime < cutoff.timestamp():
                        log_file.unlink()
            except Exception as e:
                self.get_logger('system').error(f"Log cleanup failed: {e}")

        self.executor.submit(_cleanup)

    def shutdown(self) -> None:
        """Gracefully shutdown logging"""
        self.executor.shutdown(wait=True)
        logging.shutdown()

# Example usage
if __name__ == "__main__":
    # Initialize logger
    logger = AdvancedLogger(
        log_dir="/var/log/irssh",
        app_name="irssh",
        log_level="DEBUG"
    )

    # Get component specific logger
    ssh_logger = logger.get_logger('ssh')
    ssh_logger.info("SSH service starting")

    try:
        # Simulate an error
        raise ValueError("Test error")
    except Exception as e:
        logger.log_exception(e, {"component": "ssh", "action": "startup"})

    # Cleanup on exit
    logger.cleanup_old_logs(days=7)
    logger.shutdown()
