# /opt/irssh-panel/modules/protocols/BaseProtocol.py
import os
import sys
import json
import logging
import subprocess
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import yaml

class BaseProtocol(ABC):
    def __init__(self):
        self.config = self.load_config()
        self.setup_logging()
        
    def load_config(self) -> Dict[str, Any]:
        config_path = "/etc/enhanced_ssh/config.yaml"
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            self.log_error(f"Failed to load config: {e}")
            sys.exit(1)
            
    def setup_logging(self):
        log_dir = "/var/log/irssh"
        os.makedirs(log_dir, exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f"{log_dir}/protocols.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(self.__class__.__name__)
        
    def log_info(self, message: str):
        self.logger.info(message)
        
    def log_error(self, message: str):
        self.logger.error(message)
        
    def execute_command(self, command: str) -> tuple[int, str, str]:
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = process.communicate()
            return (
                process.returncode,
                stdout.decode('utf-8'),
                stderr.decode('utf-8')
            )
        except Exception as e:
            self.log_error(f"Command execution failed: {e}")
            return (1, "", str(e))
            
    @abstractmethod
    def create_account(self, username: str, password: str) -> Dict[str, Any]:
        pass
        
    @abstractmethod
    def delete_account(self, username: str) -> bool:
        pass
        
    @abstractmethod
    def update_account(self, username: str, data: Dict[str, Any]) -> bool:
        pass
        
    @abstractmethod
    def get_status(self, username: str) -> Dict[str, Any]:
        pass
        
    @abstractmethod
    def get_configuration(self, username: str) -> Dict[str, Any]:
        pass
        
    def verify_installation(self) -> bool:
        """Verify if the protocol is properly installed and configured"""
        raise NotImplementedError
        
    def get_metrics(self) -> Dict[str, Any]:
        """Get protocol-specific metrics"""
        raise NotImplementedError
        
    def backup_configuration(self) -> bool:
        """Backup protocol-specific configuration"""
        raise NotImplementedError
        
    def restore_configuration(self, backup_path: str) -> bool:
        """Restore protocol-specific configuration"""
        raise NotImplementedError
