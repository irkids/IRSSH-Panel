from pydantic_settings import BaseSettings
from typing import List, Optional
import os

class Settings(BaseSettings):
    # Project Info
    PROJECT_NAME: str = "IRSSH Panel"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "Advanced VPN Server Management Panel"
    
    # API Settings
    API_V1_STR: str = "/api/v1"
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000"]
    
    # Database Settings
    DB_HOST: str = os.getenv("DB_HOST", "localhost")
    DB_PORT: int = int(os.getenv("DB_PORT", "5432"))
    DB_USER: str = os.getenv("DB_USER", "postgres")
    DB_PASS: str = os.getenv("DB_PASS", "")
    DB_NAME: str = os.getenv("DB_NAME", "irssh_panel")
    DATABASE_URI: Optional[str] = None

    # JWT Settings
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-super-secret-key")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    
    # Modules Directory
    MODULES_DIR: str = "/opt/irssh-panel/modules"
    
    # Logging Settings
    LOG_LEVEL: str = "INFO"
    LOG_DIR: str = "/var/log/irssh"

    # Backup Settings
    BACKUP_DIR: str = "/opt/irssh-panel/backups"
    BACKUP_RETENTION_DAYS: int = 7

    # Telegram Settings
    TELEGRAM_BOT_TOKEN: Optional[str] = None
    TELEGRAM_CHAT_ID: Optional[str] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.DATABASE_URI = f"postgresql://{self.DB_USER}:{self.DB_PASS}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

        # Ensure directories exist
        os.makedirs(self.MODULES_DIR, exist_ok=True)
        os.makedirs(self.LOG_DIR, exist_ok=True)
        os.makedirs(self.BACKUP_DIR, exist_ok=True)

    class Config:
        env_file = ".env"

settings = Settings()
