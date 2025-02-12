# backend/app/__init__.py
from .core.config import settings
from .core.database import init_db

# backend/app/api/__init__.py
from fastapi import APIRouter
router = APIRouter()

# backend/app/core/__init__.py
from .config import settings
from .database import init_db, get_db
from .security import create_access_token, verify_token

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("backend")

logger.info("Logger initialized for backend core module")

# backend/app/models/__init__.py
from .models import User, Protocol, Setting

# backend/app/schemas/__init__.py
from .schemas import UserCreate, UserUpdate, Token, Settings

# backend/app/utils/__init__.py
from .helpers import get_system_stats, monitor_bandwidth
