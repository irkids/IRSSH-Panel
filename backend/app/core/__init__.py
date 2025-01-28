"""
Core module initialization.
This module contains core functionality for the IRSSH Panel.
"""

from .config import settings
from .database import Base, engine, get_db
from .exceptions import (
    DatabaseError,
    AuthenticationError,
    ConfigurationError,
    ProtocolError
)
from .logger import setup_logging

# Setup logging when the module is imported
setup_logging()

__all__ = [
    'settings',
    'Base',
    'engine',
    'get_db',
    'DatabaseError',
    'AuthenticationError',
    'ConfigurationError',
    'ProtocolError',
    'setup_logging'
]
