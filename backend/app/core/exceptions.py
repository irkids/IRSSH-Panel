from fastapi import HTTPException, status
from typing import Optional

class IRSSHException(HTTPException):
    """Base exception for IRSSH Panel"""
    def __init__(
        self,
        status_code: int,
        detail: str,
        headers: Optional[dict] = None
    ):
        super().__init__(status_code=status_code, detail=detail, headers=headers)

class CredentialsException(IRSSHException):
    """Exception for authentication errors"""
    def __init__(self, detail: str = "Could not validate credentials"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"}
        )

class PermissionDeniedException(IRSSHException):
    """Exception for permission errors"""
    def __init__(self, detail: str = "Permission denied"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail
        )

class NotFoundException(IRSSHException):
    """Exception for not found resources"""
    def __init__(self, detail: str = "Resource not found"):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=detail
        )

class BadRequestException(IRSSHException):
    """Exception for bad requests"""
    def __init__(self, detail: str = "Bad request"):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail
        )

class DuplicateException(IRSSHException):
    """Exception for duplicate resources"""
    def __init__(self, detail: str = "Resource already exists"):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail
        )

class ModuleException(IRSSHException):
    """Exception for module errors"""
    def __init__(self, detail: str = "Module error occurred"):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail
        )

# Error handler
def register_exception_handlers(app):
    @app.exception_handler(IRSSHException)
    async def irssh_exception_handler(request, exc: IRSSHException):
        """Handle IRSSH specific exceptions"""
        return {
            "detail": exc.detail,
            "status_code": exc.status_code,
            "path": request.url.path
        }

    @app.exception_handler(Exception)
    async def global_exception_handler(request, exc: Exception):
        """Handle all unhandled exceptions"""
        # Log the error
        import traceback
        from app.core.logger import logger
        
        logger.error(f"Unhandled exception: {str(exc)}")
        logger.error(traceback.format_exc())
        
        return {
            "detail": "Internal server error occurred",
            "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
            "path": request.url.path,
            "type": type(exc).__name__
        }

class ValidationError(IRSSHException):
    """Exception for validation errors"""
    def __init__(self, errors: list):
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "message": "Validation error",
                "errors": errors
            }
        )

class DatabaseError(IRSSHException):
    """Exception for database errors"""
    def __init__(self, detail: str = "Database error occurred"):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail
        )

class ConfigurationError(IRSSHException):
    """Exception for configuration errors"""
    def __init__(self, detail: str = "Configuration error occurred"):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail
        )

class BackupError(IRSSHException):
    """Exception for backup/restore errors"""
    def __init__(self, detail: str = "Backup/restore operation failed"):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail
        )

class ProtocolError(IRSSHException):
    """Exception for protocol-specific errors"""
    def __init__(self, protocol: str, detail: str):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Protocol error ({protocol}): {detail}"
        )

class SystemError(IRSSHException):
    """Exception for system-level errors"""
    def __init__(self, detail: str = "System error occurred"):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail
        )

class RateLimitExceeded(IRSSHException):
    """Exception for rate limiting"""
    def __init__(self, detail: str = "Rate limit exceeded"):
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=detail,
            headers={"Retry-After": "60"}
        )

class ServiceUnavailable(IRSSHException):
    """Exception for service unavailability"""
    def __init__(self, detail: str = "Service temporarily unavailable"):
        super().__init__(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=detail
        )

# Custom error responses
ERROR_RESPONSES = {
    400: {"description": "Bad Request", "model": BadRequestException},
    401: {"description": "Unauthorized", "model": CredentialsException},
    403: {"description": "Forbidden", "model": PermissionDeniedException},
    404: {"description": "Not Found", "model": NotFoundException},
    409: {"description": "Conflict", "model": DuplicateException},
    422: {"description": "Validation Error", "model": ValidationError},
    429: {"description": "Too Many Requests", "model": RateLimitExceeded},
    500: {"description": "Internal Server Error", "model": IRSSHException},
    503: {"description": "Service Unavailable", "model": ServiceUnavailable}
}
