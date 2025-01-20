# app/api/router.py

from fastapi import APIRouter, Depends
from app.api.deps import get_current_active_user

from app.api.v1.endpoints import (
    auth,
    users,
    protocols,
    settings,
    monitoring
)

# Create main router
api_router = APIRouter()

# Include all routers
api_router.include_router(
    auth.router,
    prefix="/auth",
    tags=["Authentication"]
)

api_router.include_router(
    users.router,
    prefix="/users",
    tags=["Users"],
    dependencies=[Depends(get_current_active_user)]
)

api_router.include_router(
    protocols.router,
    prefix="/protocols",
    tags=["Protocols"],
    dependencies=[Depends(get_current_active_user)]
)

api_router.include_router(
    settings.router,
    prefix="/settings",
    tags=["Settings"],
    dependencies=[Depends(get_current_active_user)]
)

api_router.include_router(
    monitoring.router,
    prefix="/monitoring",
    tags=["Monitoring"],
    dependencies=[Depends(get_current_active_user)]
)

# Root API endpoint
@api_router.get("/")
async def root():
    """Root API endpoint"""
    return {
        "name": "IRSSH Panel API",
        "version": "1.0.0",
        "documentation": "/docs",
        "openapi": "/openapi.json"
    }

# Health check endpoint
@api_router.get("/health")
async def health_check():
    """API health check endpoint"""
    return {
        "status": "healthy",
        "services": {
            "api": "up",
            "database": "up"
        }
    }
