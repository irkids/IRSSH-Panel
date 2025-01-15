# backend/app/main.py

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles

from app.core.config import settings
from app.core.logger import setup_logging_middleware
from app.core.exceptions import register_exception_handlers
from app.api.router import api_router

# Create FastAPI app
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=settings.DESCRIPTION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add Gzip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Setup logging middleware
setup_logging_middleware(app)

# Register exception handlers
register_exception_handlers(app)

# Include API router
app.include_router(api_router, prefix="/api")

# Mount static files for frontend
app.mount("/", StaticFiles(directory="frontend/build", html=True), name="static")

# Startup event
@app.on_event("startup")
async def startup_event():
    # Initialize database
    from app.core.database import init_db
    await init_db()
    
    # Start background tasks
    from app.core.tasks import start_background_tasks
    await start_background_tasks()

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    # Cleanup tasks
    from app.core.tasks import cleanup_tasks
    await cleanup_tasks()

# Health check endpoint
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "version": settings.VERSION
    }
