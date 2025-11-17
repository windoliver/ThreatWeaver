"""ThreatWeaver FastAPI application entry point."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import settings
from .config.logging import configure_logging, get_logger

# Configure logging on module import
configure_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan handler for startup and shutdown events."""
    # Startup
    logger.info(
        "starting_application",
        app_name=settings.app_name,
        version=settings.app_version,
        environment=settings.environment,
    )

    yield

    # Shutdown
    logger.info("shutting_down_application")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Multi-Agent Cybersecurity Platform",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
        debug=settings.debug,
    )

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=settings.cors_allow_methods,
        allow_headers=settings.cors_allow_headers,
    )

    # Health check endpoint
    @app.get("/health", tags=["Health"])
    async def health_check() -> JSONResponse:
        """Health check endpoint."""
        logger.debug("health_check_called")
        return JSONResponse(
            status_code=200,
            content={
                "status": "healthy",
                "app": settings.app_name,
                "version": settings.app_version,
                "environment": settings.environment,
            },
        )

    # Root endpoint
    @app.get("/", tags=["Root"])
    async def root() -> JSONResponse:
        """Root endpoint with API information."""
        return JSONResponse(
            content={
                "app": settings.app_name,
                "version": settings.app_version,
                "docs": "/docs",
                "health": "/health",
            }
        )

    logger.info(
        "application_created",
        cors_origins=settings.cors_origins,
        api_prefix=settings.api_v1_prefix,
    )

    return app


# Create the application instance
app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )
