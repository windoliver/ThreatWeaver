"""API v1 routes."""

from fastapi import APIRouter

from .approvals import router as approvals_router
from .auth import router as auth_router
from .security import router as security_router
from .users import router as users_router

api_router = APIRouter()

# Include sub-routers
api_router.include_router(auth_router, prefix="/auth", tags=["Authentication"])
api_router.include_router(users_router, prefix="/users", tags=["Users"])
api_router.include_router(security_router, prefix="/security", tags=["Security"])
api_router.include_router(approvals_router, prefix="/approvals", tags=["Approvals"])
