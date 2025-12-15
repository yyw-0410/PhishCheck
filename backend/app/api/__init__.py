"""API routers for the PhishCheck backend."""

from fastapi import APIRouter

from .routes import router as v1_router
from .routers.auth import router as auth_router

api_router = APIRouter()

# Versioned API routes under /v1 prefix
api_router.include_router(v1_router, prefix="/v1")

# Auth routes (hidden from docs - internal use)
api_router.include_router(auth_router, include_in_schema=False)

__all__ = ["api_router"]

