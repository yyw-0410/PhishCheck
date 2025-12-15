"""Routers package - exports all route modules."""

from .health import router as health_router
from .email import router as email_router
from .link import router as link_router
from .file import router as file_router
from .ai_agent import router as ai_router

__all__ = [
    "health_router",
    "email_router", 
    "link_router",
    "file_router",
    "ai_router",
]
