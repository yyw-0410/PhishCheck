"""Versioned API routes - combines all sub-routers."""

from fastapi import APIRouter, Depends

from .routers.dependencies import require_api_key
from .routers.health import router as health_router
from .routers.email import router as email_router
from .routers.link import router as link_router
from .routers.file import router as file_router
from .routers.ai_agent import router as ai_router

router = APIRouter()

# Health endpoints (hidden from docs - internal use)
router.include_router(health_router, include_in_schema=False)

# Analysis endpoints (all under /analysis prefix)
router.include_router(email_router, prefix="/analysis", tags=["Analysis"])
router.include_router(link_router, prefix="/analysis", tags=["Analysis"])
router.include_router(file_router, prefix="/analysis", tags=["Analysis"])

# AI Agent endpoints
router.include_router(ai_router, prefix="/ai", tags=["AI"])

# Secure ping endpoint (hidden from docs - internal use)
@router.get("/secure/ping", dependencies=[Depends(require_api_key)], include_in_schema=False)
def secure_ping():
    """Authenticated ping endpoint."""
    return {"message": "Authenticated request successful."}
