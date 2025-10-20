"""Reusable FastAPI dependencies."""

from typing import Optional

from fastapi import Depends, Header, HTTPException, status

from app.core import Settings, get_settings


def require_api_key(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    settings: Settings = Depends(get_settings),
) -> None:
    """Validate that the caller supplied the expected API key."""
    if x_api_key != settings.secret_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )
