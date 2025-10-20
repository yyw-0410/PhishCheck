"""Compatibility module that exposes the FastAPI app instance to uvicorn."""

from app.main import app

__all__ = ["app"]
