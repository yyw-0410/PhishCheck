"""Versioned API routes."""

from fastapi import APIRouter, Depends

from .dependencies import require_api_key

router = APIRouter()


@router.get("/health")
def healthcheck():
    return {"status": "ok"}


@router.get("/")
def index():
    return {"message": "Backend running successfully!"}


@router.get("/secure/ping", dependencies=[Depends(require_api_key)])
def secure_ping():
    return {"message": "Authenticated request successful."}
