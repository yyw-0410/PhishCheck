"""Health and status check endpoints."""

from typing import Dict, Any
from fastapi import APIRouter

router = APIRouter()


@router.get(
    "/health",
    summary="Health Check",
    description="Basic health check endpoint to verify the API is running.",
    response_description="Returns status 'ok' if the API is healthy.",
)
def healthcheck() -> Dict[str, str]:
    """Basic health check endpoint."""
    return {"status": "ok"}


@router.get(
    "/health/integrations",
    summary="Integration Status",
    description="Check the status of all external API integrations (VirusTotal, URLscan, etc.).",
    response_description="Returns configuration and status for each integration.",
)
def integration_status() -> Dict[str, Any]:
    """Check status of all API integrations based on configured API keys."""
    from app.core.config import get_settings
    settings = get_settings()
    
    return {
        "virustotal": {
            "status": "live" if settings.virustotal_api_key and settings.virustotal_api_key != "YOUR_VIRUSTOTAL_API_KEY" else "offline",
            "configured": bool(settings.virustotal_api_key and settings.virustotal_api_key != "YOUR_VIRUSTOTAL_API_KEY")
        },
        "sublime": {
            "status": "live" if settings.sublime_api_key and settings.sublime_api_key != "YOUR_SUBLIME_API_KEY" else "offline",
            "configured": bool(settings.sublime_api_key and settings.sublime_api_key != "YOUR_SUBLIME_API_KEY")
        },
        "urlscan": {
            "status": "live" if settings.urlscan_api_key and settings.urlscan_api_key != "YOUR_URLSCAN_API_KEY" else "offline",
            "configured": bool(settings.urlscan_api_key and settings.urlscan_api_key != "YOUR_URLSCAN_API_KEY")
        },
        "ipqs": {
            "status": "live" if settings.ipqs_api_key and settings.ipqs_api_key != "YOUR_IPQS_API_KEY" else "offline",
            "configured": bool(settings.ipqs_api_key and settings.ipqs_api_key != "YOUR_IPQS_API_KEY")
        },
        "hybridanalysis": {
            "status": "live" if settings.hybrid_analysis_api_key and settings.hybrid_analysis_api_key != "YOUR_HYBRID_ANALYSIS_API_KEY" else "offline",
            "configured": bool(settings.hybrid_analysis_api_key and settings.hybrid_analysis_api_key != "YOUR_HYBRID_ANALYSIS_API_KEY")
        },
        "ai": {
            "status": "live" if settings.ai_api_key and settings.ai_api_key != "YOUR_AI_API_KEY" and settings.ai_enabled else "offline",
            "configured": bool(settings.ai_api_key and settings.ai_api_key != "YOUR_AI_API_KEY"),
            "enabled": settings.ai_enabled
        },
        "api_protection": {
            "enabled": settings.require_api_key
        }
    }


@router.get(
    "/",
    summary="API Root",
    description="Root endpoint confirming the backend is running.",
)
def index() -> Dict[str, str]:
    """Root endpoint."""
    return {"message": "PhishCheck API v1 - Backend running successfully!"}

