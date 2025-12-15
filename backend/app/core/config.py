"""Environment-driven configuration for the FastAPI application."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from typing import List, Optional

from dotenv import dotenv_values


def _to_bool(value: Optional[str], *, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_list(raw: Optional[str], *, fallback: List[str]) -> List[str]:
    if not raw:
        return fallback
    return [item.strip() for item in raw.split(",") if item.strip()]


_ENV_FALLBACKS = dotenv_values()


def _get_env(key: str, default: Optional[str] = None) -> Optional[str]:
    """Return environment variable with .env fallback without mutating os.environ."""
    if key in os.environ:
        return os.environ[key]
    return _ENV_FALLBACKS.get(key, default)


@dataclass(frozen=True)
class Settings:
    secret_key: str
    allowed_origins: List[str]
    trusted_hosts: List[str]
    debug: bool
    environment: str
    sublime_api_key: str
    sublime_base_url: str
    sublime_timeout: float
    virustotal_api_key: str
    urlscan_api_key: Optional[str]
    ipqs_api_key: Optional[str]
    hybrid_analysis_api_key: Optional[str]
    # AI/RAG Configuration
    ai_api_key: Optional[str]
    ai_api_key_2: Optional[str]  # Second API key for failover
    ai_enabled: bool  # Feature flag for AI/Gemini calls
    # API Protection
    require_api_key: bool  # Require X-API-Key header for analysis endpoints
    # OAuth - Google
    google_client_id: str
    google_client_secret: str
    google_redirect_uri: str
    # OAuth - Microsoft
    ms_client_id: str
    ms_client_secret: str
    ms_redirect_uri: str
    # Frontend URL (for OAuth redirects)
    frontend_url: str
    # Email verification (Resend)
    resend_api_key: Optional[str]


_REQUIRED_KEYS = [
    "SUBLIME_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
    "MS_CLIENT_ID",
    "MS_CLIENT_SECRET",
]


def _load_settings() -> Settings:
    secret_key = _get_env("SECRET_KEY")
    if not secret_key:
        raise RuntimeError(
            "Missing SECRET_KEY environment variable. "
            "Set it in your .env or system environment before starting the API."
        )

    environment = _get_env("ENVIRONMENT", "development").strip().lower()
    if environment not in {"development", "production"}:
        raise RuntimeError("ENVIRONMENT must be either 'development' or 'production'.")

    # Frontend URL - used for both CORS and OAuth redirects
    frontend_url = _get_env("FRONTEND_URL", "http://localhost:5173")
    
    # Use FRONTEND_URL for CORS, or fall back to ALLOWED_ORIGINS if explicitly set
    allowed_origins_raw = _get_env("ALLOWED_ORIGINS")
    if allowed_origins_raw:
        allowed_origins = _parse_list(allowed_origins_raw, fallback=[])
    else:
        allowed_origins = [frontend_url] if frontend_url else []
    
    if environment == "production" and not allowed_origins:
        raise RuntimeError(
            "In production you must define FRONTEND_URL or ALLOWED_ORIGINS."
        )

    default_hosts = ["localhost", "127.0.0.1"] if environment == "development" else []
    trusted_hosts = _parse_list(_get_env("BACKEND_TRUSTED_HOSTS"), fallback=default_hosts)
    if environment == "production" and not trusted_hosts:
        raise RuntimeError(
            "In production you must define BACKEND_TRUSTED_HOSTS with the domains serving this API."
        )

    debug_default = environment != "production"
    debug = _to_bool(_get_env("DEBUG"), default=debug_default)
    if environment == "production" and debug:
        raise RuntimeError("DEBUG must be disabled in production.")

    missing = [key for key in _REQUIRED_KEYS if not _get_env(key)]
    if missing:
        raise RuntimeError(
            "Missing required environment variables: "
            f"{', '.join(sorted(missing))}. "
            "Populate them in your system environment or .env file."
        )

    sublime_api_key = _get_env("SUBLIME_API_KEY")
    sublime_base_url = _get_env("SUBLIME_BASE_URL", "https://analyzer.sublime.security").rstrip("/")
    sublime_timeout_raw = _get_env("SUBLIME_TIMEOUT_SECONDS")
    sublime_timeout = float(sublime_timeout_raw) if sublime_timeout_raw else 30.0

    virustotal_api_key = _get_env("VIRUSTOTAL_API_KEY")
    urlscan_api_key = _get_env("URLSCAN_API_KEY")
    ipqs_api_key = _get_env("IPQS_API_KEY")
    hybrid_analysis_api_key = _get_env("HYBRID_ANALYSIS_API_KEY")
    
    # AI/RAG - OpenAI compatible API key (optional)
    ai_api_key = _get_env("AI_API_KEY")
    ai_api_key_2 = _get_env("AI_API_KEY_2")  # Second key for failover
    # AI feature flag - set to false to disable Gemini calls (data leak protection)
    ai_enabled = _to_bool(_get_env("AI_ENABLED"), default=True)
    
    # API Protection - set to true to require X-API-Key header on analysis endpoints
    require_api_key = _to_bool(_get_env("REQUIRE_API_KEY"), default=False)

    # OAuth - Google
    google_client_id = _get_env("GOOGLE_CLIENT_ID")
    google_client_secret = _get_env("GOOGLE_CLIENT_SECRET")
    google_redirect_uri = _get_env(
        "GOOGLE_REDIRECT_URI",
        "http://localhost:8000/api/auth/google/callback" if environment == "development" else None
    )

    # OAuth - Microsoft
    ms_client_id = _get_env("MS_CLIENT_ID")
    ms_client_secret = _get_env("MS_CLIENT_SECRET")
    ms_redirect_uri = _get_env(
        "MS_REDIRECT_URI",
        "http://localhost:8000/api/auth/microsoft/callback" if environment == "development" else None
    )

    return Settings(
        secret_key=secret_key,
        allowed_origins=allowed_origins,
        trusted_hosts=trusted_hosts,
        debug=debug,
        environment=environment,
        sublime_api_key=sublime_api_key,
        sublime_base_url=sublime_base_url,
        sublime_timeout=sublime_timeout,
        virustotal_api_key=virustotal_api_key,
        urlscan_api_key=urlscan_api_key,
        ipqs_api_key=ipqs_api_key,
        hybrid_analysis_api_key=hybrid_analysis_api_key,
        ai_api_key=ai_api_key,
        ai_api_key_2=ai_api_key_2,
        ai_enabled=ai_enabled,
        require_api_key=require_api_key,
        google_client_id=google_client_id,
        google_client_secret=google_client_secret,
        google_redirect_uri=google_redirect_uri,
        ms_client_id=ms_client_id,
        ms_client_secret=ms_client_secret,
        ms_redirect_uri=ms_redirect_uri,
        frontend_url=frontend_url,
        resend_api_key=_get_env("RESEND_API_KEY"),
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached application settings."""
    return _load_settings()
