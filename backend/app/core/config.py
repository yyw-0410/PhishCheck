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

    default_origins = ["http://localhost:5173"] if environment == "development" else []
    allowed_origins = _parse_list(_get_env("ALLOWED_ORIGINS"), fallback=default_origins)
    if environment == "production" and not allowed_origins:
        raise RuntimeError(
            "In production you must define ALLOWED_ORIGINS with the frontend domains allowed to access the API."
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

    return Settings(
        secret_key=secret_key,
        allowed_origins=allowed_origins,
        trusted_hosts=trusted_hosts,
        debug=debug,
        environment=environment,
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached application settings."""
    return _load_settings()
