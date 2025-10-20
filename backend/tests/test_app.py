"""Smoke tests for the FastAPI application."""

import os

from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.main import create_application


def _build_client() -> TestClient:
    defaults = {
        "SECRET_KEY": "test-secret",
        "ENVIRONMENT": "development",
        "ALLOWED_ORIGINS": "http://testserver",
        "BACKEND_TRUSTED_HOSTS": "testserver,localhost",
        "SUBLIME_API_KEY": "placeholder",
        "VIRUSTOTAL_API_KEY": "placeholder",
        "GOOGLE_CLIENT_ID": "placeholder",
        "GOOGLE_CLIENT_SECRET": "placeholder",
        "MS_CLIENT_ID": "placeholder",
        "MS_CLIENT_SECRET": "placeholder",
        "DEBUG": "false",
    }
    for key, value in defaults.items():
        os.environ.setdefault(key, value)

    get_settings.cache_clear()
    return TestClient(create_application())


def test_healthcheck_returns_ok():
    client = _build_client()
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_index_returns_message():
    client = _build_client()
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["message"]


def test_secure_ping_requires_api_key():
    client = _build_client()
    unauthorized = client.get("/secure/ping")
    assert unauthorized.status_code == 401

    authorized = client.get("/secure/ping", headers={"X-API-Key": "test-secret"})
    assert authorized.status_code == 200
    assert authorized.json() == {"message": "Authenticated request successful."}
