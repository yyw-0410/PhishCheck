"""Tests for the Sublime Analysis API integration wrapper."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import pytest

from app.core.config import get_settings
from app.schemas import SublimeMDM
from app.services.providers.sublime import SublimeAnalysisClient


def _default_env(monkeypatch: pytest.MonkeyPatch) -> None:
    defaults = {
        "SECRET_KEY": "test-secret",
        "ENVIRONMENT": "development",
        "ALLOWED_ORIGINS": "http://testserver",
        "BACKEND_TRUSTED_HOSTS": "testserver,localhost",
        "SUBLIME_API_KEY": "sublime-key",
        "SUBLIME_BASE_URL": "https://na-east-3.platform.sublime.security",
        "VIRUSTOTAL_API_KEY": "placeholder",
        "GOOGLE_CLIENT_ID": "placeholder",
        "GOOGLE_CLIENT_SECRET": "placeholder",
        "MS_CLIENT_ID": "placeholder",
        "MS_CLIENT_SECRET": "placeholder",
    }
    for key, value in defaults.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("SUBLIME_TIMEOUT_SECONDS", raising=False)


class DummyHTTPClient:
    """Minimal HTTPX-like client used for testing."""

    def __init__(self) -> None:
        self.requests: list[Dict[str, Any]] = []
        self.base_url = "https://mocked.example/v0"
        self._responses: Dict[str, Dict[str, Any]] = {}

    def set_response(self, endpoint: str, payload: Dict[str, Any]) -> None:
        self._responses[endpoint] = payload

    def post(self, endpoint: str, json: Dict[str, Any]) -> "DummyResponse":
        self.requests.append({"endpoint": endpoint, "json": json})
        payload = self._responses.get(endpoint)
        if payload is None:
            payload = {
                "analysis_id": "analysis-123",
                "status": "complete",
                "submitted_at": datetime(2024, 10, 1, 12, 0, tzinfo=timezone.utc).isoformat(),
                "completed_at": datetime(2024, 10, 1, 12, 1, tzinfo=timezone.utc).isoformat(),
                "engine_version": "2024.09.15",
                "verdict": {
                    "label": "MALICIOUS",
                    "score": 0.87,
                    "reasons": [
                        {
                            "rule_id": "rule-abc",
                            "title": "Credential phishing detected",
                            "description": "Suspicious login link.",
                        }
                    ],
                },
                "detections": [],
                "indicators": [],
                "message_subject": "Important security notice",
                "message_sender": "alerts@example.com",
                "headers": [],
                "body": None,
                "links": [],
                "attachments": [],
            }
        return DummyResponse(payload)

    def close(self) -> None:  # pragma: no cover - compatibility shim
        return None

class DummyResponse:
    def __init__(self, payload: Dict[str, Any]) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> Dict[str, Any]:
        return self._payload


def test_create_message_with_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    _default_env(monkeypatch)
    get_settings.cache_clear()

    dummy_http_client = DummyHTTPClient()
    client = SublimeAnalysisClient(http_client=dummy_http_client)
    raw_bytes = b"test email content"

    result = client.create_message(raw_bytes, mailbox_email_address="user@example.com", message_type="inbound")

    assert isinstance(result, SublimeMDM)
    assert result.verdict.label == "MALICIOUS"

    request = dummy_http_client.requests[-1]
    assert request["endpoint"] == "/messages/create"
    assert client._api_base_url == "https://na-east-3.platform.sublime.security/v0"
    encoded = request["json"]["raw_message"]
    assert base64.b64decode(encoded).decode("utf-8") == "test email content"
    assert request["json"]["mailbox_email_address"] == "user@example.com"
    assert request["json"]["message_type"] == {"inbound": True}


def test_create_message_from_path_uses_loader(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    _default_env(monkeypatch)
    get_settings.cache_clear()

    sample_eml = tmp_path / "sample.eml"
    sample_eml.write_text("Subject: Hi\n\nBody", encoding="utf-8")

    loader_called = {}

    def fake_load_eml(path: str) -> str:
        loader_called["path"] = path
        return "Ym9keQ=="  # base64 for "body"

    monkeypatch.setattr("app.services.providers.sublime.sublime_util.load_eml", fake_load_eml)

    dummy_http_client = DummyHTTPClient()
    client = SublimeAnalysisClient(http_client=dummy_http_client)
    result = client.create_message_from_path(sample_eml)

    assert loader_called["path"] == str(sample_eml)
    assert result.analysis_id == "analysis-123"


def test_analyze_message_posts_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    _default_env(monkeypatch)
    get_settings.cache_clear()

    dummy_http_client = DummyHTTPClient()
    dummy_http_client.set_response(
        "/messages/analyze",
        {
            "task_id": "task-1",
            "detections": [{"id": "rule-abc", "title": "Credential phishing detected"}],
        },
    )

    client = SublimeAnalysisClient(http_client=dummy_http_client)
    rules = [{"name": "test_rule"}]
    queries = [{"name": "test_query"}]

    result = client.analyze_message(
        b"email content",
        rules=rules,
        queries=queries,
        run_all_detection_rules=True,
    )

    request = dummy_http_client.requests[-1]
    assert request["endpoint"] == "/messages/analyze"
    payload = request["json"]
    assert payload["rules"] == rules
    assert payload["queries"] == queries
    assert payload["run_all_detection_rules"] is True
    assert result["detections"][0]["id"] == "rule-abc"
