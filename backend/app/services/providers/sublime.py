"""Thin wrapper around the Sublime Analysis API using direct HTTP calls."""

from __future__ import annotations

import base64
import binascii
import re
import logging
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Callable, Optional, Union, Dict, Any

import httpx

from sublime import util as sublime_util

from app.core import Settings, get_settings
from app.schemas import SublimeMDM, URLScanSubmission

logger = logging.getLogger(__name__)


def _normalize_url(url: Optional[str]) -> Optional[str]:
    """Validate and clean up extracted URLs.
    
    Removes QP artifacts and validates URL structure.
    """
    if not url:
        return None
    
    # Strip whitespace and common trailing punctuation
    cleaned = url.strip().rstrip(".,;:!?\"')")
    
    # Remove trailing = from quoted-printable soft line breaks
    while cleaned.endswith('='):
        cleaned = cleaned[:-1]
    
    # Remove trailing ?= or &= (incomplete query params from QP encoding)
    if cleaned.endswith('?') or cleaned.endswith('&'):
        cleaned = cleaned[:-1]
    
    # Must start with http:// or https://
    if not cleaned.startswith(('http://', 'https://')):
        return None
    
    # Use urlparse to validate and check for truncation
    try:
        from urllib.parse import urlparse
        parsed = urlparse(cleaned)
        
        # Must have a valid netloc (domain)
        if not parsed.netloc:
            return None
        
        # Domain must contain at least one dot (e.g., "example.com")
        # Exception: localhost is valid
        if '.' not in parsed.netloc and parsed.netloc.lower() != 'localhost':
            return None
        
        # Filter out URLs that look truncated (path ends with = or just /)
        if parsed.path.endswith('=') or parsed.path == '/=':
            return None
        
        return cleaned
    except Exception:
        return None



class SublimeAnalysisClient:
    """High-level helper that interacts with Sublime's REST API."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        *,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        self._settings = settings or get_settings()
        if not self._settings.sublime_api_key:
            raise RuntimeError("SUBLIME_API_KEY is required to talk to Sublime.")

        self._api_base_url = _build_api_base_url(self._settings.sublime_base_url)
        default_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Key": self._settings.sublime_api_key,
        }
        timeout = self._settings.sublime_timeout or 30.0
        self._client: httpx.Client
        self._owns_client = False
        if http_client is not None:
            self._client = http_client
        else:
            self._client = httpx.Client(
                base_url=self._api_base_url,
                headers=default_headers,
                timeout=timeout,
            )
            self._owns_client = True
        self._messages_create_endpoint = "/messages/create"
        self._messages_analyze_endpoint = "/messages/analyze"
        self._messages_attack_score_endpoint = "/messages/attack_score"

    def __del__(self) -> None:
        if getattr(self, "_owns_client", False):
            try:
                self._client.close()
            except Exception:
                pass

    def create_message(
        self,
        raw_message: Union[str, bytes],
        *,
        mailbox_email_address: Optional[str] = None,
        message_type: Optional[Union[str, Dict[str, bool]]] = None,
    ) -> SublimeMDM:
        """Create a Message Data Model (MDM) from a raw email."""
        payload = self.create_message_raw(
            raw_message,
            mailbox_email_address=mailbox_email_address,
            message_type=message_type,
        )
        return self._to_mdm(payload)

    def create_message_from_path(
        self,
        path: Union[str, Path],
        *,
        mailbox_email_address: Optional[str] = None,
        message_type: Optional[Union[str, Dict[str, bool]]] = None,
    ) -> SublimeMDM:
        """Convenience helper that loads a .eml/.msg/.mdm file before submission."""
        path = Path(path)
        loader = _select_loader(path)
        raw_message = loader(str(path))
        return self.create_message(
            raw_message,
            mailbox_email_address=mailbox_email_address,
            message_type=message_type,
        )

    def create_message_raw(
        self,
        raw_message: Union[str, bytes],
        *,
        mailbox_email_address: Optional[str] = None,
        message_type: Optional[Union[str, Dict[str, bool]]] = None,
        extra_fields: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Submit a raw message and return Sublime's JSON payload."""
        encoded_message = self._ensure_base64(raw_message)
        body: Dict[str, Any] = {"raw_message": encoded_message}
        if mailbox_email_address:
            body["mailbox_email_address"] = mailbox_email_address
        if message_type:
            body["message_type"] = _encode_message_type(message_type)
        if extra_fields:
            body.update(extra_fields)

        try:
            response = self._client.post(self._messages_create_endpoint, json=body)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text
            raise RuntimeError(
                f"Sublime API returned {exc.response.status_code}: {detail}"
            ) from exc
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Failed to reach Sublime API: {exc}") from exc

        try:
            return response.json()
        except ValueError as exc:
            raise RuntimeError("Sublime API returned non-JSON response.") from exc

    def evaluate_attack_score(
        self,
        raw_message: Union[str, bytes],
        *,
        extra_fields: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Request Sublime's attack scoring for a raw message."""
        encoded_message = self._ensure_base64(raw_message)
        body: Dict[str, Any] = {"raw_message": encoded_message}
        if extra_fields:
            body.update(extra_fields)

        try:
            response = self._client.post(self._messages_attack_score_endpoint, json=body)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text
            raise RuntimeError(
                f"Sublime API returned {exc.response.status_code}: {detail}"
            ) from exc
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Failed to reach Sublime API: {exc}") from exc

        try:
            return response.json()
        except ValueError as exc:
            raise RuntimeError("Sublime API returned non-JSON response.") from exc

    def analyze_message(
        self,
        raw_message: Union[str, bytes],
        *,
        rules: Optional[list[dict]] = None,
        queries: Optional[list[dict]] = None,
        mailbox_email_address: Optional[str] = None,
        message_type: Optional[Union[str, Dict[str, bool]]] = None,
        run_all_detection_rules: bool = False,
        run_active_detection_rules: bool = False,
        run_all_insights: bool = False,
        extra_fields: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Analyze a message against provided rules/queries via Sublime's Analysis API."""
        encoded_message = self._ensure_base64(raw_message)
        body: Dict[str, Any] = {"raw_message": encoded_message}
        if rules:
            body["rules"] = rules
        if queries:
            body["queries"] = queries
        if mailbox_email_address:
            body["mailbox_email_address"] = mailbox_email_address
        if message_type:
            body["message_type"] = _encode_message_type(message_type)
        if run_all_detection_rules:
            body["run_all_detection_rules"] = True
        if run_active_detection_rules:
            body["run_active_detection_rules"] = True
        if run_all_insights:
            body["run_all_insights"] = True
        if extra_fields:
            body.update(extra_fields)

        try:
            response = self._client.post(self._messages_analyze_endpoint, json=body)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text
            raise RuntimeError(
                f"Sublime API returned {exc.response.status_code}: {detail}"
            ) from exc
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Failed to reach Sublime API: {exc}") from exc

        try:
            return response.json()
        except ValueError as exc:
            raise RuntimeError("Sublime API returned non-JSON response.") from exc

    def analyze_message_from_path(
        self,
        path: Union[str, Path],
        *,
        rules: Optional[list[dict]] = None,
        queries: Optional[list[dict]] = None,
        mailbox_email_address: Optional[str] = None,
        message_type: Optional[Union[str, Dict[str, bool]]] = None,
        run_all_detection_rules: bool = False,
        run_active_detection_rules: bool = False,
        run_all_insights: bool = False,
        extra_fields: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Analyze a message located on disk against provided rules/queries."""
        path = Path(path)
        loader = _select_loader(path)
        raw_message = loader(str(path))
        return self.analyze_message(
            raw_message,
            rules=rules,
            queries=queries,
            mailbox_email_address=mailbox_email_address,
            message_type=message_type,
            run_all_detection_rules=run_all_detection_rules,
            run_active_detection_rules=run_active_detection_rules,
            run_all_insights=run_all_insights,
            extra_fields=extra_fields,
        )

    def analyze_link(self, submission: URLScanSubmission) -> None:
        """Call Sublime link_analysis and attach metadata to URLScanSubmission.

        Non-fatal helper; swallows errors to avoid blocking enrichment.
        Uses the /v0/enrichment/link_analysis/evaluate endpoint for URL phishing detection.
        """
        try:
            url = submission.url
            if not url:
                logger.debug("Sublime ML: No URL provided")
                return

            # Skip ML analysis for raw IPs (Sublime API returns 500 for these)
            if re.match(r'^https?://(\d{1,3}\.){3}\d{1,3}', url):
                logger.info("Sublime ML: Skipping analysis for raw IP address (unsupported)")
                submission.ml_link = {
                    "label": None,
                    "score": None,
                    "error": "ML analysis not available for IP-based URLs",
                    "skip_reason": "ip_address"
                }
                return

            # Pass all other URLs to Sublime ML
            base_url = self._settings.sublime_base_url.rstrip("/")
            endpoint = f"{base_url}/v0/enrichment/link_analysis/evaluate"
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Key": self._settings.sublime_api_key
            }
            body = {"no_logo_detect": False, "url": url}
            timeout = httpx.Timeout(12.0, connect=5.0)

            logger.info(f"Sublime ML: Analyzing URL {url[:50]}...")
            resp = self._client.post(endpoint, headers=headers, json=body, timeout=timeout)

            if resp.status_code >= 400:
                try:
                    error_body = resp.text
                    logger.warning(f"Sublime ML: API returned status {resp.status_code} - {error_body[:500]}")
                    submission.ml_link = {
                        "label": None,
                        "score": None,
                        "error": f"API error: {resp.status_code}",
                    }
                except (ValueError, AttributeError):
                    # Unable to read response text
                    logger.warning(f"Sublime ML: API returned status {resp.status_code}")
                    submission.ml_link = {
                        "label": None,
                        "score": None,
                        "error": f"API error: {resp.status_code}",
                    }
                return

            data = resp.json()
            logger.debug(f"Sublime ML: Response keys: {data.keys() if isinstance(data, dict) else 'not dict'}")

            # Extract credential phishing analysis (computer vision)
            credphish = data.get("credphish") if isinstance(data, dict) else None
            disposition = credphish.get("disposition") if isinstance(credphish, dict) else None
            contains_login = credphish.get("contains_login") if isinstance(credphish, dict) else None
            contains_captcha = credphish.get("contains_captcha") if isinstance(credphish, dict) else None

            # Calculate score based on disposition
            if disposition == "malicious":
                score = 0.9
            elif disposition == "suspicious":
                score = 0.6
            elif disposition == "benign":
                score = 0.1
            else:
                score = None

            # Boost score for login pages
            if contains_login and score is not None and score < 0.5:
                score = max(score, 0.4)

            # Extract effective URL info
            effective = data.get("effective_url") if isinstance(data, dict) else None
            effective_url = effective.get("url") if isinstance(effective, dict) else None

            # Extract redirect chain
            redirect_history = data.get("redirect_history") if isinstance(data, dict) else []
            redirect_urls = [r.get("url") for r in redirect_history if isinstance(r, dict)] if redirect_history else []

            # Extract screenshot (base64)
            screenshot_data = data.get("screenshot") if isinstance(data, dict) else None
            screenshot_base64 = screenshot_data.get("raw") if isinstance(screenshot_data, dict) else None

            # Build comprehensive ml_link response
            submission.ml_link = {
                "label": disposition,
                "score": score,
                "effective_url": effective_url,
                "contains_login": contains_login,
                "contains_captcha": contains_captcha,
                "redirect_count": len(redirect_urls) - 1 if redirect_urls else 0,
                "redirects": redirect_urls if len(redirect_urls) > 1 else None,
                "screenshot": f"data:image/png;base64,{screenshot_base64}" if screenshot_base64 else None,
                "page_status": data.get("page_status_code") if isinstance(data, dict) else None
            }
            logger.info(f"Sublime ML: Analysis complete - disposition={disposition}, score={score}")

        except Exception as e:
            logger.error(f"Sublime ML: Error during analysis - {e}")
            submission.ml_link = {
                "label": None,
                "score": None,
                "error": str(e),
            }
            return

    @staticmethod
    def load_eml(path: Union[str, Path]) -> str:
        """Expose Sublime's helper for callers that want manual control."""
        return sublime_util.load_eml(str(path))

    @staticmethod
    def load_msg(path: Union[str, Path]) -> str:
        """Expose Sublime's helper for MSG files."""
        return sublime_util.load_msg(str(path))

    @staticmethod
    def load_message_data_model(path: Union[str, Path]) -> dict:
        """Load a previously generated MDM JSON document."""
        return sublime_util.load_message_data_model(str(path))

    @staticmethod
    def _ensure_base64(raw_message: Union[str, bytes]) -> str:
        if isinstance(raw_message, str):
            candidate = raw_message.strip()
            if not candidate:
                raise ValueError("raw_message cannot be empty.")
            try:
                base64.b64decode(candidate, validate=True)
                return candidate
            except binascii.Error:
                raw_bytes = candidate.encode("utf-8")
        else:
            raw_bytes = raw_message

        return base64.b64encode(raw_bytes).decode("ascii")

    @staticmethod
    def _to_mdm(payload: dict) -> SublimeMDM:
        if not isinstance(payload, dict):
            raise TypeError("Unexpected Sublime response payload.")

        mdm_input = _normalize_sublime_payload(payload)
        status_value = mdm_input.get("status")
        if isinstance(status_value, str):
            normalized_status = status_value.strip().upper() or "UNKNOWN"
        elif status_value is None:
            normalized_status = "UNKNOWN"
        else:
            normalized_status = str(status_value).strip().upper() or "UNKNOWN"
        mdm_input["status"] = normalized_status
        mdm_input.setdefault("raw", payload.copy())
        try:
            return SublimeMDM.model_validate(mdm_input)
        except ValueError as exc:  # pragma: no cover - converted into clearer message
            # Surface the first validation error to aid debugging.
            details = getattr(exc, "errors", None)
            if callable(details):
                errors = details()
                if errors:
                    first = errors[0]
                    location = " -> ".join(map(str, first.get("loc", ())))
                    message = first.get("msg", "validation error")
                    raise ValueError(
                        f"Sublime response did not match the expected MDM schema: {location or '<root>'}: {message}"
                    ) from exc
            raise ValueError("Sublime response did not match the expected MDM schema.") from exc


def _select_loader(path: Path) -> Callable[[str], str]:
    suffix = path.suffix.lower()
    if suffix == ".eml":
        return sublime_util.load_eml
    if suffix == ".msg":
        return sublime_util.load_msg
    if suffix == ".json" or suffix == ".mdm":
        return sublime_util.load_message_data_model
    raise ValueError(f"Unsupported message format for '{path}'.")


def _normalize_sublime_payload(payload: dict) -> dict:
    """Massage Sublime's raw response into our internal schema expectations."""
    normalized = dict(payload)

    raw_links = payload.get("links")
    normalized_links = []
    if isinstance(raw_links, list):
        for raw_link in raw_links:
            if not isinstance(raw_link, dict):
                continue

            href = None
            text = None
            context = None

            href_url = raw_link.get("href_url") or {}
            display_url = raw_link.get("display_url") or {}

            if isinstance(href_url, dict):
                raw_href = href_url.get("url") or href_url.get("raw")
                href = _normalize_url(raw_href) if raw_href else None

            if isinstance(display_url, dict):
                text = display_url.get("url") or display_url.get("raw")

            display_text = raw_link.get("display_text")
            if isinstance(display_text, str) and display_text.strip():
                text = display_text.strip()

            context = raw_link.get("context")
            if isinstance(context, str):
                context = context.strip() or None

            if href:
                normalized_links.append(
                    {
                        "href": href,
                        "text": text,
                        "context": context,
                    }
                )

    normalized["links"] = normalized_links

    attachments = payload.get("attachments")
    if isinstance(attachments, list):
        normalized_attachments = []
        for attachment in attachments:
            if not isinstance(attachment, dict):
                continue
            normalized_attachment = dict(attachment)
            # Sublime may provide hashes under "sha256" or nested structures.
            if "sha256" not in normalized_attachment:
                sha256 = attachment.get("sha256_hash") or attachment.get("hashes", {}).get("sha256")
                if sha256:
                    normalized_attachment["sha256"] = sha256
            if "size" not in normalized_attachment and "bytes" in attachment:
                normalized_attachment["size"] = attachment["bytes"]
            normalized_attachments.append(normalized_attachment)
        normalized["attachments"] = normalized_attachments

    # Map alternate field names returned by recent Sublime responses.
    analysis_id = (
        normalized.get("analysis_id")
        or normalized.get("id")
        or payload.get("analysis_id")
        or payload.get("analysisId")
        or payload.get("id")
        or payload.get("job_id")
        or payload.get("document_id")
        or payload.get("message_id")
    )
    if analysis_id:
        normalized["analysis_id"] = str(analysis_id).strip() or str(datetime.now(timezone.utc).timestamp())
    else:
        normalized.setdefault("analysis_id", f"unknown-{datetime.now(timezone.utc).timestamp()}")

    status = normalized.get("status") or payload.get("status") or payload.get("state")
    if status:
        value = str(status).strip().upper()
        normalized["status"] = value or "UNKNOWN"
    else:
        normalized.setdefault("status", "UNKNOWN")

    submitted_at = (
        normalized.get("submitted_at")
        or payload.get("submitted_at")
        or payload.get("created_at")
        or payload.get("created")
    )
    normalized["submitted_at"] = _normalize_timestamp(submitted_at)

    completed_at = (
        normalized.get("completed_at")
        or payload.get("completed_at")
        or payload.get("finished_at")
        or payload.get("updated_at")
    )
    completed_value = _normalize_timestamp(completed_at, allow_none=True)
    if completed_value:
        normalized["completed_at"] = completed_value
    elif "completed_at" in normalized:
        normalized.pop("completed_at", None)

    engine_version = normalized.get("engine_version") or payload.get("engine")
    if engine_version:
        normalized["engine_version"] = str(engine_version)

    verdict = normalized.get("verdict") or payload.get("verdict")
    if not isinstance(verdict, dict):
        normalized["verdict"] = {"label": "UNKNOWN", "score": 0.0, "reasons": []}
    else:
        normalized["verdict"] = dict(verdict)
        normalized["verdict"].setdefault("label", "UNKNOWN")
        normalized["verdict"].setdefault("score", 0.0)
        reasons = normalized["verdict"].get("reasons")
        if not isinstance(reasons, list):
            reasons = []
        normalized["verdict"]["reasons"] = reasons

    detections = normalized.get("detections")
    if not isinstance(detections, list):
        detections = []
    normalized["detections"] = detections

    indicators = normalized.get("indicators")
    if not isinstance(indicators, list):
        indicators = []
    normalized["indicators"] = indicators

    return normalized


def _normalize_timestamp(value: Union[str, int, float, datetime, None], *, allow_none: bool = False) -> Optional[str]:
    """Coerce disparate timestamp formats into an ISO 8601 string suitable for Pydantic."""
    dt = _coerce_datetime(value)
    if dt is None:
        if allow_none:
            return None
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _coerce_datetime(value: Union[str, int, float, datetime, None]) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return None
        # ISO 8601 variants
        iso_candidate = candidate
        if iso_candidate.endswith("Z"):
            iso_candidate = iso_candidate[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(iso_candidate)
        except ValueError:
            pass
        # RFC2822 / other email-style timestamps
        try:
            parsed = parsedate_to_datetime(candidate)
            if parsed:
                return parsed
        except (TypeError, ValueError):
            pass
        # Unix epoch embedded as string
        try:
            return datetime.fromtimestamp(float(candidate), tz=timezone.utc)
        except (ValueError, OverflowError):
            return None
    return None


def _encode_message_type(message_type: Union[str, Dict[str, bool]]) -> Dict[str, bool]:
    """Convert message type inputs into the structure expected by Sublime."""
    if isinstance(message_type, dict):
        return {key: bool(value) for key, value in message_type.items()}

    value = message_type.strip().lower()
    if value not in {"inbound", "internal", "outbound"}:
        raise ValueError(f"Unsupported message_type '{message_type}'.")
    return {value: True}


def _build_api_base_url(base_url: str) -> str:
    """Ensure the base URL includes an API version suffix suitable for create_message."""
    cleaned = (base_url or "").rstrip("/")
    if cleaned.endswith("/v0") or cleaned.endswith("/v1"):
        return cleaned
    return f"{cleaned}/v0"
