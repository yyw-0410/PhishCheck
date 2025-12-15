"""URLscan.io provider for URL scanning and screenshot capture."""

from __future__ import annotations

import time
import logging
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, Optional, Set, List

import httpx

from app.core import Settings, get_settings
from app.schemas import URLScanSubmission
from .base import BaseProvider, is_urlscan_placeholder

logger = logging.getLogger(__name__)

URLSCAN_SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
URLSCAN_RESULT_URL_TEMPLATE = "https://urlscan.io/api/v1/result/{scan_id}/"
URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/"
MAX_WORKERS = 15


class UrlscanProvider(BaseProvider):
    """URLscan.io API client for URL scanning and threat detection."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        *,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        super().__init__(settings, http_client=http_client)
        self._api_key = self._settings.urlscan_api_key

    # =========================================================================
    # Submit URL for Scanning
    # =========================================================================

    def submit_scan(self, *, url: str, visibility: str) -> URLScanSubmission:
        """Submit a URL to urlscan.io for scanning."""
        submission = URLScanSubmission(url=url, visibility=visibility)
        headers = {
            "Content-Type": "application/json",
            "API-Key": self._api_key,
        }
        body = {"url": url, "visibility": visibility}
        try:
            response = self._client.post(URLSCAN_SUBMIT_URL, headers=headers, json=body)
            response.raise_for_status()
            payload = response.json()
            submission.scan_id = payload.get("uuid")
            if submission.scan_id:
                submission.result_url = f"https://urlscan.io/result/{submission.scan_id}/"
                # Use static screenshot URL (will be available after scan completes)
                submission.screenshot_url = f"https://urlscan.io/screenshots/{submission.scan_id}.png"
            submission.verdict = "pending"
        except httpx.HTTPStatusError as exc:
            submission.error = f"urlscan.io returned {exc.response.status_code}: {exc.response.text}"
        except httpx.RequestError as exc:
            submission.error = f"urlscan.io request failed: {exc}"
        except ValueError as exc:
            submission.error = f"urlscan.io response parsing error: {exc}"
        return submission

    # =========================================================================
    # Search for Existing Scans
    # =========================================================================

    def search(self, url: str) -> Optional[URLScanSubmission]:
        """Search for existing urlscan.io results for a URL."""
        if not self._api_key:
            return None

        headers = {"API-Key": self._api_key}
        params = {"q": f'page.url:"{url}"', "size": 3}
        try:
            response = self._client.get(URLSCAN_SEARCH_URL, headers=headers, params=params, timeout=5.0)
            response.raise_for_status()
            payload = response.json()
            results = payload.get("results") or []
            if not results:
                return None

            for result in results:
                task = result.get("task") or {}
                page = result.get("page") or {}
                scan_id = task.get("uuid")
                screenshot_url = result.get("screenshot") or task.get("screenshotURL")

                if not screenshot_url or is_urlscan_placeholder(screenshot_url):
                    continue

                logger.info(f"urlscan.io: Reusing cached scan {scan_id} for {url[:50]}")
                return URLScanSubmission(
                    url=url,
                    scan_id=scan_id,
                    result_url=f"https://urlscan.io/result/{scan_id}/" if scan_id else None,
                    screenshot_url=screenshot_url,
                    visibility=task.get("visibility") or page.get("visibility"),
                )

            return None
        except (httpx.HTTPStatusError, httpx.RequestError, ValueError):
            return None

    # =========================================================================
    # Batch Submit Jobs
    # =========================================================================

    def submit_jobs(
        self,
        urls: Iterable[str],
        *,
        max_items: Optional[int],
        visibility: str,
        ml_enricher=None,
    ) -> list[URLScanSubmission]:
        """Submit URLs to urlscan.io with parallel processing."""
        url_list = list(urls)
        submissions: list[URLScanSubmission] = []
        seen: Set[str] = set()
        limit = max_items if max_items and max_items > 0 else None

        # First, search for existing results in parallel
        urls_to_submit: List[str] = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            search_futures = {}
            for url in url_list:
                if url in seen:
                    continue
                seen.add(url)
                search_futures[executor.submit(self.search, url)] = url

            for future in as_completed(search_futures):
                url = search_futures[future]
                try:
                    reused = future.result(timeout=10)
                    if reused:
                        submissions.append(reused)
                    else:
                        urls_to_submit.append(url)
                except (TimeoutError, httpx.RequestError):
                    # Search failed, need to submit
                    urls_to_submit.append(url)

        # Apply limit to new submissions
        if limit is not None:
            urls_to_submit = urls_to_submit[:limit]

        # Submit new URLs in parallel
        if urls_to_submit:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                submit_futures = {
                    executor.submit(self.submit_scan, url=url, visibility=visibility): url
                    for url in urls_to_submit
                }
                for future in as_completed(submit_futures):
                    try:
                        submission = future.result(timeout=30)
                        submissions.append(submission)
                    except (TimeoutError, httpx.RequestError) as e:
                        url = submit_futures[future]
                        submissions.append(URLScanSubmission(
                            url=url,
                            error=f"Submission failed: {type(e).__name__}: {e}",
                            visibility=visibility,
                        ))

        remaining = len(url_list) - len(seen)
        if remaining > 0 and limit is not None and len(urls_to_submit) >= limit:
            submissions.append(
                URLScanSubmission(
                    url="",
                    error=f"urlscan.io submissions truncated to {limit} URLs (skipped {remaining}).",
                    visibility=visibility,
                )
            )

        # Attach ML link analysis if enricher provided
        # Run for all submissions with a URL, regardless of urlscan errors
        # Sublime ML analysis is independent of urlscan status
        if ml_enricher:
            valid_submissions = [s for s in submissions if s.url]
            if valid_submissions:
                with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                    list(executor.map(ml_enricher, valid_submissions))

        return submissions

    # =========================================================================
    # Parse Result Payload
    # =========================================================================

    def parse_result(self, submission: URLScanSubmission, payload: dict) -> None:
        """Parse urlscan.io result payload into submission object."""
        task = payload.get("task") if isinstance(payload, dict) else {}
        data = payload.get("data") if isinstance(payload, dict) else {}
        page = payload.get("page") if isinstance(payload, dict) else {}

        # Extract URL
        if isinstance(task, dict):
            url_value = task.get("url") or task.get("source") or task.get("pageURL")
            if isinstance(url_value, str) and url_value:
                submission.url = submission.url or url_value
            if submission.scan_id and not submission.result_url:
                submission.result_url = f"https://urlscan.io/result/{submission.scan_id}/"

        if not submission.url and isinstance(page, dict):
            url_value = page.get("url")
            if isinstance(url_value, str) and url_value:
                submission.url = url_value

        # Screenshot URL - prefer static screenshot over liveshot for reliability
        screenshot = None
        if isinstance(task, dict):
            screenshot = task.get("screenshotURL")
        if not screenshot and isinstance(data, dict):
            screenshot = data.get("screenshotURL") or data.get("screenshot")

        if screenshot and is_urlscan_placeholder(screenshot):
            screenshot = None

        # Fallback to static screenshot URL (more reliable than liveshot)
        if not screenshot or not screenshot.strip():
            if submission.scan_id:
                screenshot = f"https://urlscan.io/screenshots/{submission.scan_id}.png"

        submission.screenshot_url = screenshot

        # Derive verdict
        try:
            verdicts = payload.get('verdicts') if isinstance(payload, dict) else None
            overall = verdicts.get('overall') if isinstance(verdicts, dict) else None
            if isinstance(overall, dict):
                malicious = overall.get('malicious', False)
                score = overall.get('score', 0)
                if malicious or score >= 50:
                    submission.verdict = 'malicious'
                elif score >= 20:
                    submission.verdict = 'suspicious'
                else:
                    submission.verdict = 'benign'
        except (TypeError, KeyError, AttributeError):
            # Payload structure unexpected, skip verdict extraction
            pass

    # =========================================================================
    # Hydrate Submission (Wait for Results)
    # =========================================================================

    def hydrate(self, submission: URLScanSubmission) -> None:
        """Wait for URLscan.io scan to complete and fetch results."""
        if not submission.scan_id:
            return
        endpoint = URLSCAN_RESULT_URL_TEMPLATE.format(scan_id=submission.scan_id)
        delay = 2.0
        max_attempts = 8
        for attempt in range(max_attempts):
            try:
                response = self._client.get(endpoint)
                if response.status_code == 404:
                    logger.info(f"urlscan.io: Scan not ready (attempt {attempt + 1}/{max_attempts})")
                    time.sleep(delay)
                    delay = min(delay + 1.0, 5.0)
                    continue
                response.raise_for_status()
                payload = response.json()
                self.parse_result(submission, payload)
                return
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 404:
                    if attempt < max_attempts - 1:
                        time.sleep(delay)
                        delay = min(delay + 1.0, 4.0)
                        continue
                    return
                if exc.response.status_code == 429:
                    if attempt < max_attempts - 1:
                        time.sleep(delay * 2)
                        continue
                    return
                if not submission.error:
                    submission.error = f"urlscan.io result fetch failed: {exc.response.status_code}"
                return
            except httpx.RequestError:
                if attempt < max_attempts - 1:
                    time.sleep(delay)
                    delay += 1.0
                    continue
                return
            except ValueError:
                return

    # =========================================================================
    # Refresh Existing Submission
    # =========================================================================

    def refresh(self, scan_id: str, ml_enricher=None) -> URLScanSubmission:
        """Re-fetch an existing urlscan.io submission result."""
        submission = URLScanSubmission(url="", scan_id=scan_id)
        submission.result_url = f"https://urlscan.io/result/{scan_id}/"

        endpoint = URLSCAN_RESULT_URL_TEMPLATE.format(scan_id=scan_id)
        try:
            response = self._client.get(endpoint, timeout=15.0)
            if response.status_code == 200:
                payload = response.json()

                task = payload.get("task") or {}
                submission.url = task.get("url") or ""
                submission.result_url = f"https://urlscan.io/result/{scan_id}/"

                screenshot = task.get("screenshotURL")
                if not screenshot:
                    data = payload.get("data") or {}
                    screenshot = data.get("screenshotURL") or data.get("screenshot")

                is_no_screenshot = not screenshot or is_urlscan_placeholder(screenshot)
                if is_no_screenshot:
                    # Use static screenshot URL (more reliable than liveshot)
                    screenshot = f"https://urlscan.io/screenshots/{scan_id}.png"

                submission.screenshot_url = screenshot

                verdicts = payload.get("verdicts") or {}
                overall = verdicts.get("overall") or {}
                if overall.get("malicious"):
                    submission.verdict = "malicious"
                elif overall.get("score", 0) >= 1:
                    submission.verdict = "suspicious"
                else:
                    submission.verdict = "benign"

                # Attach ML link analysis if enricher provided
                if ml_enricher:
                    ml_enricher(submission)

            elif response.status_code == 404:
                submission.error = "Scan still processing or not found"
                submission.verdict = "pending"
            else:
                submission.error = f"URLscan returned {response.status_code}"
        except httpx.HTTPStatusError as e:
            submission.error = f"Failed to refresh: HTTP {e.response.status_code}"
            logger.error(f"URLscan refresh HTTP error: {e.response.status_code}")
        except httpx.RequestError as e:
            submission.error = f"Failed to refresh: {type(e).__name__}"
            logger.error(f"URLscan refresh request error: {e}")
        except (ValueError, KeyError) as e:
            submission.error = f"Failed to parse response: {e}"
            logger.error(f"URLscan refresh parsing error: {e}")

        return submission
