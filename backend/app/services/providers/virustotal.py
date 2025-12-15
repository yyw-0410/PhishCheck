"""VirusTotal provider for domain, file, and URL lookups."""

from __future__ import annotations

import base64
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, Optional, Set
from urllib.parse import urlparse

import httpx

from app.core import Settings, get_settings
from app.schemas import VirusTotalLookup
from .base import BaseProvider

logger = logging.getLogger(__name__)

VT_BASE_URL = "https://www.virustotal.com/api/v3"
VT_DOMAIN_LIMIT = 20
MAX_WORKERS = 15


class VirusTotalProvider(BaseProvider):
    """VirusTotal API client for threat intelligence lookups."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        *,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        super().__init__(settings, http_client=http_client)
        self._api_key = self._settings.virustotal_api_key

    # =========================================================================
    # Core API Call
    # =========================================================================

    def _call_vt(self, path: str, *, indicator: str, indicator_type: str) -> VirusTotalLookup:
        """Make a single VirusTotal API call."""
        lookup = VirusTotalLookup(indicator=indicator, indicator_type=indicator_type)
        headers = {"x-apikey": self._api_key}
        url = f"{VT_BASE_URL}{path}"
        try:
            response = self._client.get(url, headers=headers)
            response.raise_for_status()
            payload = response.json()
            data = payload.get("data") if isinstance(payload, dict) else None
            lookup.data = data if isinstance(data, dict) else payload
        except httpx.HTTPStatusError as exc:
            lookup.error = f"VirusTotal returned {exc.response.status_code}: {exc.response.text}"
        except httpx.RequestError as exc:
            lookup.error = f"VirusTotal request failed: {exc}"
        except ValueError as exc:
            lookup.error = f"VirusTotal response parsing error: {exc}"
        return lookup

    # =========================================================================
    # Domain Lookups
    # =========================================================================

    def lookup_domains(
        self, urls: Iterable[str], *, header_domains: Optional[Iterable[str]] = None
    ) -> list[VirusTotalLookup]:
        """Lookup domains in VirusTotal in parallel for faster results."""
        seen: dict[str, set[str]] = {}

        # From URLs
        for url in urls:
            parsed = urlparse(url)
            domain = (parsed.netloc or '').lower().strip()
            if ':' in domain:
                domain = domain.split(':')[0]
            if not domain:
                continue
            seen.setdefault(domain, set()).add('URL')

        # From headers
        if header_domains:
            for d in header_domains:
                domain = (d or '').lower().strip()
                if not domain:
                    continue
                seen.setdefault(domain, set()).add('HEADER')

        # Enforce predictable order and limit
        ordered = sorted(seen.items(), key=lambda kv: (0 if 'URL' in kv[1] else 1, kv[0]))
        if VT_DOMAIN_LIMIT and len(ordered) > VT_DOMAIN_LIMIT:
            ordered = ordered[:VT_DOMAIN_LIMIT]

        # Parallel VT lookups
        lookups: list[VirusTotalLookup] = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_domain = {}
            for domain, sources in ordered:
                future = executor.submit(
                    self._call_vt, f"/domains/{domain}",
                    indicator=domain, indicator_type="domain"
                )
                future_to_domain[future] = (domain, sources)

            for future in as_completed(future_to_domain):
                domain, sources = future_to_domain[future]
                try:
                    lookup = future.result(timeout=20)
                    lookup.sources = sorted(list(sources))
                    lookups.append(lookup)
                except Exception as e:
                    lookup = VirusTotalLookup(
                        indicator=domain,
                        indicator_type="domain",
                        error=f"Parallel lookup failed: {str(e)}"
                    )
                    lookups.append(lookup)
        return lookups

    # =========================================================================
    # File Hash Lookups
    # =========================================================================

    def lookup_files(self, hashes: Iterable[str]) -> list[VirusTotalLookup]:
        """Lookup file hashes in VirusTotal in parallel."""
        seen_hashes: Set[str] = set()
        unique_hashes = []
        for sha256 in hashes:
            normalized = sha256.lower()
            if normalized in seen_hashes:
                continue
            seen_hashes.add(normalized)
            unique_hashes.append(normalized)

        lookups: list[VirusTotalLookup] = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(
                    self._call_vt, f"/files/{h}",
                    indicator=h, indicator_type="file"
                ): h for h in unique_hashes
            }
            for future in as_completed(futures):
                try:
                    lookups.append(future.result(timeout=20))
                except Exception as e:
                    h = futures[future]
                    lookups.append(VirusTotalLookup(
                        indicator=h, indicator_type="file",
                        error=f"Parallel lookup failed: {str(e)}"
                    ))
        return lookups

    # =========================================================================
    # Full URL Lookups
    # =========================================================================

    def lookup_url(self, url: str) -> VirusTotalLookup:
        """Lookup a full URL in VirusTotal using the /urls/ endpoint.

        VT requires the URL to be base64-encoded (without padding) for the URL ID.
        """
        lookup = VirusTotalLookup(indicator=url, indicator_type="url")
        headers = {"x-apikey": self._api_key}

        # VT URL ID is base64 of URL without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        vt_url = f"{VT_BASE_URL}/urls/{url_id}"

        try:
            response = self._client.get(vt_url, headers=headers)
            response.raise_for_status()
            payload = response.json()
            data = payload.get("data") if isinstance(payload, dict) else None
            lookup.data = data if isinstance(data, dict) else payload
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                lookup.error = "URL not found in VirusTotal database"
            else:
                lookup.error = f"VirusTotal returned {exc.response.status_code}: {exc.response.text[:200]}"
        except httpx.RequestError as exc:
            lookup.error = f"VirusTotal request failed: {exc}"
        except ValueError as exc:
            lookup.error = f"VirusTotal response parsing error: {exc}"
        return lookup

    def submit_url(self, url: str) -> Optional[str]:
        """Submit a URL to VirusTotal for scanning. Returns analysis ID or None on error."""
        headers = {"x-apikey": self._api_key}
        try:
            response = self._client.post(
                f"{VT_BASE_URL}/urls",
                headers=headers,
                data={"url": url}
            )
            response.raise_for_status()
            payload = response.json()
            # Returns analysis ID like "u-<hash>-<timestamp>"
            return payload.get("data", {}).get("id")
        except httpx.HTTPStatusError as exc:
            logger.warning(f"VT URL submission failed for {url[:50]}: HTTP {exc.response.status_code}")
            return None
        except httpx.RequestError as exc:
            logger.warning(f"VT URL submission request error for {url[:50]}: {exc}")
            return None
        except (ValueError, KeyError) as exc:
            logger.warning(f"VT URL submission response parsing error for {url[:50]}: {exc}")
            return None

    def get_url_analysis(self, analysis_id: str) -> Optional[dict]:
        """Get URL analysis results by analysis ID."""
        headers = {"x-apikey": self._api_key}
        try:
            response = self._client.get(
                f"{VT_BASE_URL}/analyses/{analysis_id}",
                headers=headers
            )
            response.raise_for_status()
            return response.json().get("data", {})
        except (httpx.HTTPStatusError, httpx.RequestError, ValueError, KeyError):
            # Analysis not available or error fetching
            return None

    def scan_and_lookup_url(self, url: str, timeout: int = 30) -> VirusTotalLookup:
        """Lookup URL in VT. If not found, submit for scanning and poll for results.
        
        Args:
            url: The URL to scan/lookup
            timeout: Max seconds to wait for scan results (default 30)
        """
        import time
        
        # First try to get existing data
        lookup = self.lookup_url(url)
        if lookup.data and not lookup.error:
            return lookup  # Already have data
        
        # If 404 (not found), submit for scanning
        if lookup.error and "not found" in lookup.error.lower():
            logger.info(f"VT URL not found, submitting for scan: {url[:50]}...")
            analysis_id = self.submit_url(url)
            
            if analysis_id:
                # Poll for results
                start_time = time.time()
                while time.time() - start_time < timeout:
                    time.sleep(3)  # Wait 3 seconds between polls
                    analysis = self.get_url_analysis(analysis_id)
                    if analysis:
                        status = analysis.get("attributes", {}).get("status")
                        if status == "completed":
                            # Fetch the actual URL report now that scan is complete
                            return self.lookup_url(url)
                        elif status == "queued":
                            continue  # Still waiting
                
                # Timeout - return what we have
                lookup.error = "VT scan submitted but results not ready yet"
        
        return lookup

    def lookup_urls(self, urls: Iterable[str], *, max_items: int = 10) -> list[VirusTotalLookup]:
        """Lookup multiple URLs in VirusTotal in parallel.
        
        Checks for existing data first, submits for scanning if not found.
        """
        seen: Set[str] = set()
        unique_urls = []
        for url in urls:
            if url in seen:
                continue
            seen.add(url)
            unique_urls.append(url)
            if len(unique_urls) >= max_items:
                break

        lookups: list[VirusTotalLookup] = []
        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(unique_urls))) as executor:
            futures = {
                executor.submit(self.scan_and_lookup_url, url, 20): url 
                for url in unique_urls
            }
            for future in as_completed(futures):
                try:
                    lookups.append(future.result(timeout=30))
                except Exception as e:
                    url = futures[future]
                    lookups.append(VirusTotalLookup(
                        indicator=url, indicator_type="url",
                        error=f"URL lookup failed: {str(e)}"
                    ))
        return lookups

    # =========================================================================
    # IP Address Lookups
    # =========================================================================

    @staticmethod
    def is_ip_address(host: str) -> bool:
        """Check if a host string is an IP address (v4 or v6)."""
        import ipaddress
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def lookup_ip(self, ip: str) -> VirusTotalLookup:
        """Lookup an IP address in VirusTotal using the /ip_addresses/ endpoint.
        
        This is useful for detecting malicious IPs even when the exact URL
        hasn't been scanned - the IP may have reputation data from other scans.
        """
        return self._call_vt(
            f"/ip_addresses/{ip}",
            indicator=ip,
            indicator_type="ip"
        )
