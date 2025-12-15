"""Threat intelligence orchestration service.

Coordinates lookups against third-party threat intelligence providers.
Delegates to specialized provider modules for each external service.
"""

from __future__ import annotations

import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, Optional, Set, List
from urllib.parse import urlparse

import httpx

from app.core import Settings, get_settings
from app.schemas import (
    EmailAttachment,
    ParsedEmail,
    ThreatIntelReport,
    URLScanSubmission,
    VirusTotalLookup,
    IPQSLookup,
    HybridAnalysisLookup,
)

# Import provider modules
from app.services.providers import (
    VirusTotalProvider,
    UrlscanProvider,
    IPQSProvider,
    HybridAnalysisProvider,
)
from app.services.providers.base import normalize_domain
from app.services.providers.ipqs import extract_sender_ips
from app.services.providers.sublime import SublimeAnalysisClient



logger = logging.getLogger(__name__)

MAX_WORKERS = 15


class ThreatIntelService:
    """Coordinate lookups against third-party threat intelligence providers."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        *,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        self._settings = settings or get_settings()
        timeout = httpx.Timeout(10.0, connect=3.0)
        if http_client is not None:
            self._client = http_client
            self._owns_client = False
        else:
            self._client = httpx.Client(timeout=timeout)
            self._owns_client = True

        # Initialize providers with shared HTTP client
        self._vt = VirusTotalProvider(settings, http_client=self._client)
        self._urlscan = UrlscanProvider(settings, http_client=self._client)
        self._ipqs = IPQSProvider(settings, http_client=self._client)
        self._ha = HybridAnalysisProvider(settings, http_client=self._client)
        
        # Sublime client may not be initialized if API key is missing
        self._sublime: Optional[SublimeAnalysisClient] = None
        try:
            self._sublime = SublimeAnalysisClient(settings, http_client=self._client)
        except RuntimeError:
            logger.warning("Sublime API key not configured - link analysis disabled")


    def __del__(self) -> None:
        if getattr(self, "_owns_client", False):
            try:
                self._client.close()
            except Exception:
                pass

    # =========================================================================
    # Main Enrichment Orchestration
    # =========================================================================

    def enrich(
        self,
        parsed_email: ParsedEmail,
        *,
        extra_urls: Optional[Iterable[str]] = None,
        extra_attachments: Optional[Iterable[EmailAttachment]] = None,
        max_urlscan_submissions: Optional[int] = None,
        urlscan_visibility: str = "unlisted",
    ) -> ThreatIntelReport:
        """Gather threat intelligence data for the provided email using parallel lookups."""
        report = ThreatIntelReport()

        urls = self._collect_urls(parsed_email, extra_urls)
        header_domains = self._collect_header_domains(parsed_email)
        text_domains = self._collect_text_domains(parsed_email)
        attachments = self._collect_attachments(parsed_email, extra_attachments)
        sender_ips = extract_sender_ips(parsed_email)

        # Prepare parallel task results
        vt_results: List[VirusTotalLookup] = []
        urlscan_results: List[URLScanSubmission] = []
        ipqs_results: List[IPQSLookup] = []
        ha_results: List[HybridAnalysisLookup] = []

        # Use ThreadPoolExecutor for parallel API calls
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {}

            # VirusTotal domain + URL lookups
            if self._settings.virustotal_api_key:
                merged_sources = set(header_domains or set()) | set(text_domains or set())
                futures['vt_domains'] = executor.submit(
                    self._vt.lookup_domains, urls, header_domains=merged_sources
                )
                futures['vt_files'] = executor.submit(
                    self._vt.lookup_files, attachments
                )
                # Also do full URL lookups (scans if not found in VT)
                futures['vt_urls'] = executor.submit(
                    self._vt.lookup_urls, urls, max_items=5  # Limit to 5 URLs to avoid slowdown
                )
            elif urls or attachments:
                report.notes = self._append_note(
                    report.notes,
                    "VirusTotal enrichment skipped: VIRUSTOTAL_API_KEY not configured.",
                )

            # URLScan jobs
            limit = max_urlscan_submissions if max_urlscan_submissions is not None else 10
            if limit == 0:
                limit = 50

            if self._settings.urlscan_api_key and limit > 0:
                futures['urlscan'] = executor.submit(
                    self._urlscan.submit_jobs, urls,
                    max_items=limit, visibility=urlscan_visibility,
                    ml_enricher=self._sublime.analyze_link if self._sublime else None
                )
            elif urls and not self._settings.urlscan_api_key:
                report.notes = self._append_note(
                    report.notes,
                    "urlscan.io enrichment skipped: URLSCAN_API_KEY not configured.",
                )

            # IPQS IP lookups
            if self._settings.ipqs_api_key and sender_ips:
                futures['ipqs'] = executor.submit(self._ipqs.lookup_parallel, sender_ips)
            elif sender_ips and not self._settings.ipqs_api_key:
                report.notes = self._append_note(
                    report.notes,
                    "IPQS IP reputation skipped: IPQS_API_KEY not configured.",
                )

            # Hybrid Analysis lookups
            if self._settings.hybrid_analysis_api_key and attachments:
                futures['ha'] = executor.submit(self._ha.lookup_by_hash, list(attachments))
            elif attachments and not self._settings.hybrid_analysis_api_key:
                report.notes = self._append_note(
                    report.notes,
                    "Hybrid Analysis sandbox lookup skipped: HYBRID_ANALYSIS_API_KEY not configured.",
                )

            # Collect results
            for key, future in futures.items():
                try:
                    result = future.result(timeout=30)
                    if key == 'vt_domains':
                        vt_results.extend(result)
                    elif key == 'vt_files':
                        vt_results.extend(result)
                    elif key == 'vt_urls':
                        vt_results.extend(result)
                    elif key == 'urlscan':
                        urlscan_results.extend(result)
                    elif key == 'ipqs':
                        ipqs_results.extend(result)
                    elif key == 'ha':
                        ha_results.extend(result)
                except Exception as e:
                    logger.warning(f"Parallel task '{key}' failed: {e}")

        report.virustotal = vt_results
        report.urlscan = urlscan_results
        report.ipqs = ipqs_results
        report.hybrid_analysis = ha_results
        return report

    # =========================================================================
    # URLscan Wrapper Methods (for link router)
    # =========================================================================

    def refresh_urlscan_submission(self, scan_id: str) -> URLScanSubmission:
        """Re-fetch an existing urlscan.io submission result."""
        return self._urlscan.refresh(scan_id, ml_enricher=self._sublime.analyze_link if self._sublime else None)

    def _submit_urlscan_jobs(
        self,
        urls: Iterable[str],
        *,
        max_items: Optional[int] = None,
        visibility: str = "public",
    ) -> List[URLScanSubmission]:
        """Submit URLs to urlscan.io for scanning."""
        return self._urlscan.submit_jobs(urls, max_items=max_items, visibility=visibility)

    # =========================================================================
    # VirusTotal Wrapper Methods (for link/file routers)
    # =========================================================================

    def _lookup_virustotal_url(self, url: str) -> VirusTotalLookup:
        """Lookup a full URL in VirusTotal. Submits for scanning if not found."""
        return self._vt.scan_and_lookup_url(url)

    def _lookup_virustotal_domains(self, urls: Iterable[str]) -> List[VirusTotalLookup]:
        """Lookup domains from URLs in VirusTotal."""
        return self._vt.lookup_domains(urls)

    def _lookup_virustotal_files(self, hashes: Iterable[str]) -> List[VirusTotalLookup]:
        """Lookup file hashes in VirusTotal."""
        return self._vt.lookup_files(hashes)

    def _lookup_virustotal_ip(self, ip: str) -> VirusTotalLookup:
        """Lookup an IP address in VirusTotal."""
        return self._vt.lookup_ip(ip)

    def _is_ip_address(self, host: str) -> bool:
        """Check if a host string is an IP address."""
        return self._vt.is_ip_address(host)

    # =========================================================================
    # Sublime ML Link Analysis Wrapper
    # =========================================================================

    def _attach_ml_link(self, submission: URLScanSubmission) -> None:
        """Attach Sublime ML link analysis to a URLScan submission."""
        if self._sublime:
            self._sublime.analyze_link(submission)

    # =========================================================================
    # Hybrid Analysis Wrapper Methods (for file router)
    # =========================================================================

    def _lookup_hybrid_analysis_by_hash(self, hashes: list, hash_type: str = "sha256") -> List[HybridAnalysisLookup]:
        """Lookup file hashes in Hybrid Analysis."""
        return self._ha.lookup_by_hash(hashes, hash_type=hash_type)

    # =========================================================================
    # Download Detection
    # =========================================================================

    def check_is_download(self, url: str) -> tuple[bool, Optional[str]]:
        """Check if a URL points to a downloadable file using a HEAD request."""
        try:
            response = self._client.head(url, timeout=5.0, follow_redirects=True)
            content_type = response.headers.get("Content-Type", "").lower()
            content_disposition = response.headers.get("Content-Disposition", "").lower()

            download_types = [
                "application/octet-stream",
                "application/x-dosexec",
                "application/x-msdownload",
                "application/exe",
                "application/x-exe",
                "application/dos-exe",
                "vms/exe",
                "application/x-winexe",
                "application/msdos-windows",
                "application/x-msdos-program",
                "application/java-archive",
                "application/zip",
                "application/x-rar-compressed",
                "application/x-7z-compressed",
                "application/x-tar",
                "application/gzip",
                "application/x-apple-diskimage",
                "application/vnd.android.package-archive"
            ]

            is_download = False
            if any(dt in content_type for dt in download_types):
                is_download = True
            if "attachment" in content_disposition:
                is_download = True

            return is_download, content_type

        except Exception as e:
            logger.warning(f"Failed to check download status for {url}: {e}")
            return False, None

    # =========================================================================
    # URL/Domain Collection Helpers
    # =========================================================================

    @staticmethod
    def _collect_urls(parsed_email: ParsedEmail, extra: Optional[Iterable[str]]) -> Set[str]:
        urls: Set[str] = set()
        for link in parsed_email.links:
            if link.href:
                urls.add(link.href)
        if extra:
            urls.update(extra)
        # Limit to first 100 URLs
        if len(urls) > 100:
            urls = set(list(urls)[:100])
        return urls

    @staticmethod
    def _collect_attachments(
        parsed_email: ParsedEmail, extra: Optional[Iterable[EmailAttachment]]
    ) -> Set[str]:
        hashes: Set[str] = set()
        for att in parsed_email.attachments:
            if att.sha256:
                hashes.add(att.sha256)
        if extra:
            for att in extra:
                if att.sha256:
                    hashes.add(att.sha256)
        return hashes

    @staticmethod
    def _append_note(existing: Optional[str], new_note: str) -> str:
        if existing:
            return f"{existing}\n{new_note}"
        return new_note

    @staticmethod
    def _collect_header_domains(parsed_email: ParsedEmail) -> Set[str]:
        """Extract likely domains from headers and email addresses."""
        domains: Set[str] = set()

        def add_domain(raw: Optional[str]) -> None:
            if not raw:
                return
            at_pos = raw.find("@")
            if at_pos >= 0:
                d = normalize_domain(raw[at_pos + 1:])
                if d:
                    domains.add(d)
            else:
                d = normalize_domain(raw)
                if d:
                    domains.add(d)

        for header in parsed_email.headers:
            name = header.name.lower()
            if name in ("from", "reply-to", "return-path", "sender"):
                add_domain(header.value)
            if name in ("message-id", "references", "in-reply-to"):
                match = re.search(r"@([\w.-]+)", header.value or "")
                if match:
                    add_domain(match.group(1))

        return domains

    @staticmethod
    def _collect_text_domains(parsed_email: ParsedEmail) -> Set[str]:
        domains: Set[str] = set()
        domain_pattern = re.compile(r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')

        # Collect text from body - EmailBody has plain_text and html, not parts
        body_text = ""
        if parsed_email.body:
            if parsed_email.body.plain_text:
                body_text += parsed_email.body.plain_text + " "
            if parsed_email.body.html:
                body_text += parsed_email.body.html + " "

        for match in domain_pattern.finditer(body_text):
            d = normalize_domain(match.group(0))
            if d:
                domains.add(d)

        # Limit to 50 domains
        if len(domains) > 50:
            domains = set(list(domains)[:50])

        return domains
