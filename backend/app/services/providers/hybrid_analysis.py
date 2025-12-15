"""Hybrid Analysis provider for file sandbox analysis lookups."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List

import httpx

from app.core import Settings, get_settings
from app.schemas import HybridAnalysisLookup
from .base import BaseProvider

logger = logging.getLogger(__name__)

HYBRID_ANALYSIS_BASE_URL = "https://www.hybrid-analysis.com/api/v2"
MAX_WORKERS = 15


class HybridAnalysisProvider(BaseProvider):
    """Hybrid Analysis API client for file sandbox analysis."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        *,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        super().__init__(settings, http_client=http_client)
        self._api_key = self._settings.hybrid_analysis_api_key

    # =========================================================================
    # Enhanced Fields Extraction
    # =========================================================================

    @staticmethod
    def _extract_enhanced_fields(data: dict) -> dict:
        """Extract enhanced fields from Hybrid Analysis API response."""
        enhanced = {}

        # Basic fields
        enhanced["submit_name"] = data.get("submit_name") or data.get("submitname")
        enhanced["analysis_start_time"] = data.get("analysis_start_time")
        enhanced["size"] = data.get("size")

        # Behavioral data
        enhanced["total_processes"] = data.get("total_processes")
        enhanced["total_signatures"] = data.get("total_signatures")
        enhanced["total_network_connections"] = data.get("total_network_connections")

        # Network indicators
        domains = data.get("domains")
        if domains and isinstance(domains, list):
            enhanced["domains"] = [d for d in domains if isinstance(d, str)][:20]

        hosts = data.get("hosts")
        if hosts and isinstance(hosts, list):
            enhanced["hosts"] = [h for h in hosts if isinstance(h, str)][:20]

        # Classification
        classification_tags = data.get("classification_tags")
        if classification_tags and isinstance(classification_tags, list):
            enhanced["classification_tags"] = classification_tags

        # MITRE ATT&CK
        mitre = data.get("mitre_attcks")
        if mitre and isinstance(mitre, list):
            techniques = []
            for item in mitre:
                if isinstance(item, dict):
                    tid = item.get("technique_id") or item.get("technique")
                    if tid:
                        name = item.get("attck_id_wiki") or item.get("technique_name") or ""
                        techniques.append(f"{tid}: {name}" if name else tid)
                elif isinstance(item, str):
                    techniques.append(item)
            enhanced["mitre_attcks"] = techniques[:15]

        # Interesting flag
        is_interesting = data.get("interesting")
        if is_interesting is not None:
            enhanced["is_interesting"] = bool(is_interesting)

        return enhanced
    
    @staticmethod
    def _get_file_type(data: dict) -> Optional[str]:
        """Extract file type as a string, handling cases where API returns a list."""
        file_type = data.get("type") or data.get("type_short")
        if file_type is None:
            return None
        if isinstance(file_type, list):
            # API sometimes returns ['img', 'image'] - take the first element
            return file_type[0] if file_type else None
        return str(file_type)

    # =========================================================================
    # Single Hash Lookup
    # =========================================================================

    def lookup_single(self, file_hash: str, hash_type: str = "sha256") -> HybridAnalysisLookup:
        """Lookup a single hash in Hybrid Analysis."""
        headers = {
            "api-key": self._api_key,
            "User-Agent": "Falcon Sandbox",
            "accept": "application/json",
        }

        sha256_from_result = None

        try:
            # For SHA256, try overview endpoints first
            if hash_type == "sha256":
                # 1. Try /overview/{sha256} (has scanners_v2 with detailed data)
                overview_url = f"{HYBRID_ANALYSIS_BASE_URL}/overview/{file_hash}"
                resp = self._client.get(
                    overview_url,
                    headers=headers,
                    timeout=httpx.Timeout(15.0, connect=5.0),
                    follow_redirects=True,
                )

                if resp.status_code == 200:
                    data = resp.json()
                    logger.info(f"HA Overview API response for {file_hash}: threat_score={data.get('threat_score') if isinstance(data, dict) else 'N/A'}")

                    if isinstance(data, dict) and data:
                        verdict = data.get("verdict")
                        threat_score = data.get("threat_score")
                        threat_level = data.get("threat_level")
                        sha256_from_result = data.get("sha256") or file_hash

                        # Extract from scanners_v2
                        scanners = data.get("scanners_v2") or {}

                        # CrowdStrike ML
                        crowdstrike = scanners.get("crowdstrike_ml") or {}
                        cs_percent = crowdstrike.get("percent")
                        if cs_percent is not None and threat_score is None:
                            threat_score = cs_percent

                        # MetaDefender - get AV detections
                        metadefender = scanners.get("metadefender") or {}
                        md_positives = metadefender.get("positives")
                        
                        # Determine av_detect value
                        av_detect = None
                        if md_positives is not None:
                            av_detect = md_positives
                        elif metadefender:
                            # MetaDefender was scanned but no positives - means clean (0 detections)
                            av_detect = 0
                        else:
                            # Fall back to other fields
                            av_detect = data.get("multiscan_result") or data.get("av_detect")

                        if not verdict and threat_level is not None:
                            verdict = ["no specific threat", "suspicious", "malicious"][min(threat_level, 2)]
                        if not verdict:
                            verdict = "suspicious" if av_detect and int(str(av_detect)) > 0 else "clean"

                        enhanced = self._extract_enhanced_fields(data)
                        return HybridAnalysisLookup(
                            sha256=sha256_from_result,
                            verdict=verdict,
                            threat_score=threat_score,
                            threat_level=threat_level,
                            av_detect=int(str(av_detect)) if av_detect is not None else None,
                            vx_family=data.get("vx_family"),
                            tags=data.get("tags"),
                            file_type=self._get_file_type(data),
                            environment_description=data.get("environment_description"),
                            report_url=f"https://www.hybrid-analysis.com/sample/{sha256_from_result}",
                            **enhanced,
                        )

                # 2. Fall back to /overview/{sha256}/summary
                summary_url = f"{HYBRID_ANALYSIS_BASE_URL}/overview/{file_hash}/summary"
                resp = self._client.get(
                    summary_url,
                    headers=headers,
                    timeout=httpx.Timeout(15.0, connect=5.0),
                    follow_redirects=True,
                )

                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, dict) and data:
                        verdict = data.get("verdict")
                        threat_score = data.get("threat_score")
                        threat_level = data.get("threat_level")
                        av_detect = data.get("multiscan_result")
                        if av_detect is None:
                            av_detect = data.get("av_detect")
                        # If we have verdict, assume 0 detections if av_detect is still None
                        if av_detect is None and verdict:
                            av_detect = 0
                        sha256_from_result = data.get("sha256") or file_hash

                        if not verdict and threat_level is not None:
                            verdict = ["no specific threat", "suspicious", "malicious"][min(threat_level, 2)]
                        if not verdict:
                            verdict = "suspicious" if av_detect and int(str(av_detect)) > 0 else "clean"

                        enhanced = self._extract_enhanced_fields(data)
                        return HybridAnalysisLookup(
                            sha256=sha256_from_result,
                            verdict=verdict,
                            threat_score=threat_score,
                            threat_level=threat_level,
                            av_detect=int(str(av_detect)) if av_detect is not None else None,
                            vx_family=data.get("vx_family"),
                            tags=data.get("tags"),
                            file_type=self._get_file_type(data),
                            environment_description=data.get("environment_description"),
                            report_url=f"https://www.hybrid-analysis.com/sample/{sha256_from_result}",
                            **enhanced,
                        )

            # 3. Try /search/hash - works for any hash type
            search_url = f"{HYBRID_ANALYSIS_BASE_URL}/search/hash"
            search_resp = self._client.get(
                search_url,
                headers=headers,
                params={"hash": file_hash},
                timeout=httpx.Timeout(15.0, connect=5.0),
                follow_redirects=True,
            )

            if search_resp.status_code == 200:
                search_data = search_resp.json()
                if isinstance(search_data, list) and len(search_data) > 0:
                    best = max(search_data, key=lambda x: (x.get("threat_score") or 0, x.get("analysis_start_time") or ""))

                    verdict = best.get("verdict")
                    threat_level = best.get("threat_level")
                    av_detect_raw = best.get("av_detect")
                    multiscan = best.get("multiscan_result")
                    av_detect = multiscan if multiscan is not None else av_detect_raw
                    # If we have verdict, assume 0 detections if av_detect is still None
                    if av_detect is None and (verdict or threat_level is not None):
                        av_detect = 0
                    sha256_from_result = best.get("sha256") or file_hash

                    if not verdict and threat_level is not None:
                        verdict = ["no specific threat", "suspicious", "malicious"][min(threat_level, 2)]
                    if not verdict:
                        verdict = "suspicious" if av_detect and int(str(av_detect)) > 0 else "clean"

                    job_id = best.get("job_id")
                    report_url = f"https://www.hybrid-analysis.com/sample/{sha256_from_result}"
                    if job_id:
                        report_url += f"/{job_id}"

                    enhanced = self._extract_enhanced_fields(best)
                    return HybridAnalysisLookup(
                        sha256=sha256_from_result,
                        verdict=verdict,
                        threat_score=best.get("threat_score"),
                        threat_level=threat_level,
                        av_detect=int(str(av_detect)) if av_detect is not None else None,
                        vx_family=best.get("vx_family"),
                        tags=best.get("tags"),
                        file_type=self._get_file_type(best),
                        environment_description=best.get("environment_description"),
                        report_url=report_url,
                        **enhanced,
                    )

            # Not found
            return HybridAnalysisLookup(
                sha256=file_hash,
                verdict="not found",
                report_url=f"https://www.hybrid-analysis.com/search?query={file_hash}",
            )

        except Exception as e:
            logger.warning(f"Hybrid Analysis lookup failed for {file_hash}: {e}")
            return HybridAnalysisLookup(
                sha256=file_hash,
                error=f"Lookup failed: {str(e)}",
            )

    # =========================================================================
    # Batch Parallel Lookups
    # =========================================================================

    def lookup_by_hash(self, hashes: List[str], hash_type: str = "sha256") -> List[HybridAnalysisLookup]:
        """Query Hybrid Analysis for multiple hashes in parallel."""
        if not hashes:
            return []

        results: List[HybridAnalysisLookup] = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(self.lookup_single, h, hash_type): h
                for h in hashes
            }
            for future in as_completed(futures):
                try:
                    results.append(future.result(timeout=30))
                except Exception as e:
                    h = futures[future]
                    results.append(HybridAnalysisLookup(
                        sha256=h,
                        error=f"Parallel lookup failed: {str(e)}",
                    ))
        return results
