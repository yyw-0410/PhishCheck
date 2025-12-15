"""Aggregate email analysis workflow that orchestrates Sublime and other providers."""

from __future__ import annotations

import copy
from typing import Any, Iterable, List, Optional

from app.schemas import (
    CombinedAnalysisResult,
    EmailAttachment,
    ParsedEmail,
    SublimeAnalysisSummary,
    ThreatIntelReport,
)
from app.services.email_parser import EmailParserService
from app.services.providers.sublime import SublimeAnalysisClient
from app.services.threat_intel import ThreatIntelService
from app.core.constants import MAX_RAW_EML_SIZE_BYTES


class AnalysisPipeline:
    """Coordinate the end-to-end processing of an uploaded email artifact.
    
    This pipeline handles parsing, threat intelligence enrichment, and
    Sublime Security analysis to produce a comprehensive risk assessment.
    """

    def __init__(
        self,
        *,
        parser: Optional[EmailParserService] = None,
        sublime_client: Optional[SublimeAnalysisClient] = None,
        threat_intel_service: Optional[ThreatIntelService] = None,
    ) -> None:
        self._parser = parser or EmailParserService()
        self._sublime = sublime_client or SublimeAnalysisClient()
        self._threat_intel = threat_intel_service or ThreatIntelService()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        raw_message: bytes,
        *,
        run_all_detection_rules: bool = True,
        run_all_insights: bool = True,
        include_workflow_rules: bool = False,
        request_attack_score: bool = True,
        perform_threat_enrichment: bool = True,
        max_urlscan_submissions: Optional[int] = None,
        urlscan_visibility: str = "public",
    ) -> CombinedAnalysisResult:
        """Execute the analysis pipeline and return a consolidated view.
        
        Args:
            raw_message: Raw bytes of the .eml file.
            run_all_detection_rules: Whether to run all available detection rules.
            run_all_insights: Whether to run all available insights.
            include_workflow_rules: Include lower-severity workflow rules in results.
            request_attack_score: Request an ML-based attack score from Sublime.
            perform_threat_enrichment: Enrich indicators with VirusTotal/URLscan.
            max_urlscan_submissions: Max URLs to submit to URLscan (0-50).
            urlscan_visibility: 'public', 'unlisted', or 'private'.
            
        Returns:
            CombinedAnalysisResult: Consolidated analysis results including
            parsing, rule hits, and threat intelligence.
        """

        parsed_email = self._parser.parse(raw_message)
        sublime_summary = SublimeAnalysisSummary()

        # Step 1: Create Sublime MDM
        try:
            mdm = self._sublime.create_message(raw_message)
            sublime_summary.mdm = mdm
        except Exception as exc:  # pragma: no cover - network call
            sublime_summary.errors["sublime_create_message"] = str(exc)
            mdm = None

        # Step 2: Run Sublime analysis for rules/insights
        analysis_payload = None
        try:
            analysis_payload = self._sublime.analyze_message(
                raw_message,
                run_all_detection_rules=run_all_detection_rules,
                run_active_detection_rules=False,
                run_all_insights=run_all_insights,
            )
            sublime_summary.analysis = self._sanitize_analysis_payload(
                analysis_payload, include_workflow_rules=include_workflow_rules
            )
            sublime_summary.rule_hits = self._extract_rule_hits(
                analysis_payload, include_workflow_rules=include_workflow_rules
            )
            sublime_summary.insight_hits = self._extract_insight_hits(analysis_payload)
        except Exception as exc:  # pragma: no cover - network call
            sublime_summary.errors["sublime_analyze"] = str(exc)

        # Step 3: Attack score (optional)
        if request_attack_score:
            try:
                sublime_summary.attack_score = self._sublime.evaluate_attack_score(raw_message)
            except Exception as exc:  # pragma: no cover - network call
                sublime_summary.errors["sublime_attack_score"] = str(exc)

        # Step 4: Threat intel enrichment
        threat_report = ThreatIntelReport()
        if perform_threat_enrichment:
            try:
                extra_urls = self._collect_urls_from_mdm(mdm) if mdm else []
                extra_attachments: Iterable[EmailAttachment] = mdm.attachments if mdm else []
                threat_report = self._threat_intel.enrich(
                    parsed_email,
                    extra_urls=extra_urls,
                    extra_attachments=extra_attachments,
                    max_urlscan_submissions=max_urlscan_submissions,
                    urlscan_visibility=urlscan_visibility,
                )
            except Exception as exc:  # pragma: no cover - network call
                threat_report.notes = (
                    (threat_report.notes + " ") if threat_report.notes else ""
                ) + f"Threat intelligence enrichment failed: {exc}"

        # Decode raw EML for frontend display (truncate if very large)
        try:
            raw_eml_str = raw_message.decode("utf-8", errors="replace")
            # Truncate if larger than 500KB to avoid bloating the response
            if len(raw_eml_str) > MAX_RAW_EML_SIZE_BYTES:
                raw_eml_str = raw_eml_str[:MAX_RAW_EML_SIZE_BYTES] + "\n\n... [Content truncated - file too large] ..."
        except Exception:
            raw_eml_str = None

        return CombinedAnalysisResult(
            parsed_email=parsed_email,
            sublime=sublime_summary,
            threat_intel=threat_report,
            raw_eml=raw_eml_str,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_rule_hits(analysis_payload: Optional[dict], *, include_workflow_rules: bool) -> List[dict]:
        if not isinstance(analysis_payload, dict):
            return []
        rule_results = analysis_payload.get("rule_results") or []
        if not isinstance(rule_results, list):
            return []

        hits: List[dict] = []
        for item in rule_results:
            if not isinstance(item, dict):
                continue
            if not item.get("matched"):
                continue
            if include_workflow_rules:
                hits.append(item)
                continue
            rule = item.get("rule") or {}
            if not isinstance(rule, dict):
                hits.append(item)
                continue
            severity = rule.get("severity")
            source = (rule.get("source") or "").strip().lower()
            if severity or (source and source != "true"):
                hits.append(item)
        return hits

    @staticmethod
    def _extract_insight_hits(analysis_payload: Optional[dict]) -> List[dict]:
        if not isinstance(analysis_payload, dict):
            return []
        query_results = analysis_payload.get("query_results") or []
        if not isinstance(query_results, list):
            return []
        hits: List[dict] = []
        for item in query_results:
            if not isinstance(item, dict):
                continue
            if AnalysisPipeline._is_truthy(item.get("result")):
                query = item.get("query") or {}
                name = ""
                if isinstance(query, dict):
                    name = str(query.get("name") or "")
                if name.lower().startswith("first-time sender"):
                    continue
                hits.append(item)
        return hits

    @staticmethod
    def _sanitize_analysis_payload(
        analysis_payload: Optional[dict], *, include_workflow_rules: bool
    ) -> Any:
        """Sanitize analysis payload with filtered rule/query results."""
        if not isinstance(analysis_payload, dict):
            return analysis_payload

        sanitized = copy.deepcopy(analysis_payload)
        sanitized["rule_results"] = AnalysisPipeline._extract_rule_hits(
            analysis_payload, include_workflow_rules=include_workflow_rules
        )
        sanitized["query_results"] = AnalysisPipeline._extract_insight_hits(analysis_payload)
        return sanitized

    @staticmethod
    def _is_truthy(value: Any) -> bool:
        if value is None:
            return False
        if isinstance(value, bool):
            return value
        if isinstance(value, (list, tuple, set, dict)):
            return len(value) > 0
        if isinstance(value, (int, float)):
            return value != 0
        if isinstance(value, str):
            return value.strip() != ""
        return True

    @staticmethod
    def _collect_urls_from_mdm(mdm: Optional[Any]) -> List[str]:
        urls: List[str] = []
        if not mdm:
            return urls
        links = getattr(mdm, "links", None)
        if not isinstance(links, list):
            return urls
        for link in links:
            href = getattr(link, "href", None)
            if isinstance(href, str) and href.strip():
                urls.append(href.strip())
        return urls
