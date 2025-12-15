"""Schemas describing the combined analysis pipeline response."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from .email import ParsedEmail
from .mdm import SublimeMDM
from .threat_intel import ThreatIntelReport


class SublimeAnalysisSummary(BaseModel):
    """Bundle of Sublime analysis outputs and helper summaries."""

    mdm: Optional[SublimeMDM] = Field(
        default=None,
        description="Message Data Model returned by Sublime (if create_message succeeded).",
    )
    analysis: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Raw response from Sublime's /messages/analyze endpoint.",
    )
    attack_score: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Output from the attack score endpoint, if requested.",
    )
    rule_hits: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Subset of rule_results entries whose matched flag is true.",
    )
    insight_hits: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Insights with truthy result payloads extracted from query_results.",
    )
    errors: Dict[str, str] = Field(
        default_factory=dict,
        description="Mapping of subsystem name to error message when Sublime requests fail.",
    )


class CombinedAnalysisResult(BaseModel):
    """Primary payload returned to the frontend when an email is analyzed."""

    parsed_email: ParsedEmail = Field(description="Locally parsed representation of the uploaded email.")
    sublime: SublimeAnalysisSummary = Field(description="Aggregated Sublime analysis outputs.")
    threat_intel: ThreatIntelReport = Field(
        description="Outputs from threat intelligence providers such as VirusTotal or urlscan.io."
    )
    raw_eml: Optional[str] = Field(
        default=None,
        description="Raw EML content of the uploaded email for display purposes."
    )
