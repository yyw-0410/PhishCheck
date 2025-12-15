"""Metadata (MDM) view models for Sublime Analysis API responses."""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from .email import EmailAttachment, EmailBody, EmailHeader, EmailLink


class SublimeVerdictReason(BaseModel):
    """Explanation attached to a Sublime verdict."""

    rule_id: Optional[str] = Field(
        default=None,
        description="Identifier of the Sublime rule or detector that produced this reason.",
    )
    title: str = Field(description="Human-readable reason title.")
    description: Optional[str] = Field(default=None, description="Extended reason details.")
    reference_url: Optional[str] = Field(
        default=None, description="Documentation or knowledge-base reference."
    )


class SublimeVerdict(BaseModel):
    """Sublime classification verdict."""

    model_config = ConfigDict(extra="allow")

    label: str = Field(description="Verdict label returned by Sublime (e.g. MALICIOUS, BENIGN).")
    score: float = Field(description="Numeric risk score returned by Sublime.")
    confidence: Optional[str] = Field(
        default=None, description="Optional confidence adjective supplied by Sublime."
    )
    reasons: List[SublimeVerdictReason] = Field(
        default_factory=list,
        description="Ordered list of reasons supporting the verdict.",
    )


class SublimeIndicator(BaseModel):
    """Indicator extracted by Sublime with reputation context."""

    type: str = Field(description="Indicator type (url, domain, ip, sender_domain, attachment, etc.).")
    value: str = Field(description="Indicator value.")
    verdict: Optional[str] = Field(
        default=None, description="Indicator-specific verdict (malicious, suspicious, benign)."
    )
    details: Optional[str] = Field(
        default=None, description="Additional evidence or enrichment details."
    )


class SublimeDetection(BaseModel):
    """Individual detection finding from Sublime."""

    id: str = Field(description="Detection identifier or slug.")
    title: str = Field(description="Detection title.")
    description: Optional[str] = Field(default=None, description="Detailed description of the finding.")
    severity: Optional[str] = Field(default=None, description="Severity rating for the finding.")
    indicators: List[SublimeIndicator] = Field(
        default_factory=list, description="Indicators referenced by this finding."
    )


class SublimeMDM(BaseModel):
    """Normalized metadata model for Sublime analysis results."""

    model_config = ConfigDict(extra="allow")

    analysis_id: str = Field(description="Unique identifier for the Sublime analysis job.")
    status: str = Field(description="Current status (queued, in_progress, complete, failed).")
    submitted_at: datetime = Field(description="Timestamp (UTC) when the job was submitted.")
    completed_at: Optional[datetime] = Field(
        default=None, description="Timestamp when the job finished processing."
    )
    engine_version: Optional[str] = Field(
        default=None, description="Analysis engine version reported by Sublime."
    )
    verdict: SublimeVerdict = Field(description="Overall verdict information.")
    detections: List[SublimeDetection] = Field(
        default_factory=list, description="List of discrete detections produced."
    )
    indicators: List[SublimeIndicator] = Field(
        default_factory=list, description="Flattened list of all indicators referenced in the analysis."
    )
    message_subject: Optional[str] = Field(default=None, description="Subject observed in the message.")
    message_sender: Optional[str] = Field(default=None, description="Envelope sender or From address.")
    headers: List[EmailHeader] = Field(
        default_factory=list, description="Message headers as returned by Sublime."
    )
    body: Optional[EmailBody] = Field(
        default=None,
        description="Body content as provided in the Sublime response (if the API echo is enabled).",
    )
    links: List[EmailLink] = Field(
        default_factory=list, description="Links detected within the message."
    )
    attachments: List[EmailAttachment] = Field(
        default_factory=list, description="Attachment metadata returned by Sublime."
    )
    raw: Optional[Dict[str, object]] = Field(
        default=None,
        description="Original Sublime JSON payload for traceability or downstream use.",
    )
