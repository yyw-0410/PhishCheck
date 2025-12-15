"""Pydantic schemas for request and response payloads."""

from .email import (
    EmailAddress,
    EmailAttachment,
    EmailAuthentication,
    EmailBody,
    EmailHeader,
    EmailLink,
    ParsedEmail,
)
from .link_analysis import LinkAnalysisRequest, LinkAnalysisResult
from .analysis import CombinedAnalysisResult, SublimeAnalysisSummary
from .mdm import (
    SublimeDetection,
    SublimeIndicator,
    SublimeMDM,
    SublimeVerdict,
    SublimeVerdictReason,
)
from .threat_intel import ThreatIntelReport, URLScanSubmission, VirusTotalLookup, IPQSLookup, HybridAnalysisLookup
from .attachment_analysis import (
    FileAnalysisRequest,
    FileInfo,
    VirusTotalFileResult,
    SublimeFileResult,
    FileAnalysisResult,
)

__all__ = [
    "EmailAddress",
    "EmailAttachment",
    "EmailAuthentication",
    "EmailBody",
    "EmailHeader",
    "EmailLink",
    "LinkAnalysisRequest",
    "LinkAnalysisResult",
    "ParsedEmail",
    "CombinedAnalysisResult",
    "SublimeAnalysisSummary",
    "SublimeDetection",
    "SublimeIndicator",
    "SublimeMDM",
    "SublimeVerdict",
    "SublimeVerdictReason",
    "ThreatIntelReport",
    "URLScanSubmission",
    "VirusTotalLookup",
    "IPQSLookup",
    "HybridAnalysisLookup",
    "FileAnalysisRequest",
    "FileInfo",
    "VirusTotalFileResult",
    "SublimeFileResult",
    "FileAnalysisResult",
]
