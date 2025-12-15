"""Schemas describing third-party threat intelligence enrichments."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class VirusTotalLookup(BaseModel):
    """VirusTotal lookup result."""

    indicator: str = Field(description="Indicator that was queried (domain, URL hash, file hash, etc.).")
    indicator_type: str = Field(description="High-level indicator category (domain, url, file, ip).")
    data: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Subset of the VirusTotal response relevant to the indicator.",
    )
    error: Optional[str] = Field(default=None, description="Error encountered while querying VirusTotal.")
    sources: Optional[list[str]] = Field(
        default=None,
        description="Where this indicator came from (e.g., 'URL', 'HEADER').",
    )


class IPQSLookup(BaseModel):
    """IPQualityScore IP reputation lookup result."""

    ip: str = Field(description="IP address that was queried.")
    source: Optional[str] = Field(default=None, description="Where the IP was found (e.g., 'Sender Origin', 'Mail Relay #1', 'SPF Record').")
    fraud_score: Optional[int] = Field(default=None, description="Fraud score (0-100, higher = more risky).")
    country_code: Optional[str] = Field(default=None, description="Country code of the IP.")
    city: Optional[str] = Field(default=None, description="City location of the IP.")
    isp: Optional[str] = Field(default=None, description="Internet Service Provider.")
    is_vpn: Optional[bool] = Field(default=None, description="Whether the IP is a VPN.")
    is_tor: Optional[bool] = Field(default=None, description="Whether the IP is a Tor exit node.")
    is_proxy: Optional[bool] = Field(default=None, description="Whether the IP is a proxy.")
    is_bot: Optional[bool] = Field(default=None, description="Whether the IP is associated with bot activity.")
    is_crawler: Optional[bool] = Field(default=None, description="Whether the IP is a known crawler.")
    recent_abuse: Optional[bool] = Field(default=None, description="Whether the IP has recent abuse reports.")
    host: Optional[str] = Field(default=None, description="Hostname associated with the IP.")
    error: Optional[str] = Field(default=None, description="Error encountered while querying IPQS.")


class HybridAnalysisLookup(BaseModel):
    """Hybrid Analysis file/hash lookup result."""

    sha256: str = Field(description="SHA256 hash of the file queried.")
    verdict: Optional[str] = Field(default=None, description="Overall verdict (malicious, suspicious, no specific threat, etc.).")
    threat_score: Optional[int] = Field(default=None, description="Threat score (0-100, higher = more dangerous).")
    threat_level: Optional[int] = Field(default=None, description="Threat level (0=no threat, 1=suspicious, 2=malicious).")
    av_detect: Optional[int] = Field(default=None, description="Number of AV engines detecting as malicious.")
    vx_family: Optional[str] = Field(default=None, description="Malware family name if identified.")
    tags: Optional[List[str]] = Field(default=None, description="Tags associated with the sample.")
    file_type: Optional[str] = Field(default=None, description="Detected file type.")
    environment_description: Optional[str] = Field(default=None, description="Analysis environment used.")
    report_url: Optional[str] = Field(default=None, description="Link to full report on Hybrid Analysis.")
    error: Optional[str] = Field(default=None, description="Error encountered while querying Hybrid Analysis.")
    # Additional fields for enhanced display
    submit_name: Optional[str] = Field(default=None, description="Original submitted file name.")
    analysis_start_time: Optional[str] = Field(default=None, description="When the analysis started.")
    size: Optional[int] = Field(default=None, description="File size in bytes.")
    total_processes: Optional[int] = Field(default=None, description="Number of processes spawned during analysis.")
    total_signatures: Optional[int] = Field(default=None, description="Number of behavioral signatures matched.")
    total_network_connections: Optional[int] = Field(default=None, description="Number of network connections made.")
    domains: Optional[List[str]] = Field(default=None, description="Network domains contacted during analysis.")
    hosts: Optional[List[str]] = Field(default=None, description="Network hosts/IPs contacted during analysis.")
    classification_tags: Optional[List[str]] = Field(default=None, description="Classification tags from analysis.")
    mitre_attcks: Optional[List[str]] = Field(default=None, description="MITRE ATT&CK techniques detected.")
    is_interesting: Optional[bool] = Field(default=None, description="Whether the sample was flagged as interesting.")


class URLScanSubmission(BaseModel):
    """urlscan.io submission metadata."""

    url: str = Field(description="URL submitted to urlscan.io.")
    scan_id: Optional[str] = Field(default=None, description="UUID of the created scan job.")
    result_url: Optional[str] = Field(
        default=None,
        description="Link to the rendered scan report if the submission was accepted.",
    )
    screenshot_url: Optional[str] = Field(
        default=None,
        description="Direct link to the screenshot image captured by urlscan.io (if available).",
    )
    visibility: Optional[str] = Field(default=None, description="Visibility mode used for the submission.")
    error: Optional[str] = Field(default=None, description="Error encountered during submission.")
    verdict: Optional[str] = Field(default=None, description="High-level verdict derived from urlscan.io result.")
    tags: Optional[list[str]] = Field(default=None, description="Notable tags extracted from the result, if any.")
    ml_link: Optional[Dict[str, Any]] = Field(default=None, description="Optional result of Sublime link_analysis evaluate for this URL.")


class ThreatIntelReport(BaseModel):
    """Aggregate threat intelligence data associated with an email analysis."""

    virustotal: List[VirusTotalLookup] = Field(
        default_factory=list,
        description="VirusTotal reputation or metadata lookups.",
    )
    urlscan: List[URLScanSubmission] = Field(
        default_factory=list,
        description="urlscan.io submissions initiated for URLs discovered in the message.",
    )
    ipqs: List[IPQSLookup] = Field(
        default_factory=list,
        description="IPQualityScore IP reputation lookups for sender IPs.",
    )
    hybrid_analysis: List[HybridAnalysisLookup] = Field(
        default_factory=list,
        description="Hybrid Analysis sandbox lookups for file attachments.",
    )
    notes: Optional[str] = Field(
        default=None,
        description="Optional human-readable commentary about the enrichments performed.",
    )
