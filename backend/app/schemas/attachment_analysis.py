"""Schemas for attachment/file analysis."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from .threat_intel import HybridAnalysisLookup


class FileAnalysisRequest(BaseModel):
    """Request to analyze a file by hash or upload."""
    sha256: Optional[str] = Field(None, description="SHA256 hash of the file to look up")
    md5: Optional[str] = Field(None, description="MD5 hash of the file to look up")
    sha1: Optional[str] = Field(None, description="SHA1 hash of the file to look up")


class FileInfo(BaseModel):
    """Basic file information."""
    filename: Optional[str] = None
    size: Optional[int] = None
    sha256: Optional[str] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    content_type: Optional[str] = None


class VirusTotalFileResult(BaseModel):
    """VirusTotal file analysis result."""
    sha256: Optional[str] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    meaningful_name: Optional[str] = None
    type_description: Optional[str] = None
    type_tag: Optional[str] = None
    size: Optional[int] = None
    times_submitted: Optional[int] = None
    last_analysis_date: Optional[int] = None
    first_submission_date: Optional[int] = None
    reputation: Optional[int] = None
    stats: Optional[Dict[str, int]] = None
    tags: Optional[List[str]] = None
    names: Optional[List[str]] = None
    sandbox_verdicts: Optional[Dict[str, Any]] = None
    signature_info: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None


class SublimeFileResult(BaseModel):
    """Sublime BinExplode file analysis result."""
    file_type: Optional[str] = None
    mime_type: Optional[str] = None
    is_encrypted: Optional[bool] = None
    is_archive: Optional[bool] = None
    extracted_files: Optional[List[Dict[str, Any]]] = None
    macros: Optional[List[Dict[str, Any]]] = None
    ole_info: Optional[Dict[str, Any]] = None
    urls: Optional[List[str]] = None
    error: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None


class FileAnalysisResult(BaseModel):
    """Combined file analysis result from all sources."""
    file_info: Optional[FileInfo] = None
    virustotal: Optional[VirusTotalFileResult] = None
    sublime: Optional[SublimeFileResult] = None
    hybrid_analysis: Optional[HybridAnalysisLookup] = None
    overall_verdict: Optional[str] = None  # malicious, suspicious, low_risk, clean, unknown, not_found
    risk_score: Optional[int] = None  # 0-100
    risk_factors: Optional[List[str]] = None  # List of factors contributing to risk score
