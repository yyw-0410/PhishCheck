from typing import List, Optional
from pydantic import BaseModel, HttpUrl, field_validator
from .threat_intel import URLScanSubmission, VirusTotalLookup

class LinkAnalysisRequest(BaseModel):
    url: str
    
    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        # Add http:// if no protocol specified (more permissive for scanning phishing sites)
        if not v.startswith(('http://', 'https://')):
            v = 'http://' + v
        return v

class LinkAnalysisResult(BaseModel):
    urlscan: Optional[URLScanSubmission] = None
    virustotal: List[VirusTotalLookup] = []
    is_download: bool = False
    content_type: Optional[str] = None
