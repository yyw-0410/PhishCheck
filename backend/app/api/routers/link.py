"""Link/URL analysis endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.rate_limit import limiter
from app.schemas import URLScanSubmission, LinkAnalysisRequest, LinkAnalysisResult
from app.services import ThreatIntelService
from .dependencies import (
    AnalysisContext,
    get_analysis_context,
    get_threat_intel_service,
    optional_api_key,
)

router = APIRouter()


def _calculate_link_verdict(result: LinkAnalysisResult, url_str: str):
    """Calculate overall verdict and risk score from analysis results (additive scoring)."""
    risk_score = 0
    risk_factors = []
    
    # 1. Download link detection
    if result.is_download:
        risk_score += 25
        risk_factors.append("Direct file download link")
    
    # 2. Raw IP address detection
    import re
    ip_pattern = r'^https?://(\d{1,3}\.){3}\d{1,3}'
    if re.match(ip_pattern, url_str):
        risk_score += 10
        risk_factors.append("Uses raw IP address (no domain)")
    
    # 3. Sublime ML Score contribution
    ml = result.urlscan.ml_link if result.urlscan else None
    if ml and ml.get("score"):
        ml_score = ml.get("score", 0)
        risk_score += int(ml_score * 50)
        if ml_score >= 0.8:
            risk_factors.append("High ML malicious score")
        elif ml_score >= 0.5:
            risk_factors.append("Moderate ML suspicious score")
    
    # 4. VirusTotal contribution
    if result.virustotal:
        vt_data = result.virustotal[0].data if result.virustotal[0].data else {}
        vt_stats = vt_data.get("attributes", {}).get("last_analysis_stats", {})
        malicious = vt_stats.get("malicious", 0)
        suspicious = vt_stats.get("suspicious", 0)
        
        if malicious > 0:
            risk_score += 15 + min(malicious * 10, 45)
            risk_factors.append(f"{malicious} VT malicious detections")
        if suspicious > 0:
            risk_score += min(suspicious * 3, 15)
            risk_factors.append(f"{suspicious} VT suspicious detections")
    
    # 5. URLScan tags contribution
    if result.urlscan and result.urlscan.tags:
        tags = result.urlscan.tags
        if "phishing" in tags:
            risk_score += 20
            risk_factors.append("Tagged as phishing")
        if "malware" in tags:
            risk_score += 25
            risk_factors.append("Tagged as malware")
    
    # Cap at 100
    risk_score = min(100, risk_score)
    
    # Determine verdict
    if risk_score >= 70:
        verdict = "malicious"
    elif risk_score >= 40:
        verdict = "suspicious"
    elif risk_score >= 20:
        verdict = "low_risk"
    else:
        verdict = "clean"
    
    if not risk_factors:
        risk_factors.append("No significant threats detected")
    
    result.risk_score = risk_score
    result.overall_verdict = verdict
    result.risk_factors = risk_factors


@router.post(
    "/link",
    response_model=LinkAnalysisResult,
    summary="Analyze a URL using VirusTotal, urlscan.io, and Sublime ML.",
    dependencies=[Depends(optional_api_key), Depends(get_analysis_context('link'))],
)
@limiter.limit("20/minute")
async def analyze_link(
    request: Request,
    link_request: LinkAnalysisRequest,
    ctx: AnalysisContext = Depends(get_analysis_context('link')),
    service: ThreatIntelService = Depends(get_threat_intel_service),
):
    """Analyze a single URL."""
    result = LinkAnalysisResult()

    
    url_str = str(link_request.url)
    
    # 1. Check for download/binary content
    is_dl, c_type = service.check_is_download(url_str)
    result.is_download = is_dl
    result.content_type = c_type

    # 2. Urlscan.io (use unlisted visibility for screenshots while protecting user data)
    try:
        submission = URLScanSubmission(url=url_str, visibility="unlisted")
        urlscan_result = service._submit_urlscan_jobs([url_str], max_items=1, visibility="unlisted")
        if urlscan_result:
            submission = urlscan_result[0]
        
        # 3. Sublime ML Link Analysis
        service._attach_ml_link(submission)
        result.urlscan = submission
    except Exception as e:
        result.urlscan = URLScanSubmission(url=url_str, error=str(e))

    # 4. VirusTotal - Try full URL lookup first, then fallback to domain/IP lookup
    try:
        vt_url_result = service._lookup_virustotal_url(url_str)
        
        if vt_url_result.data and not vt_url_result.error:
            result.virustotal = [vt_url_result]
        else:
            # Extract host from URL for fallback lookup
            from urllib.parse import urlparse
            parsed = urlparse(url_str)
            host = parsed.netloc.split(':')[0] if parsed.netloc else ''
            
            # Use IP lookup for IP addresses, domain lookup for domains
            if host and service._is_ip_address(host):
                vt_ip_result = service._lookup_virustotal_ip(host)
                vt_results = [vt_ip_result] if vt_ip_result.data else []
            else:
                vt_results = service._lookup_virustotal_domains([url_str])
            
            if vt_url_result.error and "not found" not in vt_url_result.error.lower():
                vt_results.insert(0, vt_url_result)
            result.virustotal = vt_results if vt_results else [vt_url_result]
    except Exception as e:
        # Log but don't fail - VT lookup is non-critical enrichment
        import logging
        logging.getLogger(__name__).warning(f"VirusTotal lookup failed for {url_str[:50]}: {e}")
    
    # Increment analysis count after successful analysis
    ctx.increment_usage()
    
    # Calculate risk score and verdict (like File Analysis)
    _calculate_link_verdict(result, url_str)
    
    return result


@router.get(
    "/urlscan/{scan_id}",
    response_model=URLScanSubmission,
    summary="Refresh a urlscan.io submission and return the latest data.",
)
def refresh_urlscan(scan_id: str):
    """Refresh URLscan results for a given scan ID."""
    if not scan_id:
        raise HTTPException(status_code=400, detail="scan_id is required.")
    service = ThreatIntelService()
    submission = service.refresh_urlscan_submission(scan_id=scan_id)
    return submission


@router.post(
    "/virustotal/url",
    summary="Scan a URL with VirusTotal and return results.",
)
async def scan_url_virustotal(request: Request, link_request: LinkAnalysisRequest):
    """Scan/lookup a single URL with VirusTotal. Submits for scanning if not found."""
    service = ThreatIntelService()
    url_str = str(link_request.url)
    result = service._lookup_virustotal_url(url_str)
    return {
        "indicator": result.indicator,
        "indicator_type": result.indicator_type,
        "data": result.data,
        "error": result.error,
    }
