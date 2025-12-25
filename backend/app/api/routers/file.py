"""File/attachment analysis endpoint."""

import hashlib
from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile

from app.core.rate_limit import limiter
from app.schemas import FileAnalysisResult, FileInfo, VirusTotalFileResult
from app.services import ThreatIntelService
from .dependencies import (
    AnalysisContext,
    get_analysis_context,
    get_threat_intel_service,
    optional_api_key,
)

router = APIRouter()


def _calculate_file_verdict(result: FileAnalysisResult):
    """Calculate overall verdict and risk score from analysis results (additive like Link Analysis)."""
    risk_score = 0
    verdict = "unknown"
    risk_factors = []
    
    # 1. VirusTotal detections (additive)
    if result.virustotal and result.virustotal.stats:
        stats = result.virustotal.stats
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        
        if malicious > 0:
            # Base 15 points for any detection, plus up to 45 more
            risk_score += 15 + min(malicious * 10, 45)
            risk_factors.append(f"{malicious} VT malicious detections")
            verdict = "malicious" if malicious >= 5 else "suspicious"
        
        if suspicious > 0:
            risk_score += min(suspicious * 3, 15)
            risk_factors.append(f"{suspicious} VT suspicious detections")
            if verdict == "unknown":
                verdict = "suspicious"
    
    # 2. Hybrid Analysis threat score (additive - scale to 0-50)
    if result.hybrid_analysis and not result.hybrid_analysis.error:
        ha_verdict = result.hybrid_analysis.verdict
        ha_threat_score = result.hybrid_analysis.threat_score or 0
        
        if ha_threat_score > 0:
            # Scale HA threat score: 0-100 -> 0-50 contribution
            ha_contribution = int(ha_threat_score * 0.5)
            risk_score += ha_contribution
            risk_factors.append(f"HA threat score {ha_threat_score}%")
        
        # HA verdict adds extra points
        if ha_verdict == "malicious":
            risk_score += 25
            risk_factors.append("HA verdict: malicious")
            if verdict != "malicious":
                verdict = "malicious"
        elif ha_verdict == "suspicious":
            risk_score += 10
            risk_factors.append("HA verdict: suspicious")
            if verdict in ("clean", "unknown"):
                verdict = "suspicious"
        elif ha_verdict == "no specific threat" and verdict == "unknown":
            verdict = "clean"
        
        # Malware family detection (+20)
        if result.hybrid_analysis.vx_family:
            risk_score += 20
            risk_factors.append(f"Malware family: {result.hybrid_analysis.vx_family}")
            verdict = "malicious"
        
        # AV detections (+15 base + scaled)
        if result.hybrid_analysis.av_detect and result.hybrid_analysis.av_detect > 0:
            av_contribution = 15 + min(result.hybrid_analysis.av_detect * 5, 30)
            risk_score += av_contribution
            risk_factors.append(f"{result.hybrid_analysis.av_detect} AV detections")
            if verdict != "malicious":
                verdict = "suspicious"
    
    # Handle VT not found
    if result.virustotal and result.virustotal.error and "404" in result.virustotal.error:
        if result.hybrid_analysis and result.hybrid_analysis.verdict and result.hybrid_analysis.verdict != "not found":
            risk_factors.append("Not found in VirusTotal")
        else:
            verdict = "not_found"
    
    # If no risk factors and nothing detected
    if not risk_factors:
        if verdict == "unknown":
            verdict = "clean"
        risk_factors.append("No threats detected")
    
    # Cap at 100
    risk_score = min(100, risk_score)
    
    # Determine final verdict based on score if still ambiguous
    if verdict == "unknown":
        if risk_score >= 70:
            verdict = "malicious"
        elif risk_score >= 40:
            verdict = "suspicious"
        else:
            verdict = "clean"
    
    result.overall_verdict = verdict
    result.risk_score = risk_score
    result.risk_factors = risk_factors


@router.post(
    "/file",
    response_model=FileAnalysisResult,
    summary="Analyze a file by uploading it or providing its hash.",
    dependencies=[Depends(optional_api_key), Depends(get_analysis_context('file'))],
)
@limiter.limit("10/minute")
async def analyze_file(
    request: Request,
    file: UploadFile = File(None),
    sha256: str = Query(None, description="SHA256 hash to look up"),
    md5: str = Query(None, description="MD5 hash to look up"),
    ctx: AnalysisContext = Depends(get_analysis_context('file')),
    service: ThreatIntelService = Depends(get_threat_intel_service),
):
    """
    Analyze a file using VirusTotal and Hybrid Analysis.
    You can either upload a file or provide a hash for lookup.
    """
    result = FileAnalysisResult()
    file_info = FileInfo()
    
    file_hash = None
    
    # If file is uploaded, calculate hashes
    if file and file.filename:
        try:
            content = await file.read()
            file_info.filename = file.filename
            file_info.size = len(content)
            file_info.content_type = file.content_type
            
            file_info.sha256 = hashlib.sha256(content).hexdigest()
            file_info.md5 = hashlib.md5(content).hexdigest()
            file_info.sha1 = hashlib.sha1(content).hexdigest()
            file_hash = file_info.sha256
            result.file_info = file_info
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error reading file: {str(e)}")
    elif sha256:
        file_hash = sha256.lower()
        file_info.sha256 = file_hash
        result.file_info = file_info
    elif md5:
        file_hash = md5.lower()
        file_info.md5 = file_hash
        result.file_info = file_info
    else:
        raise HTTPException(status_code=400, detail="Please provide a file or hash (sha256/md5)")
    
    # VirusTotal lookup
    try:
        vt_results = service._lookup_virustotal_files([file_hash])
        if vt_results and len(vt_results) > 0:
            vt_data = vt_results[0]
            vt_result = VirusTotalFileResult()
            
            if vt_data.error:
                vt_result.error = vt_data.error
            elif vt_data.data:
                attrs = vt_data.data.get("attributes", {})
                vt_result.sha256 = attrs.get("sha256")
                vt_result.md5 = attrs.get("md5")
                vt_result.sha1 = attrs.get("sha1")
                vt_result.meaningful_name = attrs.get("meaningful_name")
                vt_result.type_description = attrs.get("type_description")
                vt_result.type_tag = attrs.get("type_tag")
                vt_result.size = attrs.get("size")
                vt_result.times_submitted = attrs.get("times_submitted")
                vt_result.last_analysis_date = attrs.get("last_analysis_date")
                vt_result.first_submission_date = attrs.get("first_submission_date")
                vt_result.reputation = attrs.get("reputation")
                vt_result.tags = attrs.get("tags")
                vt_result.names = attrs.get("names")
                vt_result.signature_info = attrs.get("signature_info")
                vt_result.sandbox_verdicts = attrs.get("sandbox_verdicts")
                vt_result.stats = attrs.get("last_analysis_stats", {})
                vt_result.raw_data = vt_data.data
                
                # Update file_info with VT data if we only had hash
                if not result.file_info.sha256 and vt_result.sha256:
                    result.file_info.sha256 = vt_result.sha256
                if not result.file_info.md5 and vt_result.md5:
                    result.file_info.md5 = vt_result.md5
                if not result.file_info.sha1 and vt_result.sha1:
                    result.file_info.sha1 = vt_result.sha1
                if not result.file_info.size and vt_result.size:
                    result.file_info.size = vt_result.size
            
            result.virustotal = vt_result
    except Exception as e:
        result.virustotal = VirusTotalFileResult(error=f"VirusTotal lookup failed: {str(e)}")
    
    # Hybrid Analysis lookup
    ha_hash = None
    hash_type = "sha256"
    
    if result.file_info and result.file_info.sha256:
        ha_hash = result.file_info.sha256
    elif result.virustotal and result.virustotal.sha256:
        ha_hash = result.virustotal.sha256
        if result.file_info:
            result.file_info.sha256 = ha_hash
    elif result.file_info and result.file_info.md5:
        ha_hash = result.file_info.md5
        hash_type = "md5"
    
    if ha_hash:
        try:
            ha_results = service._lookup_hybrid_analysis_by_hash([ha_hash], hash_type=hash_type)
            if ha_results and len(ha_results) > 0:
                result.hybrid_analysis = ha_results[0]
                if result.hybrid_analysis.sha256 and result.file_info and not result.file_info.sha256:
                    if len(result.hybrid_analysis.sha256) == 64:
                        result.file_info.sha256 = result.hybrid_analysis.sha256
        except Exception as e:
            from app.schemas.threat_intel import HybridAnalysisLookup
            result.hybrid_analysis = HybridAnalysisLookup(
                sha256=ha_hash,
                error=f"Hybrid Analysis lookup failed: {str(e)}"
            )
    
    _calculate_file_verdict(result)
    
    # Increment analysis count after successful analysis
    ctx.increment_usage()
    
    return result

