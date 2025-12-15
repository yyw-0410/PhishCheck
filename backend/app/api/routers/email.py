"""Email analysis endpoint."""

from enum import Enum

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from fastapi.concurrency import run_in_threadpool

from app.core.rate_limit import limiter
from app.core.constants import MAX_EMAIL_SIZE_BYTES, MAX_URLSCAN_SUBMISSIONS
from app.schemas import CombinedAnalysisResult
from app.services import AnalysisPipeline
from .dependencies import AnalysisContext, get_analysis_context, optional_api_key

router = APIRouter()


class URLScanVisibility(str, Enum):
    """Allowed visibility modes for URLscan.io submissions."""
    PUBLIC = "public"
    UNLISTED = "unlisted"
    PRIVATE = "private"


@router.post(
    "/email",
    response_model=CombinedAnalysisResult,
    summary="Analyze an uploaded email using Sublime and threat intelligence providers.",
    dependencies=[Depends(optional_api_key)],
)
@limiter.limit("5/minute")
async def analyze_email(
    request: Request,
    file: UploadFile = File(..., description="Raw email artifact (.eml)."),
    run_all_detection_rules: bool = Query(
        default=True,
        description="Ask Sublime to execute every available detection rule.",
    ),
    run_all_insights: bool = Query(
        default=True,
        description="Ask Sublime to evaluate every available insight.",
    ),
    include_workflow_rules: bool = Query(
        default=False,
        description="Include workflow/playbook helper rules (severity-less) in the rule hits list.",
    ),
    request_attack_score: bool = Query(
        default=True,
        description="Request Sublime's attack score in addition to rule/insight results.",
    ),
    perform_threat_enrichment: bool = Query(
        default=True,
        description="Perform VirusTotal/urlscan.io enrichment for discovered indicators.",
    ),
    max_urlscan_submissions: int = Query(
        default=10,
        ge=0,
        le=MAX_URLSCAN_SUBMISSIONS,
        description=f"Maximum number of URLs to submit to urlscan.io for scanning (max {MAX_URLSCAN_SUBMISSIONS} to protect quota).",
    ),
    urlscan_visibility: URLScanVisibility = Query(
        default=URLScanVisibility.UNLISTED,
        description="Visibility mode for urlscan.io submissions. Unlisted recommended for higher quota.",
    ),
    ctx: AnalysisContext = Depends(get_analysis_context('eml')),
):
    """Analyze an uploaded email file (.eml)."""
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    
    if file.filename and not file.filename.lower().endswith('.eml'):
        raise HTTPException(status_code=400, detail="Only .eml files allowed.")
    
    if len(raw) > MAX_EMAIL_SIZE_BYTES:
        max_mb = MAX_EMAIL_SIZE_BYTES // (1024 * 1024)
        raise HTTPException(
            status_code=413, 
            detail=f"File too large. Maximum {max_mb}MB."
        )

    pipeline = AnalysisPipeline()
    result = await run_in_threadpool(
        pipeline.run,
        raw,
        run_all_detection_rules=run_all_detection_rules,
        run_all_insights=run_all_insights,
        include_workflow_rules=include_workflow_rules,
        request_attack_score=request_attack_score,
        perform_threat_enrichment=perform_threat_enrichment,
        max_urlscan_submissions=max_urlscan_submissions,
        urlscan_visibility=urlscan_visibility,
    )
    
    # Increment analysis count after successful analysis
    ctx.increment_usage()
    
    return result
