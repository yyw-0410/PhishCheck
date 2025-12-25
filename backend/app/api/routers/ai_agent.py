"""AI Agent endpoints - chat, recommendations, and suggestions."""

import json
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.rate_limit import limiter
from app.schemas.chat import (
    ChatRequest, 
    ChatResponse, 
    SuggestedQuestionsResponse, 
    AnalysisRecommendationRequest, 
    AnalysisRecommendationResponse
)
from app.services.rag_service import get_rag_service
from .dependencies import AnalysisContext, get_analysis_context, optional_api_key

router = APIRouter()

# Reusable HTTP client for recommendation endpoint (faster than creating new client each time)
_recommendation_client: httpx.AsyncClient | None = None


async def _get_recommendation_client() -> httpx.AsyncClient:
    """Get or create a reusable HTTP client for recommendations."""
    global _recommendation_client
    if _recommendation_client is None or _recommendation_client.is_closed:
        _recommendation_client = httpx.AsyncClient(timeout=15.0)  # Increased for reliable AI calls
    return _recommendation_client


@router.post(
    "",
    response_model=ChatResponse,
    summary="Ask a question about email analysis.",
    dependencies=[Depends(optional_api_key), Depends(get_analysis_context('ai'))],
)
@limiter.limit("30/minute")
async def chat(
    request: Request,
    chat_request: ChatRequest,
    ctx: AnalysisContext = Depends(get_analysis_context('ai')),
):
    """
    Ask the PhishCheck AI assistant about the current email analysis.
    The assistant uses Gemini with internet search capabilities.
    Requires login (guests cannot use AI chat).
    """
    from app.core.config import get_settings
    settings = get_settings()
    
    if not settings.ai_enabled:
        raise HTTPException(
            status_code=503,
            detail="AI features are disabled. Set AI_ENABLED=true to enable."
        )
    
    rag_service = get_rag_service()
    
    try:
        conv_history = None
        if chat_request.conversation_history:
            conv_history = [{"role": m.role, "content": m.content} for m in chat_request.conversation_history]
        
        result = await rag_service.ask(chat_request.query, chat_request.analysis_context, conv_history)
        
        # Increment AI message count for unverified users after successful response
        ctx.increment_usage()
        
        return ChatResponse(
            answer=result.answer,
            sources=[{"title": s["title"], "id": s["id"]} for s in result.sources],
            model_used=result.model_used,
            query=result.query
        )
    except Exception as e:
        import traceback
        print(f"[CHAT ERROR] {type(e).__name__}: {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error processing question: {str(e)}")



@router.get(
    "/suggestions",
    response_model=SuggestedQuestionsResponse,
    summary="Get general suggested questions for the chatbot.",
)
def get_suggested_questions():
    """Returns a list of general suggested questions for the AI assistant."""
    rag_service = get_rag_service()
    return SuggestedQuestionsResponse(
        questions=rag_service.get_suggested_questions()
    )


@router.get(
    "/analysis-questions",
    response_model=SuggestedQuestionsResponse,
    summary="Get analysis-specific suggested questions for the chatbot.",
)
def get_analysis_questions():
    """Returns suggested questions specific to email analysis."""
    rag_service = get_rag_service()
    return SuggestedQuestionsResponse(
        questions=rag_service.get_analysis_questions()
    )


@router.post(
    "/recommendation",
    response_model=AnalysisRecommendationResponse,
    summary="Get AI recommendation based on email analysis results.",
    dependencies=[Depends(optional_api_key)],
)
async def get_analysis_recommendation(request: AnalysisRecommendationRequest):
    """
    Generate AI-powered recommendation based on email analysis results.
    Uses Gemini AI for contextual, actionable recommendations.
    Falls back to rule-based system if AI is unavailable or disabled.
    """
    from app.core.config import get_settings
    
    settings = get_settings()
    score = request.attack_score or 0
    vt_mal = request.vt_malicious or 0
    vt_sus = request.vt_suspicious or 0
    rules = request.rule_count or 0
    verdict = (request.verdict or "").lower()
    
    # Determine risk level
    if score >= 70 or (score >= 50 and vt_mal >= 2):
        risk_level = "critical"
    elif score >= 40 or vt_mal >= 2:
        risk_level = "high"
    elif score >= 20 or vt_mal >= 1 or rules >= 2:
        risk_level = "medium"
    else:
        risk_level = "low"
    
    # Try AI-powered recommendation with key rotation on 429
    api_keys = [
        settings.ai_api_key,
        getattr(settings, 'ai_api_key_2', None),
    ]
    api_keys = [k for k in api_keys if k and k != "YOUR_AI_API_KEY"]
    
    if settings.ai_enabled and api_keys:
        import logging
        logger = logging.getLogger(__name__)
        
        subject_hint = ""
        if request.subject:
            subj_lower = request.subject.lower()
            if any(w in subj_lower for w in ['invoice', 'payment', 'urgent', 'action required', 'verify', 'confirm']):
                subject_hint = "[financial/urgent themed]"
            elif any(w in subj_lower for w in ['password', 'account', 'security', 'suspended', 'locked']):
                subject_hint = "[account security themed]"
            elif any(w in subj_lower for w in ['delivery', 'package', 'shipping', 'order']):
                subject_hint = "[delivery/order themed]"
            else:
                subject_hint = "[general]"
        
        context = f"""
Email Analysis Summary:
- Attack Score: {score}/100 (Primary threat indicator from ML analysis)
- Risk Level: {risk_level.upper()}
- Verdict: {verdict or 'unknown'}
- Sender Domain Type: {request.sender_domain.split('.')[-1] if request.sender_domain and '.' in request.sender_domain else 'unknown'} TLD
- Subject Theme: {subject_hint}
- Detection Rules Matched: {rules}
- Insights Triggered: {request.insight_count or 0}
- VirusTotal: {vt_mal} malicious, {vt_sus} suspicious detections
- Has Attachments: {request.has_attachments or False}
- Attachment Types: {', '.join(request.attachment_types) if request.attachment_types else 'None'}
"""
        
        prompt = f"""You are a cybersecurity expert analyzing email threats. Based on the following analysis results, provide a brief, actionable recommendation.

{context}

Provide your response in this exact JSON format:
{{
    "recommendation": "A 1-2 sentence summary of the threat assessment and what the user should do",
    "actions": ["action 1", "action 2", "action 3"]
}}

Rules:
- Be concise and direct
- Focus on actionable advice
- If attack score < 20 and no VT detections, it's likely safe
- If attack score > 50 or multiple VT detections, it's dangerous
- Consider the sender domain and subject for context
- Provide 2-4 specific actions
- Don't be overly alarming for low-risk emails"""

        client = await _get_recommendation_client()
        
        # Try each API key until one works
        for key_index, api_key in enumerate(api_keys):
            try:
                key_label = f"key_{key_index + 1}"
                logger.info(f"AI Recommendation: Trying {key_label} for score={score}, verdict={verdict}")
                
                response = await client.post(
                    f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent?key={api_key}",
                    json={
                        "contents": [{"parts": [{"text": prompt}]}],
                        "generationConfig": {
                            "temperature": 0.3,
                            "maxOutputTokens": 512,
                        }
                    },
                    headers={"Content-Type": "application/json"},
                    timeout=15.0
                )
                
                logger.info(f"AI Recommendation: {key_label} returned status {response.status_code}")
                
                if response.status_code == 200:
                    data = response.json()
                    text = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                    
                    text = text.strip()
                    if text.startswith("```json"):
                        text = text[7:]
                    if text.startswith("```"):
                        text = text[3:]
                    if text.endswith("```"):
                        text = text[:-3]
                    text = text.strip()
                    
                    try:
                        ai_response = json.loads(text)
                        logger.info(f"AI Recommendation: Successfully parsed response from {key_label}")
                        return AnalysisRecommendationResponse(
                            recommendation=ai_response.get("recommendation", "Analysis complete."),
                            risk_level=risk_level,
                            actions=ai_response.get("actions", [])
                        )
                    except json.JSONDecodeError as e:
                        logger.warning(f"AI Recommendation: JSON parse error from {key_label}: {e}")
                        break  # Don't retry on JSON error, fall through to rule-based
                        
                elif response.status_code == 429:
                    logger.warning(f"AI Recommendation: {key_label} rate limited (429), trying next key...")
                    continue  # Try next API key
                    
                else:
                    logger.warning(f"AI Recommendation: {key_label} returned {response.status_code}")
                    continue  # Try next API key on other errors
                    
            except Exception as e:
                logger.warning(f"AI Recommendation: {key_label} exception: {type(e).__name__}: {e}")
                continue  # Try next API key on exception
        
        logger.warning("AI Recommendation: All API keys exhausted, falling back to rule-based")
    
    # Fallback: Rule-based recommendation
    # IMPORTANT: VirusTotal malicious detections should ALWAYS raise the risk level
    # A low attack score with VT malicious detections means the email contains/links to malware
    
    # Override risk level if VT detected malicious content
    if vt_mal >= 2:
        risk_level = "high" if risk_level in ["low", "medium"] else risk_level
    elif vt_mal >= 1:
        risk_level = "medium" if risk_level == "low" else risk_level
    
    # Generate recommendation based on actual threat indicators
    if vt_mal >= 2:
        # Multiple malicious detections = definitely dangerous
        rec = f"Malicious content detected! VirusTotal flagged {vt_mal} indicators. Do not interact with links or attachments."
        actions = [
            "Do NOT click any links in this email",
            "Do NOT open any attachments",
            "Report to IT/security team",
            "The email may be forwarding/referencing malicious content"
        ]
        risk_level = "high"
    elif vt_mal >= 1:
        # At least one malicious detection
        rec = f"Warning: VirusTotal detected malicious content. Exercise extreme caution."
        actions = [
            "Avoid clicking links in this email",
            "Do NOT open attachments without verification",
            "Verify sender through another channel",
            "The email may contain or reference malicious content"
        ]
        risk_level = "medium" if risk_level == "low" else risk_level
    elif risk_level == "critical":
        rec = f"High risk! Attack score {score}/100. Do not interact with this email."
        actions = [
            "Do NOT click any links",
            "Do NOT open attachments",
            "Report to IT/security team",
            "Delete this email"
        ]
    elif risk_level == "high":
        rec = f"Suspicious email with score {score}/100. Verify sender before any action."
        actions = [
            "Avoid clicking links",
            "Do NOT open attachments",
            "Verify sender identity through another channel"
        ]
    elif risk_level == "medium":
        rec = f"Some concerns found (score {score}/100). Exercise caution."
        actions = [
            "Verify sender before responding",
            "Be cautious with links/attachments",
            "Check for red flags like urgency or threats"
        ]
    elif score < 20 and verdict in ["likely_benign", "benign", "safe", ""]:
        if rules > 0:
            rec = f"Email appears safe (score {score}/100). Some detection rules triggered but no significant threats found."
            actions = [
                "Email is likely a legitimate notification",
                "Review any flagged content before clicking",
                "Safe to read but stay cautious with links"
            ]
        else:
            rec = f"Email appears safe. Attack score {score}/100 with no threats detected."
            actions = [
                "Email appears safe to open",
                "Stay alert for unusual requests"
            ]
    else:
        rec = f"Email appears safe. Attack score {score}/100."
        actions = [
            "Email appears safe",
            "Stay alert for unusual requests"
        ]
    
    return AnalysisRecommendationResponse(
        recommendation=rec,
        risk_level=risk_level,
        actions=actions
    )
