"""Reusable FastAPI dependencies."""

import secrets
from dataclasses import dataclass
from typing import Literal, Optional

from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session as DBSession

from app.core import Settings, get_settings
from app.core.database import get_db
from app.models.user import User


# Type alias for analysis types
AnalysisType = Literal['eml', 'link', 'file', 'ai']


@dataclass
class AnalysisContext:
    """Context for analysis requests with auth and rate limit info.
    
    Provides a unified object containing:
    - user: The authenticated user (if logged in)
    - is_guest: Whether this is a guest (unauthenticated) request
    - client_ip: Client IP for guest rate limiting
    - auth_service: AuthService instance for rate limit operations
    - analysis_type: The type of analysis being performed
    
    Usage:
        ctx = Depends(get_analysis_context('eml'))
        # ctx.user is the user or None
        # After analysis: ctx.increment_usage()
    """
    user: Optional[User]
    is_guest: bool
    client_ip: str
    auth_service: "AuthService"  # Forward reference
    analysis_type: AnalysisType
    
    def increment_usage(self) -> None:
        """Increment usage count after successful analysis.
        
        Call this after the analysis completes successfully.
        Only increments for unverified users and guests.
        """
        if self.user and not self.user.is_verified:
            self.auth_service.increment_analysis_count(self.user, self.analysis_type)
        elif self.is_guest:
            self.auth_service.increment_guest_count(self.client_ip, self.analysis_type)


def _get_client_ip(request: Request) -> str:
    """Get the real client IP address, handling proxies and load balancers.
    
    Checks headers in order of priority:
    1. CF-Connecting-IP (Cloudflare)
    2. X-Real-IP (nginx)
    3. X-Forwarded-For (standard proxy header, first IP)
    4. request.client.host (direct connection)
    """
    # Cloudflare
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip.strip()
    
    # Nginx proxy
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    # Standard proxy header (first IP is the original client)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    
    # Direct connection
    if request.client and request.client.host:
        return request.client.host
    
    return "unknown"


def _extract_token(
    authorization: Optional[str],
    session_token: Optional[str],
) -> Optional[str]:
    """Extract session token from cookie or Authorization header.
    
    Priority: Cookie > Authorization header (more secure)
    """
    if session_token:
        return session_token
    if authorization and authorization.startswith("Bearer "):
        return authorization.replace("Bearer ", "")
    return None


def get_analysis_context(analysis_type: AnalysisType):
    """Factory function to create an analysis context dependency.
    
    This creates a FastAPI dependency that:
    1. Extracts the session token from cookie or header
    2. Validates the session and gets the user (if logged in)
    3. Checks rate limits for the user or guest
    4. Returns an AnalysisContext object for use in the endpoint
    
    Args:
        analysis_type: The type of analysis ('eml', 'link', 'file', 'ai')
        
    Returns:
        A FastAPI dependency function
        
    Example:
        @router.post("/email")
        async def analyze_email(
            ctx: AnalysisContext = Depends(get_analysis_context('eml')),
        ):
            # Do analysis...
            ctx.increment_usage()
            return result
    """
    async def _get_context(
        request: Request,
        authorization: Optional[str] = Header(default=None),
        session_token: Optional[str] = Cookie(default=None),
        db: DBSession = Depends(get_db),
    ) -> AnalysisContext:
        from app.services.auth_service import AuthService
        
        client_ip = _get_client_ip(request)
        token = _extract_token(authorization, session_token)
        auth_service = AuthService(db)
        
        user = None
        is_guest = True
        
        if token:
            user = auth_service.validate_session(token)
            if user:
                is_guest = False
                can_analyze, remaining = auth_service.check_analysis_limit(user, analysis_type)
                if not can_analyze:
                    raise HTTPException(
                        status_code=403,
                        detail="Daily analysis limit reached. Please verify your email for unlimited access."
                    )
        
        # Check guest limit if not logged in (only for non-AI types)
        if is_guest:
            if analysis_type == 'ai':
                # AI chat requires login
                raise HTTPException(
                    status_code=401,
                    detail="Please log in to use the AI assistant."
                )
            can_analyze, remaining = auth_service.check_guest_limit(client_ip, analysis_type)
            if not can_analyze:
                raise HTTPException(
                    status_code=403,
                    detail="Daily guest limit reached. Please sign up for more analyses."
                )
        
        return AnalysisContext(
            user=user,
            is_guest=is_guest,
            client_ip=client_ip,
            auth_service=auth_service,
            analysis_type=analysis_type,
        )
    
    return _get_context


def get_optional_analysis_context(analysis_type: AnalysisType):
    """Factory for optional analysis context - doesn't enforce limits or require auth.
    
    Use this for endpoints that want to track usage but don't require
    authentication or strict rate limiting.
    """
    async def _get_context(
        request: Request,
        authorization: Optional[str] = Header(default=None),
        session_token: Optional[str] = Cookie(default=None),
        db: DBSession = Depends(get_db),
    ) -> AnalysisContext:
        from app.services.auth_service import AuthService
        
        client_ip = _get_client_ip(request)
        token = _extract_token(authorization, session_token)
        auth_service = AuthService(db)
        
        user = None
        is_guest = True
        
        if token:
            user = auth_service.validate_session(token)
            if user:
                is_guest = False
        
        return AnalysisContext(
            user=user,
            is_guest=is_guest,
            client_ip=client_ip,
            auth_service=auth_service,
            analysis_type=analysis_type,
        )
    
    return _get_context


def require_api_key(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    settings: Settings = Depends(get_settings),
) -> None:
    """Validate that the caller supplied the expected API key."""
    # Use constant-time comparison to prevent timing attacks
    if not x_api_key or not secrets.compare_digest(x_api_key, settings.secret_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )


def optional_api_key(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    settings: Settings = Depends(get_settings),
) -> None:
    """Validate API key only if REQUIRE_API_KEY is enabled in settings.
    
    This allows endpoints to be optionally protected based on environment config.
    - Development: No API key required (REQUIRE_API_KEY=false or unset)
    - Production/Demo: API key required (REQUIRE_API_KEY=true)
    """
    if settings.require_api_key:
        # Use constant-time comparison to prevent timing attacks
        if not x_api_key or not secrets.compare_digest(x_api_key, settings.secret_key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API key. Set X-API-Key header with your SECRET_KEY.",
            )


def get_current_user(
    authorization: Optional[str] = Header(default=None),
    session_token: Optional[str] = Cookie(default=None),
    db: DBSession = Depends(get_db),
) -> User:
    """Validate session token and return the authenticated user.
    
    Supports BOTH:
    - httpOnly cookie (session_token) - more secure
    - Authorization: Bearer header - backward compatible
    
    Cookie takes priority if both are present.
    """
    token = None
    
    # Priority 1: Check httpOnly cookie
    if session_token:
        token = session_token
    # Priority 2: Check Authorization header
    elif authorization and authorization.startswith("Bearer "):
        token = authorization.replace("Bearer ", "")
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    from app.services.auth_service import AuthService
    auth_service = AuthService(db)
    
    user = auth_service.validate_session(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user


def get_optional_user(
    authorization: Optional[str] = Header(default=None),
    session_token: Optional[str] = Cookie(default=None),
    db: DBSession = Depends(get_db),
) -> Optional[User]:
    """Optionally get the authenticated user if a valid token is provided.
    
    Returns None if no token or invalid token - does not raise an error.
    Supports both httpOnly cookie and Authorization header.
    """
    token = None
    
    if session_token:
        token = session_token
    elif authorization and authorization.startswith("Bearer "):
        token = authorization.replace("Bearer ", "")
    
    if not token:
        return None
    
    from app.services.auth_service import AuthService
    auth_service = AuthService(db)
    
    return auth_service.validate_session(token)


# ============== Service Dependencies ==============

def get_threat_intel_service():
    """Get a ThreatIntelService instance.
    
    Creates a fresh instance per request. This is preferred over a global
    singleton because:
    - httpx.Client should not be shared across threads
    - Each request gets a clean state
    - Memory is freed after request completes
    
    Usage:
        @router.post("/link")
        async def analyze_link(
            service: ThreatIntelService = Depends(get_threat_intel_service),
        ):
            result = service._lookup_virustotal_url(url)
    """
    from app.services import ThreatIntelService
    return ThreatIntelService()
