"""Security headers middleware for enhanced web security.

This middleware adds security headers to all HTTP responses to protect against
common web vulnerabilities like XSS, clickjacking, and MIME sniffing.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses.
    
    Implements OWASP security best practices by adding headers to:
    - Prevent clickjacking (X-Frame-Options)
    - Prevent MIME sniffing (X-Content-Type-Options)
    - Enable XSS protection (X-XSS-Protection)
    - Control referrer information (Referrer-Policy)
    - Implement Content Security Policy (CSP)
    """
    
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        
        # Content Security Policy - Restrict resource loading
        # Allows scripts/styles from self and CDN (for API docs)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "connect-src 'self';"
        )
        
        # Prevent clickjacking attacks - Don't allow page to be framed
        response.headers["X-Frame-Options"] = "DENY"
        
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Enable browser XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Control referrer information sent to other sites
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Indicate that site should only be accessed over HTTPS (production)
        # Note: Only enable in production with proper HTTPS setup
        # response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        return response
