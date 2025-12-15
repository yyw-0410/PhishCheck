"""Application factory for the FastAPI backend."""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

from app.api import api_router
from app.core import Settings, get_settings
from app.core.database import init_db
from app.core.rate_limit import limiter
from app.core.logging import configure_logging, set_request_id, get_request_id

logger = logging.getLogger(__name__)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Middleware to add request ID for request tracing."""
    
    async def dispatch(self, request: Request, call_next):
        # Use existing request ID from header or generate new one
        request_id = request.headers.get("X-Request-ID") or set_request_id()
        set_request_id(request_id)
        
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan context manager for startup and shutdown events."""
    # Startup
    init_db()
    logger.info("✅ Database initialized")
    yield
    # Shutdown (add cleanup code here if needed)


def _configure_middleware(app: FastAPI, settings: Settings) -> None:
    # Request ID middleware (first, so all requests get an ID)
    app.add_middleware(RequestIDMiddleware)
    
    # Security headers middleware (protects against XSS, clickjacking, etc.)
    from app.core.security_headers import SecurityHeadersMiddleware
    app.add_middleware(SecurityHeadersMiddleware)
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.add_middleware(GZipMiddleware, minimum_size=1024)

    if settings.environment == "production":
        app.add_middleware(HTTPSRedirectMiddleware)
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)



def create_application() -> FastAPI:
    settings = get_settings()
    
    # Configure structured logging
    configure_logging(
        environment=settings.environment,
        log_level="DEBUG" if settings.debug else "INFO"
    )
    
    application = FastAPI(
        title="PhishCheck API",
        description="""
## PhishCheck - Email & URL Phishing Analysis Platform

Analyze emails and URLs for phishing threats using multiple threat intelligence providers.

### Features
- **Email Analysis**: Upload .eml files for comprehensive phishing detection
- **Link Analysis**: Scan URLs with VirusTotal, URLscan.io, and Sublime ML
- **File Analysis**: Check file hashes against threat databases
- **AI Assistant**: Get AI-powered recommendations and explanations

### Authentication
- Guest access with limited daily quotas
- User accounts for higher limits
- API key authentication for programmatic access
        """,
        version="1.0.0",
        docs_url=None,  # Disabled - using Stoplight Elements instead
        redoc_url=None,  # Disabled - using Stoplight Elements instead
        openapi_url="/api/openapi.json",
        debug=settings.debug,
        lifespan=lifespan,
    )

    # Configure rate limiting
    application.state.limiter = limiter
    application.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Global exception handler for unhandled errors
    @application.exception_handler(Exception)
    async def global_exception_handler(request, exc: Exception):
        from fastapi.responses import JSONResponse
        request_id = get_request_id()
        logger.exception(f"[{request_id}] Unhandled exception on {request.method} {request.url.path}: {exc}")
        return JSONResponse(
            status_code=500,
            content={
                "detail": "An internal server error occurred. Please try again later.",
                "request_id": request_id,
            }
        )

    _configure_middleware(application, settings)
    application.include_router(api_router, prefix="/api")

    # Modern API documentation (Scalar - beautiful dark theme)
    @application.get("/api/docs", include_in_schema=False)
    async def scalar_docs():
        from fastapi.responses import HTMLResponse
        return HTMLResponse("""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PhishCheck API</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>">
</head>
<body>
    <script id="api-reference" data-url="/api/openapi.json"></script>
    <script>
        var configuration = {
            theme: 'purple',
            darkMode: true,
            layout: 'modern',
            showSidebar: true,
            searchHotKey: 'k',
            hideModels: true
        }
        document.getElementById('api-reference').dataset.configuration = JSON.stringify(configuration)
    </script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
</body>
</html>
        """)

    return application


app = create_application()
