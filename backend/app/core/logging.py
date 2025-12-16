"""Structured logging configuration for the application.

Provides JSON-formatted logs in production and human-readable logs in development.
Also adds request ID support for tracing.
"""

import logging
import json
import sys
import uuid
from datetime import datetime, timezone
from contextvars import ContextVar
from typing import Optional

# Context variable for request ID (thread-safe)
request_id_var: ContextVar[Optional[str]] = ContextVar('request_id', default=None)


def get_request_id() -> Optional[str]:
    """Get the current request ID from context."""
    return request_id_var.get()


def set_request_id(request_id: Optional[str] = None) -> str:
    """Set a request ID for the current context. Returns the ID."""
    rid = request_id or str(uuid.uuid4())[:8]
    request_id_var.set(rid)
    return rid


class JSONFormatter(logging.Formatter):
    """JSON log formatter for production environments."""
    
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Add request ID if available
        request_id = get_request_id()
        if request_id:
            log_entry["request_id"] = request_id
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields
        if hasattr(record, 'extra_fields'):
            log_entry.update(record.extra_fields)
        
        return json.dumps(log_entry)


class DevelopmentFormatter(logging.Formatter):
    """Human-readable formatter for development with colors and request ID."""
    
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, '')
        request_id = get_request_id()
        rid_str = f"[{request_id}] " if request_id else ""
        
        # Format: [LEVEL] [request_id] logger: message
        formatted = f"{color}[{record.levelname:8}]{self.RESET} {rid_str}{record.name}: {record.getMessage()}"
        
        if record.exc_info:
            formatted += "\n" + self.formatException(record.exc_info)
        
        return formatted


def configure_logging(environment: str = "development", log_level: str = "INFO") -> None:
    """Configure logging based on environment.
    
    Args:
        environment: 'development' or 'production'
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    
    # Remove existing handlers
    root_logger.handlers.clear()
    
    # Create handler
    handler = logging.StreamHandler(sys.stdout)
    
    # Use appropriate formatter
    if environment == "production":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(DevelopmentFormatter())
    
    root_logger.addHandler(handler)
    
    # Suppress noisy loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("python_multipart").setLevel(logging.WARNING)
    logging.getLogger("PIL").setLevel(logging.WARNING)
    logging.getLogger("pillow").setLevel(logging.WARNING)


# Convenience function for structured logging with extra fields
def log_with_context(logger: logging.Logger, level: int, message: str, **extra) -> None:
    """Log a message with extra context fields."""
    record = logger.makeRecord(
        logger.name, level, "", 0, message, (), None
    )
    record.extra_fields = extra
    logger.handle(record)
