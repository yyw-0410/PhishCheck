"""Datetime utilities for consistent timezone handling.

These utilities ensure all datetime operations use UTC consistently,
which prevents issues with timezone-naive datetimes from the database.
"""

from datetime import datetime, timezone
from typing import Optional


def utc_now() -> datetime:
    """Get current UTC datetime (timezone-aware).
    
    Use this instead of datetime.now(timezone.utc) for consistency.
    """
    return datetime.now(timezone.utc)


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensure a datetime is timezone-aware (UTC).
    
    Handles both timezone-naive datetimes (from legacy DB records)
    and already timezone-aware datetimes.
    
    Args:
        dt: A datetime that may or may not have timezone info
        
    Returns:
        Timezone-aware datetime in UTC, or None if input is None
        
    Example:
        >>> expires_at = ensure_utc(session.expires_at)
        >>> if expires_at > utc_now():
        ...     print("Still valid")
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def is_expired(expires_at: Optional[datetime]) -> bool:
    """Check if a datetime is in the past (expired).
    
    Safely handles None and timezone-naive datetimes.
    
    Args:
        expires_at: Expiration datetime to check
        
    Returns:
        True if expired or None, False if still valid
    """
    if expires_at is None:
        return True
    expires = ensure_utc(expires_at)
    return expires < utc_now()


def today_utc() -> datetime.date:
    """Get today's date in UTC.
    
    Use this for daily reset checks.
    """
    return utc_now().date()
