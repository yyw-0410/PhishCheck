"""Application-wide constants and configuration values.

This module centralizes magic numbers and configuration values used throughout
the application to improve maintainability and consistency.
"""

# File size limits
MAX_EMAIL_SIZE_BYTES = 10 * 1024 * 1024  # 10MB - Maximum size for uploaded .eml files
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024   # 50MB - Maximum size for file analysis

# Analysis limits
MAX_URLSCAN_SUBMISSIONS = 50  # Maximum URLs to submit to URLscan.io per analysis
MAX_RAW_EML_SIZE_BYTES = 500_000  # Truncate raw EML content display above this size

# Session settings
SESSION_EXPIRE_HOURS = 24 * 7  # 7 days - Session token expiration time
VERIFICATION_TOKEN_EXPIRE_HOURS = 48  # 48 hours - Email verification token expiry

# Rate limit settings - Daily limits for verified users
DAILY_LIMITS = {
    'eml': 5,   # Email analysis - most resource intensive
    'link': 10,  # Link analysis
    'file': 8,   # File hash analysis
    'ai': 20,    # AI chat messages (API cost)
}

# Guest user limits (not logged in) - Lower to encourage signup
GUEST_DAILY_LIMITS = {
    'eml': 2,   # Only 2 email analyses per day
    'link': 5,  # 5 link analyses per day
    'file': 3,  # 3 file hash lookups per day
}

# API timeouts
SUBLIME_TIMEOUT_SECONDS = 30.0  # Timeout for Sublime Security API calls
API_REQUEST_TIMEOUT_SECONDS = 60.0  # General API request timeout

# Account cleanup
UNVERIFIED_ACCOUNT_CLEANUP_DAYS = 7  # Delete unverified accounts after this many days

# Email validation
EMAIL_VERIFICATION_TOKEN_LENGTH = 32  # Length of verification token in bytes
