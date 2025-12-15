"""User database models."""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.orm import relationship

from app.core.database import Base


class User(Base):
    """User model for storing user accounts."""
    
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=True)  # Null for OAuth-only users
    name = Column(String(255), nullable=False)
    avatar = Column(Text, nullable=True)
    
    # OAuth fields - for connected email account (may differ from login email)
    oauth_provider = Column(String(50), nullable=True)  # 'google', 'microsoft', or None
    oauth_id = Column(String(255), nullable=True)
    oauth_email = Column(String(255), nullable=True)  # The connected email (e.g., Outlook email)
    oauth_access_token = Column(Text, nullable=True)
    oauth_refresh_token = Column(Text, nullable=True)
    
    # Account status
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    verification_token = Column(String(255), nullable=True, index=True)
    verification_token_expires = Column(DateTime(timezone=True), nullable=True)
    
    # Analysis usage tracking (for unverified users) - separate limits per type
    daily_eml_count = Column(Integer, default=0)
    daily_link_count = Column(Integer, default=0)
    daily_file_count = Column(Integer, default=0)
    daily_ai_count = Column(Integer, default=0)
    last_analysis_date = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    last_login = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User {self.email}>"


class Session(Base):
    """Session model for storing user sessions."""
    
    __tablename__ = "sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token = Column(String(255), unique=True, index=True, nullable=False)
    
    # Session metadata
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=False)
    
    # Relationship
    user = relationship("User", back_populates="sessions")
    
    def __repr__(self):
        return f"<Session {self.token[:8]}... for user {self.user_id}>"


class OAuthState(Base):
    """OAuth state storage for CSRF protection.
    
    Replaces in-memory state storage with database-backed solution.
    States automatically expire after 10 minutes.
    """
    
    __tablename__ = "oauth_states"
    
    id = Column(Integer, primary_key=True, index=True)
    state = Column(String(255), unique=True, index=True, nullable=False)
    provider = Column(String(50), nullable=False)  # 'google' or 'microsoft'
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    
    def __repr__(self):
        return f"<OAuthState {self.state[:8]}... for {self.provider}>"
    
    @property
    def is_expired(self) -> bool:
        """Check if the state has expired."""
        now = datetime.now(timezone.utc)
        # Handle both timezone-aware and naive datetimes for backward compatibility
        if self.expires_at.tzinfo is None:
            return self.expires_at < now.replace(tzinfo=None)
        return self.expires_at < now


class GuestRateLimit(Base):
    """Track rate limits for guest users by IP address.
    
    Guests have lower limits than registered users to encourage signup.
    Resets daily at midnight UTC.
    """
    
    __tablename__ = "guest_rate_limits"
    
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), index=True, nullable=False)  # IPv4 or IPv6
    
    # Daily usage counts per feature
    daily_eml_count = Column(Integer, default=0)
    daily_link_count = Column(Integer, default=0)
    daily_file_count = Column(Integer, default=0)
    
    # Last analysis date (for daily reset) - same name as users table
    last_analysis_date = Column(DateTime(timezone=True), nullable=True)
    
    def __repr__(self):
        return f"<GuestRateLimit {self.ip_address}>"
