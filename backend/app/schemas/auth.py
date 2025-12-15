"""Authentication schemas for request/response validation."""

import re
from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


# ============== Request Schemas ==============

class UserRegister(BaseModel):
    """Schema for user registration."""
    email: EmailStr
    password: str = Field(..., min_length=8, description="Password must be at least 8 characters")
    name: str = Field(..., min_length=1, max_length=255)
    
    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Validate password has uppercase, lowercase, and digit."""
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        return v


class UserLogin(BaseModel):
    """Schema for user login."""
    email: EmailStr
    password: str


class OAuthUserCreate(BaseModel):
    """Schema for creating/updating OAuth user."""
    email: EmailStr
    name: str
    avatar: str | None = None
    oauth_provider: str  # 'google' or 'microsoft'
    oauth_id: str
    access_token: str
    refresh_token: str | None = None


# ============== Response Schemas ==============

class UserResponse(BaseModel):
    """Schema for user response (excludes sensitive data)."""
    id: int
    email: str
    name: str
    avatar: str | None
    oauth_provider: str | None
    oauth_email: str | None  # The connected email (may differ from login email)
    is_active: bool
    is_verified: bool
    created_at: datetime
    last_login: datetime | None

    model_config = ConfigDict(from_attributes=True)


class AuthResponse(BaseModel):
    """Schema for authentication response."""
    user: UserResponse
    session_token: str
    expires_at: datetime
    message: str = "Authentication successful"


class TokenValidation(BaseModel):
    """Schema for token validation response."""
    valid: bool
    user: UserResponse | None = None
    message: str


# ============== Error Schemas ==============

class AuthError(BaseModel):
    """Schema for authentication errors."""
    detail: str
    error_code: str | None = None
