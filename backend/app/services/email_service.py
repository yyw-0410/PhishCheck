"""Email service for sending verification emails using Resend API."""

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

from app.core import get_settings

logger = logging.getLogger(__name__)

# Verification token expires in 1 hour
VERIFICATION_TOKEN_EXPIRY_HOURS = 1


class EmailService:
    """Service for sending emails via Resend API."""
    
    def __init__(self):
        self._settings = get_settings()
        self._api_key = self._settings.resend_api_key
        self._base_url = "https://api.resend.com"
    
    @property
    def is_configured(self) -> bool:
        """Check if email service is properly configured."""
        return bool(self._api_key)
    
    @staticmethod
    def generate_verification_token() -> str:
        """Generate a secure verification token."""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def get_token_expiry() -> datetime:
        """Get expiry datetime for a new token."""
        return datetime.now(timezone.utc) + timedelta(hours=VERIFICATION_TOKEN_EXPIRY_HOURS)
    
    def send_verification_email(
        self, 
        to_email: str, 
        name: str, 
        token: str
    ) -> bool:
        """Send verification email to user.
        
        Returns True if email was sent successfully, False otherwise.
        """
        if not self.is_configured:
            logger.warning("Email service not configured - RESEND_API_KEY not set")
            return False
        
        settings = get_settings()
        # URL must go to backend API - it will redirect to frontend after verification
        backend_url = "http://localhost:8000" if settings.environment == "development" else settings.frontend_url.replace(":5173", ":8000")
        verification_url = f"{backend_url}/api/auth/verify-email?token={token}"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 40px 20px; }}
                .button {{ 
                    display: inline-block; 
                    background: #3b82f6; 
                    color: white !important; 
                    padding: 12px 24px; 
                    text-decoration: none; 
                    border-radius: 6px; 
                    font-weight: 500;
                }}
                .footer {{ margin-top: 40px; color: #6b7280; font-size: 14px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Verify your email</h1>
                <p>Hi {name},</p>
                <p>Thanks for signing up for PhishCheck! Please verify your email address by clicking the button below:</p>
                <p style="margin: 30px 0;">
                    <a href="{verification_url}" class="button">Verify Email Address</a>
                </p>
                <p>Or copy and paste this link into your browser:</p>
                <p style="word-break: break-all; color: #6b7280;">{verification_url}</p>
                <p>This link will expire in 1 hour.</p>
                <div class="footer">
                    <p>If you didn't create an account with PhishCheck, you can safely ignore this email.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        try:
            with httpx.Client() as client:
                response = client.post(
                    f"{self._base_url}/emails",
                    headers={
                        "Authorization": f"Bearer {self._api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "from": "PhishCheck <onboarding@resend.dev>",
                        "to": [to_email],
                        "subject": "Verify your PhishCheck account",
                        "html": html_content
                    },
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    logger.info(f"Verification email sent to {to_email}")
                    return True
                else:
                    logger.error(f"Failed to send email: {response.status_code} - {response.text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error sending verification email: {e}")
            return False
    
    def send_password_reset_email(
        self,
        to_email: str,
        name: str,
        token: str
    ) -> bool:
        """Send password reset email.
        
        Not yet implemented - raises NotImplementedError.
        """
        raise NotImplementedError("Password reset email feature is not yet implemented")
