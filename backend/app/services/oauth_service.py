"""OAuth 2.0 service for Microsoft and Google authentication."""

import secrets
import urllib.parse
from typing import Dict, Optional

import httpx

from app.core import get_settings


class OAuthService:
    """Handles OAuth 2.0 flows for Microsoft and Google."""

    def __init__(self):
        self.settings = get_settings()

    # Microsoft OAuth
    def get_microsoft_auth_url(self, state: str) -> str:
        """Generate Microsoft OAuth authorization URL."""
        params = {
            "client_id": self.settings.ms_client_id,
            "response_type": "code",
            "redirect_uri": self.settings.ms_redirect_uri,
            "response_mode": "query",
            "scope": "openid profile email offline_access User.Read Mail.Read",
            "state": state,
        }
        base_url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
        return f"{base_url}?{urllib.parse.urlencode(params)}"

    async def exchange_microsoft_code(self, code: str) -> Dict[str, any]:
        """Exchange authorization code for Microsoft access token."""
        token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        
        data = {
            "client_id": self.settings.ms_client_id,
            "client_secret": self.settings.ms_client_secret,
            "code": code,
            "redirect_uri": self.settings.ms_redirect_uri,
            "grant_type": "authorization_code",
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, data=data)
            response.raise_for_status()
            return response.json()

    async def refresh_microsoft_token(self, refresh_token: str) -> Dict[str, any]:
        """Refresh Microsoft access token."""
        token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        
        data = {
            "client_id": self.settings.ms_client_id,
            "client_secret": self.settings.ms_client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, data=data)
            response.raise_for_status()
            return response.json()

    async def get_microsoft_user_info(self, access_token: str) -> Dict[str, any]:
        """Get Microsoft user profile information."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://graph.microsoft.com/v1.0/me",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            response.raise_for_status()
            return response.json()

    # Google OAuth
    def get_google_auth_url(self, state: str) -> str:
        """Generate Google OAuth authorization URL."""
        params = {
            "client_id": self.settings.google_client_id,
            "response_type": "code",
            "redirect_uri": self.settings.google_redirect_uri,
            "scope": "openid profile email https://www.googleapis.com/auth/gmail.readonly",
            "state": state,
            "access_type": "offline",
            "prompt": "consent",
        }
        base_url = "https://accounts.google.com/o/oauth2/v2/auth"
        return f"{base_url}?{urllib.parse.urlencode(params)}"

    async def exchange_google_code(self, code: str) -> Dict[str, any]:
        """Exchange authorization code for Google access token."""
        token_url = "https://oauth2.googleapis.com/token"
        
        data = {
            "client_id": self.settings.google_client_id,
            "client_secret": self.settings.google_client_secret,
            "code": code,
            "redirect_uri": self.settings.google_redirect_uri,
            "grant_type": "authorization_code",
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, data=data)
            response.raise_for_status()
            return response.json()

    async def refresh_google_token(self, refresh_token: str) -> Dict[str, any]:
        """Refresh Google access token."""
        token_url = "https://oauth2.googleapis.com/token"
        
        data = {
            "client_id": self.settings.google_client_id,
            "client_secret": self.settings.google_client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, data=data)
            response.raise_for_status()
            return response.json()

    async def get_google_user_info(self, access_token: str) -> Dict[str, any]:
        """Get Google user profile information."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            response.raise_for_status()
            return response.json()

    @staticmethod
    def generate_state() -> str:
        """Generate a random state parameter for OAuth security."""
        return secrets.token_urlsafe(32)
