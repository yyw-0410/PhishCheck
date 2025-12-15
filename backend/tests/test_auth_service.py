"""Tests for the authentication service."""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone, timedelta

from app.services.auth_service import AuthService, SESSION_EXPIRE_HOURS
from app.schemas.auth import UserRegister, OAuthUserCreate


class TestPasswordHashing:
    """Test password hashing utilities."""

    @patch('app.services.auth_service.bcrypt')
    def test_hash_password_calls_context(self, mock_bcrypt):
        """Hash password should call bcrypt.hashpw."""
        mock_bcrypt.gensalt.return_value = b"$2b$12$mocksalt"
        mock_bcrypt.hashpw.return_value = b"$2b$12$mockedhash"
        password = "SecurePassword123"
        result = AuthService.hash_password(password)
        mock_bcrypt.gensalt.assert_called_once()
        mock_bcrypt.hashpw.assert_called_once_with(password.encode('utf-8'), b"$2b$12$mocksalt")
        assert result == "$2b$12$mockedhash"

    @patch('app.services.auth_service.bcrypt')
    def test_verify_password_correct(self, mock_bcrypt):
        """Correct password should verify successfully."""
        mock_bcrypt.checkpw.return_value = True
        result = AuthService.verify_password("password", "hashed")
        mock_bcrypt.checkpw.assert_called_once_with(b"password", b"hashed")
        assert result is True

    @patch('app.services.auth_service.bcrypt')
    def test_verify_password_incorrect(self, mock_bcrypt):
        """Incorrect password should fail verification."""
        mock_bcrypt.checkpw.return_value = False
        result = AuthService.verify_password("wrong", "hashed")
        assert result is False


class TestSessionToken:
    """Test session token generation."""

    def test_generate_session_token_length(self):
        """Session token should be a reasonable length."""
        token = AuthService.generate_session_token()
        assert len(token) >= 32  # urlsafe_b64 of 32 bytes

    def test_generate_session_token_unique(self):
        """Each token should be unique."""
        tokens = [AuthService.generate_session_token() for _ in range(10)]
        assert len(set(tokens)) == 10  # All unique


class TestEmailDomainValidation:
    """Test email domain MX record validation."""

    @patch('dns.resolver.resolve')
    def test_valid_email_domain(self, mock_resolve):
        """Valid domain with MX records should pass."""
        # Mock an MX record with a valid exchange hostname
        mock_mx_record = MagicMock()
        mock_mx_record.exchange = "mail.gmail.com."
        mock_resolve.return_value = [mock_mx_record]
        assert AuthService.validate_email_domain("user@gmail.com") is True

    @patch('dns.resolver.resolve')
    def test_invalid_email_domain_nxdomain(self, mock_resolve):
        """Non-existent domain should fail."""
        import dns.resolver
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        assert AuthService.validate_email_domain("user@nonexistent-domain-xyz.com") is False

    @patch('dns.resolver.resolve')
    def test_null_mx_record(self, mock_resolve):
        """Null MX record (RFC 7505) should fail - domain explicitly doesn't accept email."""
        # Mock a null MX record like example.com has (priority 0, exchange ".")
        mock_mx_record = MagicMock()
        mock_mx_record.exchange = "."  # Null MX
        mock_resolve.return_value = [mock_mx_record]
        assert AuthService.validate_email_domain("user@example.com") is False

    def test_invalid_email_format(self):
        """Email without @ should fail gracefully."""
        assert AuthService.validate_email_domain("invalidemail") is False


class TestAuthServiceWithMockDB:
    """Test auth service with mocked database."""

    def _create_mock_db(self):
        """Create a mock database session."""
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = None
        return mock_db

    def test_get_user_by_email_not_found(self):
        """Should return None when user not found."""
        mock_db = self._create_mock_db()
        service = AuthService(mock_db)
        result = service.get_user_by_email("notfound@example.com")
        assert result is None

    def test_login_invalid_email(self):
        """Login with non-existent email should raise ValueError."""
        mock_db = self._create_mock_db()
        service = AuthService(mock_db)
        
        with pytest.raises(ValueError, match="Invalid email or password"):
            service.login("notfound@example.com", "password")

    def test_login_oauth_only_account(self):
        """Login to OAuth-only account should raise ValueError."""
        mock_db = self._create_mock_db()
        mock_user = MagicMock()
        mock_user.password_hash = None  # OAuth accounts have no password
        mock_user.oauth_provider = "google"
        mock_db.query.return_value.filter.return_value.first.return_value = mock_user
        
        service = AuthService(mock_db)
        
        with pytest.raises(ValueError, match="OAuth login"):
            service.login("oauth@example.com", "password")

    def test_create_session_sets_expiry(self):
        """Session should have correct expiry time."""
        mock_db = self._create_mock_db()
        mock_user = MagicMock()
        mock_user.id = 1
        
        service = AuthService(mock_db)
        
        before = datetime.now(timezone.utc)
        session = service.create_session(mock_user)
        after = datetime.now(timezone.utc)
        
        expected_expiry = before + timedelta(hours=SESSION_EXPIRE_HOURS)
        # Session expiry should be within expected range
        assert session.expires_at >= expected_expiry - timedelta(seconds=5)
        assert session.expires_at <= after + timedelta(hours=SESSION_EXPIRE_HOURS) + timedelta(seconds=5)


class TestOAuthUserCreate:
    """Test OAuth user creation/update."""

    def test_create_new_oauth_user(self):
        """Should create new user when OAuth account doesn't exist."""
        mock_db = MagicMock()
        # No existing user by OAuth or email
        mock_db.query.return_value.filter.return_value.first.return_value = None
        
        service = AuthService(mock_db)
        oauth_data = OAuthUserCreate(
            email="new@example.com",
            name="New User",
            avatar="https://example.com/avatar.jpg",
            oauth_provider="google",
            oauth_id="google-123",
            access_token="access-token-123",
            refresh_token="refresh-token-123"
        )
        
        user = service.create_or_update_oauth_user(oauth_data)
        
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called()
