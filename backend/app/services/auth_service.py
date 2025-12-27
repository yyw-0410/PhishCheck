"""Authentication service for user management."""

import secrets
import bcrypt
from datetime import datetime, timedelta, timezone
from typing import Optional
import dns.resolver

from sqlalchemy.orm import Session as DBSession

from app.models.user import User, Session
from app.schemas.auth import UserRegister, OAuthUserCreate, UserResponse, AuthResponse
from app.utils.crypto import encrypt_token
from app.core.constants import (
    SESSION_EXPIRE_HOURS,
    DAILY_LIMITS,
    GUEST_DAILY_LIMITS,
    VERIFICATION_TOKEN_EXPIRE_HOURS,
    EMAIL_VERIFICATION_TOKEN_LENGTH,
)


class AuthService:
    """Service for handling authentication operations."""
    
    def __init__(self, db: DBSession):
        self.db = db
    
    # ============== Password Utilities ==============
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt.
        
        Note: bcrypt has a 72-byte limit, handled automatically.
        """
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password_bytes, salt)
        return hashed.decode('utf-8')
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash.
        
        Args:
            plain_password: The plaintext password to verify.
            hashed_password: The bcrypt hash to check against.
            
        Returns:
            True if the password matches the hash, False otherwise.
        """
        password_bytes = plain_password.encode('utf-8')
        hashed_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    
    @staticmethod
    def generate_session_token() -> str:
        """Generate a secure random session token."""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def validate_email_domain(email: str) -> bool:
        """Check if email domain has valid MX records (can receive mail).
        
        Handles RFC 7505 null MX records (e.g., '0 .') which indicate
        a domain explicitly does NOT accept email.
        """
        try:
            domain = email.split('@')[1]
            mx_records = dns.resolver.resolve(domain, 'MX')
            
            # Check for null MX record (RFC 7505)
            # A null MX has preference 0 and exchange of "." or empty
            for record in mx_records:
                exchange = str(record.exchange).rstrip('.')
                if exchange and exchange != '':
                    # Found at least one valid MX record
                    return True
            
            # All MX records are null - domain doesn't accept email
            return False
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, IndexError):
            return False
        except dns.exception.Timeout:
            # DNS timeout - fail open to avoid blocking legitimate users
            logger.warning(f"DNS timeout checking MX for domain: {domain}")
            return True
        except Exception as e:
            # If DNS check fails for other reasons, allow the email (fail open)
            logger.warning(f"DNS check failed for domain {domain}: {type(e).__name__}: {e}")
            return True
    
    # ============== User Operations ==============
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get a user by their email address."""
        return self.db.query(User).filter(User.email == email).first()
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get a user by their ID."""
        return self.db.query(User).filter(User.id == user_id).first()
    
    def get_user_by_oauth(self, provider: str, oauth_id: str) -> Optional[User]:
        """Get a user by their OAuth provider and ID."""
        return self.db.query(User).filter(
            User.oauth_provider == provider,
            User.oauth_id == oauth_id
        ).first()
    
    def create_user(self, user_data: UserRegister) -> User:
        """Create a new user with email/password."""
        user = User(
            email=user_data.email,
            password_hash=self.hash_password(user_data.password),
            name=user_data.name,
            is_verified=False
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user
    
    def create_or_update_oauth_user(self, oauth_data: OAuthUserCreate) -> User:
        """Create or update a user from OAuth login."""
        # Check if user exists by OAuth ID
        user = self.get_user_by_oauth(oauth_data.oauth_provider, oauth_data.oauth_id)
        
        if not user:
            # Check if user exists by email (linking accounts)
            user = self.get_user_by_email(oauth_data.email)
        
        if user:
            # Update existing user's OAuth tokens
            user.oauth_provider = oauth_data.oauth_provider
            user.oauth_id = oauth_data.oauth_id
            user.oauth_email = oauth_data.email  # Store the connected email
            user.oauth_access_token = encrypt_token(oauth_data.access_token)
            user.oauth_refresh_token = encrypt_token(oauth_data.refresh_token)
            user.avatar = oauth_data.avatar or user.avatar
            user.name = oauth_data.name or user.name
            user.is_verified = True  # OAuth users are verified
        else:
            # Create new user
            user = User(
                email=oauth_data.email,
                name=oauth_data.name,
                avatar=oauth_data.avatar,
                oauth_provider=oauth_data.oauth_provider,
                oauth_id=oauth_data.oauth_id,
                oauth_email=oauth_data.email,  # Same as login email for new OAuth users
                oauth_access_token=encrypt_token(oauth_data.access_token),
                oauth_refresh_token=encrypt_token(oauth_data.refresh_token),
                is_verified=True
            )
            self.db.add(user)
        
        self.db.commit()
        self.db.refresh(user)
        return user
    
    def disconnect_oauth(self, user_id: int) -> bool:
        """Disconnect OAuth from a user account.
        
        Only works for email/password users who linked an OAuth account.
        Returns True if disconnected, False if user not found or is OAuth-only.
        """
        user = self.get_user_by_id(user_id)
        
        if not user:
            return False
        
        # Can't disconnect if this is an OAuth-only account (no password)
        if not user.password_hash:
            return False
        
        # Clear OAuth fields
        user.oauth_provider = None
        user.oauth_id = None
        user.oauth_email = None
        user.oauth_access_token = None
        user.oauth_refresh_token = None
        
        self.db.commit()
        return True
    
    # ============== Session Operations ==============
    
    def create_session(
        self, 
        user: User, 
        ip_address: str = None, 
        user_agent: str = None
    ) -> Session:
        """Create a new session for a user.
        
        Cleans up old sessions for this user before creating a new one.
        Only one active session per user is allowed.
        """
        # Clean up old sessions for this user (keep only 1 session per user)
        self.db.query(Session).filter(Session.user_id == user.id).delete()
        
        session = Session(
            user_id=user.id,
            token=self.generate_session_token(),
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=SESSION_EXPIRE_HOURS)
        )
        
        # Update user's last login
        user.last_login = datetime.now(timezone.utc)
        
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        return session
    
    def get_session(self, token: str) -> Optional[Session]:
        """Get a session by token if valid and not expired."""
        session = self.db.query(Session).filter(Session.token == token).first()
        
        if session:
            # Handle both timezone-aware and naive datetimes for backward compatibility
            expires_at = session.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at > datetime.now(timezone.utc):
                return session
        
        # Delete expired session
        if session:
            self.db.delete(session)
            self.db.commit()
        
        return None
    
    def delete_session(self, token: str) -> bool:
        """Delete a session (logout)."""
        session = self.db.query(Session).filter(Session.token == token).first()
        if session:
            self.db.delete(session)
            self.db.commit()
            return True
        return False
    
    def delete_all_user_sessions(self, user_id: int) -> int:
        """Delete all sessions for a user (logout everywhere)."""
        count = self.db.query(Session).filter(Session.user_id == user_id).delete()
        self.db.commit()
        return count
    
    # ============== Authentication Operations ==============
    
    def register(self, user_data: UserRegister) -> tuple[User, Session]:
        """Register a new user and create a session."""
        # Validate email domain has MX records (can receive mail)
        if not self.validate_email_domain(user_data.email):
            raise ValueError("Invalid email domain. Please use a valid email address that can receive mail.")
        
        # Check if email already exists
        existing_user = self.get_user_by_email(user_data.email)
        
        if existing_user:
            # Check if email is linked to an OAuth account
            if existing_user.oauth_provider:
                raise ValueError(f"This email is linked to a {existing_user.oauth_provider.title()} account. Please sign in with that provider.")
            # Email exists with password
            raise ValueError("Email already registered")
        
        user = self.create_user(user_data)
        session = self.create_session(user)
        
        # Send verification email (don't fail registration if email fails)
        self.send_verification_email(user)
        
        return user, session
    
    def login(self, email: str, password: str) -> tuple[User, Session]:
        """Authenticate user with email/password."""
        user = self.get_user_by_email(email)
        
        if not user:
            # Perform dummy hash to prevent timing attack that reveals user existence
            self.hash_password("dummy_password_for_timing_equalization")
            raise ValueError("Invalid email or password")
        
        if not user.password_hash:
            raise ValueError("This account uses OAuth login. Please sign in with Google or Microsoft.")
        
        if not self.verify_password(password, user.password_hash):
            raise ValueError("Invalid email or password")
        
        if not user.is_active:
            raise ValueError("Account is deactivated")
        
        session = self.create_session(user)
        return user, session
    
    def oauth_login(self, oauth_data: OAuthUserCreate) -> tuple[User, Session]:
        """Authenticate/register user via OAuth."""
        user = self.create_or_update_oauth_user(oauth_data)
        session = self.create_session(user)
        return user, session
    
    def validate_session(self, token: str) -> Optional[User]:
        """Validate a session token and return the user."""
        session = self.get_session(token)
        if session:
            return self.get_user_by_id(session.user_id)
        return None
    
    def logout(self, token: str) -> bool:
        """Logout user by deleting their session."""
        return self.delete_session(token)
    
    # ============== Email Verification Operations ==============
    
    def send_verification_email(self, user: User) -> bool:
        """Generate token and send verification email to user.
        
        Returns True if email was sent, False if email service not configured.
        """
        from app.services.email_service import EmailService
        
        email_service = EmailService()
        
        # Generate new verification token
        token = email_service.generate_verification_token()
        user.verification_token = token
        user.verification_token_expires = email_service.get_token_expiry()
        self.db.commit()
        
        # Send email
        return email_service.send_verification_email(
            to_email=user.email,
            name=user.name,
            token=token
        )
    
    def verify_email(self, token: str) -> Optional[User]:
        """Verify user email with token.
        
        Returns the user if verification successful, None otherwise.
        """
        from datetime import datetime, timezone
        
        user = self.db.query(User).filter(User.verification_token == token).first()
        
        if not user:
            return None
        
        # Check if token expired
        if user.verification_token_expires:
            expires = user.verification_token_expires
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if expires < datetime.now(timezone.utc):
                return None
        
        # Mark as verified and clear token
        user.is_verified = True
        user.verification_token = None
        user.verification_token_expires = None
        self.db.commit()
        
        return user
    
    def resend_verification(self, email: str) -> tuple[bool, str]:
        """Resend verification email to user.
        
        Returns (success, message) tuple.
        """
        user = self.get_user_by_email(email)
        
        if not user:
            return False, "Email not found"
        
        if user.is_verified:
            return False, "Email already verified"
        
        if user.oauth_provider:
            return False, "OAuth accounts are automatically verified"
        
        sent = self.send_verification_email(user)
        if sent:
            return True, "Verification email sent"
        else:
            return False, "Failed to send email. Please try again later."
    
    # ============== Account Cleanup Operations ==============
    
    def cleanup_unverified_accounts(self, days_old: int = 7) -> int:
        """Delete unverified email/password accounts older than specified days.
        
        OAuth accounts are never deleted (they're always verified).
        Returns the number of accounts deleted.
        """
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_old)
        
        # Find unverified accounts older than cutoff
        # Only delete email/password accounts (oauth_provider IS NULL)
        stale_users = self.db.query(User).filter(
            User.is_verified == False,
            User.oauth_provider == None,
            User.created_at < cutoff_date
        ).all()
        
        count = len(stale_users)
        
        for user in stale_users:
            # Sessions are deleted via cascade
            self.db.delete(user)
        
        if count > 0:
            self.db.commit()
        
        return count
    
    # ============== Analysis Limit Operations ==============
    
    def _get_limit_for_type(self, analysis_type: str) -> int:
        """Get the daily limit for a specific analysis type."""
        # Use imported DAILY_LIMITS from constants module
        return DAILY_LIMITS.get(analysis_type, 5)
    
    def _get_count_field(self, user: User, analysis_type: str) -> int:
        """Get the count field value for a specific analysis type."""
        if analysis_type == 'eml':
            return user.daily_eml_count or 0
        elif analysis_type == 'link':
            return user.daily_link_count or 0
        elif analysis_type == 'file':
            return user.daily_file_count or 0
        elif analysis_type == 'ai':
            return user.daily_ai_count or 0
        return 0
    
    def _set_count_field(self, user: User, analysis_type: str, value: int) -> None:
        """Set the count field value for a specific analysis type."""
        if analysis_type == 'eml':
            user.daily_eml_count = value
        elif analysis_type == 'link':
            user.daily_link_count = value
        elif analysis_type == 'file':
            user.daily_file_count = value
        elif analysis_type == 'ai':
            user.daily_ai_count = value
    
    def _reset_daily_counts_if_needed(self, user: User) -> bool:
        """Reset all daily counts if it's a new day (midnight). Returns True if reset occurred."""
        today = datetime.now(timezone.utc).date()
        if user.last_analysis_date:
            last_date = user.last_analysis_date
            if last_date.tzinfo is None:
                last_date = last_date.replace(tzinfo=timezone.utc)
            if last_date.date() < today:
                user.daily_eml_count = 0
                user.daily_link_count = 0
                user.daily_file_count = 0
                user.daily_ai_count = 0
                user.last_analysis_date = None
                self.db.commit()
                return True
        return False
    
    def check_analysis_limit(self, user: User, analysis_type: str = 'eml') -> tuple[bool, int]:
        """Check if user can perform analysis of a specific type.
        
        Args:
            user: The user to check
            analysis_type: 'eml', 'link', or 'file'
        
        Returns (can_analyze, remaining_count) tuple.
        Verified users have unlimited access.
        """
        if user.is_verified:
            return True, -1  # -1 means unlimited
        
        self._reset_daily_counts_if_needed(user)
        
        limit = self._get_limit_for_type(analysis_type)
        current_count = self._get_count_field(user, analysis_type)
        remaining = limit - current_count
        can_analyze = remaining > 0
        
        return can_analyze, remaining
    
    def increment_analysis_count(self, user: User, analysis_type: str = 'eml') -> int:
        """Increment user's daily analysis count for a specific type.
        
        Args:
            user: The user to update
            analysis_type: 'eml', 'link', or 'file'
        
        Returns remaining count. Only affects unverified users.
        """
        if user.is_verified:
            return -1  # Unlimited
        
        self._reset_daily_counts_if_needed(user)
        
        current_count = self._get_count_field(user, analysis_type)
        new_count = current_count + 1
        self._set_count_field(user, analysis_type, new_count)
        user.last_analysis_date = datetime.now(timezone.utc)
        self.db.commit()
        
        limit = self._get_limit_for_type(analysis_type)
        return limit - new_count
    
    def get_remaining_analyses(self, user: User, analysis_type: str = 'eml') -> int:
        """Get remaining analysis count for user for a specific type.
        
        Args:
            user: The user to check
            analysis_type: 'eml', 'link', or 'file'
        
        Returns -1 for verified users (unlimited).
        """
        if user.is_verified:
            return -1
        
        self._reset_daily_counts_if_needed(user)
        
        limit = self._get_limit_for_type(analysis_type)
        current_count = self._get_count_field(user, analysis_type)
        return max(0, limit - current_count)
    
    def get_all_remaining_analyses(self, user: User) -> dict:
        """Get remaining analysis counts for all types.
        
        Returns dict with 'eml', 'link', 'file', 'ai' keys.
        Values are -1 for verified users (unlimited).
        """
        if user.is_verified:
            return {'eml': -1, 'link': -1, 'file': -1, 'ai': -1}
        
        self._reset_daily_counts_if_needed(user)
        
        return {
            'eml': max(0, self.DAILY_LIMITS['eml'] - (user.daily_eml_count or 0)),
            'link': max(0, self.DAILY_LIMITS['link'] - (user.daily_link_count or 0)),
            'file': max(0, self.DAILY_LIMITS['file'] - (user.daily_file_count or 0)),
            'ai': max(0, self.DAILY_LIMITS['ai'] - (user.daily_ai_count or 0)),
        }

    # ============== Guest Rate Limit Operations (IP-based) ==============
    
    def _get_or_create_guest_record(self, ip_address: str):
        """Get or create a guest rate limit record for an IP."""
        from app.models.user import GuestRateLimit
        
        record = self.db.query(GuestRateLimit).filter(
            GuestRateLimit.ip_address == ip_address
        ).first()
        
        if not record:
            record = GuestRateLimit(ip_address=ip_address)
            self.db.add(record)
            self.db.commit()
            self.db.refresh(record)
        
        return record
    
    def _reset_guest_counts_if_needed(self, record) -> bool:
        """Reset guest daily counts if it's a new day."""
        today = datetime.now(timezone.utc).date()
        if record.last_analysis_date:
            last_date = record.last_analysis_date
            if last_date.tzinfo is None:
                last_date = last_date.replace(tzinfo=timezone.utc)
            if last_date.date() < today:
                record.daily_eml_count = 0
                record.daily_link_count = 0
                record.daily_file_count = 0
                record.last_analysis_date = None
                self.db.commit()
                return True
        return False
    
    def _get_guest_count(self, record, analysis_type: str) -> int:
        """Get guest count for a type."""
        if analysis_type == 'eml':
            return record.daily_eml_count or 0
        elif analysis_type == 'link':
            return record.daily_link_count or 0
        elif analysis_type == 'file':
            return record.daily_file_count or 0
        return 0
    
    def _set_guest_count(self, record, analysis_type: str, value: int):
        """Set guest count for a type."""
        if analysis_type == 'eml':
            record.daily_eml_count = value
        elif analysis_type == 'link':
            record.daily_link_count = value
        elif analysis_type == 'file':
            record.daily_file_count = value
    
    def check_guest_limit(self, ip_address: str, analysis_type: str) -> tuple[bool, int]:
        """Check if guest can perform analysis.
        
        Returns (can_analyze, remaining) tuple.
        """
        if analysis_type not in GUEST_DAILY_LIMITS:
            return False, 0  # AI requires login
        
        record = self._get_or_create_guest_record(ip_address)
        self._reset_guest_counts_if_needed(record)
        
        limit = GUEST_DAILY_LIMITS[analysis_type]
        current = self._get_guest_count(record, analysis_type)
        remaining = limit - current
        
        return remaining > 0, remaining
    
    def increment_guest_count(self, ip_address: str, analysis_type: str) -> int:
        """Increment guest usage count. Returns remaining."""
        if analysis_type not in GUEST_DAILY_LIMITS:
            return 0
        
        record = self._get_or_create_guest_record(ip_address)
        self._reset_guest_counts_if_needed(record)
        
        current = self._get_guest_count(record, analysis_type)
        new_count = current + 1
        self._set_guest_count(record, analysis_type, new_count)
        record.last_analysis_date = datetime.now(timezone.utc)
        self.db.commit()
        
        return GUEST_DAILY_LIMITS[analysis_type] - new_count
    
    def cleanup_old_guest_records(self, days_old: int = 1) -> int:
        """Delete guest rate limit records older than specified days.
        
        Since limits reset daily, records from previous days are stale.
        Default is 1 day (delete anything from before today).
        
        Returns the number of records deleted.
        """
        from app.models.user import GuestRateLimit
        
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_old)
        
        # Delete records where last_analysis_date is before cutoff
        # Also delete records with no last_analysis_date that are just empty
        stale_records = self.db.query(GuestRateLimit).filter(
            GuestRateLimit.last_analysis_date < cutoff_date
        ).all()
        
        count = len(stale_records)
        
        for record in stale_records:
            self.db.delete(record)
        
        if count > 0:
            self.db.commit()
        
        return count
