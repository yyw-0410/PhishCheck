"""Authentication routes - OAuth and email/password."""

import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Query, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session as DBSession

from app.core.config import get_settings
from app.core.database import get_db
from app.models.user import OAuthState
from app.schemas.auth import (
    AuthResponse,
    OAuthUserCreate,
    PasswordChange,
    ProfileUpdate,
    TokenValidation,
    UserLogin,
    UserRegister,
    UserResponse,
)
from app.services.auth_service import AuthService
from app.services.oauth_service import OAuthService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["authentication"])

# OAuth state TTL in minutes
OAUTH_STATE_TTL_MINUTES = 10

# Cookie settings
COOKIE_NAME = "session_token"
COOKIE_MAX_AGE = 7 * 24 * 60 * 60  # 7 days in seconds


# ============== OAuth Helper Functions ==============

def _create_oauth_state(db: DBSession, provider: str) -> str:
    """Generate and store OAuth state for CSRF protection."""
    oauth = OAuthService()
    state = oauth.generate_state()
    
    oauth_state = OAuthState(
        state=state,
        provider=provider,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=OAUTH_STATE_TTL_MINUTES)
    )
    db.add(oauth_state)
    db.commit()
    
    return state


def _validate_oauth_state(db: DBSession, state: str, provider: str) -> None:
    """Validate OAuth state parameter and clean up expired states.
    
    Raises HTTPException if state is invalid or expired.
    """
    oauth_state = db.query(OAuthState).filter(OAuthState.state == state).first()
    
    if not oauth_state or oauth_state.provider != provider:
        raise HTTPException(status_code=400, detail="Invalid state parameter")
    
    if oauth_state.is_expired:
        db.delete(oauth_state)
        db.commit()
        raise HTTPException(status_code=400, detail="OAuth state expired. Please try again.")
    
    # Delete the used state
    db.delete(oauth_state)
    db.commit()
    
    # Clean up any other expired states (background cleanup)
    db.query(OAuthState).filter(OAuthState.expires_at < datetime.now(timezone.utc)).delete()
    db.commit()


def _create_oauth_login(
    db: DBSession,
    email: str,
    name: str,
    avatar: str | None,
    provider: str,
    oauth_id: str,
    access_token: str,
    refresh_token: str | None
) -> tuple:
    """Create or update OAuth user and create session."""
    auth_service = AuthService(db)
    
    oauth_data = OAuthUserCreate(
        email=email,
        name=name,
        avatar=avatar,
        oauth_provider=provider,
        oauth_id=oauth_id,
        access_token=access_token,
        refresh_token=refresh_token
    )
    
    return auth_service.oauth_login(oauth_data)


def _build_oauth_redirect(user, session, provider: str) -> RedirectResponse:
    """Build redirect response to frontend with session data and set httpOnly cookie."""
    settings = get_settings()
    frontend_url = f"{settings.frontend_url}/auth/{provider}/callback"
    
    params = urlencode({
        'session_token': session.token,
        'email': user.email,
        'name': user.name,
        'picture': user.avatar or ''
    })
    
    response = RedirectResponse(url=f"{frontend_url}?{params}")
    
    # Set httpOnly cookie for OAuth login (same as regular login)
    response.set_cookie(
        key=COOKIE_NAME,
        value=session.token,
        max_age=COOKIE_MAX_AGE,
        path="/",
        httponly=True,
        secure=settings.environment == "production",
        samesite="lax"
    )
    
    return response


# ============== Email/Password Authentication ==============

@router.post("/register", response_model=AuthResponse)
async def register(user_data: UserRegister, response: Response, db: DBSession = Depends(get_db)):
    """Register a new user with email and password."""
    auth_service = AuthService(db)
    settings = get_settings()
    
    try:
        user, session = auth_service.register(user_data)
        
        # Set httpOnly cookie for secure session
        response.set_cookie(
            key=COOKIE_NAME,
            value=session.token,
            max_age=COOKIE_MAX_AGE,
            path="/",
            httponly=True,
            secure=settings.environment == "production",
            samesite="lax"
        )
        
        return AuthResponse(
            user=UserResponse.model_validate(user),
            session_token=session.token,
            expires_at=session.expires_at,
            message="Registration successful. Please check your email to verify your account."
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/verify-email")
async def verify_email(token: str = Query(..., description="Verification token from email"), db: DBSession = Depends(get_db)):
    """Verify user email with token from verification email."""
    auth_service = AuthService(db)
    settings = get_settings()
    
    user = auth_service.verify_email(token)
    
    if user:
        # Redirect to frontend with success
        return RedirectResponse(
            url=f"{settings.frontend_url}/verify-email?success=true&email={user.email}"
        )
    else:
        # Redirect to frontend with error (token invalid or expired)
        return RedirectResponse(
            url=f"{settings.frontend_url}/verify-email?success=false&error=invalid_token"
        )


@router.post("/resend-verification")
async def resend_verification(email: str = Query(..., description="Email to resend verification to"), db: DBSession = Depends(get_db)):
    """Resend verification email to user."""
    auth_service = AuthService(db)
    
    success, message = auth_service.resend_verification(email)
    
    if success:
        return {"message": message}
    else:
        raise HTTPException(status_code=400, detail=message)


@router.post("/login", response_model=AuthResponse)
async def login(user_data: UserLogin, response: Response, db: DBSession = Depends(get_db)):
    """Login with email and password."""
    auth_service = AuthService(db)
    settings = get_settings()
    
    try:
        user, session = auth_service.login(user_data.email, user_data.password)
        
        # Set httpOnly cookie for secure session
        response.set_cookie(
            key=COOKIE_NAME,
            value=session.token,
            max_age=COOKIE_MAX_AGE,
            path="/",
            httponly=True,
            secure=settings.environment == "production",
            samesite="lax"
        )
        
        return AuthResponse(
            user=UserResponse.model_validate(user),
            session_token=session.token,
            expires_at=session.expires_at,
            message="Login successful"
        )
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))


@router.post("/logout")
async def logout(
    response: Response,
    authorization: str = Header(None),
    session_token: str = Cookie(None),
    db: DBSession = Depends(get_db)
):
    """Logout user by invalidating session.
    
    Always returns success - follows idempotency principle.
    Even if session is already invalid/expired, we clear the cookie.
    """
    token = session_token or (authorization.replace("Bearer ", "") if authorization and authorization.startswith("Bearer ") else None)
    
    # Try to invalidate the session if token exists
    if token:
        auth_service = AuthService(db)
        auth_service.logout(token)  # Ignore result - session may already be invalid
    
    # Always clear the cookie and return success
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"message": "Logged out successfully"}


@router.post("/disconnect-oauth", response_model=UserResponse)
async def disconnect_oauth(
    authorization: str = Header(None),
    session_token: str = Cookie(None),
    db: DBSession = Depends(get_db)
):
    """Disconnect OAuth provider from current user account.
    
    Only works for email/password users who have linked an OAuth account.
    OAuth-only accounts cannot disconnect (they would have no way to login).
    """
    token = session_token or (authorization.replace("Bearer ", "") if authorization and authorization.startswith("Bearer ") else None)
    
    if not token:
        raise HTTPException(status_code=401, detail="Missing authorization token")
    
    auth_service = AuthService(db)
    
    user = auth_service.validate_session(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid session")
    
    if not user.password_hash:
        raise HTTPException(status_code=400, detail="Cannot disconnect OAuth from OAuth-only account")
    
    if not user.oauth_provider:
        raise HTTPException(status_code=400, detail="No OAuth account connected")
    
    success = auth_service.disconnect_oauth(user.id)
    if success:
        # Refresh user data
        db.refresh(user)
        return UserResponse.model_validate(user)
    else:
        raise HTTPException(status_code=500, detail="Failed to disconnect OAuth")


@router.get("/me", response_model=UserResponse)
async def get_current_user(
    authorization: str = Header(None),
    session_token: str = Cookie(None),
    db: DBSession = Depends(get_db)
):
    """Get current authenticated user."""
    token = session_token or (authorization.replace("Bearer ", "") if authorization and authorization.startswith("Bearer ") else None)
    
    if not token:
        raise HTTPException(status_code=401, detail="Missing authorization token")
    
    auth_service = AuthService(db)
    
    user = auth_service.validate_session(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    return UserResponse.model_validate(user)


@router.get("/me/analysis-limit")
async def get_analysis_limit(
    authorization: str = Header(None),
    session_token: str = Cookie(None),
    db: DBSession = Depends(get_db)
):
    """Get current user's analysis limit status for all types.
    
    Returns remaining counts per analysis type for unverified users.
    Verified users get unlimited (-1).
    """
    token = session_token or (authorization.replace("Bearer ", "") if authorization and authorization.startswith("Bearer ") else None)
    
    if not token:
        # Not logged in - no limit tracking
        return {
            "limits": {"eml": -1, "link": -1, "file": -1},
            "limit_per_type": -1,
            "is_verified": None,
            "message": "Not logged in"
        }
    
    auth_service = AuthService(db)
    
    user = auth_service.validate_session(token)
    if not user:
        return {
            "limits": {"eml": -1, "link": -1, "file": -1},
            "max_limits": {"eml": -1, "link": -1, "file": -1},
            "is_verified": None,
            "message": "Not logged in"
        }
    
    remaining = auth_service.get_all_remaining_analyses(user)
    max_limits = auth_service.DAILY_LIMITS if not user.is_verified else {"eml": -1, "link": -1, "file": -1}
    
    return {
        "limits": remaining,
        "max_limits": max_limits,
        "is_verified": user.is_verified,
        "message": "Unlimited" if user.is_verified else f"EML: {remaining['eml']}/{max_limits['eml']}, Link: {remaining['link']}/{max_limits['link']}, File: {remaining['file']}/{max_limits['file']}"
    }


@router.post("/validate", response_model=TokenValidation)
async def validate_token(
    authorization: str = Header(None),
    session_token: str = Cookie(None),
    db: DBSession = Depends(get_db)
):
    """Validate a session token."""
    token = session_token or (authorization.replace("Bearer ", "") if authorization and authorization.startswith("Bearer ") else None)
    
    if not token:
        return TokenValidation(valid=False, message="Missing authorization token")
    
    auth_service = AuthService(db)
    
    user = auth_service.validate_session(token)
    if user:
        return TokenValidation(
            valid=True, 
            user=UserResponse.model_validate(user),
            message="Token is valid"
        )
    
    return TokenValidation(valid=False, message="Invalid or expired token")


# ============== Account Management ==============

@router.patch("/profile", response_model=UserResponse)
async def update_profile(
    profile_data: ProfileUpdate,
    authorization: str = Header(None),
    session_token: str = Cookie(None),
    db: DBSession = Depends(get_db)
):
    """Update user profile (name and avatar)."""
    token = session_token or (authorization.replace("Bearer ", "") if authorization and authorization.startswith("Bearer ") else None)
    
    if not token:
        raise HTTPException(status_code=401, detail="Missing authorization token")
    
    auth_service = AuthService(db)
    user = auth_service.validate_session(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    # Update fields if provided
    if profile_data.name is not None:
        user.name = profile_data.name
    if profile_data.avatar is not None:
        user.avatar = profile_data.avatar if profile_data.avatar else None
    
    user.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)
    
    return UserResponse.model_validate(user)


@router.post("/password")
async def change_password(
    password_data: PasswordChange,
    authorization: str = Header(None),
    session_token: str = Cookie(None),
    db: DBSession = Depends(get_db)
):
    """Change user password."""
    import bcrypt
    
    token = session_token or (authorization.replace("Bearer ", "") if authorization and authorization.startswith("Bearer ") else None)
    
    if not token:
        raise HTTPException(status_code=401, detail="Missing authorization token")
    
    auth_service = AuthService(db)
    user = auth_service.validate_session(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    # OAuth-only users cannot change password
    if not user.password_hash:
        raise HTTPException(status_code=400, detail="OAuth accounts cannot change password")
    
    # Verify current password
    if not bcrypt.checkpw(password_data.current_password.encode('utf-8'), user.password_hash.encode('utf-8')):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    # Hash and save new password
    new_hash = bcrypt.hashpw(password_data.new_password.encode('utf-8'), bcrypt.gensalt())
    user.password_hash = new_hash.decode('utf-8')
    user.updated_at = datetime.now(timezone.utc)
    db.commit()
    
    return {"message": "Password changed successfully"}


@router.delete("/account")
async def delete_account(
    response: Response,
    authorization: str = Header(None),
    session_token: str = Cookie(None),
    db: DBSession = Depends(get_db)
):
    """Delete user account and all associated data."""
    token = session_token or (authorization.replace("Bearer ", "") if authorization and authorization.startswith("Bearer ") else None)
    
    if not token:
        raise HTTPException(status_code=401, detail="Missing authorization token")
    
    auth_service = AuthService(db)
    user = auth_service.validate_session(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    user_id = user.id
    
    # Delete all user sessions first
    from app.models.user import Session
    db.query(Session).filter(Session.user_id == user_id).delete()
    
    # Delete the user
    db.delete(user)
    db.commit()
    
    # Clear cookie
    response.delete_cookie(COOKIE_NAME)
    
    logger.info(f"Account deleted: user_id={user_id}")
    return {"message": "Account deleted successfully"}


# ============== Microsoft OAuth ==============

@router.get("/microsoft/login")
async def microsoft_login(db: DBSession = Depends(get_db)):
    """Redirect user to Microsoft OAuth consent page."""
    state = _create_oauth_state(db, "microsoft")
    auth_url = OAuthService().get_microsoft_auth_url(state)
    return RedirectResponse(url=auth_url)


@router.get("/microsoft/callback")
async def microsoft_callback(
    code: str = Query(..., description="Authorization code from Microsoft"),
    state: str = Query(..., description="State parameter for security"),
    db: DBSession = Depends(get_db)
):
    """Handle Microsoft OAuth callback."""
    _validate_oauth_state(db, state, "microsoft")
    
    try:
        oauth = OAuthService()
        tokens = await oauth.exchange_microsoft_code(code)
        user_info = await oauth.get_microsoft_user_info(tokens["access_token"])
        
        display_name = user_info.get('displayName', 'User')
        avatar = f"https://ui-avatars.com/api/?name={quote(display_name)}&background=random"
        
        user, session = _create_oauth_login(
            db=db,
            email=user_info.get('mail') or user_info.get('userPrincipalName', ''),
            name=display_name,
            avatar=avatar,
            provider='microsoft',
            oauth_id=user_info.get('id', ''),
            access_token=tokens['access_token'],
            refresh_token=tokens.get('refresh_token')
        )
        
        return _build_oauth_redirect(user, session, "microsoft")
    
    except Exception as e:
        logger.error(f"Microsoft OAuth failed: {e}")
        raise HTTPException(status_code=500, detail="Authentication failed. Please try again.")


# ============== Google OAuth ==============

@router.get("/google/login")
async def google_login(db: DBSession = Depends(get_db)):
    """Redirect user to Google OAuth consent page."""
    state = _create_oauth_state(db, "google")
    auth_url = OAuthService().get_google_auth_url(state)
    return RedirectResponse(url=auth_url)


@router.get("/google/callback")
async def google_callback(
    code: str = Query(..., description="Authorization code from Google"),
    state: str = Query(..., description="State parameter for security"),
    db: DBSession = Depends(get_db)
):
    """Handle Google OAuth callback."""
    _validate_oauth_state(db, state, "google")
    
    try:
        oauth = OAuthService()
        tokens = await oauth.exchange_google_code(code)
        user_info = await oauth.get_google_user_info(tokens["access_token"])
        
        user, session = _create_oauth_login(
            db=db,
            email=user_info['email'],
            name=user_info['name'],
            avatar=user_info.get('picture'),
            provider='google',
            oauth_id=user_info.get('id', user_info.get('sub', '')),
            access_token=tokens['access_token'],
            refresh_token=tokens.get('refresh_token')
        )
        
        return _build_oauth_redirect(user, session, "google")
    
    except Exception as e:
        logger.error(f"Google OAuth failed: {e}")
        raise HTTPException(status_code=500, detail="Authentication failed. Please try again.")
