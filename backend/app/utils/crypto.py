"""Cryptographic utilities for encrypting sensitive data at rest."""

import base64
import logging
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings

logger = logging.getLogger(__name__)


def _get_fernet() -> Fernet:
    """Get Fernet cipher using the SECRET_KEY.
    
    The SECRET_KEY is derived to a valid Fernet key (32 bytes, base64 encoded).
    """
    settings = get_settings()
    # Use first 32 bytes of SECRET_KEY hash for Fernet
    import hashlib
    key_hash = hashlib.sha256(settings.secret_key.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(key_hash)
    return Fernet(fernet_key)


def encrypt_token(token: Optional[str]) -> Optional[str]:
    """Encrypt a token for storage at rest.
    
    Args:
        token: Plain text token to encrypt
        
    Returns:
        Base64-encoded encrypted token, or None if input is None
    """
    if not token:
        return None
    
    try:
        fernet = _get_fernet()
        encrypted = fernet.encrypt(token.encode('utf-8'))
        return encrypted.decode('utf-8')
    except Exception as e:
        logger.error(f"Failed to encrypt token: {e}")
        # Return None rather than storing plain text
        return None


def decrypt_token(encrypted_token: Optional[str]) -> Optional[str]:
    """Decrypt a stored token.
    
    Args:
        encrypted_token: Base64-encoded encrypted token
        
    Returns:
        Decrypted plain text token, or None if decryption fails
    """
    if not encrypted_token:
        return None
    
    try:
        fernet = _get_fernet()
        decrypted = fernet.decrypt(encrypted_token.encode('utf-8'))
        return decrypted.decode('utf-8')
    except InvalidToken:
        logger.warning("Invalid encrypted token - possible key rotation or corruption")
        return None
    except Exception as e:
        logger.error(f"Failed to decrypt token: {e}")
        return None
