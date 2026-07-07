import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Any, Union, Optional
from jose import jwt
from passlib.context import CryptContext
from src.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALGORITHM = "HS256"


# ── Password Utilities ────────────────────────────────────────────────────────

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


# ── Access Token ──────────────────────────────────────────────────────────────

def create_access_token(
    subject: Union[str, Any],
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Short-lived access token (default 15 minutes).
    Stored in HttpOnly cookie in browser sessions.
    Also returned in JSON response body for API key clients.
    """
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "type": "access",
    }
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGORITHM)


# ── Refresh Token ─────────────────────────────────────────────────────────────

def create_refresh_token(
    subject: Union[str, Any],
    token_version: int = 0,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Long-lived refresh token (default 7 days).
    Stored in a separate HttpOnly Secure cookie.
    Includes token_version for family-based revocation.
    """
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    )
    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "type": "refresh",
        "ver": token_version,
        "jti": secrets.token_hex(16),  # Unique token ID for revocation
    }
    return jwt.encode(to_encode, settings.REFRESH_SECRET_KEY, algorithm=ALGORITHM)


def decode_refresh_token(token: str) -> Optional[dict]:
    """
    Decodes a refresh token, returning the payload or None if invalid.
    """
    try:
        payload = jwt.decode(token, settings.REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            return None
        return payload
    except Exception:
        return None


def hash_refresh_token(token: str) -> str:
    """SHA-256 hash of the raw refresh token for DB storage."""
    return hashlib.sha256(token.encode()).hexdigest()


# ── CSRF Protection ───────────────────────────────────────────────────────────

def generate_csrf_token(session_id: str) -> str:
    """
    Generate a CSRF token bound to a session/user identifier.
    Double-submit cookie pattern — sent as readable cookie + validated in header.
    """
    payload = {
        "sub": session_id,
        "type": "csrf",
        "exp": datetime.utcnow() + timedelta(hours=24),
        "nonce": secrets.token_hex(8),
    }
    return jwt.encode(payload, settings.CSRF_SECRET_KEY, algorithm=ALGORITHM)


def verify_csrf_token(token: str, session_id: str) -> bool:
    """
    Verify the CSRF token matches the session identity.
    Returns True if valid, False otherwise.
    """
    try:
        payload = jwt.decode(
            token, settings.CSRF_SECRET_KEY, algorithms=[ALGORITHM]
        )
        return payload.get("type") == "csrf" and payload.get("sub") == session_id
    except Exception:
        return False
