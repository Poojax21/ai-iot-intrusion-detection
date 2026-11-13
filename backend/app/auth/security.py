"""
Cryptographic security utilities for Password Hashing, JWT Tokens, and Sensor Keys.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import re
import secrets
from typing import Any, Dict, Optional, Tuple

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
import jwt

from ..config import settings
from ..database.base import utc_now, generate_uuid

# Argon2id password hasher with secure defaults
_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=65536,  # 64 MB
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


def hash_password(password: str) -> str:
    """Hash password using Argon2id."""
    return _hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against Argon2id hash with constant-time security."""
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validate password complexity:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, ""


def hash_token(raw_token: str) -> str:
    """Hash refresh token or sensor API key using SHA-256."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def generate_sensor_key(prefix: str = "pahredaar_sk") -> Tuple[str, str]:
    """Generate high-entropy sensor API key and its SHA-256 hash."""
    random_part = secrets.token_urlsafe(32)
    raw_key = f"{prefix}_{random_part}"
    key_hash = hash_token(raw_key)
    return raw_key, key_hash


def create_access_token(
    user_id: str,
    org_id: str,
    role: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Generate signed JWT access token."""
    expire = utc_now() + (expires_delta or timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {
        "sub": user_id,
        "org_id": org_id,
        "role": role,
        "type": "access",
        "exp": expire,
        "iat": utc_now(),
        "jti": generate_uuid(),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(
    user_id: str,
    family_id: Optional[str] = None,
    expires_delta: Optional[timedelta] = None,
) -> Tuple[str, str, str, datetime]:
    """
    Generate secure refresh token string, hash, family_id, and expiration.
    Returns: (raw_token, token_hash, family_id, expires_at)
    """
    raw_token = f"rt_{secrets.token_urlsafe(48)}"
    token_hash = hash_token(raw_token)
    fam_id = family_id or generate_uuid()
    expires_at = utc_now() + (expires_delta or timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS))
    return raw_token, token_hash, fam_id, expires_at


def decode_jwt_token(token: str) -> Dict[str, Any]:
    """Decode and validate JWT access token signature, algorithm, and expiration."""
    return jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        options={"require": ["exp", "sub", "org_id", "role", "type"]},
    )
