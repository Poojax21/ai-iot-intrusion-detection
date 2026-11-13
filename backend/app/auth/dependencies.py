"""
FastAPI Authentication and Authorization Dependencies.
"""

from typing import Annotated, Optional, Tuple
from fastapi import Depends, Header, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..config import settings
from ..database.session import get_db
from ..database.models import User, Organization, Sensor
from ..database.base import generate_uuid, utc_now
from .security import decode_jwt_token, hash_token
from .rbac import Role, Permission, has_permission

# Optional HTTPBearer to handle both header and cookie authentication
security_scheme = HTTPBearer(auto_error=False)

DEFAULT_ORG_ID = "default-org-id"
DEFAULT_ORG_SLUG = "default-org"


async def get_or_create_default_org(db: AsyncSession) -> Organization:
    """Ensure a default organization exists for backward compatibility."""
    stmt = select(Organization).where((Organization.slug == DEFAULT_ORG_SLUG) | (Organization.id == DEFAULT_ORG_ID))
    result = await db.execute(stmt)
    org = result.scalar_one_or_none()
    if not org:
        org = Organization(
            id=DEFAULT_ORG_ID,
            name="Default Organization",
            slug=DEFAULT_ORG_SLUG,
            is_active=True,
        )
        db.add(org)
        await db.flush()
    return org


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Extract and validate the authenticated user from JWT Bearer token."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    try:
        payload = decode_jwt_token(token)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    stmt = (
        select(User)
        .options(selectinload(User.organization))
        .where(User.id == user_id)
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account does not exist or has been deactivated",
        )

    if not user.organization or not user.organization.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization has been deactivated",
        )

    return user


async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """Optional authentication: returns User if valid token provided, else None."""
    if not credentials or not credentials.credentials:
        return None
    try:
        return await get_current_user(credentials=credentials, db=db)
    except HTTPException:
        return None


def require_roles(*allowed_roles: str):
    """Enforce role-based access control dependency."""
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Insufficient role permissions (Requires one of: {', '.join(allowed_roles)})",
            )
        return current_user
    return role_checker


def require_permissions(*required_permissions: Permission):
    """Enforce fine-grained permission dependency."""
    async def perm_checker(current_user: User = Depends(get_current_user)) -> User:
        for perm in required_permissions:
            if not has_permission(current_user.role, perm):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Forbidden: Missing required permission '{perm.value}'",
                )
        return current_user
    return perm_checker


async def get_current_org(current_user: User = Depends(get_current_user)) -> Organization:
    """Return the active organization for the current user."""
    return current_user.organization


async def verify_sensor_identity(
    x_sensor_key: Optional[str] = Header(None, alias="X-Sensor-Key"),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
) -> Tuple[Optional[Sensor], str]:
    """
    Validate sensor identity and resolve active organization ID.
    Supports:
    1. Disabled Ingest Auth dev mode (assigned to Default Organization).
    2. Legacy API_KEY fallback (assigned to Default Organization).
    3. Registered Sensor API Key (X-Sensor-Key or Bearer token hashed via SHA-256).
    Returns: (sensor_model_or_none, organization_id)
    """
    raw_key = x_sensor_key or x_api_key
    if not raw_key and authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            raw_key = parts[1]

    # Mode 1: Authentication disabled
    if not settings.ENABLE_INGEST_AUTH:
        return None, DEFAULT_ORG_ID

    if not raw_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sensor authentication key required",
        )

    # Legacy Static API_KEY fallback
    if settings.API_KEY and raw_key == settings.API_KEY:
        return None, DEFAULT_ORG_ID

    # Mode 2: Registered Database Sensor Key (scoped session without holding locks)
    from ..database.session import async_db_session
    async with async_db_session() as db:
        key_hash = hash_token(raw_key)
        stmt = (
            select(Sensor)
            .options(selectinload(Sensor.organization))
            .where(Sensor.api_key_hash == key_hash, Sensor.is_active.is_(True))
        )
        result = await db.execute(stmt)
        sensor = result.scalar_one_or_none()

        if sensor:
            sensor.last_seen = utc_now()
            return sensor, sensor.organization_id

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or revoked sensor API key",
    )
