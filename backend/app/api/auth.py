"""
Authentication & Session Management API Routes.
"""

import re
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..database.session import get_db
from ..database.models import User, Organization
from ..database.repositories import UserRepository, OrganizationRepository, AuditRepository
from ..database.base import utc_now
from ..schemas import (
    UserRegister,
    UserLogin,
    TokenResponse,
    TokenRefreshRequest,
    UserOut,
)
from ..auth.security import (
    hash_password,
    verify_password,
    validate_password_strength,
    create_access_token,
    create_refresh_token,
    hash_token,
)
from ..auth.rbac import Role, get_role_permissions
from ..auth.dependencies import get_current_user

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


def _slugify(text: str) -> str:
    slug = re.sub(r"[^\w\s-]", "", text.lower()).strip()
    return re.sub(r"[-\s]+", "-", slug)


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: UserRegister, request: Request, db: AsyncSession = Depends(get_db)):
    # 1. Validate password strength
    is_valid, msg = validate_password_strength(payload.password)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    user_repo = UserRepository(db)
    org_repo = OrganizationRepository(db)
    audit_repo = AuditRepository(db)

    # 2. Resolve or create Organization
    slug = payload.organization_slug or _slugify(payload.organization_name)
    org = await org_repo.get_by_slug(slug)
    is_first_user_in_org = False

    if not org:
        org = await org_repo.create(name=payload.organization_name, slug=slug)
        is_first_user_in_org = True
    else:
        # Check if users already exist in this organization
        existing_users_stmt = select(User).where(User.organization_id == org.id)
        existing_res = await db.execute(existing_users_stmt)
        if not existing_res.scalars().first():
            is_first_user_in_org = True

    # 3. Check for existing account
    existing_user = await user_repo.get_by_email(payload.email, org_id=org.id)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists in the organization.",
        )

    # 4. Hash password and create user
    # First user who creates the organization becomes the Administrator
    user_role = Role.ADMIN.value if is_first_user_in_org else Role.VIEWER.value
    pwd_hash = hash_password(payload.password)
    user = await user_repo.create(
        organization_id=org.id,
        full_name=payload.full_name,
        email=payload.email,
        password_hash=pwd_hash,
        role=user_role,
    )

    # 5. Issue JWT Tokens
    access_token = create_access_token(user.id, org.id, user.role)
    raw_rt, rt_hash, family_id, expires_at = create_refresh_token(user.id)
    await user_repo.store_refresh_token(user.id, rt_hash, family_id, expires_at)

    # 6. Audit Event
    await audit_repo.record_event(
        organization_id=org.id,
        user_id=user.id,
        action="auth.register.success",
        resource_type="user",
        resource_id=user.id,
        source_ip=request.client.host if request.client else None,
        metadata={"email": user.email, "role": user.role, "org": org.name},
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=raw_rt,
        token_type="bearer",
        expires_in_sec=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=user.email,
        organization=user.organization.name if user.organization else (user.organization_id or "default-org"),
    )


@router.post("/login", response_model=TokenResponse)
async def login(payload: UserLogin, request: Request, db: AsyncSession = Depends(get_db)):
    user_repo = UserRepository(db)
    audit_repo = AuditRepository(db)

    # Lookup user
    user = await user_repo.get_by_email(payload.email)
    generic_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect email or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not user:
        raise generic_error

    if not verify_password(payload.password, user.password_hash):
        await audit_repo.record_event(
            organization_id=user.organization_id,
            user_id=user.id,
            action="auth.login.failure",
            resource_type="user",
            resource_id=user.id,
            source_ip=request.client.host if request.client else None,
            metadata={"email": payload.email, "reason": "invalid_password"},
        )
        raise generic_error

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account has been deactivated. Contact an administrator.",
        )

    if not user.organization or not user.organization.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization has been suspended.",
        )

    # Issue Tokens
    access_token = create_access_token(user.id, user.organization_id, user.role)
    raw_rt, rt_hash, family_id, expires_at = create_refresh_token(user.id)
    await user_repo.store_refresh_token(user.id, rt_hash, family_id, expires_at)
    await user_repo.update_last_login(user.id)

    # Audit Event
    await audit_repo.record_event(
        organization_id=user.organization_id,
        user_id=user.id,
        action="auth.login.success",
        resource_type="user",
        resource_id=user.id,
        source_ip=request.client.host if request.client else None,
        metadata={"email": user.email, "role": user.role},
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=raw_rt,
        token_type="bearer",
        expires_in_sec=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=user.email,
        organization=user.organization.name if user.organization else (user.organization_id or "default-org"),
    )


from datetime import timezone

def ensure_utc(dt):
    if dt is None:
        return utc_now()
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


@router.post("/refresh", response_model=TokenResponse)
async def refresh_tokens(payload: TokenRefreshRequest, request: Request, db: AsyncSession = Depends(get_db)):
    user_repo = UserRepository(db)
    audit_repo = AuditRepository(db)

    rt_hash = hash_token(payload.refresh_token)
    stored_token = await user_repo.get_refresh_token(rt_hash)

    if not stored_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    # Reuse Detection Check:
    # If the token was already revoked, someone is replaying a stolen token!
    if stored_token.is_revoked:
        await user_repo.revoke_family(stored_token.family_id)
        await audit_repo.record_event(
            organization_id=stored_token.user.organization_id,
            user_id=stored_token.user_id,
            action="auth.refresh.reuse_detected",
            resource_type="token_family",
            resource_id=stored_token.family_id,
            source_ip=request.client.host if request.client else None,
            metadata={"alert": "Refresh token reuse detected; entire family revoked."},
        )
        await db.commit()  # Persist revocation and audit event before raising HTTP 401
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token reuse detected. All sessions in this family have been terminated for security.",
        )

    # Check Expiration
    if ensure_utc(stored_token.expires_at) < utc_now():
        stored_token.is_revoked = True
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired. Please log in again.",
        )

    user = stored_token.user
    if not user.is_active or not user.organization.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account or organization inactive",
        )

    # Rotate Token:
    # Invalidate old token and issue new refresh token in the same family
    raw_new_rt, new_rt_hash, _, new_expires_at = create_refresh_token(user.id, family_id=stored_token.family_id)
    await user_repo.rotate_refresh_token(stored_token, new_rt_hash, new_expires_at)
    new_access_token = create_access_token(user.id, user.organization_id, user.role)

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=raw_new_rt,
        token_type="bearer",
        expires_in_sec=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/logout")
async def logout(payload: TokenRefreshRequest, db: AsyncSession = Depends(get_db)):
    user_repo = UserRepository(db)
    rt_hash = hash_token(payload.refresh_token)
    await user_repo.revoke_token(rt_hash)
    return {"status": "logged_out", "message": "Session invalidated successfully"}


@router.get("/me", response_model=UserOut)
async def get_me(current_user: User = Depends(get_current_user)):
    return UserOut(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        role=current_user.role,
        organization_id=current_user.organization_id,
        organization_name=current_user.organization.name,
        is_active=current_user.is_active,
        permissions=list(get_role_permissions(current_user.role)),
    )
