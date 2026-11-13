"""
User and Refresh Token Repository.
"""

from datetime import datetime
from typing import List, Optional
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..models.user import User, RefreshToken
from ..base import generate_uuid, utc_now


class UserRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_id(self, user_id: str) -> Optional[User]:
        stmt = select(User).options(selectinload(User.organization)).where(User.id == user_id)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str, org_id: Optional[str] = None) -> Optional[User]:
        stmt = select(User).options(selectinload(User.organization)).where(User.email == email.lower())
        if org_id:
            stmt = stmt.where(User.organization_id == org_id)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def create(
        self,
        organization_id: str,
        full_name: str,
        email: str,
        password_hash: str,
        role: str = "viewer",
    ) -> User:
        user = User(
            id=generate_uuid(),
            organization_id=organization_id,
            full_name=full_name,
            email=email.lower(),
            password_hash=password_hash,
            role=role,
            is_active=True,
            is_verified=True,
        )
        self.db.add(user)
        await self.db.flush()
        return user

    async def update_last_login(self, user_id: str):
        stmt = update(User).where(User.id == user_id).values(last_login=utc_now())
        await self.db.execute(stmt)

    async def store_refresh_token(
        self,
        user_id: str,
        token_hash: str,
        family_id: str,
        expires_at: datetime,
    ) -> RefreshToken:
        token = RefreshToken(
            id=generate_uuid(),
            user_id=user_id,
            token_hash=token_hash,
            family_id=family_id,
            expires_at=expires_at,
            is_revoked=False,
        )
        self.db.add(token)
        await self.db.flush()
        return token

    async def get_refresh_token(self, token_hash: str) -> Optional[RefreshToken]:
        stmt = (
            select(RefreshToken)
            .options(selectinload(RefreshToken.user).selectinload(User.organization))
            .where(RefreshToken.token_hash == token_hash)
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def rotate_refresh_token(
        self,
        old_token: RefreshToken,
        new_token_hash: str,
        new_expires_at: datetime,
    ) -> RefreshToken:
        old_token.is_revoked = True
        new_token = RefreshToken(
            id=generate_uuid(),
            user_id=old_token.user_id,
            token_hash=new_token_hash,
            family_id=old_token.family_id,
            expires_at=new_expires_at,
            is_revoked=False,
        )
        self.db.add(new_token)
        await self.db.flush()
        return new_token

    async def revoke_family(self, family_id: str):
        stmt = update(RefreshToken).where(RefreshToken.family_id == family_id).values(is_revoked=True)
        await self.db.execute(stmt)

    async def revoke_token(self, token_hash: str):
        stmt = update(RefreshToken).where(RefreshToken.token_hash == token_hash).values(is_revoked=True)
        await self.db.execute(stmt)
