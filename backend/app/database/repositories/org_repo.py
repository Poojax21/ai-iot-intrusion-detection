"""
Organization Repository for Tenant Management.
"""

from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.organization import Organization
from ..base import generate_uuid


class OrganizationRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_id(self, org_id: str) -> Optional[Organization]:
        stmt = select(Organization).where(Organization.id == org_id)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_slug(self, slug: str) -> Optional[Organization]:
        stmt = select(Organization).where(Organization.slug == slug)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def create(self, name: str, slug: str) -> Organization:
        org = Organization(
            id=generate_uuid(),
            name=name,
            slug=slug,
            is_active=True,
        )
        self.db.add(org)
        await self.db.flush()
        return org

    async def list_all(self) -> List[Organization]:
        stmt = select(Organization).order_by(Organization.name)
        result = await self.db.execute(stmt)
        return list(result.scalars().all())
