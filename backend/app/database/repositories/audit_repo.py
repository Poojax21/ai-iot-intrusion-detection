"""
Audit Event Repository for Security & Compliance Auditing.
"""

from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..models.audit import AuditEvent
from ..base import utc_now


class AuditRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def record_event(
        self,
        organization_id: str,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        user_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        audit = AuditEvent(
            organization_id=organization_id,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            timestamp=utc_now(),
            source_ip=source_ip,
            event_metadata=metadata or {},
        )
        self.db.add(audit)
        await self.db.flush()
        return audit

    async def list_by_organization(self, organization_id: str, limit: int = 100) -> List[AuditEvent]:
        stmt = (
            select(AuditEvent)
            .options(selectinload(AuditEvent.user))
            .where(AuditEvent.organization_id == organization_id)
            .order_by(AuditEvent.timestamp.desc())
            .limit(limit)
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())
