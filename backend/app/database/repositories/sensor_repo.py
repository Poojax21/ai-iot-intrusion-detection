"""
Sensor Repository for Network Probe Registration and Key Lifecycle.
"""

from typing import List, Optional
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.sensor import Sensor
from ..base import generate_uuid, utc_now


class SensorRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(
        self,
        organization_id: str,
        sensor_name: str,
        sensor_identifier: str,
        api_key_hash: str,
        rate_limit_per_sec: int = 500,
    ) -> Sensor:
        sensor = Sensor(
            id=generate_uuid(),
            organization_id=organization_id,
            sensor_name=sensor_name,
            sensor_identifier=sensor_identifier,
            api_key_hash=api_key_hash,
            rate_limit_per_sec=rate_limit_per_sec,
            is_active=True,
            last_seen=None,
        )
        self.db.add(sensor)
        await self.db.flush()
        return sensor

    async def list_by_organization(self, organization_id: str) -> List[Sensor]:
        stmt = (
            select(Sensor)
            .where(Sensor.organization_id == organization_id)
            .order_by(Sensor.created_at.desc())
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_by_id(self, sensor_id: str, organization_id: str) -> Optional[Sensor]:
        stmt = select(Sensor).where(
            Sensor.id == sensor_id,
            Sensor.organization_id == organization_id,
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def rotate_key(self, sensor_id: str, organization_id: str, new_api_key_hash: str) -> bool:
        stmt = (
            update(Sensor)
            .where(Sensor.id == sensor_id, Sensor.organization_id == organization_id)
            .values(api_key_hash=new_api_key_hash, updated_at=utc_now())
        )
        result = await self.db.execute(stmt)
        return result.rowcount > 0

    async def set_active_status(self, sensor_id: str, organization_id: str, is_active: bool) -> bool:
        stmt = (
            update(Sensor)
            .where(Sensor.id == sensor_id, Sensor.organization_id == organization_id)
            .values(is_active=is_active, updated_at=utc_now())
        )
        result = await self.db.execute(stmt)
        return result.rowcount > 0
