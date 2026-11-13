"""
Device Repository for IoT Asset Inventory and Posture Tracking.
"""

from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.device import Device
from ..base import generate_uuid, utc_now


def _to_dt(ts: float | None) -> datetime:
    if ts is None:
        return utc_now()
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc)
    except Exception:
        return utc_now()


class DeviceRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_identifier(self, organization_id: str, device_identifier: str) -> Optional[Device]:
        stmt = select(Device).where(
            Device.organization_id == organization_id,
            Device.device_identifier == device_identifier,
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_organization(self, organization_id: str) -> List[Device]:
        stmt = (
            select(Device)
            .where(Device.organization_id == organization_id)
            .order_by(Device.risk_score.desc())
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def touch_device(
        self,
        organization_id: str,
        flow: dict,
        bump_alert: bool = False,
        composite_risk: Optional[float] = None,
        risk_tier: Optional[str] = None,
        temporal_risk: Optional[float] = None,
        graph_risk: Optional[float] = None,
    ) -> Device:
        dev_ident = flow["device_id"]
        stmt = select(Device).where(
            Device.organization_id == organization_id,
            Device.device_identifier == dev_ident,
        )
        result = await self.db.execute(stmt)
        dev = result.scalar_one_or_none()

        tier = risk_tier or "LOW"
        t_risk = float(temporal_risk or 0.0)
        g_risk = float(graph_risk or 0.0)
        ts_dt = _to_dt(flow.get("ts"))

        if not dev:
            initial_risk = float(composite_risk) if composite_risk is not None else (1.0 if bump_alert else 0.0)
            dev = Device(
                id=generate_uuid(),
                organization_id=organization_id,
                device_identifier=dev_ident,
                device_type=flow.get("device_type"),
                ip_address=flow.get("src_ip"),
                status="active",
                flow_count=1,
                alert_count=1 if bump_alert else 0,
                risk_score=initial_risk,
                risk_tier=tier,
                temporal_risk=t_risk,
                graph_risk=g_risk,
                first_seen=ts_dt,
                last_seen=ts_dt,
            )
            self.db.add(dev)
        else:
            dev.flow_count += 1
            if bump_alert:
                dev.alert_count += 1
            if composite_risk is not None:
                dev.risk_score = float(composite_risk)
            else:
                dev.risk_score = min(100.0, dev.risk_score * 0.98 + (10.0 if bump_alert else 0.0))
            dev.last_seen = ts_dt
            dev.ip_address = flow.get("src_ip")
            dev.risk_tier = tier
            dev.temporal_risk = t_risk
            dev.graph_risk = g_risk

        await self.db.flush()
        return dev
