"""
Network Flow Repository for Telemetry Ingestion.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.flow import NetworkFlow
from ..base import utc_now


def _to_dt(ts: float | None) -> datetime:
    if ts is None:
        return utc_now()
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc)
    except Exception:
        return utc_now()


class FlowRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def record_flow(
        self,
        organization_id: str,
        device_id: str,
        flow: dict,
        gate_score: float,
        is_flagged: bool,
        risk_score: Optional[float] = None,
        flow_features: Optional[dict] = None,
    ) -> NetworkFlow:
        nf = NetworkFlow(
            organization_id=organization_id,
            device_id=device_id,
            timestamp=_to_dt(flow.get("ts")),
            source_ip=flow["src_ip"],
            destination_ip=flow["dst_ip"],
            source_port=int(flow["src_port"]),
            destination_port=int(flow["dst_port"]),
            protocol=flow["proto"],
            duration=float(flow.get("duration", 0.0)),
            orig_bytes=int(flow.get("orig_bytes", 0)),
            resp_bytes=int(flow.get("resp_bytes", 0)),
            orig_pkts=int(flow.get("orig_pkts", 0)),
            resp_pkts=int(flow.get("resp_pkts", 0)),
            conn_state=flow.get("conn_state", "SF"),
            flow_features=flow_features or {},
            gate_score=float(gate_score),
            is_flagged=bool(is_flagged),
            risk_score=float(risk_score) if risk_score is not None else None,
        )
        self.db.add(nf)
        await self.db.flush()
        return nf

    async def list_by_organization(self, organization_id: str, limit: int = 100) -> List[NetworkFlow]:
        stmt = (
            select(NetworkFlow)
            .where(NetworkFlow.organization_id == organization_id)
            .order_by(NetworkFlow.id.desc())
            .limit(limit)
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def count_by_organization(self, organization_id: str) -> int:
        stmt = select(func.count()).select_from(NetworkFlow).where(NetworkFlow.organization_id == organization_id)
        result = await self.db.execute(stmt)
        return result.scalar() or 0
