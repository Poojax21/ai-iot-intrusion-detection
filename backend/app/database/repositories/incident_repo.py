"""
Incident Repository for Threat Correlation and SOC Response Lifecycle.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import uuid
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..models.incident import Incident
from ..base import utc_now


def _to_dt(ts: float | None) -> datetime:
    if ts is None:
        return utc_now()
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc)
    except Exception:
        return utc_now()


class IncidentRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def correlate_incident(
        self,
        organization_id: str,
        device_id: str,
        device_identifier: str,
        flow: dict,
        attack_type: str,
        severity: str,
        mitre: Optional[str],
    ) -> Incident:
        now_dt = _to_dt(flow.get("ts"))
        window_dt = now_dt - timedelta(seconds=60.0)

        # Look for open or acknowledged incident on the same device within the correlation window
        stmt = (
            select(Incident)
            .where(
                Incident.organization_id == organization_id,
                Incident.device_id == device_id,
                Incident.status.in_(["OPEN", "ACKNOWLEDGED"]),
                Incident.last_seen >= window_dt,
            )
            .order_by(Incident.id.desc())
            .limit(1)
        )
        result = await self.db.execute(stmt)
        active_inc = result.scalar_one_or_none()

        sev_order = {"info": 1, "warning": 2, "critical": 3}
        if not active_inc:
            inc_id = f"INC-{int(now_dt.timestamp())}-{device_identifier[:4]}-{uuid.uuid4().hex[:6]}"
            title = f"{attack_type.upper().replace('_', ' ')} Incident on {device_identifier}"
            summary = f"Detected {attack_type} activity targeting or originating from {flow.get('src_ip', 'unknown')}."
            incident = Incident(
                organization_id=organization_id,
                incident_id=inc_id,
                device_id=device_id,
                title=title,
                description=summary,
                severity=severity,
                status="OPEN",
                attack_type=attack_type,
                alert_count=1,
                first_seen=now_dt,
                last_seen=now_dt,
                mitre=mitre,
            )
            self.db.add(incident)
            await self.db.flush()
            return incident
        else:
            active_inc.alert_count += 1
            active_inc.last_seen = now_dt
            current_sev = active_inc.severity
            if sev_order.get(severity, 1) > sev_order.get(current_sev, 1):
                active_inc.severity = severity
            active_inc.description = f"{active_inc.description.split(' (Total alerts:')[0]} (Total alerts: {active_inc.alert_count})"
            await self.db.flush()
            return active_inc

    async def list_by_organization(
        self,
        organization_id: str,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[Incident]:
        stmt = (
            select(Incident)
            .where(Incident.organization_id == organization_id)
            .order_by(Incident.last_seen.desc())
            .limit(limit)
        )
        if status:
            stmt = stmt.where(Incident.status == status)
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_by_incident_id(self, incident_id: str, organization_id: str) -> Optional[Incident]:
        stmt = select(Incident).where(
            Incident.incident_id == incident_id,
            Incident.organization_id == organization_id,
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def acknowledge(self, incident_id: str, organization_id: str, user_id: Optional[str] = None) -> bool:
        stmt = (
            update(Incident)
            .where(
                Incident.incident_id == incident_id,
                Incident.organization_id == organization_id,
                Incident.status == "OPEN",
            )
            .values(
                status="ACKNOWLEDGED",
                acknowledged_at=utc_now(),
                assigned_to=user_id,
                updated_at=utc_now(),
            )
        )
        result = await self.db.execute(stmt)
        return result.rowcount > 0

    async def resolve(
        self,
        incident_id: str,
        organization_id: str,
        notes: str = "",
        user_id: Optional[str] = None,
    ) -> bool:
        stmt = (
            update(Incident)
            .where(
                Incident.incident_id == incident_id,
                Incident.organization_id == organization_id,
                Incident.status.in_(["OPEN", "ACKNOWLEDGED"]),
            )
            .values(
                status="RESOLVED",
                resolved_at=utc_now(),
                resolution_notes=notes,
                assigned_to=user_id,
                updated_at=utc_now(),
            )
        )
        result = await self.db.execute(stmt)
        return result.rowcount > 0

    async def get_metrics(self, organization_id: str) -> Dict[str, Any]:
        total_stmt = select(func.count()).select_from(Incident).where(Incident.organization_id == organization_id)
        open_stmt = total_stmt.where(Incident.status == "OPEN")
        ack_stmt = total_stmt.where(Incident.status == "ACKNOWLEDGED")
        res_stmt = total_stmt.where(Incident.status == "RESOLVED")

        total = (await self.db.execute(total_stmt)).scalar() or 0
        open_cnt = (await self.db.execute(open_stmt)).scalar() or 0
        ack_cnt = (await self.db.execute(ack_stmt)).scalar() or 0
        res_cnt = (await self.db.execute(res_stmt)).scalar() or 0

        # Calculate MTTA & MTTR across all incidents in the organization
        resolved_incidents_stmt = select(Incident).where(
            Incident.organization_id == organization_id,
            Incident.resolved_at.is_not(None),
        )
        resolved_res = await self.db.execute(resolved_incidents_stmt)
        resolved_list = list(resolved_res.scalars().all())

        ack_incidents_stmt = select(Incident).where(
            Incident.organization_id == organization_id,
            Incident.acknowledged_at.is_not(None),
        )
        ack_res = await self.db.execute(ack_incidents_stmt)
        ack_list = list(ack_res.scalars().all())

        mtta_secs = [
            (inc.acknowledged_at - inc.first_seen).total_seconds()
            for inc in ack_list
            if inc.acknowledged_at and inc.first_seen
        ]
        mttr_secs = [
            (inc.resolved_at - inc.first_seen).total_seconds()
            for inc in resolved_list
            if inc.resolved_at and inc.first_seen
        ]

        avg_mtta = sum(mtta_secs) / len(mtta_secs) if mtta_secs else 0.0
        avg_mttr = sum(mttr_secs) / len(mttr_secs) if mttr_secs else 0.0

        return {
            "total_incidents": total,
            "open_incidents": open_cnt,
            "acknowledged_incidents": ack_cnt,
            "resolved_incidents": res_cnt,
            "mean_time_to_acknowledge_sec": round(avg_mtta, 2),
            "mean_time_to_resolve_sec": round(avg_mttr, 2),
        }
