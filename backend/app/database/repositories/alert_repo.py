"""
Alert Repository for Threat Detection Storage and Metrics.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.alert import Alert
from ..base import utc_now


def _to_dt(ts: float | None) -> datetime:
    if ts is None:
        return utc_now()
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc)
    except Exception:
        return utc_now()


class AlertRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def record_alert(
        self,
        organization_id: str,
        device_id: str,
        flow: dict,
        attack_type: str,
        mitre: Optional[str],
        severity: str,
        gate_score: float,
        anomaly_score: float,
        confidence_tier: str,
        top_features: list,
        shap_values: Optional[list] = None,
        shap_base_value: Optional[float] = None,
        decision: Optional[str] = None,
        is_unknown: bool = False,
        novelty_score: Optional[float] = None,
        calibrated_anomaly_score: Optional[float] = None,
        reason_codes: Optional[list] = None,
        composite_device_risk: Optional[float] = None,
        fused_event_threat: Optional[float] = None,
        risk_tier: Optional[str] = None,
        temporal_risk: Optional[float] = None,
        graph_risk: Optional[float] = None,
        risk_breakdown: Optional[dict] = None,
        flow_id: Optional[int] = None,
    ) -> Alert:
        alert = Alert(
            organization_id=organization_id,
            device_id=device_id,
            flow_id=flow_id,
            timestamp=_to_dt(flow.get("ts")),
            attack_type=attack_type,
            mitre=mitre,
            severity=severity,
            gate_score=float(gate_score),
            anomaly_score=float(anomaly_score),
            confidence_tier=confidence_tier,
            top_features=top_features or [],
            raw_flow=flow or {},
            shap_values=shap_values or [],
            shap_base_value=float(shap_base_value) if shap_base_value is not None else None,
            decision=decision,
            is_unknown=bool(is_unknown),
            novelty_score=float(novelty_score) if novelty_score is not None else None,
            calibrated_anomaly_score=float(calibrated_anomaly_score) if calibrated_anomaly_score is not None else None,
            reason_codes=reason_codes or [],
            composite_device_risk=float(composite_device_risk) if composite_device_risk is not None else None,
            fused_event_threat=float(fused_event_threat) if fused_event_threat is not None else None,
            risk_tier=risk_tier,
            temporal_risk=float(temporal_risk) if temporal_risk is not None else None,
            graph_risk=float(graph_risk) if graph_risk is not None else None,
            risk_breakdown=risk_breakdown or {},
            status="active",
        )
        self.db.add(alert)
        await self.db.flush()
        return alert

    async def list_by_organization(self, organization_id: str, limit: int = 100) -> List[Alert]:
        stmt = (
            select(Alert)
            .where(Alert.organization_id == organization_id)
            .order_by(Alert.id.desc())
            .limit(limit)
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def count_by_organization(self, organization_id: str) -> int:
        stmt = select(func.count()).select_from(Alert).where(Alert.organization_id == organization_id)
        result = await self.db.execute(stmt)
        return result.scalar() or 0

    async def count_unknown(self, organization_id: str) -> int:
        stmt = (
            select(func.count())
            .select_from(Alert)
            .where(
                Alert.organization_id == organization_id,
                (Alert.is_unknown.is_(True)) | (Alert.attack_type == "unknown_suspicious"),
            )
        )
        result = await self.db.execute(stmt)
        return result.scalar() or 0

    async def counts_by_attack_type(self, organization_id: str) -> Dict[str, int]:
        stmt = (
            select(Alert.attack_type, func.count(Alert.id))
            .where(Alert.organization_id == organization_id)
            .group_by(Alert.attack_type)
        )
        result = await self.db.execute(stmt)
        return {row[0]: row[1] for row in result.all()}
