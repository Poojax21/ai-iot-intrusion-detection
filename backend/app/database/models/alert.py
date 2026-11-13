"""
Alert model for Multi-Modal Threat Detections & SHAP Explanations.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base, utc_now


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(String(36), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    flow_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("network_flows.id", ondelete="SET NULL"), nullable=True, index=True)

    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    attack_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    mitre: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="warning", nullable=False, index=True)
    gate_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    confidence_tier: Mapped[str] = mapped_column(String(16), default="medium", nullable=False)

    top_features: Mapped[List[Any]] = mapped_column(JSON, default=list, nullable=False)
    raw_flow: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    shap_values: Mapped[List[Any]] = mapped_column(JSON, default=list, nullable=False)
    shap_base_value: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    decision: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    is_unknown: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    novelty_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    calibrated_anomaly_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    reason_codes: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)

    composite_device_risk: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    fused_event_threat: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    risk_tier: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    temporal_risk: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    graph_risk: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    risk_breakdown: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)

    __table_args__ = (
        Index("ix_alert_org_ts", "organization_id", "timestamp"),
        Index("ix_alert_org_attack", "organization_id", "attack_type"),
        Index("ix_alert_org_sev", "organization_id", "severity"),
    )

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization", back_populates="alerts")
    device: Mapped["Device"] = relationship("Device", back_populates="alerts")
    flow: Mapped[Optional["NetworkFlow"]] = relationship("NetworkFlow", back_populates="alerts")
