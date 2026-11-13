"""
Network Flow model for Ingestion and Traffic Telemetry.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base, utc_now


class NetworkFlow(Base):
    __tablename__ = "network_flows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(String(36), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    destination_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    source_port: Mapped[int] = mapped_column(Integer, nullable=False)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    duration: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    orig_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    resp_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    orig_pkts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    resp_pkts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    conn_state: Mapped[str] = mapped_column(String(16), default="SF", nullable=False)

    flow_features: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    gate_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    is_flagged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    __table_args__ = (
        Index("ix_flow_org_ts", "organization_id", "timestamp"),
        Index("ix_flow_org_flagged", "organization_id", "is_flagged"),
    )

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization", back_populates="flows")
    device: Mapped["Device"] = relationship("Device", back_populates="flows")
    alerts: Mapped[List["Alert"]] = relationship("Alert", back_populates="flow")
