"""
Device model for IoT endpoints and asset posture tracking.
"""

from datetime import datetime
from typing import List, Optional
from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base, TimestampMixin, generate_uuid, utc_now


class Device(Base, TimestampMixin):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    device_identifier: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    device_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    mac_address: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    
    flow_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    alert_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    risk_tier: Mapped[str] = mapped_column(String(16), default="LOW", nullable=False)
    temporal_risk: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    graph_risk: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    __table_args__ = (
        Index("ix_device_org_identifier", "organization_id", "device_identifier", unique=True),
        Index("ix_device_risk_tier", "organization_id", "risk_tier"),
    )

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization", back_populates="devices")
    flows: Mapped[List["NetworkFlow"]] = relationship("NetworkFlow", back_populates="device", cascade="all, delete-orphan")
    alerts: Mapped[List["Alert"]] = relationship("Alert", back_populates="device", cascade="all, delete-orphan")
    incidents: Mapped[List["Incident"]] = relationship("Incident", back_populates="device", cascade="all, delete-orphan")
    risk_history: Mapped[List["RiskHistory"]] = relationship("RiskHistory", back_populates="device", cascade="all, delete-orphan")
