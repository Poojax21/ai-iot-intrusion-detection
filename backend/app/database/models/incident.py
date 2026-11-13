"""
Incident model for Correlated Threats & SOC Response Lifecycle.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base, TimestampMixin, utc_now


class Incident(Base, TimestampMixin):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    incident_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(String(36), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="warning", nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", nullable=False, index=True)  # OPEN, ACKNOWLEDGED, RESOLVED
    attack_type: Mapped[str] = mapped_column(String(64), nullable=False)
    alert_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    mitre: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    assigned_to: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    __table_args__ = (
        Index("ix_incident_org_status", "organization_id", "status"),
        Index("ix_incident_org_last_seen", "organization_id", "last_seen"),
    )

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization", back_populates="incidents")
    device: Mapped["Device"] = relationship("Device", back_populates="incidents")
    assignee: Mapped[Optional["User"]] = relationship("User")
