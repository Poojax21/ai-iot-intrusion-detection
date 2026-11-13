"""
Sensor model for Network Probes and Secure Ingestion.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base, TimestampMixin, generate_uuid


class Sensor(Base, TimestampMixin):
    __tablename__ = "sensors"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    sensor_name: Mapped[str] = mapped_column(String(128), nullable=False)
    sensor_identifier: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    api_key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    rate_limit_per_sec: Mapped[int] = mapped_column(Integer, default=500, nullable=False)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_sensor_org_identifier", "organization_id", "sensor_identifier", unique=True),
    )

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization", back_populates="sensors")
