"""
Risk History model for continuous posture and threat trajectory tracking.
"""

from datetime import datetime
from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base, utc_now


class RiskHistory(Base):
    __tablename__ = "risk_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(String(36), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)

    event_risk: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    posture_risk: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    risk_tier: Mapped[str] = mapped_column(String(16), default="LOW", nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    __table_args__ = (
        Index("ix_risk_hist_org_dev_ts", "organization_id", "device_id", "timestamp"),
    )

    # Relationships
    device: Mapped["Device"] = relationship("Device", back_populates="risk_history")
