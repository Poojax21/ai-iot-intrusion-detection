"""
Base Declarative Model and common mixins for SQLAlchemy 2.x.
"""

from datetime import datetime, timezone
from typing import Any, Dict
import uuid

from sqlalchemy import DateTime, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


def generate_uuid() -> str:
    """Generate a clean 32-character hexadecimal UUID string."""
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    """Base declarative class for all Pahredaar-IoT models."""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model attributes to a standard dictionary."""
        res = {}
        for col in self.__table__.columns:
            val = getattr(self, col.name)
            if isinstance(val, datetime):
                res[col.name] = val.isoformat()
            else:
                res[col.name] = val
        return res


class TimestampMixin:
    """Standard audit timestamps for models."""
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )
