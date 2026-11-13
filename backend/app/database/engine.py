"""
Database engine configuration supporting PostgreSQL (asyncpg) and SQLite (aiosqlite).
"""

from typing import AsyncGenerator
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool, QueuePool

from ..config import settings
from .base import Base
# Ensure all models are imported so Base.metadata knows about them
from . import models  # noqa: F401


def normalize_async_url(url: str) -> str:
    """Ensure URL uses an asynchronous driver for AsyncEngine."""
    if url.startswith("sqlite://"):
        return url.replace("sqlite://", "sqlite+aiosqlite://", 1)
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


def get_engine_args(url: str) -> dict:
    """Return appropriate connection pool parameters for the target database dialect."""
    args = {"echo": settings.DEBUG}
    if "sqlite" in url:
        args["connect_args"] = {"check_same_thread": False}
    elif "postgresql" in url:
        args["poolclass"] = QueuePool
        args["pool_size"] = settings.DB_POOL_SIZE
        args["max_overflow"] = settings.DB_MAX_OVERFLOW
        args["pool_timeout"] = settings.DB_POOL_TIMEOUT
        args["pool_recycle"] = settings.DB_POOL_RECYCLE
        args["pool_pre_ping"] = True
    return args


# Asynchronous Engine
_async_url = normalize_async_url(settings.DATABASE_URL)
async_engine: AsyncEngine = create_async_engine(
    _async_url,
    **get_engine_args(_async_url),
)

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    autoflush=False,
    expire_on_commit=False,
)


async def init_db_async():
    """Create all database tables asynchronously if they do not exist."""
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db_async():
    """Dispose of the database engine connections cleanly."""
    await async_engine.dispose()


def get_sync_database_url() -> str:
    """Convert async URL into synchronous URL for Alembic or sync utilities."""
    url = settings.DATABASE_URL
    if url.startswith("sqlite+aiosqlite:"):
        return url.replace("sqlite+aiosqlite:", "sqlite:")
    if url.startswith("postgresql+asyncpg:"):
        return url.replace("postgresql+asyncpg:", "postgresql+psycopg:")
    return url
