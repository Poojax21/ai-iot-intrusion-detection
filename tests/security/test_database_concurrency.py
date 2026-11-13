"""
Database Concurrency, Pooling & Transaction Rollback Tests.
"""

import asyncio
import time
import pytest
from sqlalchemy import select, func

from backend.app.database.engine import AsyncSessionLocal
from backend.app.database.models import User, Organization, AuditEvent
from backend.app.database.base import generate_uuid, utc_now
from backend.app.auth.security import hash_password


@pytest.mark.asyncio
async def test_concurrent_database_transactions():
    """Verify concurrent async session handling without pool exhaustion or deadlocks."""
    suffix = int(time.time() * 1000)

    # 1. Setup tenant
    async with AsyncSessionLocal() as db:
        org = Organization(
            id=generate_uuid(),
            name=f"Concurrency Org {suffix}",
            slug=f"concurrent-org-{suffix}",
            is_active=True,
        )
        db.add(org)
        await db.commit()
        org_id = org.id

    # 2. Concurrently insert 20 audit events across separate sessions
    async def insert_audit_event(i: int):
        async with AsyncSessionLocal() as db:
            event = AuditEvent(
                organization_id=org_id,
                action=f"concurrent.task.{i}",
                resource_type="concurrency_test",
                resource_id=f"item-{i}",
                timestamp=utc_now(),
                event_metadata={"index": i},
            )
            db.add(event)
            await db.commit()

    tasks = [insert_audit_event(i) for i in range(20)]
    await asyncio.gather(*tasks)

    # 3. Verify all 20 records were persisted safely
    async with AsyncSessionLocal() as db:
        stmt = select(func.count()).select_from(AuditEvent).where(AuditEvent.organization_id == org_id)
        result = await db.execute(stmt)
        count = result.scalar()
        assert count == 20


@pytest.mark.asyncio
async def test_transaction_rollback_safety():
    """Verify that an exception causes a clean rollback without corrupting the session."""
    suffix = int(time.time() * 1000)

    async with AsyncSessionLocal() as db:
        org = Organization(
            id=generate_uuid(),
            name=f"Rollback Org {suffix}",
            slug=f"rollback-org-{suffix}",
            is_active=True,
        )
        db.add(org)
        await db.commit()
        org_id = org.id

    # Attempt a transaction that fails halfway
    try:
        async with AsyncSessionLocal() as db:
            user1 = User(
                id=generate_uuid(),
                organization_id=org_id,
                full_name="Valid User",
                email=f"valid_{suffix}@org.io",
                password_hash=hash_password("Pass123!"),
                role="viewer",
            )
            db.add(user1)
            await db.flush()

            # Trigger an intentional error (duplicate primary key constraint violation)
            bad_user = User(
                id=user1.id,  # Duplicate PK
                organization_id=org_id,
                full_name="Duplicate PK User",
                email=f"dup_{suffix}@org.io",
                password_hash="hash",
                role="viewer",
            )
            db.add(bad_user)
            await db.commit()
    except Exception:
        pass  # Expected rollback

    # Verify user1 was rolled back and not persisted
    async with AsyncSessionLocal() as db:
        stmt = select(User).where(User.organization_id == org_id)
        result = await db.execute(stmt)
        users = list(result.scalars().all())
        assert len(users) == 0
