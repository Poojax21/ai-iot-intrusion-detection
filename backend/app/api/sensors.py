"""
Sensor Provisioning & Key Lifecycle Management API Routes.
"""

import re
import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..database.session import get_db
from ..database.models import User
from ..database.repositories import SensorRepository, AuditRepository
from ..database.base import utc_now
from ..schemas import (
    SensorCreate,
    SensorCreateResponse,
    SensorOut,
    SensorRotateKeyResponse,
)
from ..auth.security import generate_sensor_key
from ..auth.rbac import Role
from ..auth.dependencies import get_current_user_optional, require_roles

router = APIRouter(prefix="/api/sensors", tags=["Sensors"])


@router.post("", response_model=SensorCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_sensor(
    payload: SensorCreate,
    request: Request,
    current_user: User = Depends(require_roles(Role.ADMIN.value)),
    db: AsyncSession = Depends(get_db),
):
    sensor_repo = SensorRepository(db)
    audit_repo = AuditRepository(db)

    org_id = current_user.organization_id
    user_id = current_user.id

    s_name = payload.sensor_name or payload.name or "Unnamed Sensor"
    s_ident = payload.sensor_identifier or (re.sub(r"[^a-zA-Z0-9_-]", "-", s_name.lower()) + "-" + uuid.uuid4().hex[:6])

    raw_key, key_hash = generate_sensor_key()
    try:
        sensor = await sensor_repo.create(
            organization_id=org_id,
            sensor_name=s_name,
            sensor_identifier=s_ident,
            api_key_hash=key_hash,
            rate_limit_per_sec=payload.rate_limit_per_sec,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Sensor identifier '{s_ident}' already exists or invalid in this organization.",
        )

    await audit_repo.record_event(
        organization_id=org_id,
        user_id=user_id,
        action="sensor.create",
        resource_type="sensor",
        resource_id=sensor.id,
        source_ip=request.client.host if request.client else None,
        metadata={"sensor_name": sensor.sensor_name, "identifier": sensor.sensor_identifier},
    )

    return SensorCreateResponse(
        id=sensor.id,
        sensor_name=sensor.sensor_name,
        sensor_identifier=sensor.sensor_identifier,
        api_key=raw_key,
        organization_id=sensor.organization_id,
        rate_limit_per_sec=sensor.rate_limit_per_sec,
        name=sensor.sensor_name,
        key=raw_key,
        prefix=raw_key[:8] if raw_key else "pds_xxxx",
    )


@router.get("", response_model=List[SensorOut])
async def list_sensors(
    current_user: User = Depends(require_roles(Role.ADMIN.value, Role.ANALYST.value)),
    db: AsyncSession = Depends(get_db),
):
    sensor_repo = SensorRepository(db)
    sensors = await sensor_repo.list_by_organization(current_user.organization_id)
    return [
        SensorOut(
            id=s.id,
            sensor_name=s.sensor_name,
            sensor_identifier=s.sensor_identifier,
            is_active=s.is_active,
            rate_limit_per_sec=s.rate_limit_per_sec,
            last_seen=s.last_seen.isoformat() if s.last_seen else None,
            created_at=s.created_at.isoformat() if s.created_at else utc_now().isoformat(),
            name=s.sensor_name,
            prefix="pds_" + s.id[:4],
            status="active" if s.is_active else "revoked",
        )
        for s in sensors
    ]


@router.post("/{sensor_id}/rotate-key", response_model=SensorRotateKeyResponse)
async def rotate_sensor_key(
    sensor_id: str,
    request: Request,
    current_user: User = Depends(require_roles(Role.ADMIN.value)),
    db: AsyncSession = Depends(get_db),
):
    sensor_repo = SensorRepository(db)
    audit_repo = AuditRepository(db)

    sensor = await sensor_repo.get_by_id(sensor_id, current_user.organization_id)
    if not sensor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sensor not found")

    new_raw_key, new_key_hash = generate_sensor_key()
    await sensor_repo.rotate_key(sensor_id, current_user.organization_id, new_key_hash)

    await audit_repo.record_event(
        organization_id=current_user.organization_id,
        user_id=current_user.id,
        action="sensor.rotate_key",
        resource_type="sensor",
        resource_id=sensor.id,
        source_ip=request.client.host if request.client else None,
        metadata={"sensor_identifier": sensor.sensor_identifier},
    )

    return SensorRotateKeyResponse(
        id=sensor.id,
        sensor_identifier=sensor.sensor_identifier,
        api_key=new_raw_key,
        rotated_at=utc_now().isoformat(),
    )


@router.post("/{sensor_id}/deactivate")
async def deactivate_sensor(
    sensor_id: str,
    request: Request,
    current_user: User = Depends(require_roles(Role.ADMIN.value)),
    db: AsyncSession = Depends(get_db),
):
    sensor_repo = SensorRepository(db)
    audit_repo = AuditRepository(db)

    sensor = await sensor_repo.get_by_id(sensor_id, current_user.organization_id)
    if not sensor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sensor not found")

    await sensor_repo.set_active_status(sensor_id, current_user.organization_id, is_active=False)

    await audit_repo.record_event(
        organization_id=current_user.organization_id,
        user_id=current_user.id,
        action="sensor.deactivate",
        resource_type="sensor",
        resource_id=sensor.id,
        source_ip=request.client.host if request.client else None,
        metadata={"sensor_identifier": sensor.sensor_identifier},
    )

    return {"status": "deactivated", "sensor_id": sensor_id}


@router.delete("/{sensor_id}")
async def delete_sensor(
    sensor_id: str,
    request: Request,
    current_user: User = Depends(require_roles(Role.ADMIN.value)),
    db: AsyncSession = Depends(get_db),
):
    sensor_repo = SensorRepository(db)
    sensor = await sensor_repo.get_by_id(sensor_id, current_user.organization_id)
    if not sensor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sensor not found")
    await sensor_repo.set_active_status(sensor_id, current_user.organization_id, is_active=False)
    return {"status": "revoked", "sensor_id": sensor_id}
