"""
Role-Based Access Control (RBAC) Permission Enforcement Tests.
Verifies server-side permission checks across Admin, Analyst, and Viewer roles.
"""

import time
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.database.engine import AsyncSessionLocal
from backend.app.database.repositories import UserRepository
from backend.app.auth.security import create_access_token, hash_password


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.mark.asyncio
async def test_rbac_endpoint_restrictions(client):
    suffix = int(time.time() * 1000)
    org_name = f"RBAC Facility {suffix}"

    # 1. Register admin
    admin_reg = client.post(
        "/api/auth/register",
        json={
            "email": f"admin_{suffix}@corp.io",
            "password": "Password123!@#",
            "full_name": "Admin User",
            "organization_name": org_name,
        },
    )
    assert admin_reg.status_code == 201
    admin_token = admin_reg.json()["access_token"]

    # Get admin org_id
    me_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {admin_token}"})
    org_id = me_resp.json()["organization_id"]

    # 2. Programmatically create an Analyst and a Viewer in the same organization
    async with AsyncSessionLocal() as db:
        user_repo = UserRepository(db)
        analyst = await user_repo.create(
            organization_id=org_id,
            full_name="Analyst User",
            email=f"analyst_{suffix}@corp.io",
            password_hash=hash_password("Password123!@#"),
            role="analyst",
        )
        viewer = await user_repo.create(
            organization_id=org_id,
            full_name="Viewer User",
            email=f"viewer_{suffix}@corp.io",
            password_hash=hash_password("Password123!@#"),
            role="viewer",
        )
        await db.commit()
        analyst_id = analyst.id
        viewer_id = viewer.id

    analyst_token = create_access_token(analyst_id, org_id, "analyst")
    viewer_token = create_access_token(viewer_id, org_id, "viewer")

    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}

    # 3. Test Admin-only endpoint: POST /api/sensors
    sensor_payload = {"sensor_name": "Core Edge Probe", "sensor_identifier": f"probe-{suffix}"}

    # Admin CAN create sensor
    admin_sensor_resp = client.post("/api/sensors", json=sensor_payload, headers=admin_headers)
    assert admin_sensor_resp.status_code == 201
    sensor_id = admin_sensor_resp.json()["id"]

    # Analyst CANNOT create sensor (403 Forbidden)
    analyst_sensor_resp = client.post(
        "/api/sensors",
        json={"sensor_name": "Unauthorized Probe", "sensor_identifier": f"bad-{suffix}"},
        headers=analyst_headers,
    )
    assert analyst_sensor_resp.status_code == 403

    # Viewer CANNOT create sensor (403 Forbidden)
    viewer_sensor_resp = client.post(
        "/api/sensors",
        json={"sensor_name": "Unauthorized Probe 2", "sensor_identifier": f"bad2-{suffix}"},
        headers=viewer_headers,
    )
    assert viewer_sensor_resp.status_code == 403

    # 4. Test Incident modification: Viewer CANNOT acknowledge or resolve
    inc_ack_viewer = client.post("/api/incidents/fake-inc-id/acknowledge", headers=viewer_headers)
    assert inc_ack_viewer.status_code == 403
    assert "Viewers cannot acknowledge" in inc_ack_viewer.json()["detail"]

    inc_res_viewer = client.post("/api/incidents/fake-inc-id/resolve", headers=viewer_headers)
    assert inc_res_viewer.status_code == 403
    assert "Viewers cannot resolve" in inc_res_viewer.json()["detail"]

    # 5. Test Audit Logs: Admin CAN view, Analyst CANNOT view
    audit_admin_resp = client.get("/api/audit-logs", headers=admin_headers)
    assert audit_admin_resp.status_code == 200

    audit_analyst_resp = client.get("/api/audit-logs", headers=analyst_headers)
    assert audit_analyst_resp.status_code == 403
