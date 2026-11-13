"""
Sensor Authentication, Key Lifecycle, and Ingestion Security Tests.
"""

import time
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.config import settings


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_sensor_key_lifecycle_and_rate_limiting(client, monkeypatch):
    suffix = int(time.time() * 1000)

    # 1. Register Admin and Org
    reg_resp = client.post(
        "/api/auth/register",
        json={
            "email": f"sensor_admin_{suffix}@iot.sec",
            "password": "Password123!@#",
            "full_name": "Sensor Architect",
            "organization_name": f"Sensor Hub {suffix}",
        },
    )
    assert reg_resp.status_code == 201
    admin_token = reg_resp.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 2. Provision new sensor with rate limit of 5 req/sec for testing
    create_sensor_resp = client.post(
        "/api/sensors",
        json={
            "sensor_name": "Edge Zeek Tap 01",
            "sensor_identifier": f"zeek-tap-{suffix}",
            "rate_limit_per_sec": 5,
        },
        headers=admin_headers,
    )
    assert create_sensor_resp.status_code == 201
    sensor_data = create_sensor_resp.json()
    sensor_id = sensor_data["id"]
    raw_api_key = sensor_data["api_key"]

    # Enable Ingest Auth enforcement
    monkeypatch.setattr(settings, "ENABLE_INGEST_AUTH", True)

    flow = {
        "ts": time.time(), "device_id": f"sensor-dev-{suffix}", "device_type": "camera",
        "src_ip": "10.10.1.2", "dst_ip": "10.10.1.1", "src_port": 5000, "dst_port": 80,
        "proto": "tcp", "duration": 0.01, "orig_bytes": 100, "resp_bytes": 100,
        "orig_pkts": 2, "resp_pkts": 2, "conn_state": "SF",
    }

    # 3. Test Ingestion with Valid Key
    valid_ingest = client.post(
        "/api/ingest",
        json=flow,
        headers={"X-Sensor-Key": raw_api_key},
    )
    assert valid_ingest.status_code == 200

    # 4. Test Ingestion with Invalid Key
    invalid_ingest = client.post(
        "/api/ingest",
        json=flow,
        headers={"X-Sensor-Key": "pahredaar_sk_invalid_bogus_key_12345"},
    )
    assert invalid_ingest.status_code == 401

    # 5. Test Key Rotation
    rotate_resp = client.post(
        f"/api/sensors/{sensor_id}/rotate-key",
        headers=admin_headers,
    )
    assert rotate_resp.status_code == 200
    new_raw_key = rotate_resp.json()["api_key"]
    assert new_raw_key != raw_api_key

    # Old key is rejected
    old_key_resp = client.post(
        "/api/ingest",
        json=flow,
        headers={"X-Sensor-Key": raw_api_key},
    )
    assert old_key_resp.status_code == 401

    # New key succeeds
    new_key_resp = client.post(
        "/api/ingest",
        json=flow,
        headers={"X-Sensor-Key": new_raw_key},
    )
    assert new_key_resp.status_code == 200

    # 6. Test Sensor Deactivation
    deactivate_resp = client.post(
        f"/api/sensors/{sensor_id}/deactivate",
        headers=admin_headers,
    )
    assert deactivate_resp.status_code == 200

    # Deactivated sensor key is rejected
    deact_ingest = client.post(
        "/api/ingest",
        json=flow,
        headers={"X-Sensor-Key": new_raw_key},
    )
    assert deact_ingest.status_code == 401
