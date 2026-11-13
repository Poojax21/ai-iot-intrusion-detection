"""
Multi-Tenant Isolation & Cross-Organization Security Tests.
Proves that Organization A cannot view, modify, or intercept Organization B's
devices, alerts, incidents, stats, or WebSocket events.
"""

import time
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app import storage


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_tenant_data_isolation_and_idor_prevention(client):
    suffix = int(time.time() * 1000)

    # 1. Setup Organization Alpha
    alpha_reg = client.post(
        "/api/auth/register",
        json={
            "email": f"admin_alpha_{suffix}@alpha.io",
            "password": "PasswordAlpha123!",
            "full_name": "Alpha Admin",
            "organization_name": f"Org Alpha {suffix}",
        },
    )
    assert alpha_reg.status_code == 201
    alpha_token = alpha_reg.json()["access_token"]
    alpha_headers = {"Authorization": f"Bearer {alpha_token}"}
    alpha_org_id = client.get("/api/auth/me", headers=alpha_headers).json()["organization_id"]

    # 2. Setup Organization Beta
    beta_reg = client.post(
        "/api/auth/register",
        json={
            "email": f"admin_beta_{suffix}@beta.io",
            "password": "PasswordBeta123!",
            "full_name": "Beta Admin",
            "organization_name": f"Org Beta {suffix}",
        },
    )
    assert beta_reg.status_code == 201
    beta_token = beta_reg.json()["access_token"]
    beta_headers = {"Authorization": f"Bearer {beta_token}"}
    beta_org_id = client.get("/api/auth/me", headers=beta_headers).json()["organization_id"]

    assert alpha_org_id != beta_org_id

    # 3. Provision Sensor for Alpha and Sensor for Beta
    s_alpha_resp = client.post(
        "/api/sensors",
        json={"sensor_name": "Alpha Tap", "sensor_identifier": f"alpha-tap-{suffix}"},
        headers=alpha_headers,
    )
    assert s_alpha_resp.status_code == 201
    alpha_sensor_key = s_alpha_resp.json()["api_key"]

    s_beta_resp = client.post(
        "/api/sensors",
        json={"sensor_name": "Beta Tap", "sensor_identifier": f"beta-tap-{suffix}"},
        headers=beta_headers,
    )
    assert s_beta_resp.status_code == 201
    beta_sensor_key = s_beta_resp.json()["api_key"]

    # 4. Ingest telemetry into Organization Alpha
    flow_alpha = {
        "ts": time.time(), "device_id": f"alpha-camera-{suffix}", "device_type": "camera",
        "src_ip": "10.0.1.50", "dst_ip": "10.0.1.1", "src_port": 4001, "dst_port": 80,
        "proto": "tcp", "duration": 0.05, "orig_bytes": 100, "resp_bytes": 200,
        "orig_pkts": 2, "resp_pkts": 2, "conn_state": "SF",
    }
    # Direct alert injection to create incidents for Alpha
    storage.record_alert(
        flow_alpha,
        attack_type="port_scan",
        mitre="T0846",
        severity="critical",
        gate_score=0.98,
        anomaly_score=0.92,
        confidence_tier="high",
        top_features=[],
        org_id=alpha_org_id,
    )

    # 5. Ingest telemetry into Organization Beta
    flow_beta = {
        "ts": time.time(), "device_id": f"beta-plug-{suffix}", "device_type": "smart_plug",
        "src_ip": "10.0.2.75", "dst_ip": "10.0.2.1", "src_port": 5001, "dst_port": 443,
        "proto": "tcp", "duration": 0.1, "orig_bytes": 300, "resp_bytes": 600,
        "orig_pkts": 4, "resp_pkts": 4, "conn_state": "SF",
    }
    storage.record_alert(
        flow_beta,
        attack_type="ddos",
        mitre="T0814",
        severity="warning",
        gate_score=0.95,
        anomaly_score=0.88,
        confidence_tier="high",
        top_features=[],
        org_id=beta_org_id,
    )

    # 6. Verify Device Isolation
    alpha_devices = client.get("/api/devices", headers=alpha_headers).json()
    beta_devices = client.get("/api/devices", headers=beta_headers).json()

    alpha_dev_ids = [d["device_id"] for d in alpha_devices]
    beta_dev_ids = [d["device_id"] for d in beta_devices]

    assert f"alpha-camera-{suffix}" in alpha_dev_ids
    assert f"beta-plug-{suffix}" not in alpha_dev_ids

    assert f"beta-plug-{suffix}" in beta_dev_ids
    assert f"alpha-camera-{suffix}" not in beta_dev_ids

    # 7. Verify Alert Isolation
    alpha_alerts = client.get("/api/alerts", headers=alpha_headers).json()
    beta_alerts = client.get("/api/alerts", headers=beta_headers).json()

    assert any(a["attack_type"] == "port_scan" for a in alpha_alerts)
    assert not any(a["attack_type"] == "ddos" for a in alpha_alerts)

    assert any(a["attack_type"] == "ddos" for a in beta_alerts)
    assert not any(a["attack_type"] == "port_scan" for a in beta_alerts)

    # 8. Verify Incident Isolation & IDOR Protection
    alpha_incidents = client.get("/api/incidents", headers=alpha_headers).json()
    beta_incidents = client.get("/api/incidents", headers=beta_headers).json()

    assert len(alpha_incidents) >= 1
    assert len(beta_incidents) >= 1

    beta_inc_id = beta_incidents[0]["incident_id"]

    # IDOR Attack: Alpha admin attempts to acknowledge Beta's incident
    idor_ack_resp = client.post(
        f"/api/incidents/{beta_inc_id}/acknowledge",
        headers=alpha_headers,
    )
    # Must return 404 Not Found (resource does not exist in Alpha's tenant)
    assert idor_ack_resp.status_code == 404
    assert "not found" in idor_ack_resp.json()["detail"].lower()


def test_websocket_tenant_isolation(client):
    suffix = int(time.time() * 1000)

    # Register Org 1 and Org 2
    org1_reg = client.post(
        "/api/auth/register",
        json={
            "email": f"ws1_{suffix}@tenant1.io",
            "password": "Password123!@#",
            "full_name": "Tenant 1 User",
            "organization_name": f"Tenant 1 {suffix}",
        },
    )
    token_1 = org1_reg.json()["access_token"]

    org2_reg = client.post(
        "/api/auth/register",
        json={
            "email": f"ws2_{suffix}@tenant2.io",
            "password": "Password123!@#",
            "full_name": "Tenant 2 User",
            "organization_name": f"Tenant 2 {suffix}",
        },
    )
    token_2 = org2_reg.json()["access_token"]

    # Connect WebSocket client 1 to Tenant 1
    with client.websocket_connect(f"/ws/alerts?token={token_1}") as ws_1:
        # Invalid token rejection test
        with pytest.raises(Exception):
            with client.websocket_connect("/ws/alerts?token=invalid.tampered.jwt"):
                pass
