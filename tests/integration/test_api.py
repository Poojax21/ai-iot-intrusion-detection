"""
Integration tests for FastAPI endpoints: health, ingest, alerts, devices, and stats.
"""

import time
from backend.app.detection import engine


def test_api_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["models_loaded"] is True
    assert data["hint"] is None


def test_api_stats_empty(client):
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()
    assert data["total_flows"] == 0
    assert data["total_alerts"] == 0
    assert data["alerts_by_type"] == {}


def test_api_devices_empty(client):
    response = client.get("/api/devices")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 0


def test_api_alerts_empty(client):
    response = client.get("/api/alerts")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 0


def test_api_ingest_validation_error(client):
    # Invalid record: negative duration, missing proto
    invalid_flow = {
        "ts": time.time(),
        "device_id": "bad-device",
        "src_ip": "1.2.3.4",
        "dst_ip": "5.6.7.8",
        "src_port": 100,
        "dst_port": 200,
        "duration": -1.0,
        "orig_bytes": -50,
        "resp_bytes": 0,
        "orig_pkts": 1,
        "resp_pkts": 0,
    }
    response = client.post("/api/ingest", json=invalid_flow)
    assert response.status_code == 422


def test_api_ingest_benign_flow(client, sample_benign_flow):
    response = client.post("/api/ingest", json=sample_benign_flow)
    assert response.status_code == 200
    data = response.json()
    assert data["flagged"] is False
    assert data["alert"] is None

    # Check stats and devices updated
    stats_res = client.get("/api/stats").json()
    assert stats_res["total_flows"] == 1
    assert stats_res["total_alerts"] == 0

    dev_res = client.get("/api/devices").json()
    assert len(dev_res) == 1
    assert dev_res[0]["device_id"] == sample_benign_flow["device_id"]


def test_api_ingest_and_alert_generation(client, sample_benign_flow, sample_ddos_flow):
    device_id = "test-sensor-alert-fleet"
    flow_warmup = {**sample_benign_flow, "device_id": device_id}

    # Warm up past the grace period (15 flows)
    for _ in range(16):
        res = client.post("/api/ingest", json=flow_warmup)
        assert res.status_code == 200

    # Submit DDoS attack
    attack = {**sample_ddos_flow, "device_id": device_id}
    res_attack = client.post("/api/ingest", json=attack)
    assert res_attack.status_code == 200
    data = res_attack.json()
    assert data["flagged"] is True
    assert data["alert"] is not None
    assert data["alert"]["attack_type"] is not None
    assert data["alert"]["device_id"] == device_id

    # Verify alert appears in /api/alerts
    alerts_res = client.get("/api/alerts").json()
    assert len(alerts_res) >= 1
    latest_alert = alerts_res[0]
    assert latest_alert["device_id"] == device_id
    assert latest_alert["gate_score"] > 0.0

    # Verify stats reflect the new alert
    stats = client.get("/api/stats").json()
    assert stats["total_alerts"] >= 1
    assert latest_alert["attack_type"] in stats["alerts_by_type"]
