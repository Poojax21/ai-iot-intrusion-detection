"""
Integration tests for Alert Quality, Incident Management & Lifecycle Tracking.
"""

import time
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app import storage


@pytest.fixture
def client():
    return TestClient(app)


def test_incident_correlation_and_lifecycle(client):
    storage.init_db()

    dev_id = f"test-inc-{int(time.time()*1000)}"
    t0 = 1000.0

    # 1. Ingest first attack flow
    flow_1 = {
        "ts": t0, "device_id": dev_id, "device_type": "camera",
        "src_ip": "192.168.1.55", "dst_ip": "192.168.1.1",
        "src_port": 40001, "dst_port": 80, "proto": "tcp",
        "duration": 0.05, "orig_bytes": 100, "resp_bytes": 200,
        "orig_pkts": 2, "resp_pkts": 2, "conn_state": "SF",
    }
    # Record first alert directly
    storage.record_alert(
        flow_1,
        attack_type="port_scan",
        mitre="T0846",
        severity="warning",
        gate_score=0.95,
        anomaly_score=0.90,
        confidence_tier="high",
        top_features=[],
    )

    # Verify incident was created
    incidents = storage.list_incidents()
    assert len(incidents) >= 1
    inc = next(i for i in incidents if i["device_id"] == dev_id)
    assert inc["status"] == "OPEN"
    assert inc["alert_count"] == 1
    assert inc["attack_type"] == "port_scan"
    inc_id = inc["incident_id"]

    # 2. Ingest second alert within 60s for the same device
    flow_2 = dict(flow_1)
    flow_2["ts"] = t0 + 10.0
    storage.record_alert(
        flow_2,
        attack_type="ddos",
        mitre="T0814",
        severity="critical",
        gate_score=0.99,
        anomaly_score=0.95,
        confidence_tier="high",
        top_features=[],
    )

    # Verify incident alert_count was incremented and severity upgraded to critical
    inc_updated = next(i for i in storage.list_incidents() if i["incident_id"] == inc_id)
    assert inc_updated["alert_count"] == 2
    assert inc_updated["severity"] == "critical"

    # 3. Test API acknowledge endpoint
    resp_ack = client.post(f"/api/incidents/{inc_id}/acknowledge")
    assert resp_ack.status_code == 200
    assert resp_ack.json()["status"] == "acknowledged"

    inc_ack = next(i for i in storage.list_incidents() if i["incident_id"] == inc_id)
    assert inc_ack["status"] == "ACKNOWLEDGED"
    assert inc_ack["acknowledged_at"] is not None

    # 4. Test API resolve endpoint
    resp_res = client.post(f"/api/incidents/{inc_id}/resolve", json={"notes": "Device isolated and remediated."})
    assert resp_res.status_code == 200
    assert resp_res.json()["status"] == "resolved"

    inc_res = next(i for i in storage.list_incidents() if i["incident_id"] == inc_id)
    assert inc_res["status"] == "RESOLVED"
    assert inc_res["resolved_at"] is not None
    assert "remediated" in inc_res["resolution_notes"]

    # 5. Test Metrics Endpoint
    resp_met = client.get("/api/incidents/metrics")
    assert resp_met.status_code == 200
    metrics = resp_met.json()
    assert metrics["total_incidents"] >= 1
    assert metrics["resolved_incidents"] >= 1
    assert "suppression_metrics" in metrics


def test_duplicate_alert_suppression():
    dev = "test-suppress-dev-02"
    t = 2000.0
    # First alert should not be suppressed
    assert storage.should_suppress_alert(dev, "ddos", t, window_sec=5.0) is False
    # Identical alert within 5 seconds should be suppressed
    assert storage.should_suppress_alert(dev, "ddos", t + 1.0, window_sec=5.0) is True
    # Different attack type should not be suppressed
    assert storage.should_suppress_alert(dev, "port_scan", t + 2.0, window_sec=5.0) is False
    # Alert after suppression window expires should not be suppressed
    assert storage.should_suppress_alert(dev, "ddos", t + 6.0, window_sec=5.0) is False
