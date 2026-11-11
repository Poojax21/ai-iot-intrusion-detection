"""
Integration tests for Open-Set Recognition through FastAPI Endpoints.
"""

import time
import pytest
from backend.app.schemas import FlowRecord


def test_api_health_reports_open_set_status(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "open_set_enabled" in data
    assert data["open_set_enabled"] is True


def test_api_ingest_returns_open_set_fields(client, sample_benign_flow):
    res = client.post("/api/ingest", json=sample_benign_flow)
    assert res.status_code == 200
    data = res.json()

    assert "flagged" in data
    assert "gate_score" in data
    assert "anomaly_score" in data
    assert "calibrated_anomaly_score" in data
    assert "novelty_score" in data
    assert "decision" in data
    assert "is_unknown" in data
    assert "reason_codes" in data
    assert isinstance(data["reason_codes"], list)


def test_api_stats_includes_unknown_counter(client):
    res = client.get("/api/stats")
    assert res.status_code == 200
    stats = res.json()
    assert "total_flows" in stats
    assert "total_alerts" in stats
    assert "unknown_alerts" in stats
    assert "alerts_by_type" in stats


def test_alert_suppression_prevents_storms(client, sample_ddos_flow):
    device_id = "test-storm-suppress-device"
    flow = {**sample_ddos_flow, "device_id": device_id}

    # Warm up grace period
    for _ in range(16):
        client.post("/api/ingest", json=flow)

    # First attack flow generates an alert
    r1 = client.post("/api/ingest", json=flow)
    assert r1.status_code == 200
    data1 = r1.json()

    # Immediate second identical attack flow within 5s window should be suppressed
    r2 = client.post("/api/ingest", json=flow)
    assert r2.status_code == 200
    data2 = r2.json()

    # If first was an alert, second should be suppressed (alert=None)
    if data1.get("alert") is not None:
        assert data2.get("alert") is None
