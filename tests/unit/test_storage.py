"""
Unit tests for SQLite storage layer, persistence, and device risk score decay.
"""

from backend.app import storage


def test_init_db(temp_db):
    with storage.get_conn(temp_db) as conn:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        assert "flows" in tables
        assert "alerts" in tables
        assert "devices" in tables


def test_record_flow_and_device_tracking(temp_db, sample_benign_flow):
    storage.record_flow(sample_benign_flow, gate_score=0.01, is_flagged=False)
    
    stats = storage.get_stats()
    assert stats["total_flows"] == 1
    assert stats["total_alerts"] == 0

    devices = storage.list_devices()
    assert len(devices) == 1
    dev = devices[0]
    assert dev["device_id"] == sample_benign_flow["device_id"]
    assert dev["flow_count"] == 1
    assert dev["alert_count"] == 0
    assert dev["risk_score"] == 0.0


def test_record_alert_and_risk_increase(temp_db, sample_ddos_flow):
    alert_id = storage.record_alert(
        sample_ddos_flow,
        attack_type="ddos",
        mitre="T0814",
        severity="critical",
        gate_score=0.95,
        anomaly_score=0.82,
        confidence_tier="high",
        top_features=[("pkt_rate", 9000.0)],
        shap_values=[{"feature": "pkt_rate", "value": 9000.0, "contribution": 0.45}],
        shap_base_value=0.05,
    )
    assert alert_id is not None
    assert alert_id >= 1

    alerts = storage.list_alerts(limit=10)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["attack_type"] == "ddos"
    assert alert["severity"] == "critical"
    assert alert["gate_score"] == 0.95
    assert len(alert["shap_values"]) == 1

    devices = storage.list_devices()
    assert len(devices) == 1
    dev = devices[0]
    assert dev["alert_count"] == 1
    assert dev["risk_score"] > 0.0


def test_risk_score_decay(temp_db, sample_benign_flow):
    # Trigger alert
    storage.record_alert(
        sample_benign_flow,
        attack_type="port_scan",
        mitre="T0846",
        severity="warning",
        gate_score=0.75,
        anomaly_score=0.6,
        confidence_tier="medium",
        top_features=[],
    )
    dev_after_alert = storage.list_devices()[0]
    initial_risk = dev_after_alert["risk_score"]
    assert initial_risk > 0.0

    # Stream 10 benign flows from same device
    for _ in range(10):
        storage.record_flow(sample_benign_flow, gate_score=0.02, is_flagged=False)

    dev_decayed = storage.list_devices()[0]
    assert dev_decayed["risk_score"] < initial_risk
