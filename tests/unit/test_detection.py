"""
Unit tests for detection pipeline, scoring logic, grace period, and explainability.
"""

from pathlib import Path
from backend.app.detection import DetectionEngine, GRACE_PERIOD_FLOWS


def test_engine_initialization():
    engine = DetectionEngine()
    assert engine.models_loaded is True
    assert 0.0 < engine.gate_threshold < 1.0
    assert engine.scaler is not None
    assert engine.anomaly_model is not None
    assert engine.gate_model is not None
    assert engine.multiclass_model is not None


def test_grace_period_suppresses_alert(sample_ddos_flow):
    engine = DetectionEngine(grace_period_flows=15)
    # The first flow from a brand new device must be marked as in_grace_period
    res = engine.score_flow(sample_ddos_flow)
    assert res["in_grace_period"] is True
    assert res["is_flagged"] is False


def test_attack_flagged_after_grace_period(sample_benign_flow, sample_ddos_flow):
    engine = DetectionEngine(grace_period_flows=5)
    device_id = "test-grace-device-99"
    flow_warmup = {**sample_benign_flow, "device_id": device_id}

    # Warm up baseline past the 5-flow grace period
    for _ in range(6):
        res = engine.score_flow(flow_warmup)
        assert res["is_flagged"] is False

    # Now send massive DDoS attack from the same device
    attack = {**sample_ddos_flow, "device_id": device_id}
    res_attack = engine.score_flow(attack)
    assert res_attack["in_grace_period"] is False
    assert res_attack["is_flagged"] is True
    assert res_attack["gate_score"] > engine.gate_threshold
    assert "attack_type" in res_attack
    assert "mitre" in res_attack
    assert res_attack["attack_type"] in [
        "ddos", "unclassified_anomaly", "unknown_suspicious", "port_scan", "brute_force", "mirai_beacon"
    ]
    assert "shap_values" in res_attack
    assert len(res_attack["shap_values"]) > 0
    first_shap = res_attack["shap_values"][0]
    assert "feature" in first_shap
    assert "value" in first_shap
    assert "contribution" in first_shap


def test_fail_open_on_missing_models(tmp_path, sample_ddos_flow):
    # Empty directory with no models
    empty_dir = tmp_path / "empty_models"
    empty_dir.mkdir()
    engine = DetectionEngine(model_dir=empty_dir)
    assert engine.models_loaded is False

    # Scoring must fail open gracefully without raising an unhandled exception
    res = engine.score_flow(sample_ddos_flow)
    assert res["error"] == "models_not_trained"
    assert res["is_flagged"] is False
    assert res["gate_score"] == 0.0
