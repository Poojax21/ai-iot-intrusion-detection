"""
Unit tests for Hierarchical Risk Engine (backend/app/risk/risk_engine.py).
"""

import time
import pytest
from backend.app.risk.risk_engine import HierarchicalRiskEngine, RiskEvidenceBreakdown


def test_hierarchical_risk_initial_and_attack_elevation():
    engine = HierarchicalRiskEngine(decay_half_life_sec=60.0)
    dev_id = "test-device-risk-01"
    t0 = 1000.0

    # 1. Benign flow should maintain low risk
    flow_benign = {
        "is_flagged": False, "gate_score": 0.001, "calibrated_anomaly_score": 0.40,
        "is_unknown": False, "model_version": "open_set_v1",
    }
    r1 = engine.evaluate_risk(dev_id, t0, flow_benign)
    assert r1.composite_device_risk == 0.0
    assert r1.risk_tier == "LOW"

    # 2. Attack flow should elevate device risk
    flow_attack = {
        "is_flagged": True, "attack_type": "ddos", "severity": "critical",
        "gate_score": 0.999, "calibrated_anomaly_score": 0.99,
        "is_unknown": False, "model_version": "open_set_v1",
    }
    r2 = engine.evaluate_risk(dev_id, t0 + 1.0, flow_attack)
    assert r2.composite_device_risk > 20.0
    assert r2.risk_tier in ("ELEVATED", "HIGH", "CRITICAL")
    assert "FLOW_FLAGGED_DDOS" in r2.reason_codes


def test_hierarchical_risk_temporal_decay():
    engine = HierarchicalRiskEngine(decay_half_life_sec=60.0)
    dev_id = "test-device-decay-02"
    t0 = 2000.0

    # Elevate risk with an attack
    flow_attack = {
        "is_flagged": True, "attack_type": "port_scan", "severity": "critical",
        "gate_score": 0.99, "calibrated_anomaly_score": 0.95,
    }
    r_high = engine.evaluate_risk(dev_id, t0, flow_attack)
    peak_risk = r_high.composite_device_risk
    assert peak_risk > 20.0

    # After 1 half-life (60 seconds) of quiet benign traffic, risk should drop to ~50%
    flow_quiet = {"is_flagged": False, "gate_score": 0.0, "calibrated_anomaly_score": 0.1}
    r_decayed = engine.evaluate_risk(dev_id, t0 + 60.0, flow_quiet)
    expected_decay = peak_risk * 0.5
    assert abs(r_decayed.composite_device_risk - expected_decay) < 2.0


def test_hierarchical_risk_duplicate_suppression():
    engine = HierarchicalRiskEngine()
    dev_id = "test-device-dupe-03"
    t0 = 3000.0

    flow_attack = {
        "is_flagged": True, "attack_type": "brute_force", "severity": "warning",
        "gate_score": 0.85, "calibrated_anomaly_score": 0.90,
    }

    # First attack flow
    r1 = engine.evaluate_risk(dev_id, t0, flow_attack, is_suppressed_duplicate=False)
    risk_after_first = r1.composite_device_risk

    # Second identical flow marked as suppressed duplicate
    r2 = engine.evaluate_risk(dev_id, t0 + 1.0, flow_attack, is_suppressed_duplicate=True)
    assert r2.risk_increment == 0.0
    assert "DUPLICATE_ALERT_SUPPRESSED" in r2.reason_codes
    # Risk should not increase on duplicate
    assert r2.composite_device_risk <= risk_after_first


def test_hierarchical_risk_multimodal_synthesis():
    engine = HierarchicalRiskEngine()
    dev_id = "test-device-multi-04"
    t0 = 4000.0

    flow = {
        "is_flagged": True, "attack_type": "unknown_suspicious", "severity": "warning",
        "gate_score": 0.70, "calibrated_anomaly_score": 0.95, "is_unknown": True, "novelty_score": 1.5,
    }
    temporal = {
        "temporal_risk": 0.92, "temporal_flagged": True, "model_version": "temporal_v1",
    }
    graph = {
        "graph_risk": 0.88, "is_lateral_movement": True, "model_version": "graph_v1",
    }

    res = engine.evaluate_risk(dev_id, t0, flow, temporal_result=temporal, graph_result=graph)
    assert res.flow_risk > 0.6
    assert res.novelty_risk > 0.4
    assert res.temporal_risk == 0.92
    assert res.graph_risk >= 0.85
    assert "INTERNAL_LATERAL_MOVEMENT" in res.reason_codes
    assert "TEMPORAL_SEQUENCE_EVIDENCE" in res.reason_codes
    assert "OPEN_SET_ZERO_DAY_EVIDENCE" in res.reason_codes
