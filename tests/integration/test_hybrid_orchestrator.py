"""
Integration Tests for Phase 4 Advanced Hybrid AI Detection Engine & Orchestrator.
"""

import time
import pytest
from fastapi.testclient import TestClient

from backend.app.config import settings
from backend.app.detection import DetectionEngine
from backend.app.main import app
from backend.app import storage


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    """Isolate DB storage for clean testing."""
    test_db = tmp_path / "test_hybrid.db"
    monkeypatch.setattr(storage, "DB_PATH", test_db)
    storage.init_db()
    yield


def test_hybrid_engine_initialization():
    """Verify DetectionEngine loads all Phase 4 modules when available."""
    engine = DetectionEngine()
    assert engine.models_loaded is True
    # Components should be initialized or gracefully handled
    assert hasattr(engine, "shap_explainer")
    assert hasattr(engine, "temporal_detector")
    assert hasattr(engine, "graph_detector")
    assert hasattr(engine, "risk_engine")


def test_hybrid_flow_scoring_contract():
    """Test full multi-modal inference returns complete contract."""
    engine = DetectionEngine()

    flow = {
        "ts": time.time(),
        "device_id": "test_cam_01",
        "src_ip": "192.168.1.50",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 80,
        "proto": "tcp",
        "duration": 0.5,
        "orig_bytes": 1000,
        "resp_bytes": 500,
        "orig_pkts": 10,
        "resp_pkts": 8,
        "conn_state": "SF",
        "device_type": "camera",
    }

    result = engine.score_flow(flow)

    assert "is_flagged" in result
    assert "gate_score" in result
    assert "anomaly_score" in result
    assert "temporal" in result
    assert "graph" in result

    # Check temporal result
    if result["temporal"] is not None:
        assert "temporal_risk" in result["temporal"]
        assert "sequence_length" in result["temporal"]
        assert 0.0 <= result["temporal"]["temporal_risk"] <= 100.0

    # Check graph result
    if result["graph"] is not None:
        assert "graph_risk" in result["graph"]
        assert 0.0 <= result["graph"]["graph_risk"] <= 100.0

    # Check hierarchical risk
    if "risk_breakdown" in result:
        assert "composite_device_risk" in result
        assert "risk_tier" in result
        assert result["risk_tier"] in ["LOW", "ELEVATED", "HIGH", "CRITICAL"]
        assert 0.0 <= result["composite_device_risk"] <= 100.0


def test_fail_open_resilience():
    """Verify that failures in any sub-detector never crash score_flow."""
    engine = DetectionEngine()

    # Intentionally poison a component with an invalid object
    engine.temporal_detector = "invalid_not_a_detector"
    engine.graph_detector = "invalid_not_a_detector"

    flow = {
        "ts": time.time(),
        "device_id": "test_resilient_01",
        "src_ip": "192.168.1.99",
        "dst_ip": "8.8.8.8",
        "src_port": 50000,
        "dst_port": 53,
        "proto": "udp",
        "duration": 0.01,
        "orig_bytes": 60,
        "resp_bytes": 120,
        "orig_pkts": 1,
        "resp_pkts": 1,
        "conn_state": "SF",
    }

    # Must execute safely without throwing exceptions
    result = engine.score_flow(flow)
    assert isinstance(result, dict)
    assert "is_flagged" in result


def test_api_ingest_and_storage_enrichment():
    """Verify /api/ingest persists composite risk and delivers full schema."""
    client = TestClient(app)

    flow_payload = {
        "ts": time.time(),
        "device_id": "device_smart_bulb_01",
        "src_ip": "192.168.1.105",
        "dst_ip": "192.168.1.1",
        "src_port": 40123,
        "dst_port": 80,
        "proto": "tcp",
        "duration": 0.05,
        "orig_bytes": 200,
        "resp_bytes": 400,
        "orig_pkts": 3,
        "resp_pkts": 4,
        "conn_state": "SF",
        "device_type": "smart_bulb",
    }

    resp = client.post("/api/ingest", json=flow_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "flagged" in data
    assert "composite_device_risk" in data

    # Verify /api/devices reflects the device
    dev_resp = client.get("/api/devices")
    assert dev_resp.status_code == 200
    devices = dev_resp.json()
    assert len(devices) >= 1
    dev = next(d for d in devices if d["device_id"] == "device_smart_bulb_01")
    assert "risk_score" in dev
    assert "risk_tier" in dev
