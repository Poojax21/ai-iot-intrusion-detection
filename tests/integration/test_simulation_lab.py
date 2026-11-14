"""
Integration tests for Real-Time IoT Attack Simulation, Legitimate Traffic Generation & Detection.
"""

import time
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app import storage
from backend.app.api import lab


@pytest.fixture
def client():
    return TestClient(app)


def test_lab_discovery_endpoints(client):
    """Test attack scenarios, legitimate types, and targets discovery endpoints."""
    # 1. Attacks
    res_attacks = client.get("/api/lab/attacks")
    assert res_attacks.status_code == 200
    attacks = res_attacks.json()
    assert len(attacks) >= 5
    attack_ids = {a["id"] for a in attacks}
    assert "ddos_syn_flood" in attack_ids
    assert "port_scan_syn" in attack_ids
    assert "brute_force_cred" in attack_ids
    assert "mirai_c2_flood" in attack_ids
    assert "zero_day_payload" in attack_ids

    # 2. Legitimate types
    res_legit = client.get("/api/lab/legitimate_types")
    assert res_legit.status_code == 200
    legit = res_legit.json()
    assert len(legit) >= 5
    legit_ids = {l["id"] for l in legit}
    assert "http_telemetry" in legit_ids
    assert "device_heartbeat" in legit_ids
    assert "sensor_updates" in legit_ids

    # 3. Targets
    res_targets = client.get("/api/lab/targets")
    assert res_targets.status_code == 200
    targets = res_targets.json()
    assert len(targets) >= 1
    t0 = targets[0]
    assert "id" in t0
    assert "ip" in t0
    assert "security_status" in t0
    assert t0["connection_status"] == "Online"


def test_mixed_attack_and_legitimate_simulation_lifecycle(client):
    """Test launching a simulation session with concurrent multi-attacks and legitimate traffic."""
    storage.init_db()

    # Get an authorized target
    res_targets = client.get("/api/lab/targets")
    target_id = res_targets.json()[0]["id"]

    # Launch simulation with 2 attacks and 2 legitimate traffic generators
    payload = {
        "target_id": target_id,
        "attack_types": ["ddos_syn_flood", "port_scan_syn"],
        "legitimate_types": ["http_telemetry", "sensor_updates"],
        "duration_s": 10,
        "intensity": "high",
    }

    res_run = client.post("/api/lab/runs", json=payload)
    assert res_run.status_code == 200
    data = res_run.json()
    run_id = data["run_id"]
    assert run_id.startswith("sim_")
    assert data["status"] == "running"
    assert data["target_id"] == target_id

    # Check run status endpoint
    res_status = client.get(f"/api/lab/runs/{run_id}")
    assert res_status.status_code == 200
    status_data = res_status.json()
    assert status_data["id"] == run_id
    assert "metrics" in status_data
    assert "attack_terminal" in status_data
    assert "device_terminal" in status_data

    # Test pause simulation
    res_pause = client.post(f"/api/lab/runs/{run_id}/pause")
    assert res_pause.status_code == 200
    assert res_pause.json()["status"] == "paused"

    # Test resume simulation
    res_resume = client.post(f"/api/lab/runs/{run_id}/resume")
    assert res_resume.status_code == 200
    assert res_resume.json()["status"] == "running"

    # Test stop simulation
    res_stop = client.post(f"/api/lab/runs/{run_id}/stop")
    assert res_stop.status_code == 200
    assert res_stop.json()["status"] == "stopped"

    # Verify run status is stopped
    res_final = client.get(f"/api/lab/runs/{run_id}")
    assert res_final.json()["status"] == "stopped"


def test_backward_compatibility_single_scenario(client):
    """Verify legacy single scenario_id API continues to work seamlessly."""
    payload = {
        "scenario_id": "port_scan",
        "target_id": "camera-bdd640fb",
        "duration_s": 5,
        "intensity": "low",
    }
    res = client.post("/api/lab/runs", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "run_id" in data
    # Stop it immediately
    client.post(f"/api/lab/runs/{data['run_id']}/stop")
