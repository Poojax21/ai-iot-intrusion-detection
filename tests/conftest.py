"""
Pytest configuration, shared fixtures, and testing environment initialization.
"""

import os
import sys
import time
import pytest
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app import storage
from backend.app.detection import DetectionEngine, engine
from backend.app.features import DeviceState, build_feature_vector


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """Provides an isolated SQLite database for testing, leaving production DB untouched."""
    db_file = tmp_path / "test_iot_ids.db"
    monkeypatch.setattr(storage, "DB_PATH", db_file)
    storage.init_db(db_file)
    yield db_file


@pytest.fixture
def client(temp_db):
    """FastAPI TestClient wired to the temporary test database."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def sample_benign_flow():
    """A standard benign flow from a smart plug."""
    return {
        "ts": time.time(),
        "device_id": "plug-test-01",
        "device_type": "smart_plug",
        "src_ip": "192.168.1.101",
        "dst_ip": "203.0.113.1",
        "src_port": 50123,
        "dst_port": 443,
        "proto": "tcp",
        "duration": 0.5,
        "orig_bytes": 320,
        "resp_bytes": 480,
        "orig_pkts": 3,
        "resp_pkts": 4,
        "conn_state": "SF",
        "mac_unstable": False,
    }


@pytest.fixture
def sample_port_scan_flow():
    """A standard port scan flow."""
    return {
        "ts": time.time(),
        "device_id": "camera-test-01",
        "device_type": "camera",
        "src_ip": "192.168.1.101",
        "dst_ip": "203.0.113.88",
        "src_port": 49152,
        "dst_port": 2222,
        "proto": "tcp",
        "duration": 0.002,
        "orig_bytes": 48,
        "resp_bytes": 0,
        "orig_pkts": 1,
        "resp_pkts": 0,
        "conn_state": "S0",
        "mac_unstable": False,
    }


@pytest.fixture
def sample_ddos_flow():
    """A standard DDoS flow with high packet count and short duration."""
    return {
        "ts": time.time(),
        "device_id": "sensor-test-02",
        "device_type": "temp_sensor",
        "src_ip": "192.168.1.102",
        "dst_ip": "192.168.1.250",
        "src_port": 12345,
        "dst_port": 80,
        "proto": "tcp",
        "duration": 0.005,
        "orig_bytes": 1200,
        "resp_bytes": 0,
        "orig_pkts": 45,
        "resp_pkts": 0,
        "conn_state": "S0",
        "mac_unstable": False,
    }
