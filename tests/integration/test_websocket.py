"""
Integration test for WebSocket live alert broadcasting (/ws/alerts).
"""

import json
from fastapi.testclient import TestClient


def test_websocket_alert_broadcast(client, sample_benign_flow, sample_ddos_flow):
    device_id = "test-ws-device-01"
    flow_warmup = {**sample_benign_flow, "device_id": device_id}

    # Warm up past grace period
    for _ in range(16):
        client.post("/api/ingest", json=flow_warmup)

    # Connect WebSocket client and verify message reception
    with client.websocket_connect("/ws/alerts") as websocket:
        # Ingest attack flow
        attack = {**sample_ddos_flow, "device_id": device_id}
        res = client.post("/api/ingest", json=attack)
        assert res.status_code == 200
        assert res.json()["flagged"] is True

        # Receive live alert over WebSocket
        raw_msg = websocket.receive_text()
        msg = json.loads(raw_msg)
        assert msg["type"] == "alert"
        assert msg["data"]["device_id"] == device_id
        assert msg["data"]["attack_type"] is not None
