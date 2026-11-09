"""
Unit tests for feature extraction and per-device state tracking.
"""

from backend.app.features import (
    FEATURE_COLUMNS,
    ATTACK_LABELS,
    DeviceState,
    build_feature_vector,
    _proto_one_hot,
    _conn_state_one_hot,
)


def test_feature_columns_contract():
    assert len(FEATURE_COLUMNS) == 20
    assert "duration" in FEATURE_COLUMNS
    assert "is_new_edge" in FEATURE_COLUMNS
    assert "device_zscore" in FEATURE_COLUMNS
    assert "proto_tcp" in FEATURE_COLUMNS
    assert "conn_state_sf" in FEATURE_COLUMNS


def test_attack_labels():
    assert ATTACK_LABELS == ["benign", "port_scan", "ddos", "brute_force", "mirai_beacon"]


def test_proto_one_hot():
    assert _proto_one_hot("tcp") == (1.0, 0.0, 0.0)
    assert _proto_one_hot("UDP") == (0.0, 1.0, 0.0)
    assert _proto_one_hot("icmp") == (0.0, 0.0, 1.0)
    assert _proto_one_hot("unknown") == (0.0, 0.0, 0.0)


def test_conn_state_one_hot():
    assert _conn_state_one_hot("SF") == (1.0, 0.0, 0.0, 0.0)
    assert _conn_state_one_hot("S0") == (0.0, 1.0, 0.0, 0.0)
    assert _conn_state_one_hot("REJ") == (0.0, 0.0, 1.0, 0.0)
    assert _conn_state_one_hot("RSTO") == (0.0, 0.0, 0.0, 1.0)


def test_device_state_new_edge_and_fanout():
    state = DeviceState()
    assert state.flow_count == 0

    # First flow to 10.0.0.1 -> new edge
    is_new, fanout, zscore = state.update_and_score("10.0.0.1", 500.0)
    assert is_new is True
    assert fanout == 1
    assert state.flow_count == 1
    assert zscore == 0.0  # Not enough history yet

    # Second flow to 10.0.0.1 -> repeated edge
    is_new2, fanout2, _ = state.update_and_score("10.0.0.1", 520.0)
    assert is_new2 is False
    assert fanout2 == 1
    assert state.flow_count == 2

    # Flow to 10.0.0.2 -> new edge, fanout increases
    is_new3, fanout3, _ = state.update_and_score("10.0.0.2", 490.0)
    assert is_new3 is True
    assert fanout3 == 2


def test_device_state_zscore_calculation():
    state = DeviceState()
    # Feed 10 steady flows of 1000 bytes/s
    for _ in range(10):
        state.update_and_score("10.0.0.1", 1000.0)

    # Now send an extreme spike: 50,000 bytes/s
    is_new, fanout, zscore = state.update_and_score("10.0.0.1", 50000.0)
    assert zscore > 3.0  # Significant statistical anomaly


def test_build_feature_vector(sample_benign_flow):
    state = DeviceState()
    vec = build_feature_vector(sample_benign_flow, state)
    assert len(vec) == len(FEATURE_COLUMNS)
    assert isinstance(vec, list)
    # Validate specific indices:
    # duration is index 0
    assert vec[0] == sample_benign_flow["duration"]
    # total_bytes is index 5
    assert vec[5] == sample_benign_flow["orig_bytes"] + sample_benign_flow["resp_bytes"]
    # proto_tcp is index 13
    assert vec[13] == 1.0
