"""
Unit tests for feature alignment and vector parity.
"""

from backend.app.features import DeviceState, FEATURE_COLUMNS
from training.feature_contract import StandardRecord, canonical_contract
from training.preprocessing.feature_alignment import align_features_v1, batch_align_features


def test_align_features_single_record():
    rec = StandardRecord(
        timestamp=1000.0,
        source_ip="192.168.1.15",
        destination_ip="203.0.113.1",
        source_port=45000,
        destination_port=443,
        protocol="tcp",
        duration=1.0,
        source_bytes=400,
        destination_bytes=600,
        source_packets=4,
        destination_packets=6,
        connection_state="SF",
        source_device_id="cam-1",
    )
    state = DeviceState()
    vec = align_features_v1(rec, state)
    assert len(vec) == 20
    assert vec[0] == 1.0       # duration
    assert vec[1] == 400.0     # orig_bytes
    assert vec[2] == 600.0     # resp_bytes
    assert vec[13] == 1.0     # proto_tcp
    assert vec[16] == 1.0     # conn_state_sf


def test_batch_align_features():
    records = [
        StandardRecord(
            timestamp=1000.0 + i,
            source_ip="192.168.1.15",
            destination_ip=f"203.0.113.{i+1}",
            source_port=45000 + i,
            destination_port=443,
            protocol="tcp",
            duration=0.5,
            source_bytes=300,
            destination_bytes=500,
            source_packets=3,
            destination_packets=5,
            connection_state="SF",
            source_device_id="cam-1",
        )
        for i in range(5)
    ]
    matrix, states = batch_align_features(records)
    assert matrix.shape == (5, 20)
    assert "cam-1" in states
    assert states["cam-1"].flow_count == 5
