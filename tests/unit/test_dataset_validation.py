"""
Unit tests for record validation constraints.
"""

from training.feature_contract import StandardRecord
from training.preprocessing.validation import validate_flow_record


def test_valid_flow_record():
    rec = StandardRecord(
        timestamp=100.0,
        source_ip="192.168.1.10",
        destination_ip="203.0.113.1",
        source_port=1234,
        destination_port=80,
        protocol="tcp",
        duration=1.0,
        source_bytes=100,
        destination_bytes=200,
        source_packets=2,
        destination_packets=2,
        connection_state="SF",
    )
    ok, err = validate_flow_record(rec)
    assert ok is True
    assert err is None


def test_invalid_negative_duration():
    rec = StandardRecord(
        timestamp=100.0,
        source_ip="192.168.1.10",
        destination_ip="203.0.113.1",
        source_port=1234,
        destination_port=80,
        protocol="tcp",
        duration=-5.0,
        source_bytes=100,
        destination_bytes=200,
        source_packets=2,
        destination_packets=2,
        connection_state="SF",
    )
    ok, err = validate_flow_record(rec)
    assert ok is False
    assert "Negative duration" in err
