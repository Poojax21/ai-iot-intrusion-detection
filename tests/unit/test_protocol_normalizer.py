"""
Unit tests for protocol normalization.
"""

from training.preprocessing.protocol_normalizer import normalize_protocol


def test_protocol_strings():
    assert normalize_protocol("tcp") == "tcp"
    assert normalize_protocol("TCP") == "tcp"
    assert normalize_protocol("UDP") == "udp"
    assert normalize_protocol("icmp") == "icmp"
    assert normalize_protocol("ICMP") == "icmp"


def test_protocol_numeric():
    # IANA numbers: 6=tcp, 17=udp, 1=icmp
    assert normalize_protocol(6) == "tcp"
    assert normalize_protocol("6") == "tcp"
    assert normalize_protocol(6.0) == "tcp"
    assert normalize_protocol(17) == "udp"
    assert normalize_protocol("17") == "udp"
    assert normalize_protocol(1) == "icmp"
    assert normalize_protocol(89) == "other"  # OSPF


def test_protocol_missing_and_unknown():
    assert normalize_protocol("-") == "other"
    assert normalize_protocol("(empty)") == "other"
    assert normalize_protocol(None) == "other"
    assert normalize_protocol("arp") == "other"
    assert normalize_protocol("unknown_protocol_xyz") == "other"
