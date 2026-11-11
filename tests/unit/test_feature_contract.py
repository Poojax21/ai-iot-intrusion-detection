"""
Unit tests for FeatureContract, StandardRecord, and V1 feature definitions.
"""

from training.feature_contract import (
    FeatureContract,
    FeatureDefinition,
    StandardRecord,
    canonical_contract,
    V1_FEATURE_DEFINITIONS,
)
from backend.app.features import FEATURE_COLUMNS


def test_v1_feature_definitions_count():
    assert len(V1_FEATURE_DEFINITIONS) == 20
    assert len(canonical_contract.feature_names) == 20
    # Must exactly match FEATURE_COLUMNS from production backend
    assert canonical_contract.feature_names == FEATURE_COLUMNS


def test_standard_record_conversion():
    rec = StandardRecord(
        timestamp=1000.0,
        source_ip="192.168.1.15",
        destination_ip="203.0.113.5",
        source_port=45000,
        destination_port=443,
        protocol="tcp",
        duration=1.5,
        source_bytes=500,
        destination_bytes=1000,
        source_packets=5,
        destination_packets=10,
        connection_state="SF",
        source_device_id="camera-01",
        original_label="Benign",
        normalized_label="BENIGN",
    )
    d = rec.to_dict()
    assert d["ts"] == 1000.0
    assert d["src_ip"] == "192.168.1.15"
    assert d["orig_bytes"] == 500
    assert d["resp_bytes"] == 1000
    assert d["device_id"] == "camera-01"


def test_contract_vector_validation():
    # Valid vector
    valid_vec = [1.0] * 20
    # duration, orig_bytes, resp_bytes, ...
    ok, err = canonical_contract.validate_vector(valid_vec)
    assert ok is True
    assert err is None

    # Length mismatch
    short_vec = [1.0] * 19
    ok_short, err_short = canonical_contract.validate_vector(short_vec)
    assert ok_short is False
    assert "Length mismatch" in err_short

    # NaN in vector
    nan_vec = [1.0] * 20
    nan_vec[3] = float("nan")
    ok_nan, err_nan = canonical_contract.validate_vector(nan_vec)
    assert ok_nan is False
    assert "invalid value" in err_nan


def test_compatibility_evaluation():
    zeek_cols = ["ts", "id.orig_h", "id.resp_h", "proto", "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "conn_state"]
    res = canonical_contract.evaluate_dataset_compatibility(zeek_cols)
    assert res["compatibility_percentage"] == 100.0
    assert res["is_fully_compatible"] is True
