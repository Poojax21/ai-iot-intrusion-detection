"""
Integration test for training and inference preprocessing parity.
"""

from backend.app.detection import DetectionEngine
from backend.app.features import DeviceState, build_feature_vector
from training.preprocessing.feature_alignment import align_features_v1
from training.feature_contract import StandardRecord


def test_preprocessing_parity_with_backend_engine(sample_benign_flow):
    # 1. Backend inference path
    state_backend = DeviceState()
    vec_backend = build_feature_vector(sample_benign_flow, state_backend)

    # 2. Dataset pipeline path
    rec = StandardRecord(
        timestamp=sample_benign_flow["ts"],
        source_ip=sample_benign_flow["src_ip"],
        destination_ip=sample_benign_flow["dst_ip"],
        source_port=sample_benign_flow["src_port"],
        destination_port=sample_benign_flow["dst_port"],
        protocol=sample_benign_flow["proto"],
        duration=sample_benign_flow["duration"],
        source_bytes=sample_benign_flow["orig_bytes"],
        destination_bytes=sample_benign_flow["resp_bytes"],
        source_packets=sample_benign_flow["orig_pkts"],
        destination_packets=sample_benign_flow["resp_pkts"],
        connection_state=sample_benign_flow["conn_state"],
        source_device_id=sample_benign_flow["device_id"],
    )
    state_dataset = DeviceState()
    vec_dataset = align_features_v1(rec, state_dataset)

    # Invariant: identical outputs
    assert vec_backend == vec_dataset

    # Verify existing V1 model can score both
    engine = DetectionEngine(grace_period_flows=0)
    res_b = engine.score_flow(sample_benign_flow)
    assert res_b["is_flagged"] is False
