"""
Unit tests for Temporal Sequence Intelligence (training/temporal/).
"""

from pathlib import Path
import numpy as np
import pytest
import torch

from training.temporal.sequence_builder import DeviceSequenceBuffer, build_causal_sequences
from training.temporal.models import TemporalGRU, TemporalLSTM
from training.temporal.temporal_detector import TemporalDetector


def test_device_sequence_buffer_isolation_and_padding():
    buf = DeviceSequenceBuffer(sequence_length=4, feature_dim=3)

    # 1. Device A cold-start flow
    vec_a1 = np.array([1.0, 2.0, 3.0])
    w_a1 = buf.push_and_get_window("dev_A", vec_a1)

    assert w_a1.shape == (4, 3)
    # First 3 steps should be zero-padded, last step should be vec_a1
    np.testing.assert_array_equal(w_a1[0], np.zeros(3))
    np.testing.assert_array_equal(w_a1[1], np.zeros(3))
    np.testing.assert_array_equal(w_a1[2], np.zeros(3))
    np.testing.assert_array_equal(w_a1[3], vec_a1)

    # 2. Device B should be isolated (cold start with no dev_A history)
    vec_b1 = np.array([9.0, 9.0, 9.0])
    w_b1 = buf.push_and_get_window("dev_B", vec_b1)
    assert w_b1.shape == (4, 3)
    np.testing.assert_array_equal(w_b1[3], vec_b1)

    # 3. Fill dev_A past capacity to test FIFO eviction
    buf.push_and_get_window("dev_A", np.array([2.0, 2.0, 2.0]))
    buf.push_and_get_window("dev_A", np.array([3.0, 3.0, 3.0]))
    w_a4 = buf.push_and_get_window("dev_A", np.array([4.0, 4.0, 4.0]))

    # Now all 4 rows are filled (no zero-padding)
    assert not np.any(np.all(w_a4 == 0, axis=1))
    np.testing.assert_array_equal(w_a4[0], vec_a1)
    np.testing.assert_array_equal(w_a4[3], np.array([4.0, 4.0, 4.0]))


def test_causal_sequence_dataset_construction():
    features = np.random.randn(20, 5).astype(np.float32)
    labels = np.array([0] * 15 + [1] * 5)
    dev_ids = ["dev_1"] * 10 + ["dev_2"] * 10
    ts = np.arange(100.0, 120.0)

    dataset = build_causal_sequences(features, labels, dev_ids, ts, sequence_length=4)
    assert dataset.X.shape == (20, 4, 5)
    assert len(dataset.y) == 20
    assert len(dataset.device_ids) == 20


def test_temporal_detector_scoring_and_persistence(tmp_path):
    model = TemporalGRU(input_dim=5, hidden_dim=16, num_layers=1, num_classes=2)
    detector = TemporalDetector(
        model=model,
        model_type="gru",
        sequence_length=4,
        feature_dim=5,
        class_names=["benign", "attack"],
        threshold=0.50,
        version="test_v1",
    )

    flow_vec = np.array([0.1, 0.2, 0.3, 0.4, 0.5])
    res = detector.score_flow("dev_X", flow_vec)

    assert "temporal_risk" in res
    assert 0.0 <= res["temporal_risk"] <= 1.0
    assert "temporal_pred" in res
    assert "temporal_flagged" in res
    assert res["history_length"] == 1
    assert "reason_codes" in res

    # Save and Load roundtrip
    out_dir = tmp_path / "temp_detector"
    detector.save(out_dir)

    loaded = TemporalDetector.load(out_dir)
    assert loaded.model_type == "gru"
    assert loaded.sequence_length == 4
    assert loaded.feature_dim == 5
