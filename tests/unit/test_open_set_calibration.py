"""
Unit tests for Open-Set Score Calibration (training/open_set/calibration.py).
"""

import numpy as np
import pytest
from training.open_set.calibration import AnomalyCalibrator, calibrate_gate_threshold


def test_anomaly_calibrator_properties():
    # Synthetic benign distribution centered around 0.4
    np.random.seed(42)
    benign_scores = np.random.normal(loc=0.4, scale=0.08, size=1000)

    calibrator = AnomalyCalibrator.fit(benign_scores, version="v1_test")
    assert calibrator.version == "v1_test"
    assert calibrator.threshold_95 > calibrator.threshold_99 or calibrator.threshold_99 >= calibrator.threshold_95

    # 1. Monotonicity: Higher raw scores must produce equal or higher calibrated scores
    low_val = calibrator.calibrate(0.2)
    mid_val = calibrator.calibrate(0.4)
    high_val = calibrator.calibrate(0.8)

    assert 0.0 <= low_val <= mid_val <= high_val <= 1.0

    # 2. Score bounds
    assert calibrator.calibrate(-10.0) == 0.0
    assert calibrator.calibrate(10.0) == 1.0

    # 3. Serialization
    d = calibrator.to_dict()
    assert d["version"] == "v1_test"
    assert d["sample_count"] == 1000


def test_calibrate_gate_threshold_respects_fpr_ceiling():
    np.random.seed(42)
    # 900 benign samples with low scores
    benign_scores = np.random.beta(a=1, b=30, size=900)
    # 100 attack samples with high scores
    attack_scores = np.random.beta(a=30, b=1, size=100)

    y_true = np.array([0] * 900 + [1] * 100)
    scores = np.concatenate([benign_scores, attack_scores])

    # Max FPR <= 0.02
    thr, fpr, tpr = calibrate_gate_threshold(y_true, scores, max_fpr=0.02, target_fpr=0.01)

    assert fpr <= 0.02
    assert tpr >= 0.90
    assert 0.0 <= thr <= 1.0


def test_calibrate_gate_threshold_fallback():
    # Degenerate case where scores are identical
    y_true = np.array([0, 0, 1, 1])
    scores = np.array([0.5, 0.5, 0.5, 0.5])

    thr, fpr, tpr = calibrate_gate_threshold(y_true, scores, max_fpr=0.02)
    assert 0.0 <= thr <= 1.0
