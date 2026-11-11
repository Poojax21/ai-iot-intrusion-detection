"""
Unit tests for OpenSetClassifier 4-way triage logic (training/open_set/classifier.py).
"""

from pathlib import Path
import numpy as np
import pytest
from training.open_set.classifier import OpenSetClassifier, OpenSetDecisionOutcome


@pytest.fixture
def trained_classifier():
    model_dir = Path("backend/app/models/open_set_v1")
    if not model_dir.exists() or not (model_dir / "open_set_metadata.json").exists():
        pytest.skip("open_set_v1 models not present")
    return OpenSetClassifier.load(model_dir)


from backend.app.features import DeviceState, build_feature_vector


def test_classifier_triage_benign(trained_classifier, sample_benign_flow):
    # Valid benign flow built through feature extractor
    state = DeviceState()
    # Warm up device state so baseline is established
    for _ in range(6):
        vec = build_feature_vector(sample_benign_flow, state)

    decision = trained_classifier.predict_sample(vec)

    assert decision.outcome == OpenSetDecisionOutcome.BENIGN
    assert decision.predicted_class == "benign"
    assert decision.is_unknown is False
    assert "LOW_GATE_AND_ANOMALY" in decision.reason_codes


def test_classifier_triage_known_attack(trained_classifier):
    # Port scan signature: duration 0.001, orig_bytes 48, orig_pkts 1, conn_state S0
    x_scan = np.array([
        0.001, 48.0, 0.0, 1.0, 0.0, 48.0, 1.0,
        48000.0, 1000.0, 48.0, 1.0, 15.0, 2.5,
        1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0
    ])
    decision = trained_classifier.predict_sample(x_scan)

    assert decision.outcome in (OpenSetDecisionOutcome.KNOWN_ATTACK, OpenSetDecisionOutcome.UNKNOWN_SUSPICIOUS)
    if decision.outcome == OpenSetDecisionOutcome.KNOWN_ATTACK:
        assert decision.predicted_class in ("port_scan", "ddos")
        assert decision.is_unknown is False


def test_classifier_batch_prediction_parity(trained_classifier, sample_benign_flow):
    state = DeviceState()
    for _ in range(6):
        vec = build_feature_vector(sample_benign_flow, state)

    X = np.array([vec] * 5)
    batch_decisions = trained_classifier.predict_batch(X)
    assert len(batch_decisions) == 5

    single_decision = trained_classifier.predict_sample(X[0])
    assert batch_decisions[0].outcome == single_decision.outcome
    assert batch_decisions[0].is_unknown == single_decision.is_unknown


def test_classifier_save_load_roundtrip(tmp_path, trained_classifier):
    out_dir = tmp_path / "saved_open_set"
    trained_classifier.save(out_dir)

    assert (out_dir / "open_set_metadata.json").exists()
    assert (out_dir / "gate_model.pkl").exists()

    loaded = OpenSetClassifier.load(out_dir)
    assert loaded.version == trained_classifier.version
    assert loaded.class_names == trained_classifier.class_names
    assert loaded.gate_threshold == trained_classifier.gate_threshold
