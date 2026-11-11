"""
Unit tests for Exact TreeSHAP Explainability (training/explainability/shap_explainer.py).
"""

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

from backend.app.features import FEATURE_COLUMNS
from training.explainability.shap_explainer import TreeShapExplainer, ExplanationResult


@pytest.fixture
def trained_toy_rf():
    np.random.seed(42)
    n_samples = 150
    n_features = len(FEATURE_COLUMNS)  # 20 features

    X = np.random.randn(n_samples, n_features)
    # Target heavily driven by feature 0 (duration) and feature 1 (orig_bytes)
    y = ((X[:, 0] > 0.3) | (X[:, 1] > 0.5)).astype(int)

    rf = RandomForestClassifier(n_estimators=15, max_depth=5, random_state=42)
    rf.fit(X, y)
    return rf, X, y


def test_treeshap_additive_correctness(trained_toy_rf):
    rf, X, y = trained_toy_rf
    explainer = TreeShapExplainer(
        model=rf,
        feature_names=FEATURE_COLUMNS,
        class_names=["benign", "attack"],
        tolerance=1e-3,
    )

    assert explainer.is_exact is True

    # Test multiple instances to verify additivity across distribution
    for i in range(5):
        sample_raw = X[i] * 10.0 + 50.0  # Synthetic unscaled raw
        sample_scaled = X[i]

        result = explainer.explain(
            x_raw=sample_raw,
            x_scaled=sample_scaled,
            target_class="attack",
            top_k=5,
        )

        assert isinstance(result, ExplanationResult)
        assert result.method == "exact_treeshap"
        assert result.satisfies_additivity is True

        # Mathematical Efficiency / Additivity property:
        # f(x) == phi_0 + sum(phi_i)
        phi_sum = sum(result.contributions.values())
        reconstructed = result.base_value + phi_sum
        assert abs(reconstructed - result.actual_model_output) < 1e-3
        assert abs(result.reconstructed_prediction - result.actual_model_output) < 1e-3

        # Verify top features alignment
        assert len(result.top_features) == 5
        assert all("feature" in item and "contribution" in item for item in result.top_features)
        assert result.top_features[0]["feature"] in FEATURE_COLUMNS


def test_treeshap_multiclass_support():
    np.random.seed(42)
    X = np.random.randn(120, 20)
    y = np.random.choice(["benign", "port_scan", "ddos"], size=120)

    rf = RandomForestClassifier(n_estimators=10, max_depth=4, random_state=42)
    rf.fit(X, y)

    explainer = TreeShapExplainer(
        model=rf,
        feature_names=FEATURE_COLUMNS,
        class_names=sorted(list(set(y))),
    )

    res = explainer.explain(x_raw=X[0], x_scaled=X[0], target_class="port_scan")
    assert res.target_class_idx == explainer.class_names.index("port_scan")
    assert res.satisfies_additivity is True
    assert len(res.contributions) == 20


def test_treeshap_fallback_mode(trained_toy_rf, monkeypatch):
    rf, X, y = trained_toy_rf
    # Simulate missing or failing shap
    explainer = TreeShapExplainer(
        model=rf,
        feature_names=FEATURE_COLUMNS,
        class_names=["benign", "attack"],
    )
    explainer._explainer = None  # Force fallback path

    res = explainer.explain(x_raw=X[0], x_scaled=X[0], target_class="attack")
    assert res.method == "ablation_fallback"
    assert len(res.contributions) == 20
    assert len(res.top_features) == 8
