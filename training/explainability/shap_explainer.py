"""
Exact TreeSHAP Explainability Module for Tree-Based Intrusion Detection Models.

Computes mathematically exact Shapley value attributions using shap.TreeExplainer,
verifies the efficiency/additive property (sum(phi_i) + phi_0 == f(x)),
and supports graceful fallback to heuristic ablation when SHAP is unavailable.
"""

from dataclasses import dataclass, field
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np

try:
    import shap
    HAS_SHAP = True
except ImportError:
    HAS_SHAP = False
    shap = None


@dataclass
class ExplanationResult:
    predicted_class: str
    target_class_idx: int
    base_value: float                        # phi_0: Expected value
    contributions: Dict[str, float]           # Feature name -> Shapley value phi_i
    top_features: List[Dict[str, Any]]        # Sorted top contributors
    satisfies_additivity: bool                # True if sum(phi) + phi_0 == f(x)
    reconstructed_prediction: float          # phi_0 + sum(phi_i)
    actual_model_output: float               # Model predict_proba output
    method: str                              # "exact_treeshap" or "ablation_fallback"
    latency_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "predicted_class": self.predicted_class,
            "target_class_idx": self.target_class_idx,
            "base_value": round(float(self.base_value), 5),
            "contributions": {k: round(float(v), 5) for k, v in self.contributions.items()},
            "top_features": self.top_features,
            "satisfies_additivity": self.satisfies_additivity,
            "reconstructed_prediction": round(float(self.reconstructed_prediction), 5),
            "actual_model_output": round(float(self.actual_model_output), 5),
            "method": self.method,
            "latency_ms": round(float(self.latency_ms), 3),
        }


class TreeShapExplainer:
    """
    Wraps tree-based classifiers (e.g. RandomForest) with exact TreeSHAP attribution.
    """

    def __init__(
        self,
        model: Any,
        feature_names: List[str],
        class_names: Optional[List[str]] = None,
        tolerance: float = 1e-3,
    ):
        self.model = model
        self.feature_names = list(feature_names)
        self.tolerance = tolerance

        if class_names is not None:
            self.class_names = list(class_names)
        elif hasattr(model, "classes_"):
            self.class_names = [str(c) for c in model.classes_]
        else:
            self.class_names = ["class_0", "class_1"]

        self._explainer = None
        self._init_explainer()

    def _init_explainer(self):
        if not HAS_SHAP:
            return

        try:
            # TreeExplainer with interventional/tree_path_dependent feature perturbation
            self._explainer = shap.TreeExplainer(self.model)
        except Exception:
            self._explainer = None

    @property
    def is_exact(self) -> bool:
        return self._explainer is not None

    def explain(
        self,
        x_raw: np.ndarray,
        x_scaled: np.ndarray,
        target_class: Optional[Union[str, int]] = None,
        top_k: int = 8,
    ) -> ExplanationResult:
        """
        Explains a single feature vector instance.
        """
        t0 = time.perf_counter()

        x_s = np.asarray(x_scaled, dtype=np.float64)
        if x_s.ndim == 1:
            x_s = x_s.reshape(1, -1)

        x_r = np.asarray(x_raw, dtype=np.float64).flatten()

        # Model predicted probabilities
        probs = self.model.predict_proba(x_s)[0]

        # Determine target class index
        if target_class is None:
            target_idx = int(np.argmax(probs))
        elif isinstance(target_class, int):
            target_idx = target_class
        else:
            target_idx = self.class_names.index(target_class) if target_class in self.class_names else int(np.argmax(probs))

        pred_class = self.class_names[target_idx]
        actual_output = float(probs[target_idx])

        # Attempt Exact TreeSHAP
        if self._explainer is not None:
            try:
                shap_vals = self._explainer.shap_values(x_s)

                # shap_values format varies by shap version:
                # Can be list of (1, D) arrays, or 3D array (1, D, num_classes)
                if isinstance(shap_vals, list):
                    phi = np.asarray(shap_vals[target_idx][0], dtype=np.float64)
                elif isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 3:
                    phi = np.asarray(shap_vals[0, :, target_idx], dtype=np.float64)
                elif isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 2:
                    phi = np.asarray(shap_vals[0], dtype=np.float64)
                else:
                    phi = np.asarray(shap_vals, dtype=np.float64).flatten()

                # Expected base value
                expected_vals = self._explainer.expected_value
                if isinstance(expected_vals, (list, np.ndarray)):
                    phi_0 = float(expected_vals[target_idx])
                else:
                    phi_0 = float(expected_vals)

                reconstructed = float(phi_0 + np.sum(phi))
                is_additive = bool(abs(reconstructed - actual_output) < self.tolerance)

                contributions = {name: float(phi[i]) for i, name in enumerate(self.feature_names)}

                # Build top_k features
                top_feats = []
                for i, name in enumerate(self.feature_names):
                    raw_val = round(float(x_r[i]), 4) if i < len(x_r) else 0.0
                    top_feats.append({
                        "feature": name,
                        "value": raw_val,
                        "raw_value": raw_val,
                        "scaled_value": round(float(x_s[0, i]), 4),
                        "contribution": round(float(phi[i]), 5),
                    })
                top_feats.sort(key=lambda d: abs(d["contribution"]), reverse=True)

                t_delta = (time.perf_counter() - t0) * 1000.0

                return ExplanationResult(
                    predicted_class=pred_class,
                    target_class_idx=target_idx,
                    base_value=phi_0,
                    contributions=contributions,
                    top_features=top_feats[:top_k],
                    satisfies_additivity=is_additive,
                    reconstructed_prediction=reconstructed,
                    actual_model_output=actual_output,
                    method="exact_treeshap",
                    latency_ms=t_delta,
                )
            except Exception:
                # Graceful fallback to heuristic ablation on unexpected failure
                pass

        # Fallback: Scaler-Mean Heuristic Ablation
        return self._heuristic_ablation_fallback(x_r, x_s, target_idx, pred_class, actual_output, top_k, t0)

    def _heuristic_ablation_fallback(
        self,
        x_r: np.ndarray,
        x_s: np.ndarray,
        target_idx: int,
        pred_class: str,
        actual_output: float,
        top_k: int,
        t0: float,
    ) -> ExplanationResult:
        """
        Heuristic ablation against scaler-mean (0.0) baseline.
        Does NOT satisfy strict Shapley efficiency/additivity.
        """
        baseline_x = np.zeros_like(x_s)
        phi_0 = float(self.model.predict_proba(baseline_x)[0, target_idx])

        contributions = {}
        top_feats = []

        n_feats = len(self.feature_names)
        ablated_batch = np.repeat(x_s, n_feats, axis=0)
        np.fill_diagonal(ablated_batch, 0.0)
        ablated_probs = self.model.predict_proba(ablated_batch)[:, target_idx]

        for i, name in enumerate(self.feature_names):
            contrib = float(actual_output - ablated_probs[i])
            contributions[name] = contrib
            raw_val = round(float(x_r[i]), 4) if i < len(x_r) else 0.0
            top_feats.append({
                "feature": name,
                "value": raw_val,
                "raw_value": raw_val,
                "scaled_value": round(float(x_s[0, i]), 4),
                "contribution": round(contrib, 5),
            })

        top_feats.sort(key=lambda d: abs(d["contribution"]), reverse=True)
        reconstructed = float(phi_0 + sum(contributions.values()))
        is_additive = bool(abs(reconstructed - actual_output) < self.tolerance)
        t_delta = (time.perf_counter() - t0) * 1000.0

        return ExplanationResult(
            predicted_class=pred_class,
            target_class_idx=target_idx,
            base_value=phi_0,
            contributions=contributions,
            top_features=top_feats[:top_k],
            satisfies_additivity=is_additive,
            reconstructed_prediction=reconstructed,
            actual_model_output=actual_output,
            method="ablation_fallback",
            latency_ms=t_delta,
        )
