"""
Score Calibration Module for Open-Set Detection.

Provides empirical calibration of raw IsolationForest anomaly scores to a [0, 1] scale
and ROC-based threshold calibration constrained to an operational false-positive ceiling (<= 2%).
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from sklearn.metrics import roc_curve


@dataclass
class AnomalyCalibrator:
    """
    Calibrates raw IsolationForest anomaly scores against a reference benign distribution.
    Produces a calibrated anomaly score S_anom in [0.0, 1.0] representing the percentile.
    """
    sorted_benign_scores: np.ndarray
    threshold_95: float
    threshold_99: float
    version: str = "v1"

    @classmethod
    def fit(cls, raw_benign_scores: np.ndarray, version: str = "v1") -> "AnomalyCalibrator":
        """Fits calibration on benign validation raw scores."""
        clean_scores = np.sort(np.asarray(raw_benign_scores, dtype=np.float64))
        if len(clean_scores) == 0:
            raise ValueError("Cannot fit calibrator on empty scores array")

        t95 = float(np.percentile(clean_scores, 95.0))
        t99 = float(np.percentile(clean_scores, 99.0))

        return cls(
            sorted_benign_scores=clean_scores,
            threshold_95=t95,
            threshold_99=t99,
            version=version,
        )

    def calibrate(self, raw_score: float) -> float:
        """
        Maps raw score to a calibrated percentile in [0.0, 1.0].
        Scores higher than any benign sample approach 1.0.
        """
        if len(self.sorted_benign_scores) == 0:
            return 0.5

        # Rank of raw_score among benign scores
        idx = np.searchsorted(self.sorted_benign_scores, raw_score, side="right")
        percentile = float(idx) / float(len(self.sorted_benign_scores))
        return round(float(np.clip(percentile, 0.0, 1.0)), 4)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes calibrator metadata."""
        return {
            "version": self.version,
            "sample_count": len(self.sorted_benign_scores),
            "threshold_95": self.threshold_95,
            "threshold_99": self.threshold_99,
            "min_score": float(self.sorted_benign_scores[0]) if len(self.sorted_benign_scores) > 0 else 0.0,
            "max_score": float(self.sorted_benign_scores[-1]) if len(self.sorted_benign_scores) > 0 else 1.0,
        }


def calibrate_gate_threshold(
    y_true_binary: np.ndarray,
    y_gate_scores: np.ndarray,
    max_fpr: float = 0.02,
    target_fpr: float = 0.01,
) -> Tuple[float, float, float]:
    """
    Selects an optimal decision threshold subject to FPR <= max_fpr (<= 2%).
    Fitted strictly on validation data to prevent test leakage.

    Among thresholds achieving maximum TPR, selects the threshold with FPR
    closest to target_fpr (or the median of the optimal plateau) to avoid
    fragile edge-point extremes.

    Returns (threshold, achieved_fpr, achieved_tpr).
    """
    y_true = np.asarray(y_true_binary, dtype=int)
    scores = np.asarray(y_gate_scores, dtype=np.float64)

    fpr, tpr, thresholds = roc_curve(y_true, scores)
    valid_mask = (fpr <= max_fpr) & np.isfinite(thresholds)

    if not np.any(valid_mask):
        # Fallback to the conservative maximum finite threshold
        finite_thr = thresholds[np.isfinite(thresholds)]
        fallback = float(np.max(finite_thr)) if len(finite_thr) > 0 else 0.5
        return fallback, float(fpr[0]), float(tpr[0])

    valid_indices = np.where(valid_mask)[0]
    max_tpr = np.max(tpr[valid_indices])
    best_candidates = valid_indices[tpr[valid_indices] == max_tpr]

    # Select candidate with FPR closest to target_fpr
    fpr_diffs = np.abs(fpr[best_candidates] - target_fpr)
    best_candidate_idx = best_candidates[np.argmin(fpr_diffs)]

    return (
        float(thresholds[best_candidate_idx]),
        float(fpr[best_candidate_idx]),
        float(tpr[best_candidate_idx]),
    )
