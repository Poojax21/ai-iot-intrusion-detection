"""
Two-stage detection pipeline (plan §6):

  Stage 1 (runs on EVERY flow, cheap):
    - unsupervised anomaly score (IsolationForest, benign-only trained)
    - binary gate (RandomForest, tuned to a hard FPR ceiling)
    -> if EITHER crosses its threshold, the flow is "flagged"

  Stage 2 (runs ONLY on flagged flows):
    - multiclass attack-type classifier
    - SHAP-style per-alert explanation (ablation contributions against the
      scaler-mean baseline — see _shap_explain; swap for exact TreeSHAP
      via the `shap` package if needed, same wire shape)

Also owns per-device rolling baseline state (features.DeviceState) — this is
what makes detection behavioral/per-device instead of a global threshold.
"""

import json
import time
from pathlib import Path
from threading import Lock

import joblib
import numpy as np

from .features import (
    FEATURE_COLUMNS, ATTACK_LABELS, ID_TO_LABEL, MITRE_MAP,
    DeviceState, build_feature_vector,
)

MODEL_DIR = Path(__file__).parent / "models"

# New-device grace period (plan §10/§11): a device with little to no traffic
# history looks statistically "anomalous" almost by definition (its rolling
# baseline hasn't formed yet). Rather than alerting on every brand-new
# device's first few flows, we observe-only until enough history exists to
# make the per-device baseline meaningful. This is the single biggest lever
# for cutting false positives on a freshly-connected fleet (real or
# simulated) without weakening detection once a device is established.
GRACE_PERIOD_FLOWS = 15


class DetectionEngine:
    def __init__(self):
        self.lock = Lock()
        self.device_states: dict[str, DeviceState] = {}
        self._load_models()

    def _load_models(self):
        try:
            self.scaler = joblib.load(MODEL_DIR / "feature_scaler.pkl")
            self.anomaly_model = joblib.load(MODEL_DIR / "anomaly_model.pkl")
            self.gate_model = joblib.load(MODEL_DIR / "gate_model.pkl")
            self.multiclass_model = joblib.load(MODEL_DIR / "multiclass_model.pkl")
            with open(MODEL_DIR / "gate_threshold.json") as f:
                self.gate_threshold = json.load(f)["gate_threshold"]
            with open(MODEL_DIR / "feature_columns.json") as f:
                saved = json.load(f)
            if saved["feature_columns"] != FEATURE_COLUMNS:
                raise RuntimeError(
                    "Feature column mismatch between saved models and features.py! "
                    "Retrain the models (they were trained on a different feature set)."
                )
            self.models_loaded = True
        except FileNotFoundError:
            # Models not trained yet — run the training notebook first.
            # The backend still starts so the API/frontend are inspectable,
            # but /api/ingest will report a clear error instead of crashing.
            self.models_loaded = False
            self.scaler = self.anomaly_model = self.gate_model = self.multiclass_model = None
            self.gate_threshold = 0.5

    def _device_state(self, device_id: str) -> DeviceState:
        if device_id not in self.device_states:
            self.device_states[device_id] = DeviceState()
        return self.device_states[device_id]

    def score_flow(self, flow: dict) -> dict:
        """Returns a dict with gate_score, anomaly_score, is_flagged, and
        (if flagged) attack_type/mitre/severity/confidence_tier/top_features/
        shap_values/shap_base_value."""
        if not self.models_loaded:
            return {
                "error": "models_not_trained",
                "gate_score": 0.0, "anomaly_score": 0.0, "is_flagged": False,
            }

        with self.lock:
            state = self._device_state(flow["device_id"])
            vec = build_feature_vector(flow, state)
            flow_count = state.flow_count

        X = np.array([vec])
        X_s = self.scaler.transform(X)

        gate_score = float(self.gate_model.predict_proba(X_s)[0, 1])
        anomaly_score = float(-self.anomaly_model.score_samples(X_s)[0])
        # anomaly threshold: flag top ~5% most anomalous by the training-time contamination setting;
        # simple fixed cutoff kept in sync with the notebook's IsolationForest(contamination=0.05)
        anomaly_flag = self.anomaly_model.predict(X_s)[0] == -1

        in_grace_period = flow_count <= GRACE_PERIOD_FLOWS
        is_flagged = (not in_grace_period) and ((gate_score >= self.gate_threshold) or anomaly_flag)

        result = {
            "gate_score": gate_score,
            "anomaly_score": anomaly_score,
            "is_flagged": bool(is_flagged),
            "in_grace_period": in_grace_period,
            "feature_vector": vec,
        }

        if is_flagged:
            probs = self.multiclass_model.predict_proba(X_s)[0]
            pred_id = int(np.argmax(probs))
            attack_type = ID_TO_LABEL[pred_id]
            confidence = float(probs[pred_id])

            if attack_type == "benign":
                # gate/anomaly fired but the multiclass head disagrees on "what" —
                # surface as a low-confidence anomaly rather than inventing an attack label
                attack_type = "unclassified_anomaly"
                mitre = "N/A - unsupervised anomaly only, no matching known attack pattern"
            else:
                mitre = MITRE_MAP.get(attack_type, "N/A")

            if confidence >= 0.85 and gate_score >= 0.9:
                tier = "high"
                severity = "critical"
            elif confidence >= 0.6:
                tier = "medium"
                severity = "warning"
            else:
                tier = "low"
                severity = "info"

            result.update({
                "attack_type": attack_type,
                "mitre": mitre,
                "severity": severity,
                "confidence_tier": tier,
                "confidence": confidence,
                "top_features": self._top_features(vec),
                "shap_values": self._shap_explain(X_s, vec),
                "shap_base_value": self._shap_base_value(X_s),
                "shap_method": "ablation_vs_scaler_mean",
            })

        return result

    def _shap_base_value(self, X_s) -> float:
        """P(attack) for average traffic (scaled zero-vector = scaler mean).
        This is the SHAP `expected_value`: contributions push from here to
        the alert's gate_score."""
        try:
            baseline = np.zeros_like(X_s)
            return float(self.gate_model.predict_proba(baseline)[0, 1])
        except Exception:
            return 0.0

    def _shap_explain(self, X_s, vec, k=8):
        """SHAP-style additive contributions without the `shap` dependency.

        contribution[i] = P_attack(full) - P_attack(feature i reset to its
        baseline mean). Positive = pushes toward attack, negative = pushes
        toward benign. Faithful to the live gate model (same predict_proba),
        O(n_features) predicts per alert — cheap for 20 features.

        Swap-in path for exact TreeSHAP: replace this body with
        `shap.TreeExplainer(self.gate_model).shap_values(X_s)` and keep the
        same return shape [{feature, value, contribution}].
        """
        try:
            full = float(self.gate_model.predict_proba(X_s)[0, 1])
            out = []
            for i, name in enumerate(FEATURE_COLUMNS):
                ablated = X_s.copy()
                ablated[0, i] = 0.0  # scaler-mean baseline for feature i
                s = float(self.gate_model.predict_proba(ablated)[0, 1])
                out.append({
                    "feature": name,
                    "value": round(float(vec[i]), 3),
                    "contribution": round(float(full - s), 5),
                })
            out.sort(key=lambda d: abs(d["contribution"]), reverse=True)
            return out[:k]
        except Exception:
            # Never break alerting because explanation failed.
            return [
                {"feature": name, "value": val, "contribution": 0.0}
                for name, val in self._top_features(vec, k=k)
            ]

    @staticmethod
    def _top_features(vec, k=3):
        """Legacy compact summary (kept for backward compat with old rows).
        Prefer `shap_values` for per-alert reasoning."""
        interesting_idx = [FEATURE_COLUMNS.index(c) for c in
                            ["device_zscore", "byte_rate", "pkt_rate", "src_fanout_recent", "is_new_edge"]]
        scored = sorted(
            ((FEATURE_COLUMNS[i], round(vec[i], 3)) for i in interesting_idx),
            key=lambda t: abs(t[1]), reverse=True,
        )
        return scored[:k]


engine = DetectionEngine()
