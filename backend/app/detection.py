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
from .config import settings

try:
    from training.open_set.classifier import OpenSetClassifier, OpenSetDecisionOutcome
    OPEN_SET_AVAILABLE = True
except ImportError:
    OPEN_SET_AVAILABLE = False
    OpenSetClassifier = None
    OpenSetDecisionOutcome = None

try:
    from training.explainability import TreeShapExplainer
    TREESHAP_AVAILABLE = True
except ImportError:
    TREESHAP_AVAILABLE = False
    TreeShapExplainer = None

try:
    from training.temporal import TemporalDetector
    TEMPORAL_AVAILABLE = True
except ImportError:
    TEMPORAL_AVAILABLE = False
    TemporalDetector = None

try:
    from training.graph import GraphDetector
    GRAPH_AVAILABLE = True
except ImportError:
    GRAPH_AVAILABLE = False
    GraphDetector = None

try:
    from backend.app.risk import HierarchicalRiskEngine
    RISK_ENGINE_AVAILABLE = True
except ImportError:
    RISK_ENGINE_AVAILABLE = False
    HierarchicalRiskEngine = None

MODEL_DIR = settings.MODEL_DIR
GRACE_PERIOD_FLOWS = settings.GRACE_PERIOD_FLOWS


class DetectionEngine:
    def __init__(self, model_dir: Path | None = None, grace_period_flows: int | None = None):
        self.lock = Lock()
        self.device_states: dict[str, DeviceState] = {}
        self.model_dir = Path(model_dir) if model_dir else MODEL_DIR
        self.grace_period_flows = (
            grace_period_flows if grace_period_flows is not None else GRACE_PERIOD_FLOWS
        )
        self._load_models()

    def _load_models(self):
        self.open_set_classifier = None
        try:
            self.scaler = joblib.load(self.model_dir / "feature_scaler.pkl")
            self.anomaly_model = joblib.load(self.model_dir / "anomaly_model.pkl")
            self.gate_model = joblib.load(self.model_dir / "gate_model.pkl")
            self.multiclass_model = joblib.load(self.model_dir / "multiclass_model.pkl")
            with open(self.model_dir / "gate_threshold.json") as f:
                self.gate_threshold = json.load(f)["gate_threshold"]
            with open(self.model_dir / "feature_columns.json") as f:
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

        # Optional Phase 3: Open-Set Classifier Loading
        if OPEN_SET_AVAILABLE and getattr(settings, "ENABLE_OPEN_SET", True):
            # If a custom model_dir was provided, look for open_set_v1 inside that directory
            if self.model_dir != MODEL_DIR:
                open_set_dir = self.model_dir / "open_set_v1"
            else:
                open_set_dir = getattr(settings, "OPEN_SET_MODEL_DIR", self.model_dir / "open_set_v1")
            if open_set_dir and Path(open_set_dir).exists() and (Path(open_set_dir) / "open_set_metadata.json").exists():
                try:
                    self.open_set_classifier = OpenSetClassifier.load(open_set_dir)
                except Exception:
                    self.open_set_classifier = None

        # Phase 4 Component A: Exact TreeSHAP Explainer
        self.shap_explainer = None
        if TREESHAP_AVAILABLE and getattr(settings, "ENABLE_TREESHAP", True):
            target_gate = self.gate_model or (self.open_set_classifier.gate_model if self.open_set_classifier else None)
            if target_gate is not None:
                try:
                    self.shap_explainer = TreeShapExplainer(
                        model=target_gate,
                        feature_names=FEATURE_COLUMNS,
                        class_names=["benign", "attack"],
                    )
                except Exception:
                    self.shap_explainer = None

        # Phase 4 Component B: Temporal Sequence Intelligence
        self.temporal_detector = None
        if TEMPORAL_AVAILABLE and getattr(settings, "ENABLE_TEMPORAL", True):
            temp_dir = getattr(settings, "TEMPORAL_MODEL_DIR", None)
            if temp_dir and Path(temp_dir).exists() and (Path(temp_dir) / "temporal_metadata.json").exists():
                try:
                    self.temporal_detector = TemporalDetector.load(temp_dir)
                except Exception:
                    self.temporal_detector = None

        # Phase 4 Component C: Communication Graph Intelligence
        self.graph_detector = None
        if GRAPH_AVAILABLE and getattr(settings, "ENABLE_GRAPH", True):
            graph_dir = getattr(settings, "GRAPH_MODEL_DIR", None)
            if graph_dir and Path(graph_dir).exists() and (Path(graph_dir) / "graph_metadata.json").exists():
                try:
                    self.graph_detector = GraphDetector.load(graph_dir)
                except Exception:
                    self.graph_detector = None

        # Phase 4 Component D: Hierarchical Risk Engine
        self.risk_engine = None
        if RISK_ENGINE_AVAILABLE and getattr(settings, "ENABLE_HIERARCHICAL_RISK", True):
            try:
                self.risk_engine = HierarchicalRiskEngine(
                    suppression_window_sec=getattr(settings, "ALERT_SUPPRESSION_WINDOW_SEC", 5.0)
                )
            except Exception:
                self.risk_engine = None

    def _device_state(self, device_id: str) -> DeviceState:
        if device_id not in self.device_states:
            self.device_states[device_id] = DeviceState()
        return self.device_states[device_id]

    def score_flow(self, flow: dict) -> dict:
        """Returns a dict with gate_score, anomaly_score, is_flagged, and
        (if flagged) attack_type/mitre/severity/confidence_tier/top_features/
        shap_values/shap_base_value."""
        if not self.models_loaded and self.open_set_classifier is None:
            return {
                "error": "models_not_trained",
                "gate_score": 0.0, "anomaly_score": 0.0, "is_flagged": False,
            }

        with self.lock:
            state = self._device_state(flow["device_id"])
            vec = build_feature_vector(flow, state)
            flow_count = state.flow_count

        in_grace_period = flow_count <= self.grace_period_flows

        current_scaler = self.scaler if self.scaler is not None else (self.open_set_classifier.scaler if self.open_set_classifier else None)
        X = np.array([vec])
        X_s = current_scaler.transform(X) if current_scaler is not None else X

        # Phase 4 Component B: Temporal sequence scoring
        temporal_res = None
        if self.temporal_detector is not None:
            try:
                temporal_res = self.temporal_detector.score_flow(flow["device_id"], X_s[0])
            except Exception:
                temporal_res = None

        # Phase 4 Component C: Communication graph scoring
        graph_res = None
        if self.graph_detector is not None:
            try:
                graph_res = self.graph_detector.score_flow(flow)
            except Exception:
                graph_res = None

        # Path A: Open-Set Detection Engine (Phase 3)
        if self.open_set_classifier is not None:
            dec = self.open_set_classifier.predict_sample(vec, feature_names=FEATURE_COLUMNS)
            gate_score = dec.gate_score
            anomaly_score = dec.raw_anomaly_score
            calibrated_anomaly = dec.calibrated_anomaly_score
            novelty_score = dec.novelty_score

            is_flagged = (not in_grace_period) and (
                dec.outcome in (OpenSetDecisionOutcome.KNOWN_ATTACK, OpenSetDecisionOutcome.UNKNOWN_SUSPICIOUS)
            )

            result = {
                "gate_score": gate_score,
                "anomaly_score": anomaly_score,
                "calibrated_anomaly_score": calibrated_anomaly,
                "novelty_score": novelty_score,
                "is_flagged": bool(is_flagged),
                "in_grace_period": in_grace_period,
                "feature_vector": vec,
                "decision": dec.outcome.value,
                "is_unknown": dec.is_unknown,
                "reason_codes": dec.reason_codes,
            }

            if is_flagged:
                if dec.outcome == OpenSetDecisionOutcome.UNKNOWN_SUSPICIOUS:
                    attack_type = "unknown_suspicious"
                    mitre = "T1204 (Zero-Day / Novel Vector - Open-Set Anomaly)"
                    confidence = dec.confidence
                    tier = "medium" if confidence >= 0.70 else "low"
                    severity = "warning"
                else:
                    attack_type = dec.predicted_class or "unclassified_anomaly"
                    mitre = MITRE_MAP.get(attack_type, "N/A")
                    confidence = dec.confidence
                    if confidence >= 0.85 and gate_score >= 0.9:
                        tier = "high"
                        severity = "critical"
                    elif confidence >= 0.6:
                        tier = "medium"
                        severity = "warning"
                    else:
                        tier = "low"
                        severity = "info"

                shap_method = "exact_treeshap" if (self.shap_explainer and self.shap_explainer.is_exact) else "ablation_vs_scaler_mean"
                result.update({
                    "attack_type": attack_type,
                    "mitre": mitre,
                    "severity": severity,
                    "confidence_tier": tier,
                    "confidence": confidence,
                    "top_features": self._top_features(vec),
                    "shap_values": self._shap_explain(X_s, vec),
                    "shap_base_value": self._shap_base_value(X_s),
                    "shap_method": shap_method,
                })

        else:
            # Path B: Baseline V1 Fallback
            gate_score = float(self.gate_model.predict_proba(X_s)[0, 1])
            anomaly_score = float(-self.anomaly_model.score_samples(X_s)[0])
            anomaly_flag = self.anomaly_model.predict(X_s)[0] == -1

            is_flagged = (not in_grace_period) and ((gate_score >= self.gate_threshold) or anomaly_flag)

            result = {
                "gate_score": gate_score,
                "anomaly_score": anomaly_score,
                "calibrated_anomaly_score": 0.0,
                "novelty_score": 0.0,
                "is_flagged": bool(is_flagged),
                "in_grace_period": in_grace_period,
                "feature_vector": vec,
                "decision": "known_attack" if is_flagged else "benign",
                "is_unknown": False,
                "reason_codes": [],
            }

            if is_flagged:
                probs = self.multiclass_model.predict_proba(X_s)[0]
                pred_id = int(np.argmax(probs))
                attack_type = ID_TO_LABEL[pred_id]
                confidence = float(probs[pred_id])

                if attack_type == "benign":
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

                shap_method = "exact_treeshap" if (self.shap_explainer and self.shap_explainer.is_exact) else "ablation_vs_scaler_mean"
                result.update({
                    "attack_type": attack_type,
                    "mitre": mitre,
                    "severity": severity,
                    "confidence_tier": tier,
                    "confidence": confidence,
                    "top_features": self._top_features(vec),
                    "shap_values": self._shap_explain(X_s, vec),
                    "shap_base_value": self._shap_base_value(X_s),
                    "shap_method": shap_method,
                })

        # Phase 4 Component D: Multi-tier Hierarchical Risk Synthesis
        risk_breakdown = None
        if self.risk_engine is not None:
            try:
                risk_breakdown = self.risk_engine.evaluate_risk(
                    device_id=flow["device_id"],
                    timestamp=flow.get("ts", time.time()),
                    flow_result=result,
                    temporal_result=temporal_res,
                    graph_result=graph_res,
                )
            except Exception:
                risk_breakdown = None

        result["temporal"] = temporal_res
        result["graph"] = graph_res
        if risk_breakdown is not None:
            result["risk_breakdown"] = risk_breakdown.to_dict()
            result["composite_device_risk"] = risk_breakdown.composite_device_risk
            result["risk_tier"] = risk_breakdown.risk_tier

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
        """Exact TreeSHAP attribution when available, with heuristic fallback."""
        if getattr(self, "shap_explainer", None) is not None:
            try:
                explanation = self.shap_explainer.explain(
                    x_raw=vec,
                    x_scaled=X_s,
                    target_class="attack",
                    top_k=k,
                )
                return explanation.top_features
            except Exception:
                pass

        try:
            full = float(self.gate_model.predict_proba(X_s)[0, 1])
            n_cols = len(FEATURE_COLUMNS)
            ablated_batch = np.repeat(X_s, n_cols, axis=0)
            np.fill_diagonal(ablated_batch, 0.0)
            ablated_probs = self.gate_model.predict_proba(ablated_batch)[:, 1]

            out = []
            for i, name in enumerate(FEATURE_COLUMNS):
                raw_val = round(float(vec[i]), 3)
                out.append({
                    "feature": name,
                    "value": raw_val,
                    "raw_value": raw_val,
                    "scaled_value": round(float(X_s[0, i]), 4),
                    "contribution": round(float(full - ablated_probs[i]), 5),
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
