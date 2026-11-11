"""
Open-Set Classifier & Triage Engine.

Combines Stage-1 statistical gating, calibrated anomaly scoring, multiclass confidence
estimation, and feature-space geometry into a 4-outcome open-set decision:
  - BENIGN
  - KNOWN_ATTACK
  - UNKNOWN_SUSPICIOUS
  - UNCERTAIN
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import json
import joblib
import numpy as np

from training.open_set.calibration import AnomalyCalibrator
from training.open_set.geometry import CentroidGeometry


class OpenSetDecisionOutcome(str, Enum):
    BENIGN = "BENIGN"
    KNOWN_ATTACK = "KNOWN_ATTACK"
    UNKNOWN_SUSPICIOUS = "UNKNOWN_SUSPICIOUS"
    UNCERTAIN = "UNCERTAIN"


@dataclass
class OpenSetDecision:
    outcome: OpenSetDecisionOutcome
    predicted_class: Optional[str]
    is_unknown: bool
    confidence: float
    gate_score: float
    calibrated_anomaly_score: float
    raw_anomaly_score: float
    novelty_score: float
    closest_known_class: str
    reason_codes: List[str]
    feature_evidence: List[Dict[str, Any]]
    model_version: str = "open_set_v1"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "predicted_class": self.predicted_class,
            "is_unknown": self.is_unknown,
            "confidence": round(self.confidence, 4),
            "gate_score": round(self.gate_score, 4),
            "calibrated_anomaly_score": round(self.calibrated_anomaly_score, 4),
            "raw_anomaly_score": round(self.raw_anomaly_score, 4),
            "novelty_score": round(self.novelty_score, 4),
            "closest_known_class": self.closest_known_class,
            "reason_codes": self.reason_codes,
            "feature_evidence": self.feature_evidence,
            "model_version": self.model_version,
        }


class OpenSetClassifier:
    """
    Open-set decision engine combining supervised and unsupervised models.
    """

    def __init__(
        self,
        scaler: Any,
        anomaly_model: Any,
        gate_model: Any,
        multiclass_model: Any,
        anomaly_calibrator: AnomalyCalibrator,
        geometry: CentroidGeometry,
        class_names: List[str],
        gate_threshold: float = 0.60,
        confidence_threshold: float = 0.70,
        novelty_threshold: float = 1.25,
        version: str = "open_set_v1",
    ):
        self.scaler = scaler
        self.anomaly_model = anomaly_model
        self.gate_model = gate_model
        self.multiclass_model = multiclass_model
        self.anomaly_calibrator = anomaly_calibrator
        self.geometry = geometry
        self.class_names = class_names
        self.gate_threshold = gate_threshold
        self.confidence_threshold = confidence_threshold
        self.novelty_threshold = novelty_threshold
        self.version = version

    def predict_sample(
        self,
        x_raw: np.ndarray,
        feature_names: Optional[List[str]] = None,
    ) -> OpenSetDecision:
        """
        Evaluates a single raw feature vector against the open-set framework.
        """
        feat_names = feature_names or [f"feature_{i}" for i in range(len(x_raw))]
        x = np.asarray(x_raw, dtype=np.float64).reshape(1, -1)
        x_s = self.scaler.transform(x)

        # 1. Stage 1a: Anomaly score & calibration
        raw_anomaly = float(-self.anomaly_model.score_samples(x_s)[0])
        calibrated_anomaly = self.anomaly_calibrator.calibrate(raw_anomaly)
        anomaly_flag = self.anomaly_model.predict(x_s)[0] == -1

        # 2. Stage 1b: Binary gate score
        gate_score = float(self.gate_model.predict_proba(x_s)[0, 1])
        gate_flag = gate_score >= self.gate_threshold

        # 3. Geometry / Novelty
        geo_info = self.geometry.compute_novelty(x_s[0])
        novelty_score = geo_info["novelty_score"]
        closest_class = geo_info["closest_class"]
        is_geo_ood = geo_info["is_geometric_ood"]

        # 4. Multiclass probabilities
        probs = self.multiclass_model.predict_proba(x_s)[0]
        pred_idx = int(np.argmax(probs))
        pred_class = self.class_names[pred_idx] if pred_idx < len(self.class_names) else "unknown"
        confidence = float(probs[pred_idx])

        # Second highest probability for margin
        sorted_probs = np.sort(probs)
        margin = float(sorted_probs[-1] - sorted_probs[-2]) if len(sorted_probs) > 1 else confidence

        # Reason codes and feature evidence
        reasons: List[str] = []
        evidence = self._extract_evidence(x_raw, x_s[0], feat_names)

        # -------------------------------------------------------------
        # 5. Open-Set Triage Logic
        # -------------------------------------------------------------
        # Condition A: Completely Benign
        if not gate_flag and not anomaly_flag and calibrated_anomaly < 0.90:
            outcome = OpenSetDecisionOutcome.BENIGN
            reasons.append("LOW_GATE_AND_ANOMALY")
            return OpenSetDecision(
                outcome=outcome,
                predicted_class="benign",
                is_unknown=False,
                confidence=round(1.0 - gate_score, 4),
                gate_score=gate_score,
                calibrated_anomaly_score=calibrated_anomaly,
                raw_anomaly_score=raw_anomaly,
                novelty_score=novelty_score,
                closest_known_class="benign",
                reason_codes=reasons,
                feature_evidence=evidence[:3],
                model_version=self.version,
            )

        # Condition B: High-confidence known attack match
        pred_dist, pred_ratio = self.geometry.distance_to_class(x_s[0], pred_class)
        is_pred_class_in_bounds = pred_ratio <= self.novelty_threshold

        if pred_class != "benign" and confidence >= self.confidence_threshold and is_pred_class_in_bounds:
            outcome = OpenSetDecisionOutcome.KNOWN_ATTACK
            reasons.append("HIGH_CONFIDENCE_KNOWN_MATCH")
            reasons.append(f"IN_BOUNDS_{pred_class.upper()}")
            return OpenSetDecision(
                outcome=outcome,
                predicted_class=pred_class,
                is_unknown=False,
                confidence=confidence,
                gate_score=gate_score,
                calibrated_anomaly_score=calibrated_anomaly,
                raw_anomaly_score=raw_anomaly,
                novelty_score=pred_ratio,
                closest_known_class=pred_class,
                reason_codes=reasons,
                feature_evidence=evidence[:4],
                model_version=self.version,
            )

        # Condition C: Unknown Suspicious (Zero-Day or OOD Attack)
        # Flow is flagged by Stage 1, but classifier is uncertain or sample is in OOD space
        if gate_flag or anomaly_flag or calibrated_anomaly >= 0.95:
            if pred_class == "benign":
                reasons.append("GATE_FLAG_MULTICLASS_BENIGN_DISAGREEMENT")
            elif confidence < self.confidence_threshold:
                reasons.append("LOW_CLASSIFIER_CONFIDENCE")
                reasons.append(f"LOW_CONFIDENCE_{pred_class.upper()}")
            if is_geo_ood:
                reasons.append("FEATURE_SPACE_OOD_DISTANCE")
            if margin < 0.20:
                reasons.append("AMBIGUOUS_CLASS_MARGIN")
            if calibrated_anomaly >= 0.98:
                reasons.append("EXTREME_ANOMALY_PERCENTILE")

            outcome = OpenSetDecisionOutcome.UNKNOWN_SUSPICIOUS
            return OpenSetDecision(
                outcome=outcome,
                predicted_class=None,  # Do NOT force a known label on unknown attack
                is_unknown=True,
                confidence=round(max(calibrated_anomaly, gate_score), 4),
                gate_score=gate_score,
                calibrated_anomaly_score=calibrated_anomaly,
                raw_anomaly_score=raw_anomaly,
                novelty_score=novelty_score,
                closest_known_class=closest_class,
                reason_codes=reasons,
                feature_evidence=evidence[:5],
                model_version=self.version,
            )

        # Condition D: Uncertain / Borderline
        outcome = OpenSetDecisionOutcome.UNCERTAIN
        reasons.append("ELEVATED_ANOMALY_SUBTHRESHOLD_GATE")
        return OpenSetDecision(
            outcome=outcome,
            predicted_class=None,
            is_unknown=True,
            confidence=round(calibrated_anomaly, 4),
            gate_score=gate_score,
            calibrated_anomaly_score=calibrated_anomaly,
            raw_anomaly_score=raw_anomaly,
            novelty_score=novelty_score,
            closest_known_class=closest_class,
            reason_codes=reasons,
            feature_evidence=evidence[:3],
            model_version=self.version,
        )

    def predict_batch(
        self,
        X_raw: np.ndarray,
        feature_names: Optional[List[str]] = None,
    ) -> List[OpenSetDecision]:
        """
        Vectorized high-throughput batch inference over N raw feature vectors.
        """
        X = np.asarray(X_raw, dtype=np.float64)
        n_samples = len(X)
        if n_samples == 0:
            return []

        feat_names = feature_names or [f"feature_{i}" for i in range(X.shape[1])]
        X_s = self.scaler.transform(X)

        raw_anomalies = -self.anomaly_model.score_samples(X_s)
        anomaly_flags = self.anomaly_model.predict(X_s) == -1
        gate_scores = self.gate_model.predict_proba(X_s)[:, 1]
        probs_matrix = self.multiclass_model.predict_proba(X_s)

        decisions = []
        for i in range(n_samples):
            raw_anomaly = float(raw_anomalies[i])
            calibrated_anomaly = self.anomaly_calibrator.calibrate(raw_anomaly)
            anomaly_flag = bool(anomaly_flags[i])
            gate_score = float(gate_scores[i])
            gate_flag = gate_score >= self.gate_threshold

            geo_info = self.geometry.compute_novelty(X_s[i])
            novelty_score = geo_info["novelty_score"]
            closest_class = geo_info["closest_class"]
            is_geo_ood = geo_info["is_geometric_ood"]

            probs = probs_matrix[i]
            pred_idx = int(np.argmax(probs))
            pred_class = self.class_names[pred_idx] if pred_idx < len(self.class_names) else "unknown"
            confidence = float(probs[pred_idx])

            sorted_probs = np.sort(probs)
            margin = float(sorted_probs[-1] - sorted_probs[-2]) if len(sorted_probs) > 1 else confidence

            reasons: List[str] = []
            evidence = self._extract_evidence(X[i], X_s[i], feat_names)

            pred_dist, pred_ratio = self.geometry.distance_to_class(X_s[i], pred_class)
            is_pred_class_in_bounds = pred_ratio <= self.novelty_threshold

            if not gate_flag and not anomaly_flag and calibrated_anomaly < 0.90:
                reasons.append("LOW_GATE_AND_ANOMALY")
                decisions.append(OpenSetDecision(
                    outcome=OpenSetDecisionOutcome.BENIGN,
                    predicted_class="benign",
                    is_unknown=False,
                    confidence=round(1.0 - gate_score, 4),
                    gate_score=gate_score,
                    calibrated_anomaly_score=calibrated_anomaly,
                    raw_anomaly_score=raw_anomaly,
                    novelty_score=novelty_score,
                    closest_known_class="benign",
                    reason_codes=reasons,
                    feature_evidence=evidence[:3],
                    model_version=self.version,
                ))
            elif pred_class != "benign" and confidence >= self.confidence_threshold and is_pred_class_in_bounds:
                reasons.append("HIGH_CONFIDENCE_KNOWN_MATCH")
                reasons.append(f"IN_BOUNDS_{pred_class.upper()}")
                decisions.append(OpenSetDecision(
                    outcome=OpenSetDecisionOutcome.KNOWN_ATTACK,
                    predicted_class=pred_class,
                    is_unknown=False,
                    confidence=confidence,
                    gate_score=gate_score,
                    calibrated_anomaly_score=calibrated_anomaly,
                    raw_anomaly_score=raw_anomaly,
                    novelty_score=pred_ratio,
                    closest_known_class=pred_class,
                    reason_codes=reasons,
                    feature_evidence=evidence[:4],
                    model_version=self.version,
                ))
            elif gate_flag or anomaly_flag or calibrated_anomaly >= 0.95:
                if pred_class == "benign":
                    reasons.append("GATE_FLAG_MULTICLASS_BENIGN_DISAGREEMENT")
                elif confidence < self.confidence_threshold:
                    reasons.append("LOW_CLASSIFIER_CONFIDENCE")
                    reasons.append(f"LOW_CONFIDENCE_{pred_class.upper()}")
                if is_geo_ood:
                    reasons.append("FEATURE_SPACE_OOD_DISTANCE")
                if margin < 0.20:
                    reasons.append("AMBIGUOUS_CLASS_MARGIN")
                if calibrated_anomaly >= 0.98:
                    reasons.append("EXTREME_ANOMALY_PERCENTILE")

                decisions.append(OpenSetDecision(
                    outcome=OpenSetDecisionOutcome.UNKNOWN_SUSPICIOUS,
                    predicted_class=None,
                    is_unknown=True,
                    confidence=round(max(calibrated_anomaly, gate_score), 4),
                    gate_score=gate_score,
                    calibrated_anomaly_score=calibrated_anomaly,
                    raw_anomaly_score=raw_anomaly,
                    novelty_score=novelty_score,
                    closest_known_class=closest_class,
                    reason_codes=reasons,
                    feature_evidence=evidence[:5],
                    model_version=self.version,
                ))
            else:
                reasons.append("ELEVATED_ANOMALY_SUBTHRESHOLD_GATE")
                decisions.append(OpenSetDecision(
                    outcome=OpenSetDecisionOutcome.UNCERTAIN,
                    predicted_class=None,
                    is_unknown=True,
                    confidence=round(calibrated_anomaly, 4),
                    gate_score=gate_score,
                    calibrated_anomaly_score=calibrated_anomaly,
                    raw_anomaly_score=raw_anomaly,
                    novelty_score=novelty_score,
                    closest_known_class=closest_class,
                    reason_codes=reasons,
                    feature_evidence=evidence[:3],
                    model_version=self.version,
                ))

        return decisions

    def _extract_evidence(
        self, x_raw: np.ndarray, x_s: np.ndarray, feat_names: List[str]
    ) -> List[Dict[str, Any]]:
        """Identifies top features deviating most from the training scaler mean."""
        evidence = []
        for i, name in enumerate(feat_names):
            val_raw = float(x_raw[i])
            z_score = float(x_s[i])  # In StandardScaler, x_s is the z-score vs training mean
            evidence.append({
                "feature": name,
                "raw_value": round(val_raw, 4),
                "z_deviation": round(z_score, 4),
            })
        evidence.sort(key=lambda d: abs(d["z_deviation"]), reverse=True)
        return evidence

    def save(self, output_dir: Path | str):
        """Serializes models, calibrator, geometry, and metadata into a directory."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        joblib.dump(self.scaler, out / "feature_scaler.pkl")
        joblib.dump(self.anomaly_model, out / "anomaly_model.pkl")
        joblib.dump(self.gate_model, out / "gate_model.pkl")
        joblib.dump(self.multiclass_model, out / "multiclass_model.pkl")
        joblib.dump(self.anomaly_calibrator, out / "anomaly_calibrator.pkl")
        joblib.dump(self.geometry, out / "centroid_geometry.pkl")

        meta = {
            "version": self.version,
            "class_names": self.class_names,
            "gate_threshold": self.gate_threshold,
            "confidence_threshold": self.confidence_threshold,
            "novelty_threshold": self.novelty_threshold,
            "geometry_metadata": self.geometry.to_dict(),
            "calibrator_metadata": self.anomaly_calibrator.to_dict(),
        }
        with open(out / "open_set_metadata.json", "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

    @classmethod
    def load(cls, model_dir: Path | str) -> "OpenSetClassifier":
        """Loads a serialized OpenSetClassifier from directory."""
        p = Path(model_dir)
        scaler = joblib.load(p / "feature_scaler.pkl")
        anomaly_model = joblib.load(p / "anomaly_model.pkl")
        gate_model = joblib.load(p / "gate_model.pkl")
        multiclass_model = joblib.load(p / "multiclass_model.pkl")
        anomaly_calibrator = joblib.load(p / "anomaly_calibrator.pkl")
        geometry = joblib.load(p / "centroid_geometry.pkl")

        with open(p / "open_set_metadata.json", "r", encoding="utf-8") as f:
            meta = json.load(f)

        return cls(
            scaler=scaler,
            anomaly_model=anomaly_model,
            gate_model=gate_model,
            multiclass_model=multiclass_model,
            anomaly_calibrator=anomaly_calibrator,
            geometry=geometry,
            class_names=meta["class_names"],
            gate_threshold=meta["gate_threshold"],
            confidence_threshold=meta["confidence_threshold"],
            novelty_threshold=meta["novelty_threshold"],
            version=meta.get("version", "open_set_v1"),
        )
