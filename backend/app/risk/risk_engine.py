"""
Hierarchical Risk Scoring Engine for Multi-Modal Threat Synthesis.

Synthesizes evidence across four distinct operational dimensions:
  1. Flow Risk (Stage 1 Binary Gate & Calibrated Anomaly Percentile)
  2. Novelty Risk (Open-Set OOD Distance & Classifier Entropy)
  3. Temporal Risk (Sequential Multi-Flow LSTM/GRU State)
  4. Graph Risk (Topological Interaction & Lateral Movement)

Applies exponential temporal decay and duplicate suppression without arbitrary score averaging.
"""

from dataclasses import dataclass, field
import math
import time
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class RiskEvidenceBreakdown:
    flow_risk: float
    novelty_risk: float
    temporal_risk: float
    graph_risk: float
    historical_risk_before: float
    decayed_prior_risk: float
    risk_increment: float
    composite_device_risk: float
    risk_tier: str                           # LOW, ELEVATED, HIGH, CRITICAL
    reason_codes: List[str]
    model_versions: Dict[str, str]
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "composite_device_risk": round(float(self.composite_device_risk), 2),
            "risk_tier": self.risk_tier,
            "components": {
                "flow_risk": round(float(self.flow_risk), 4),
                "novelty_risk": round(float(self.novelty_risk), 4),
                "temporal_risk": round(float(self.temporal_risk), 4),
                "graph_risk": round(float(self.graph_risk), 4),
            },
            "history": {
                "prior_risk": round(float(self.historical_risk_before), 2),
                "decayed_prior": round(float(self.decayed_prior_risk), 2),
                "risk_increment": round(float(self.risk_increment), 2),
            },
            "reason_codes": self.reason_codes,
            "model_versions": self.model_versions,
            "timestamp": self.timestamp,
        }


class HierarchicalRiskEngine:
    """
    Stateful multi-modal risk synthesizer with exponential decay and duplicate suppression.
    """

    def __init__(
        self,
        weight_flow: float = 0.35,
        weight_novelty: float = 0.25,
        weight_temporal: float = 0.25,
        weight_graph: float = 0.15,
        decay_half_life_sec: float = 120.0,
        suppression_window_sec: float = 5.0,
    ):
        total_w = weight_flow + weight_novelty + weight_temporal + weight_graph
        self.w_flow = weight_flow / total_w
        self.w_novelty = weight_novelty / total_w
        self.w_temp = weight_temporal / total_w
        self.w_graph = weight_graph / total_w

        self.decay_half_life_sec = max(decay_half_life_sec, 1.0)
        self.suppression_window_sec = suppression_window_sec

        # Device state: device_id -> { "risk": float, "last_updated": float, "last_attack": str, "last_attack_ts": float }
        self._device_records: Dict[str, Dict[str, Any]] = {}

    def _get_device_record(self, device_id: str, now: float) -> Dict[str, Any]:
        if device_id not in self._device_records:
            self._device_records[device_id] = {
                "risk": 0.0,
                "last_updated": now,
                "last_attack": None,
                "last_attack_ts": 0.0,
            }
        return self._device_records[device_id]

    def _apply_decay(self, current_risk: float, dt_sec: float) -> float:
        """Applies continuous exponential half-life decay to prior risk score."""
        if dt_sec <= 0.0 or current_risk <= 0.0:
            return current_risk
        decay_factor = math.exp(- (dt_sec * math.log(2.0)) / self.decay_half_life_sec)
        return float(current_risk * decay_factor)

    def evaluate_risk(
        self,
        device_id: str,
        timestamp: float,
        flow_result: Dict[str, Any],
        temporal_result: Optional[Dict[str, Any]] = None,
        graph_result: Optional[Dict[str, Any]] = None,
        is_suppressed_duplicate: bool = False,
    ) -> RiskEvidenceBreakdown:
        """
        Synthesizes multimodal model outputs into an updated device-level risk score.
        """
        now = float(timestamp)
        rec = self._get_device_record(device_id, now)

        dt = max(0.0, now - rec["last_updated"])
        prior_risk = rec["risk"]
        decayed_risk = self._apply_decay(prior_risk, dt)

        # 1. Flow Risk Component
        # Gate score is probability of attack; calibrated anomaly is benign ECDF percentile
        gate_score = float(flow_result.get("gate_score", 0.0))
        cal_anomaly = float(flow_result.get("calibrated_anomaly_score", 0.0))
        flow_risk = max(gate_score, cal_anomaly if cal_anomaly >= 0.90 else 0.0)

        # 2. Novelty Risk Component
        # If flow was identified as open-set unknown, incorporate normalized novelty ratio
        is_unknown = bool(flow_result.get("is_unknown", False))
        nov_ratio = float(flow_result.get("novelty_score", 1.0) or 1.0)
        if is_unknown:
            novelty_risk = min(1.0, max(0.5, nov_ratio / 2.0))
        else:
            novelty_risk = 0.0

        # 3. Temporal Risk Component
        # If temporal model executed, extract attack probability; otherwise reallocate neutrally
        if temporal_result and "temporal_risk" in temporal_result:
            temporal_risk = float(temporal_result["temporal_risk"])
        else:
            temporal_risk = flow_risk  # Impute from flow risk if temporal disabled

        # 4. Graph Risk Component
        # If graph engine executed, extract topological risk; otherwise reallocate neutrally
        if graph_result and "graph_risk" in graph_result:
            graph_risk = float(graph_result["graph_risk"])
            if graph_result.get("is_lateral_movement", False):
                graph_risk = max(graph_risk, 0.85)
        else:
            graph_risk = flow_risk

        reasons = []

        # Check for duplicate attack suppression
        if is_suppressed_duplicate:
            risk_increment = 0.0
            reasons.append("DUPLICATE_ALERT_SUPPRESSED")
        else:
            # Multi-modal fusion
            fused_signal = (
                self.w_flow * flow_risk
                + self.w_novelty * novelty_risk
                + self.w_temp * temporal_risk
                + self.w_graph * graph_risk
            )

            # Map to additive risk increment in [0, 40] points per confirmed event
            if flow_result.get("is_flagged", False):
                base_impact = 25.0
                if flow_result.get("severity") == "critical":
                    base_impact = 35.0
                risk_increment = base_impact * fused_signal
            elif flow_risk > 0.40 or temporal_risk > 0.60 or graph_risk > 0.60:
                risk_increment = 10.0 * fused_signal
            else:
                risk_increment = 0.0

        new_device_risk = min(100.0, max(0.0, decayed_risk + risk_increment))

        # Assign risk tier
        if new_device_risk >= 80.0:
            tier = "CRITICAL"
        elif new_device_risk >= 55.0:
            tier = "HIGH"
        elif new_device_risk >= 25.0:
            tier = "ELEVATED"
        else:
            tier = "LOW"

        # Harvest reason codes
        if flow_result.get("is_flagged"):
            reasons.append(f"FLOW_FLAGGED_{flow_result.get('attack_type', 'ATTACK').upper()}")
        if is_unknown:
            reasons.append("OPEN_SET_ZERO_DAY_EVIDENCE")
        if temporal_result and temporal_result.get("temporal_flagged"):
            reasons.append("TEMPORAL_SEQUENCE_EVIDENCE")
        if graph_result and graph_result.get("is_lateral_movement"):
            reasons.append("INTERNAL_LATERAL_MOVEMENT")

        # Update persistent device state
        rec["risk"] = new_device_risk
        rec["last_updated"] = now

        versions = {
            "flow_version": flow_result.get("model_version", "v1"),
            "temporal_version": temporal_result.get("model_version", "none") if temporal_result else "disabled",
            "graph_version": graph_result.get("model_version", "none") if graph_result else "disabled",
            "risk_engine": "hierarchical_v1",
        }

        return RiskEvidenceBreakdown(
            flow_risk=flow_risk,
            novelty_risk=novelty_risk,
            temporal_risk=temporal_risk,
            graph_risk=graph_risk,
            historical_risk_before=prior_risk,
            decayed_prior_risk=decayed_risk,
            risk_increment=risk_increment,
            composite_device_risk=new_device_risk,
            risk_tier=tier,
            reason_codes=reasons,
            model_versions=versions,
            timestamp=now,
        )
