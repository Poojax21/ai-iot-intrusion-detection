"""
Hierarchical Risk Scoring Engine for Multi-Modal Threat Synthesis.

Synthesizes evidence across four distinct operational dimensions:
  1. Flow Risk (Stage 1 Binary Gate & Calibrated Anomaly Percentile)
  2. Novelty Risk (Open-Set OOD Distance & Classifier Entropy)
  3. Temporal Risk (Sequential Multi-Flow LSTM/GRU State)
  4. Graph Risk (Topological Interaction & Lateral Movement)

Applies a non-dilutive dominant-signal architecture with corroboration amplification,
exponential temporal decay, and duplicate suppression.
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
    fused_event_threat: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "composite_device_risk": round(float(self.composite_device_risk), 2),
            "fused_event_threat": round(float(self.fused_event_threat), 2),
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
    Stateful multi-modal risk synthesizer with non-dilutive dominant-signal fusion,
    exponential decay, and duplicate suppression.
    """

    def __init__(
        self,
        weight_flow: float = 0.40,
        weight_novelty: float = 0.30,
        weight_temporal: float = 0.20,
        weight_graph: float = 0.10,
        decay_half_life_sec: float = 120.0,
        suppression_window_sec: float = 5.0,
        corroboration_bonus: float = 0.50,
    ):
        total_w = weight_flow + weight_novelty + weight_temporal + weight_graph
        self.w_flow = weight_flow / total_w
        self.w_novelty = weight_novelty / total_w
        self.w_temp = weight_temporal / total_w
        self.w_graph = weight_graph / total_w

        self.decay_half_life_sec = max(decay_half_life_sec, 1.0)
        self.suppression_window_sec = suppression_window_sec
        self.corroboration_bonus = max(0.0, min(1.0, corroboration_bonus))

        # Device state: device_id -> { "risk": float, "last_updated": float, "last_attack": str, "last_attack_ts": float }
        self._device_records: Dict[str, Dict[str, Any]] = {}
        self._recent_alerts: Dict[str, float] = {}

    @property
    def device_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Alias for backward compatibility with audit and evaluation harnesses."""
        return self._device_records

    @property
    def recent_alerts(self) -> Dict[str, float]:
        """Alias for backward compatibility with audit and evaluation harnesses."""
        return self._recent_alerts

    def clear_device_state(self, device_id: Optional[str] = None) -> None:
        """Resets device state for clean testing and stateful teardown."""
        if device_id:
            self._device_records.pop(device_id, None)
        else:
            self._device_records.clear()
            self._recent_alerts.clear()

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
        Synthesizes multimodal model outputs into both:
          1. Fused event threat (per-flow normalized threat score in [0, 100])
          2. Composite device risk (stateful decaying threat posture in [0, 100])
        """
        now = float(timestamp)
        rec = self._get_device_record(device_id, now)

        dt = max(0.0, now - rec["last_updated"])
        prior_risk = rec["risk"]
        decayed_risk = self._apply_decay(prior_risk, dt)

        # 1. Flow Risk Component
        gate_score = float(flow_result.get("gate_score", 0.0) or 0.0)
        cal_anomaly = float(flow_result.get("calibrated_anomaly_score", 0.0) or 0.0)
        flow_risk = max(gate_score, cal_anomaly if cal_anomaly >= 0.90 else 0.0)

        # 2. Novelty Risk Component
        is_unknown = bool(flow_result.get("is_unknown", False))
        nov_ratio = float(flow_result.get("novelty_score", 1.0) or 1.0)
        if is_unknown:
            novelty_risk = min(1.0, max(0.5, nov_ratio / 2.0))
        else:
            novelty_risk = 0.0

        # 3. Temporal Risk Component
        has_temporal = False
        if temporal_result and "temporal_risk" in temporal_result and temporal_result["temporal_risk"] is not None:
            temporal_risk = float(temporal_result["temporal_risk"])
            has_temporal = True
        else:
            temporal_risk = 0.0

        # 4. Graph Risk Component
        has_graph = False
        if graph_result and "graph_risk" in graph_result and graph_result["graph_risk"] is not None:
            graph_risk = float(graph_result["graph_risk"])
            if graph_result.get("is_lateral_movement", False):
                graph_risk = max(graph_risk, 0.85)
            has_graph = True
        else:
            graph_risk = 0.0

        reasons = []

        # Check for duplicate attack suppression
        if is_suppressed_duplicate:
            risk_increment = 0.0
            fused_signal = 0.0
            reasons.append("DUPLICATE_ALERT_SUPPRESSED")
        else:
            # Non-dilutive dominant-signal architecture:
            # Base threat is driven by the primary detection modalities (flow gate + open-set novelty)
            base_threat = max(flow_risk, novelty_risk)

            # Secondary modalities (temporal sequences & communication graph) corroborate and elevate
            active_sec_weight = 0.0
            sec_accum = 0.0
            if has_temporal:
                sec_accum += self.w_temp * temporal_risk
                active_sec_weight += self.w_temp
            if has_graph:
                sec_accum += self.w_graph * graph_risk
                active_sec_weight += self.w_graph

            secondary_signal = (sec_accum / active_sec_weight) if active_sec_weight > 0.0 else 0.0

            # Fused non-dilutive event threat:
            # High base_threat cannot be averaged down by non-participating modalities.
            if flow_result.get("is_flagged", False):
                fused_signal = min(1.0, base_threat + (1.0 - base_threat) * (self.corroboration_bonus * secondary_signal))
                base_impact = 35.0 if flow_result.get("severity") == "critical" else 25.0
                risk_increment = base_impact * fused_signal
            elif base_threat > 0.40 or temporal_risk > 0.60 or graph_risk > 0.60:
                # Emerging or low-and-slow threat pattern
                fused_signal = min(1.0, max(base_threat, 0.5 * temporal_risk + 0.5 * graph_risk))
                risk_increment = 10.0 * fused_signal
            else:
                fused_signal = max(0.0, base_threat)
                risk_increment = 0.0

        fused_event_threat = round(fused_signal * 100.0, 2)
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
        if has_temporal and temporal_result.get("temporal_flagged"):
            reasons.append("TEMPORAL_SEQUENCE_EVIDENCE")
        if has_graph and graph_result.get("is_lateral_movement"):
            reasons.append("INTERNAL_LATERAL_MOVEMENT")

        # Update persistent device state
        rec["risk"] = new_device_risk
        rec["last_updated"] = now

        versions = {
            "flow_version": flow_result.get("model_version", "v1"),
            "temporal_version": temporal_result.get("model_version", "none") if temporal_result else "disabled",
            "graph_version": graph_result.get("model_version", "none") if graph_result else "disabled",
            "risk_engine": "hierarchical_v2",
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
            fused_event_threat=fused_event_threat,
        )
