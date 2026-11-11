"""
Runtime Temporal Detection Engine Adapter.

Manages rolling device sequence buffers and performs low-latency sequential inference.
"""

import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional
import numpy as np
import torch

from .models import TemporalGRU, TemporalLSTM
from .sequence_builder import DeviceSequenceBuffer


class TemporalDetector:
    """
    Inference adapter managing real-time sequence buffering and scoring.
    """

    def __init__(
        self,
        model: torch.nn.Module,
        model_type: str = "gru",
        sequence_length: int = 10,
        feature_dim: int = 20,
        class_names: Optional[List[str]] = None,
        threshold: float = 0.50,
        version: str = "temporal_v1",
    ):
        self.model = model
        self.model_type = model_type.lower()
        self.sequence_length = sequence_length
        self.feature_dim = feature_dim
        self.class_names = class_names or ["benign", "attack"]
        self.threshold = threshold
        self.version = version

        self.model.eval()
        self.buffer = DeviceSequenceBuffer(sequence_length=sequence_length, feature_dim=feature_dim)

    def score_flow(
        self,
        device_id: str,
        scaled_feature_vector: np.ndarray,
        timestamp: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Ingests a scaled flow vector, updates the device sequence, and computes temporal risk.
        """
        t0 = time.perf_counter()
        window = self.buffer.push_and_get_window(device_id, scaled_feature_vector)

        # Convert to tensor: shape (1, seq_len, feature_dim)
        x_tensor = torch.from_numpy(window).unsqueeze(0)

        with torch.no_grad():
            logits = self.model(x_tensor)
            probs = torch.softmax(logits, dim=-1).squeeze(0).numpy()

        pred_idx = int(np.argmax(probs))
        pred_label = self.class_names[pred_idx] if pred_idx < len(self.class_names) else "unknown"

        # Probability of non-benign attack in temporal sequence
        attack_prob = float(1.0 - probs[0]) if len(probs) > 1 else float(probs[0])
        is_flagged = bool(attack_prob >= self.threshold)

        history_len = len(self.buffer.buffers.get(device_id, []))
        reasons = []

        if is_flagged:
            reasons.append("TEMPORAL_SEQUENCE_ATTACK_PATTERN")
            if history_len >= self.sequence_length:
                reasons.append("SUSTAINED_BURST_SEQUENCE")
            else:
                reasons.append("EARLY_SEQUENCE_ANOMALY")
        elif attack_prob < 0.15:
            reasons.append("BENIGN_STEADY_STATE")

        latency_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "temporal_risk": round(attack_prob, 4),
            "temporal_pred": pred_label,
            "temporal_flagged": is_flagged,
            "history_length": history_len,
            "sequence_length": history_len,
            "reason_codes": reasons,
            "model_version": self.version,
            "latency_ms": round(latency_ms, 3),
        }

    def save(self, output_dir: Path | str):
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        torch.save(self.model.state_dict(), out / "temporal_model.pt")

        meta = {
            "model_type": self.model_type,
            "version": self.version,
            "sequence_length": self.sequence_length,
            "feature_dim": self.feature_dim,
            "class_names": self.class_names,
            "threshold": self.threshold,
            "hidden_dim": getattr(self.model, "hidden_dim", 48),
            "num_layers": getattr(self.model, "num_layers", 2),
        }
        with open(out / "temporal_metadata.json", "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

    @classmethod
    def load(cls, model_dir: Path | str) -> "TemporalDetector":
        p = Path(model_dir)
        with open(p / "temporal_metadata.json", "r", encoding="utf-8") as f:
            meta = json.load(f)

        mtype = meta.get("model_type", "gru")
        input_dim = meta.get("feature_dim", 20)
        hidden_dim = meta.get("hidden_dim", 48)
        num_layers = meta.get("num_layers", 2)
        num_classes = len(meta.get("class_names", ["benign", "attack"]))

        if mtype == "lstm":
            model = TemporalLSTM(
                input_dim=input_dim,
                hidden_dim=hidden_dim,
                num_layers=num_layers,
                num_classes=num_classes,
            )
        else:
            model = TemporalGRU(
                input_dim=input_dim,
                hidden_dim=hidden_dim,
                num_layers=num_layers,
                num_classes=num_classes,
            )

        state_dict = torch.load(p / "temporal_model.pt", map_location="cpu")
        model.load_state_dict(state_dict)

        return cls(
            model=model,
            model_type=mtype,
            sequence_length=meta.get("sequence_length", 10),
            feature_dim=input_dim,
            class_names=meta.get("class_names", ["benign", "attack"]),
            threshold=meta.get("threshold", 0.50),
            version=meta.get("version", "temporal_v1"),
        )
