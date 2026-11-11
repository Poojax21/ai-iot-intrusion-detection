"""
Runtime Graph Detection Engine Adapter.

Maintains rolling network graph snapshots and evaluates topological risk per communication.
"""

import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional
import numpy as np
import torch

from .graph_schema import IncrementalGraphTracker, GraphSnapshotData
from .models import GraphSAGENet, GraphStatisticsBaseline, HAS_PYG


class GraphDetector:
    """
    Inference adapter managing rolling communication graphs and topological anomaly scoring.
    """

    def __init__(
        self,
        model: Optional[torch.nn.Module] = None,
        model_type: str = "graphsage",
        window_seconds: float = 60.0,
        in_channels: int = 5,
        threshold: float = 0.50,
        version: str = "graph_v1",
    ):
        self.model = model
        self.model_type = model_type.lower()
        self.window_seconds = window_seconds
        self.in_channels = in_channels
        self.threshold = threshold
        self.version = version

        if self.model is not None:
            self.model.eval()

        self.baseline_engine = GraphStatisticsBaseline()
        self.tracker = IncrementalGraphTracker(window_seconds=window_seconds)

    def score_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Updates topology with current flow and evaluates communication graph risk.
        """
        t0 = time.perf_counter()
        self.tracker.add_flow(flow)

        snapshot = self.tracker.build_snapshot(current_ts=flow.get("ts"))

        src_str = str(flow.get("src_ip", "unknown_src"))
        dst_str = str(flow.get("dst_ip", "unknown_dst"))

        src_idx = snapshot.node_mapping.get(src_str)
        dst_idx = snapshot.node_mapping.get(dst_str)

        graph_risk = 0.0
        reasons = []

        # Neural GraphSAGE forward pass if available
        if self.model is not None and HAS_PYG and self.model_type == "graphsage":
            try:
                x_t = torch.from_numpy(snapshot.node_features)
                e_t = torch.from_numpy(snapshot.edge_index)
                with torch.no_grad():
                    logits = self.model(x_t, e_t)
                    probs = torch.softmax(logits, dim=-1).numpy()

                if src_idx is not None and src_idx < len(probs):
                    graph_risk = float(probs[src_idx, 1])
            except Exception:
                # Fallback to deterministic topological baseline
                stats_risks = self.baseline_engine.score_nodes(snapshot.node_features)
                graph_risk = float(stats_risks[src_idx]) if src_idx is not None and src_idx < len(stats_risks) else 0.0
        else:
            # Deterministic topological baseline
            stats_risks = self.baseline_engine.score_nodes(snapshot.node_features)
            graph_risk = float(stats_risks[src_idx]) if src_idx is not None and src_idx < len(stats_risks) else 0.0

        is_flagged = bool(graph_risk >= self.threshold)

        # Detect potential lateral movement (internal-to-internal communication)
        is_lateral = bool(
            src_str.startswith("192.168.") and dst_str.startswith("192.168.") and src_str != dst_str
        )
        if is_lateral:
            reasons.append("INTERNAL_LATERAL_EDGE")

        if is_flagged:
            reasons.append("TOPOLOGICAL_FANOUT_ANOMALY")
        elif graph_risk < 0.15:
            reasons.append("STABLE_GRAPH_COMMUNITY")

        latency_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "graph_risk": round(graph_risk, 4),
            "graph_flagged": is_flagged,
            "active_nodes": snapshot.num_nodes,
            "active_edges": snapshot.num_edges,
            "is_lateral_movement": is_lateral,
            "reason_codes": reasons,
            "model_version": self.version,
            "latency_ms": round(latency_ms, 3),
        }

    def save(self, output_dir: Path | str):
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        if self.model is not None and hasattr(self.model, "state_dict"):
            torch.save(self.model.state_dict(), out / "graph_model.pt")

        meta = {
            "model_type": self.model_type,
            "version": self.version,
            "window_seconds": self.window_seconds,
            "in_channels": self.in_channels,
            "threshold": self.threshold,
        }
        with open(out / "graph_metadata.json", "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

    @classmethod
    def load(cls, model_dir: Path | str) -> "GraphDetector":
        p = Path(model_dir)
        with open(p / "graph_metadata.json", "r", encoding="utf-8") as f:
            meta = json.load(f)

        mtype = meta.get("model_type", "graphsage")
        in_ch = meta.get("in_channels", 5)

        model = None
        if mtype == "graphsage" and HAS_PYG and (p / "graph_model.pt").exists():
            try:
                model = GraphSAGENet(in_channels=in_ch, hidden_channels=32, out_channels=2)
                state = torch.load(p / "graph_model.pt", map_location="cpu")
                model.load_state_dict(state)
            except Exception:
                model = None

        return cls(
            model=model,
            model_type=mtype,
            window_seconds=meta.get("window_seconds", 60.0),
            in_channels=in_ch,
            threshold=meta.get("threshold", 0.50),
            version=meta.get("version", "graph_v1"),
        )
