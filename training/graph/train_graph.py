"""
Empirical Comparison & Training Pipeline for Graph Intelligence.

Compares GraphSAGE vs. Topological Statistics Baseline on identical snapshots
and serializes the production model artifacts.
"""

import json
from pathlib import Path
import time
from typing import Dict, List, Tuple
import numpy as np
from sklearn.metrics import f1_score, roc_auc_score, accuracy_score
import torch
import torch.nn as nn

from simulator.synthetic_traffic import generate_dataset
from .graph_schema import IncrementalGraphTracker, GraphSnapshotData
from .models import GraphSAGENet, GraphStatisticsBaseline, HAS_PYG
from .graph_detector import GraphDetector


def build_snapshot_dataset(flows: List[Dict], window_sec: float = 60.0, step: int = 25) -> List[Tuple[GraphSnapshotData, np.ndarray]]:
    """
    Builds a list of (snapshot, node_labels) pairs along the flow stream.
    Node is labeled 1 if it generated an attack flow in this active window.
    """
    tracker = IncrementalGraphTracker(window_seconds=window_sec)
    dataset = []

    for i, f in enumerate(flows):
        tracker.add_flow(f)
        if i >= 50 and i % step == 0:
            snap = tracker.build_snapshot(current_ts=f["ts"])
            if snap.num_nodes > 0:
                # Active attack nodes in this window
                cutoff = f["ts"] - window_sec
                active_flows = [fl for fl in tracker.recent_flows if fl["ts"] >= cutoff]
                attack_srcs = {fl["src_ip"] for fl in active_flows if fl.get("label") != "benign"}

                node_y = np.zeros(snap.num_nodes, dtype=np.int64)
                for ent, idx in snap.node_mapping.items():
                    if ent in attack_srcs:
                        node_y[idx] = 1

                dataset.append((snap, node_y))

    return dataset


def run_graph_comparison_experiment(
    n_flows: int = 8000,
    window_sec: float = 60.0,
    output_dir: str = "backend/app/models/graph_v1",
    seed: int = 42,
) -> Dict:
    """
    Trains GraphSAGE and benchmarks it against the topological statistics baseline.
    """
    torch.manual_seed(seed)
    np.random.seed(seed)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    print(f"=== Generating Flow Dataset for Graph Modeling (n_flows={n_flows}) ===")
    flows = generate_dataset(n_devices=8, n_flows=n_flows, attack_ratio=0.15, seed=seed)
    flows = sorted(flows, key=lambda f: f["ts"])

    # Chronological partition
    n = len(flows)
    i_tr = int(n * 0.70)
    i_val = int(n * 0.85)

    train_flows = flows[:i_tr]
    val_flows = flows[i_tr:i_val]
    test_flows = flows[i_val:]

    print("=== Building Snapshot Datasets ===")
    train_snapshots = build_snapshot_dataset(train_flows, window_sec=window_sec, step=25)
    val_snapshots = build_snapshot_dataset(val_flows, window_sec=window_sec, step=25)
    test_snapshots = build_snapshot_dataset(test_flows, window_sec=window_sec, step=25)

    print(f"Snapshots -> Train: {len(train_snapshots)}, Val: {len(val_snapshots)}, Test: {len(test_snapshots)}")

    # 1. Baseline Evaluation
    print("=== Evaluating Topological Statistics Baseline ===")
    baseline = GraphStatisticsBaseline()
    t0 = time.perf_counter()
    val_base_preds = []
    val_base_targets = []

    for snap, y in val_snapshots:
        if len(y) > 0:
            scores = baseline.score_nodes(snap.node_features)
            val_base_preds.extend((scores >= 0.50).astype(int))
            val_base_targets.extend(y)

    base_latency = ((time.perf_counter() - t0) / max(len(val_snapshots), 1)) * 1000.0
    base_acc = float(accuracy_score(val_base_targets, val_base_preds)) if val_base_targets else 0.0
    base_f1 = float(f1_score(val_base_targets, val_base_preds, average="macro", zero_division=0)) if val_base_targets else 0.0

    print(f"Baseline -> Val F1: {base_f1:.4f}, Acc: {base_acc:.4f}, Latency: {base_latency:.3f} ms / snapshot")

    # 2. GraphSAGE Training & Evaluation
    sage_model = None
    sage_f1 = 0.0
    sage_acc = 0.0
    sage_latency = 0.0
    sage_params = 0

    if HAS_PYG:
        print("=== Training Candidate Architecture: GraphSAGENet ===")
        sage_model = GraphSAGENet(in_channels=5, hidden_channels=32, out_channels=2)
        sage_params = sum(p.numel() for p in sage_model.parameters())
        optimizer = torch.optim.Adam(sage_model.parameters(), lr=0.005)
        criterion = nn.CrossEntropyLoss()

        sage_model.train()
        for epoch in range(6):
            for snap, y in train_snapshots:
                if snap.num_nodes == 0 or len(y) == 0:
                    continue
                optimizer.zero_grad()
                x_t = torch.from_numpy(snap.node_features)
                e_t = torch.from_numpy(snap.edge_index)
                y_t = torch.from_numpy(y)
                logits = sage_model(x_t, e_t)
                loss = criterion(logits, y_t)
                loss.backward()
                optimizer.step()

        # Validation evaluation
        sage_model.eval()
        t0 = time.perf_counter()
        val_sage_preds = []
        val_sage_targets = []

        with torch.no_grad():
            for snap, y in val_snapshots:
                if snap.num_nodes > 0 and len(y) > 0:
                    x_t = torch.from_numpy(snap.node_features)
                    e_t = torch.from_numpy(snap.edge_index)
                    logits = sage_model(x_t, e_t)
                    preds = torch.argmax(logits, dim=-1).numpy()
                    val_sage_preds.extend(preds)
                    val_sage_targets.extend(y)

        sage_latency = ((time.perf_counter() - t0) / max(len(val_snapshots), 1)) * 1000.0
        sage_acc = float(accuracy_score(val_sage_targets, val_sage_preds)) if val_sage_targets else 0.0
        sage_f1 = float(f1_score(val_sage_targets, val_sage_preds, average="macro", zero_division=0)) if val_sage_targets else 0.0

        print(f"GraphSAGE -> Val F1: {sage_f1:.4f}, Acc: {sage_acc:.4f}, Latency: {sage_latency:.3f} ms / snapshot, Params: {sage_params}")

    # Empirical model selection: Retain GraphSAGE if available and outperforming baseline
    if HAS_PYG and sage_model is not None and sage_f1 >= base_f1:
        selected_type = "graphsage"
        selected_model = sage_model
        reason = "GraphSAGE demonstrated higher neighborhood topology F1 and multi-hop structure representation"
    else:
        selected_type = "topological_baseline"
        selected_model = None
        reason = "Topological baseline selected for deterministic execution and lower compute requirements"

    print(f"[DECISION] Selected '{selected_type.upper()}': {reason}")

    detector = GraphDetector(
        model=selected_model,
        model_type=selected_type,
        window_seconds=window_sec,
        in_channels=5,
        threshold=0.50,
        version="graph_v1",
    )
    detector.save(out_path)

    comparison_results = {
        "selected_architecture": selected_type,
        "selection_rationale": reason,
        "window_seconds": window_sec,
        "candidates": {
            "topological_baseline": {
                "val_macro_f1": round(base_f1, 4),
                "val_accuracy": round(base_acc, 4),
                "latency_ms_per_snapshot": round(base_latency, 3),
            },
            "graphsage": {
                "val_macro_f1": round(sage_f1, 4),
                "val_accuracy": round(sage_acc, 4),
                "latency_ms_per_snapshot": round(sage_latency, 3),
                "parameter_count": sage_params,
                "pyg_available": HAS_PYG,
            },
        },
    }

    with open(out_path / "architecture_comparison.json", "w", encoding="utf-8") as f:
        json.dump(comparison_results, f, indent=2)

    print(f"[SUCCESS] Graph model artifacts saved to '{out_path}'")
    return comparison_results


if __name__ == "__main__":
    run_graph_comparison_experiment()
