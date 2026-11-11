"""
Unit tests for Communication Graph Intelligence (training/graph/).
"""

from pathlib import Path
import numpy as np
import pytest

from training.graph.graph_schema import IncrementalGraphTracker, GraphSnapshotData
from training.graph.models import GraphStatisticsBaseline
from training.graph.graph_detector import GraphDetector


def test_graph_tracker_window_purge():
    tracker = IncrementalGraphTracker(window_seconds=10.0)

    # Old flow at ts=100
    tracker.add_flow({
        "ts": 100.0, "src_ip": "192.168.1.10", "dst_ip": "203.0.113.1",
        "orig_bytes": 100, "resp_bytes": 200, "orig_pkts": 2, "resp_pkts": 2,
    })

    # Recent flow at ts=115 (older than 10s cutoff should be purged on snapshot)
    tracker.add_flow({
        "ts": 115.0, "src_ip": "192.168.1.10", "dst_ip": "203.0.113.2",
        "orig_bytes": 100, "resp_bytes": 200, "orig_pkts": 2, "resp_pkts": 2,
    })

    snapshot = tracker.build_snapshot(current_ts=115.0)
    assert snapshot.num_edges == 1
    assert snapshot.edge_index.shape == (2, 1)


def test_topological_baseline_detects_fanout():
    baseline = GraphStatisticsBaseline()

    # Node 0 has 20 unique peers with out_degree 20 (scanner behavior)
    # Node 1 has 1 unique peer with out_degree 1 (steady sensor)
    node_feats = np.array([
        [0.0, 20.0, 10.0, 0.0, 20.0],
        [5.0, 1.0, 5.0, 5.0, 1.0],
        [5.0, 1.0, 5.0, 5.0, 1.0],
        [5.0, 1.0, 5.0, 5.0, 1.0],
    ], dtype=np.float32)

    risks = baseline.score_nodes(node_feats)
    assert len(risks) == 4
    # Scanner node should receive significantly higher risk than steady nodes
    assert risks[0] > risks[1]
    assert risks[0] > 0.50


def test_graph_detector_scoring_and_lateral_movement(tmp_path):
    detector = GraphDetector(
        model=None,
        model_type="topological_baseline",
        window_seconds=30.0,
        version="test_graph_v1",
    )

    # 1. External flow
    flow_ext = {
        "ts": 1000.0, "src_ip": "192.168.1.10", "dst_ip": "203.0.113.5",
        "orig_bytes": 300, "resp_bytes": 400, "orig_pkts": 4, "resp_pkts": 4,
        "proto": "tcp", "conn_state": "SF",
    }
    res_ext = detector.score_flow(flow_ext)
    assert "graph_risk" in res_ext
    assert 0.0 <= res_ext["graph_risk"] <= 1.0
    assert res_ext["is_lateral_movement"] is False

    # 2. Internal-to-internal lateral edge
    flow_lat = {
        "ts": 1001.0, "src_ip": "192.168.1.10", "dst_ip": "192.168.1.50",
        "orig_bytes": 100, "resp_bytes": 0, "orig_pkts": 2, "resp_pkts": 0,
        "proto": "tcp", "conn_state": "S0",
    }
    res_lat = detector.score_flow(flow_lat)
    assert res_lat["is_lateral_movement"] is True
    assert "INTERNAL_LATERAL_EDGE" in res_lat["reason_codes"]

    # 3. Save and load
    out_dir = tmp_path / "saved_graph"
    detector.save(out_dir)
    loaded = GraphDetector.load(out_dir)
    assert loaded.model_type == "topological_baseline"
    assert loaded.version == "test_graph_v1"
