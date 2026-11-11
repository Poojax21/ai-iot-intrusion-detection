"""
Graph Schema and Temporal Snapshot Builder for IoT Communication Topologies.

Models communication as directed multigraphs with node and edge attributes,
strictly enforcing causal, past-only snapshot construction without future-edge leakage.
"""

from dataclasses import dataclass, field
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import numpy as np


@dataclass
class GraphSnapshotData:
    num_nodes: int
    num_edges: int
    node_mapping: Dict[str, int]               # Entity ID / IP -> node index
    inverse_mapping: Dict[int, str]
    edge_index: np.ndarray                     # Shape: (2, num_edges)
    node_features: np.ndarray                  # Shape: (num_nodes, node_feat_dim)
    edge_features: np.ndarray                  # Shape: (num_edges, edge_feat_dim)
    timestamp: float


class IncrementalGraphTracker:
    """
    Maintains an active network topology over a rolling temporal window.
    """

    def __init__(self, window_seconds: float = 60.0, max_cached_flows: int = 500):
        self.window_seconds = window_seconds
        self.max_cached_flows = max_cached_flows
        self.recent_flows: List[Dict[str, Any]] = []
        self.known_nodes: Set[str] = set()

    def add_flow(self, flow: Dict[str, Any]):
        """Ingests a new flow and purges entries older than window_seconds."""
        now = float(flow.get("ts", time.time()))
        src = str(flow.get("src_ip", "unknown_src"))
        dst = str(flow.get("dst_ip", "unknown_dst"))

        self.known_nodes.add(src)
        self.known_nodes.add(dst)
        self.recent_flows.append(flow)

        cutoff = now - self.window_seconds
        # Purge stale flows
        if len(self.recent_flows) > self.max_cached_flows or (self.recent_flows and self.recent_flows[0]["ts"] < cutoff):
            self.recent_flows = [f for f in self.recent_flows if f["ts"] >= cutoff][-self.max_cached_flows:]

    def build_snapshot(self, current_ts: Optional[float] = None) -> GraphSnapshotData:
        """
        Builds a frozen PyG/NetworkX-compatible snapshot from the active window.
        """
        now = current_ts or (self.recent_flows[-1]["ts"] if self.recent_flows else time.time())
        cutoff = now - self.window_seconds
        active = [f for f in self.recent_flows if f["ts"] >= cutoff]

        # Extract active entities
        entities = sorted(list(self.known_nodes))
        node_map = {ent: i for i, ent in enumerate(entities)}
        inv_map = {i: ent for ent, i in node_map.items()}
        num_nodes = max(len(entities), 1)

        # Node feature accumulators
        in_degrees = np.zeros(num_nodes, dtype=np.float32)
        out_degrees = np.zeros(num_nodes, dtype=np.float32)
        bytes_sent = np.zeros(num_nodes, dtype=np.float32)
        bytes_recv = np.zeros(num_nodes, dtype=np.float32)
        peer_sets: Dict[int, Set[int]] = {i: set() for i in range(num_nodes)}

        src_indices = []
        dst_indices = []
        edge_feat_rows = []

        for f in active:
            u_str = str(f.get("src_ip", "unknown_src"))
            v_str = str(f.get("dst_ip", "unknown_dst"))

            if u_str not in node_map:
                continue
            if v_str not in node_map:
                continue

            u = node_map[u_str]
            v = node_map[v_str]

            src_indices.append(u)
            dst_indices.append(v)

            out_degrees[u] += 1.0
            in_degrees[v] += 1.0

            orig_b = float(f.get("orig_bytes", 0))
            resp_b = float(f.get("resp_bytes", 0))
            bytes_sent[u] += orig_b
            bytes_recv[v] += resp_b
            peer_sets[u].add(v)

            # Edge feature vector: [dur, orig_b, resp_b, orig_pkts, resp_pkts, is_tcp, is_udp, is_sf, is_s0]
            proto = str(f.get("proto", "tcp")).lower()
            state = str(f.get("conn_state", "SF")).upper()
            edge_feat = [
                float(f.get("duration", 0.0)),
                orig_b,
                resp_b,
                float(f.get("orig_pkts", 0)),
                float(f.get("resp_pkts", 0)),
                1.0 if proto == "tcp" else 0.0,
                1.0 if proto == "udp" else 0.0,
                1.0 if state == "SF" else 0.0,
                1.0 if state == "S0" else 0.0,
            ]
            edge_feat_rows.append(edge_feat)

        # Compile node features: [in_degree, out_degree, log(bytes_sent+1), log(bytes_recv+1), num_unique_peers]
        unique_peers = np.array([float(len(peer_sets[i])) for i in range(num_nodes)], dtype=np.float32)
        node_feats = np.column_stack([
            in_degrees,
            out_degrees,
            np.log1p(bytes_sent),
            np.log1p(bytes_recv),
            unique_peers,
        ])

        if src_indices:
            edge_index = np.array([src_indices, dst_indices], dtype=np.int64)
            edge_features = np.array(edge_feat_rows, dtype=np.float32)
        else:
            edge_index = np.empty((2, 0), dtype=np.int64)
            edge_features = np.empty((0, 9), dtype=np.float32)

        return GraphSnapshotData(
            num_nodes=num_nodes,
            num_edges=len(src_indices),
            node_mapping=node_map,
            inverse_mapping=inv_map,
            edge_index=edge_index,
            node_features=node_feats,
            edge_features=edge_features,
            timestamp=now,
        )
