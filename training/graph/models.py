"""
Graph Neural Network Models and Topological Baselines:
  - GraphSAGENet: PyTorch Geometric 2-hop neighborhood aggregation
  - GraphStatisticsBaseline: Deterministic topological degree/fan-out anomaly baseline
"""

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

try:
    from torch_geometric.nn import SAGEConv
    HAS_PYG = True
except ImportError:
    HAS_PYG = False
    SAGEConv = None


class GraphSAGENet(nn.Module):
    """
    2-Layer GraphSAGE neural network for node-level communication representation.
    """

    def __init__(
        self,
        in_channels: int = 5,
        hidden_channels: int = 32,
        out_channels: int = 2,
        dropout: float = 0.2,
    ):
        super().__init__()
        if not HAS_PYG:
            raise RuntimeError("torch_geometric is required to instantiate GraphSAGENet")

        self.conv1 = SAGEConv(in_channels, hidden_channels, aggr="mean")
        self.conv2 = SAGEConv(hidden_channels, hidden_channels, aggr="mean")
        self.classifier = nn.Sequential(
            nn.Linear(hidden_channels, 16),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(16, out_channels),
        )

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """
        x: (num_nodes, in_channels)
        edge_index: (2, num_edges)
        returns logits: (num_nodes, out_channels)
        """
        if edge_index.shape[1] == 0:
            # Self-loop fallback if graph currently has no edges
            num_nodes = x.shape[0]
            edge_index = torch.arange(num_nodes, dtype=torch.long, device=x.device).repeat(2, 1)

        h = self.conv1(x, edge_index)
        h = F.relu(h)
        h = self.conv2(h, edge_index)
        h = F.relu(h)
        return self.classifier(h)


class GraphStatisticsBaseline:
    """
    Fast, deterministic topological baseline without neural network overhead.
    Computes fan-out z-scores, degree anomalies, and peer dispersion.
    """

    def __init__(self, fanout_threshold: float = 3.0):
        self.fanout_threshold = fanout_threshold

    def score_nodes(self, node_features: np.ndarray) -> np.ndarray:
        """
        node_features: [in_degree, out_degree, log(bytes_sent+1), log(bytes_recv+1), num_unique_peers]
        returns anomaly risk in [0.0, 1.0] for each node.
        """
        if len(node_features) == 0:
            return np.empty(0, dtype=np.float32)

        out_degrees = node_features[:, 1]
        unique_peers = node_features[:, 4]

        # Fan-out ratio: unique peers per out-degree
        ratio = unique_peers / np.maximum(out_degrees, 1.0)

        # Scanner heuristic: High out-degree with high unique peer count
        peer_z = (unique_peers - np.mean(unique_peers)) / (np.std(unique_peers) + 1e-5)
        risk = 1.0 / (1.0 + np.exp(-(peer_z - 1.5)))
        return np.clip(risk, 0.0, 1.0).astype(np.float32)
