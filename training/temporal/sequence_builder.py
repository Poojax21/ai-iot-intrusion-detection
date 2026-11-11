"""
Leakage-Safe Temporal Sequence Builder for IoT Flow Streams.

Constructs strictly causal, per-device flow sequences of length W.
Prevents cross-device contamination and future-window leakage across data splits.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import numpy as np


@dataclass
class SequenceDataset:
    X: np.ndarray       # Shape: (N, sequence_length, feature_dim)
    y: np.ndarray       # Shape: (N,) binary or multiclass labels
    device_ids: List[str]
    timestamps: np.ndarray


class DeviceSequenceBuffer:
    """
    Maintains a rolling, per-device causal buffer of past feature vectors.
    """

    def __init__(self, sequence_length: int = 10, feature_dim: int = 20):
        self.sequence_length = sequence_length
        self.feature_dim = feature_dim
        self.buffers: Dict[str, List[np.ndarray]] = {}

    def push_and_get_window(self, device_id: str, feature_vector: np.ndarray) -> np.ndarray:
        """
        Appends the current flow's feature vector to the device history
        and returns a fixed-length window of shape (sequence_length, feature_dim).
        Cold starts are zero-prepadded.
        """
        vec = np.asarray(feature_vector, dtype=np.float32).flatten()
        if device_id not in self.buffers:
            self.buffers[device_id] = []

        history = self.buffers[device_id]
        history.append(vec)

        if len(history) > self.sequence_length:
            history.pop(0)

        # Build window with pre-padding if history < sequence_length
        window = np.zeros((self.sequence_length, self.feature_dim), dtype=np.float32)
        n_available = len(history)
        window[self.sequence_length - n_available:] = np.array(history, dtype=np.float32)

        return window

    def reset_device(self, device_id: str):
        if device_id in self.buffers:
            self.buffers[device_id].clear()

    def clear_all(self):
        self.buffers.clear()


def build_causal_sequences(
    features: np.ndarray,
    labels: np.ndarray,
    device_ids: List[str],
    timestamps: np.ndarray,
    sequence_length: int = 10,
) -> SequenceDataset:
    """
    Builds causal sequences from a stream of time-ordered flows.
    Strictly prevents future leakage: window for flow t contains only [t-W+1, ..., t].
    """
    n_samples, feature_dim = features.shape
    buffer = DeviceSequenceBuffer(sequence_length=sequence_length, feature_dim=feature_dim)

    seq_X = []
    seq_y = []
    seq_dev = []
    seq_ts = []

    for i in range(n_samples):
        dev = device_ids[i]
        feat = features[i]
        lbl = labels[i]
        ts = timestamps[i]

        window = buffer.push_and_get_window(dev, feat)
        seq_X.append(window)
        seq_y.append(lbl)
        seq_dev.append(dev)
        seq_ts.append(ts)

    return SequenceDataset(
        X=np.array(seq_X, dtype=np.float32),
        y=np.array(seq_y),
        device_ids=seq_dev,
        timestamps=np.array(seq_ts, dtype=np.float64),
    )
