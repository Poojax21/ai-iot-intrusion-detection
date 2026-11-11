"""
PyTorch Neural Sequence Models for Temporal Intrusion Detection:
  - TemporalGRU: High-throughput, low-parameter Gated Recurrent Unit
  - TemporalLSTM: Long Short-Term Memory Network with explicit cell state
"""

import torch
import torch.nn as nn
import torch.nn.functional as F


class TemporalGRU(nn.Module):
    """
    Lightweight, high-efficiency GRU for real-time edge & CPU inference.
    """

    def __init__(
        self,
        input_dim: int = 20,
        hidden_dim: int = 48,
        num_layers: int = 2,
        num_classes: int = 2,
        dropout: float = 0.2,
    ):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.num_classes = num_classes

        self.gru = nn.GRU(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )

        self.fc = nn.Sequential(
            nn.Linear(hidden_dim, 24),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(24, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        x shape: (batch_size, seq_len, input_dim)
        returns logits: (batch_size, num_classes)
        """
        # gru_out shape: (batch_size, seq_len, hidden_dim)
        gru_out, _ = self.gru(x)
        # Pool the last time-step output
        last_hidden = gru_out[:, -1, :]
        logits = self.fc(last_hidden)
        return logits


class TemporalLSTM(nn.Module):
    """
    Standard LSTM sequence network with distinct cell and hidden states.
    """

    def __init__(
        self,
        input_dim: int = 20,
        hidden_dim: int = 48,
        num_layers: int = 2,
        num_classes: int = 2,
        dropout: float = 0.2,
    ):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.num_classes = num_classes

        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )

        self.fc = nn.Sequential(
            nn.Linear(hidden_dim, 24),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(24, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        x shape: (batch_size, seq_len, input_dim)
        returns logits: (batch_size, num_classes)
        """
        lstm_out, _ = self.lstm(x)
        last_hidden = lstm_out[:, -1, :]
        logits = self.fc(last_hidden)
        return logits
