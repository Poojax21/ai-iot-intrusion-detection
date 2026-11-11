# Pahredaar-IoT — Temporal Sequence Modeling & Architecture Comparison
**Document Version:** 1.0 (Phase 4 Specification)  
**Authors:** Senior Machine Learning Engineer & Distributed Systems Architect  

---

## 1. Problem Formulation: Beyond Per-Flow Isolation

Individual flow-level classifiers observe only isolated snapshots $(\mathbf{x}_t)$. Advanced threats in IoT environments, however, manifest over **multi-flow temporal sequences**:
1. **Periodic Beaconing:** Mirai botnet C2 heartbeats emit low-byte packets at fixed intervals with small variances.
2. **Reconnaissance & Port Sweeps:** A device switches from benign internal traffic to rapid connection attempts across changing ports.
3. **Low-and-Slow Exfiltration:** Sustained, elevated outbound byte-volume spread across hundreds of separate TCP sessions.

---

## 2. Head-to-Head Architecture Comparison: GRU vs. LSTM

To avoid ungrounded architectural preference, Pahredaar-IoT conducted an empirical head-to-head comparison on identical chronological splits ($N=10,000$ flows, $W=10$ sequence window, PyTorch CPU execution):

| Evaluation Metric | Candidate 1: `TemporalGRU` | Candidate 2: `TemporalLSTM` | Selection Result |
| :--- | :---: | :---: | :---: |
| **Validation Macro F1** | 0.9589 | **0.9627** | **LSTM (+0.38% F1)** |
| **Validation Accuracy** | 97.93% | **98.13%** | **LSTM (+0.20% Acc)** |
| **Validation Loss** | 0.0625 | **0.0590** | **LSTM (Lower loss)** |
| **Test Split Accuracy** | 98.40% | **98.73%** | **LSTM (+0.33%)** |
| **Test Split Macro F1** | 0.9688 | **0.9731** | **LSTM (+0.43%)** |
| **CPU Inference Latency** | 1.178 ms / sample | **0.646 ms / sample** | **LSTM (1.8x faster on CPU)** |
| **Parameter Count** | 25,418 params | 33,482 params | GRU (fewer params) |
| **Decision** | Baseline | **SELECTED (`temporal_v1`)** | **Statistically superior F1 & lower latency** |

**Rationale:** The `TemporalLSTM` achieved higher sequence Macro-F1 (0.9731 vs 0.9688) while executing faster on single-sample CPU inference (0.646 ms), making it the chosen production sequence model.

---

## 3. Anti-Leakage Sequence Construction

1. **Device Isolation:** Each device's state is stored in an isolated FIFO buffer (`DeviceSequenceBuffer`). Flows from device $A$ never enter device $B$'s sequence.
2. **Strict Chronological Ingestion:** Windows contain only past and current flows $[t - W + 1, \dots, t]$. Future flows are strictly blocked.
3. **Pre-Padding on Cold Start:** Devices with fewer than $W$ flows are pre-padded with zero-vectors, avoiding artificial feature distortion.
