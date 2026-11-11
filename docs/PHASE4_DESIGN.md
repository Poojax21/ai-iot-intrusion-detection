# Pahredaar-IoT — Phase 4: Advanced Hybrid AI Engine Design
**Document Version:** 1.0 (Phase 4 Specification)  
**Authors:** Senior Machine Learning Engineer, Principal Cybersecurity Architect & Software Quality Engineer  
**Status:** Approved Design Document  

---

## 1. Executive Summary & Design Philosophy

Phase 4 transforms the Pahredaar-IoT Intrusion Detection Platform from an isolated per-flow classifier into an **Advanced Hybrid AI Engine** synthesizing four orthogonal dimensions of network security intelligence:

1. **Local Flow Semantics & Exact Attribution:** Exact TreeSHAP feature attributions replacing heuristic ablations.
2. **Temporal Dynamics:** Deep sequential state modeling (GRU / LSTM) capturing multi-step reconnaissance, periodic beaconing, and burst trends.
3. **Spatial Interaction Topologies:** Graph Neural Network (GraphSAGE) and topological graph telemetry mapping lateral movement, bipartite communication, and unexpected fan-out.
4. **Hierarchical Risk Synthesis:** Multi-tier evidence fusion (Flow $\to$ Temporal $\to$ Graph $\to$ Device Risk) with decay, duplicate suppression, and calibrated reasoning.

```
       +-------------------------------------------------------------+
       |                     INCOMING FLOW RECORD                    |
       +-------------------------------------------------------------+
                                      |
            +-------------------------+-------------------------+
            |                                                   |
            v                                                   v
+-----------------------+                           +-----------------------+
|  Stage 1 & 2: Flow    |                           |  Device Behavioral    |
|  Detection & Open-Set |                           |  State Maintenance    |
|  (Gate, Anomaly, OOD) |                           |  (History, Sequences) |
+-----------------------+                           +-----------------------+
            |                                                   |
            +-------------------------+-------------------------+
                                      |
                                      v
                      +-------------------------------+
                      |   Hybrid AI Inference Engine  |
                      +-------------------------------+
                       /              |              \
                      v               v               v
            +----------------+ +---------------+ +---------------+
            | Exact TreeSHAP | | Temporal GRU  | |   GraphSAGE   |
            | Explainer      | | Sequence Net  | | Topology Net  |
            +----------------+ +---------------+ +---------------+
                      \               |               /
                       v              v              v
                      +-------------------------------+
                      |   Hierarchical Risk Engine    |
                      |   Flow -> Temp -> Graph -> Dev|
                      +-------------------------------+
                                      |
                                      v
                      +-------------------------------+
                      | Consolidated Output & Triage  |
                      | Alert, Reason Codes, Evidence |
                      +-------------------------------+
```

---

## 2. Component Architecture & Interfaces

### Component A: Exact TreeSHAP Explainability (`training/explainability/`)
- **Objective:** Provide mathematically exact Shapley value attributions for Random Forest gate and multiclass decisions.
- **Mathematical Property:** Satisfies efficiency / additivity:
  $$f(\mathbf{x}) = \phi_0 + \sum_{i=1}^D \phi_i(\mathbf{x}) \pm \epsilon, \quad |\epsilon| < 10^{-4}$$
- **Interface:** `TreeShapExplainer(model, feature_names)` with `explain_instance(x_raw, x_scaled)`.
- **Outputs:**
  - `expected_value`: Base probability ($\phi_0$).
  - `contributions`: Feature attribution vector ($\{\phi_i\}$).
  - `top_features`: Sorted list of positive and negative driving signals.
  - `satisfies_additivity`: Boolean check confirming exact mathematical reconciliation.
- **Latency Optimization:** Pre-computed and cached tree paths; isolated async explanation for non-blocking alerting.

---

### Component B: Temporal Sequence Intelligence (`training/temporal/`)
- **Objective:** Detect stealthy low-and-slow reconnaissance, Mirai periodic beaconing, and multi-flow state transitions.
- **Architecture Trade-Off Evaluation:**
  - **GRU (Gated Recurrent Unit):** Fewer parameters (3 gates vs. 4), lower latency on CPU, faster convergence on sequence windows ($W \in [5, 15]$).
  - **LSTM (Long Short-Term Memory):** Separate cell state, superior for very long dependencies ($W > 50$), higher compute footprint.
  - **Selection Criteria:** Empirical throughput and F1 benchmark on identical chronological splits.
- **Sequence Construction & Anti-Leakage Safeguards:**
  - Strict chronological ordering per `device_id`.
  - Zero cross-device mixing.
  - Non-overlapping sequence window partitioning across Train, Val, and Test.
  - Initial cold-start padding ($L < W$) with zero-masking.

---

### Component C: Communication Graph Intelligence (`training/graph/`)
- **Objective:** Model network topology to detect lateral movement, scanner fan-out, and unauthorized node bridging.
- **Graph Representation:**
  - **Nodes ($\mathcal{V}$):** Internal devices, gateway, and external endpoints. Node features $\mathbf{h}_v \in \mathbb{R}^{d_v}$ summarize local device activity (byte rates, degree, entropy).
  - **Edges ($\mathcal{E}$):** Directed communication pairs $(u, v)$. Edge features $\mathbf{e}_{uv} \in \mathbb{R}^{d_e}$ capture connection statistics (duration, packet counts, protocol, error flags).
- **Graph Engine:**
  - Primary: PyTorch Geometric `SAGEConv` (GraphSAGE mean aggregator) aggregating 1-hop and 2-hop neighborhood representations.
  - Baseline / Fallback: NetworkX graph topological metrics (in-degree, out-degree, clustering coefficient, bipartite fan-out ratio).
- **Anti-Leakage Safeguard:** Snapshot graphs are constructed strictly using causal time windows $[t - \Delta t, t]$. Future edges are never included.

---

### Component D: Hierarchical Risk Engine (`backend/app/risk/`)
- **Objective:** Compute transparent, audit-ready device risk scores from multi-modal evidence without arbitrary score averaging.
- **Mathematical Formulation:**
  $$R_{device}(t) = \min\left(100, \, R_{device}(t-1) \cdot \lambda^{\Delta t} + \Delta R(t)\right)$$
  $$\Delta R(t) = w_{flow} \cdot S_{flow} + w_{novelty} \cdot S_{novelty} + w_{temporal} \cdot S_{temporal} + w_{graph} \cdot S_{graph}$$
  - $\lambda \in (0, 1)$: Exponential time-decay factor (default 0.98 per 60s).
  - $w_i$: Calibrated component weights normalized to $\sum w_i = 1.0$.
  - $\Delta R(t) = 0$ if the alert is an unconfirmed duplicate within the suppression window.
- **Risk Tiers:**
  - `0 - 24`: LOW (Normal fleet activity)
  - `25 - 54`: ELEVATED (Uncertain / anomalous flow tail)
  - `55 - 79`: HIGH (Confirmed known attack or persistent sequence anomaly)
  - `80 - 100`: CRITICAL (Multi-stage attack, lateral movement, or OOD zero-day)

---

## 3. Graceful Fallback & Production Safety Matrix

| Scenario / Failure Mode | Detection Behavior | Risk Engine Behavior | System Health Status |
| :--- | :--- | :--- | :--- |
| **All Models Healthy** | Full Hybrid (Flow + TreeSHAP + Temporal + Graph) | Full 4-Tier Hierarchical Risk | `OK` (Full Hybrid) |
| **TreeSHAP Timeout / Error** | Fallback to Scaler-Mean Ablation | Unaffected (Flow risk preserved) | `DEGRADED` (SHAP heuristic) |
| **Temporal Model Disabled / Missing** | Flow + Open-Set Detection | $w_{temporal}$ reallocated to Flow & Graph | `OK` (Temporal bypassed) |
| **Graph Construction Timeout** | Flow + Temporal Detection | Graph risk omitted; topological baseline used | `DEGRADED` (Graph baseline) |
| **Complete ML Failure** | Fail-open ingestion; raw metadata stored | Baseline risk decay continues | `CRITICAL` (ML unavailable) |

---

## 4. Implementation Sequence

1. **Component A:** Exact TreeSHAP Explainer (`training/explainability/`).
2. **Component B:** Temporal Sequence Intelligence (`training/temporal/`).
3. **Component C:** Graph Intelligence (`training/graph/`).
4. **Component D:** Hierarchical Risk Engine (`backend/app/risk/`).
5. **Component E:** Hybrid Inference Orchestrator (`backend/app/detection.py`).
6. **Component F:** Empirical Ablation Study & Benchmarks (`docs/HYBRID_EVALUATION.md`).
7. **Component G:** Dashboard Telemetry Integration (`frontend/index.html`).
8. **Component H:** Complete Regression Testing & Documentation.
