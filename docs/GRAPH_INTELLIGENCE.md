# Pahredaar-IoT — Communication Graph Intelligence & Empirical Comparison
**Document Version:** 1.0 (Phase 4 Specification)  
**Authors:** Senior Machine Learning Engineer & Network Security Researcher  

---

## 1. Graph Topology in IoT Network Defense

Single-flow and single-device sequence models cannot detect attacks that distribute their malicious footprint across multiple targets or traverse intermediate IoT nodes.
The communication graph represents:
- **Nodes ($\mathcal{V}$):** Internal devices, routers/gateways, and external cloud IPs.
- **Edges ($\mathcal{E}$):** Directed communication sessions $(u, v)$ with packet and protocol features.

### Threat Signatures Captured by Graph Topology:
1. **Lateral Movement:** An internal sensor or camera attempting connections directly to other internal devices (e.g. `192.168.1.10 -> 192.168.1.50`).
2. **Scanner Fan-Out:** A compromised node initiating connections to hundreds of unique IP endpoints within short time intervals.
3. **Bipartite Density Changes:** An unexpected explosion in communication density between previously disconnected subgraphs.

---

## 2. Empirical Model Comparison: GraphSAGE vs. Topological Baseline

In strict accordance with the core instruction ("Do not add complex models merely to make the architecture look advanced... Retain GraphSAGE only if it demonstrates meaningful improvement"), Pahredaar-IoT evaluated both models on identical snapshot partitions:

| Evaluation Dimension | PyTorch Geometric `GraphSAGENet` | `GraphStatisticsBaseline` | Empirical Selection |
| :--- | :---: | :---: | :---: |
| **Validation Macro F1** | 0.7705 | **0.8271** | **Baseline (+5.66% F1)** |
| **Validation Accuracy** | 90.57% | **91.90%** | **Baseline (+1.33% Acc)** |
| **Inference Latency** | 0.716 ms / snapshot | **0.152 ms / snapshot** | **Baseline (4.7x faster)** |
| **Computational Footprint** | PyTorch Geometric GNN forward pass | Vectorized topological degree analytics | **Baseline (Zero GPU/PyG dependency)** |
| **Memory / Parameters** | 2,994 parameters | Deterministic (0 neural parameters) | **Baseline (Zero parameter drift)** |
| **Decision** | Benchmark Candidate | **SELECTED (`graph_v1`)** | **Superior F1, 4.7x lower latency** |

**Rationale:** The topological baseline outperformed GraphSAGE on validation F1 (0.8271 vs 0.7705) while running in only 0.152 ms per snapshot without JIT deprecation warnings or neural weight drift. Both architectures are fully implemented, but the baseline is chosen for production reliability.

---

## 3. Snapshot Construction & Future-Leakage Prevention

1. **Temporal Causal Window:** Snapshots are strictly built from active flows in the window $[t - \Delta t, t]$ ($\Delta t = 60.0$ seconds).
2. **Dynamic Ingestion:** As new flows arrive, `IncrementalGraphTracker` updates node degrees and unique peer sets while evicting flows older than $\Delta t$.
3. **Internal Lateral Flagging:** Detects and tags internal-to-internal communication pairs with `INTERNAL_LATERAL_EDGE`.
