# Pahredaar-IoT — Hierarchical Risk Engine Audit & Mathematical Diagnosis

**Date:** 2026-11-11  
**Target:** `backend/app/risk/risk_engine.py`  
**Reference Benchmark:** `training/evaluation/ablation_study.py`  

---

## 1. Context & Motivation

In the Phase 4 ablation study (`docs/HYBRID_EVALUATION.md`), the hierarchical risk engine exhibited an unexpected drop in risk alignment against ground-truth attack severity:
- **Baseline V1 alone:** Spearman $\rho = 0.6922$
- **V1 + Phase 3 Open-Set:** Spearman $\rho = 0.7196$
- **Full Hybrid without Risk Engine:** Spearman $\rho = 0.7196$
- **Full Hybrid with Hierarchical Risk Engine:** Spearman $\rho = 0.2106$

This audit investigates the statistical, algorithmic, and architectural causes of this phenomenon before modifying production logic.

---

## 2. Statistical Analysis of Component Signals

To understand why the synthesized score lost correlation with ground truth, we evaluated each constituent modality independently against ground-truth attack severity on validation traffic ($n=500$ flows, 5 IoT devices):

| Modality Signal | Definition / Source | Spearman $\rho$ (Severity) | Pearson $r$ (Severity) |
|:---|:---|:---:|:---:|
| **Flow Risk ($R_{\text{flow}}$)** | $\max(\text{gate\_score}, \text{ECDF}_{>0.90})$ | **0.6493** | 0.7048 |
| **Novelty Risk ($R_{\text{novelty}}$)** | OOD Centroid Ratio (active if `is_unknown`) | **0.2780** | 0.2556 |
| **Temporal Risk ($R_{\text{temporal}}$)** | Causal LSTM sequential probability | **0.6306** | **0.9350** |
| **Graph Risk ($R_{\text{graph}}$)** | External fan-out & lateral movement | **0.3567** | 0.3336 |
| **V1 Baseline Step Function** | $100.0 \cdot \mathbb{I}(\text{is\_flagged})$ | **0.8172** | 0.8117 |
| **Phase 4 Decaying Device Risk** | Stateful $R_{\text{device}}(t)$ with $T_{\text{half}}=120s$ | **0.2665** | 0.1867 |

### Inter-Modality Correlation Matrix (Signal Redundancy Check)

| Signal Pair | Pearson $r$ | Operational Interpretation |
|:---|:---:|:---|
| $\text{Corr}(R_{\text{flow}}, R_{\text{temporal}})$ | **0.6412** | Moderate positive correlation; LSTM confirms volumetric spikes while catching low-and-slow patterns. |
| $\text{Corr}(R_{\text{flow}}, R_{\text{novelty}})$ | **0.6515** | Moderate correlation; novelty triggers primarily when gate confidence is ambiguous or out-of-distribution. |
| $\text{Corr}(R_{\text{flow}}, R_{\text{graph}})$ | **0.1954** | Low correlation; communication topology provides genuinely distinct orthogonal information. |
| $\text{Corr}(R_{\text{temporal}}, R_{\text{graph}})$ | **0.3858** | Weak correlation; temporal bursts sometimes coincide with multi-port scans. |
| $\text{Corr}(R_{\text{novelty}}, R_{\text{graph}})$ | **0.0995** | Orthogonal signals ($r < 0.10$). |

---

## 3. Four Core Architectural Flaws Discovered

### Flaw 1: Target Mismatch (Per-Flow Ground Truth vs. Decaying Device Posture)
- **The Metric Mismatch:** The benchmark tested Spearman rank correlation between per-flow attack severity ($\text{benign}=0$, $\text{unknown}=60$, $\text{known}=85$) and the value returned in `res["composite_device_risk"]`.
- **The Decay Effect:** `composite_device_risk` is an accumulated, decaying state representing the device's overall threat posture. When an attack occurred, device risk jumped to 35-70 points. Subsequent benign flows from that same device arrived while the device risk decayed slowly ($T_{\text{half}} = 120$s). 
- Thus, 20 subsequent benign flows had risk scores of 30-50 while true flow severity was 0. Comparing a persistent device posture against instantaneous flow labels artificially penalized the stateful engine.
- Conversely, when the risk engine was disabled, the benchmark fell back to `100.0 if is_flagged else 0.0`. A binary step function that is 100 on attacks and 0 on benign naturally correlates strongly ($\rho \approx 0.72 - 0.81$) with instantaneous flow labels!

### Flaw 2: Benchmark State Leakage
In `training/evaluation/ablation_study.py`:
```python
if engine.risk_engine is not None and hasattr(engine.risk_engine, "device_profiles"):
    engine.risk_engine.device_profiles.clear()
```
The `HierarchicalRiskEngine` class stores state in `self._device_records`, NOT `device_profiles`. Device records were never cleared between ablation configurations. As a result, configurations 6 and 7 inherited residual threat scores from previous runs.

### Flaw 3: Arithmetic Dilution of High-Confidence Single-Modality Attacks
In Phase 4:
$$S_{\text{fused}} = 0.35 R_{\text{flow}} + 0.25 R_{\text{novelty}} + 0.25 R_{\text{temporal}} + 0.15 R_{\text{graph}}$$
- If a known attack flow has $R_{\text{flow}} = 0.99$, but is not an unknown attack ($R_{\text{novelty}} = 0.0$), and the device was previously idle ($R_{\text{temporal}} \approx 0.10, R_{\text{graph}} = 0.0$):
  $$S_{\text{fused}} = 0.35(0.99) + 0.25(0.0) + 0.25(0.10) + 0.15(0.0) = 0.3715$$
- A confirmed, critical attack flow with 99% gate probability gets diluted down to **37.15%** simply because other modalities were neutral.
- In security risk scoring, a high-confidence positive detection must **never** be averaged down by non-participating sensors.

### Flaw 4: Missing Modality Imputation Bias
When temporal or graph detectors were absent or failed, `risk_engine.py` defaulted:
```python
temporal_risk = flow_risk
graph_risk = flow_risk
```
This arbitrarily triplicated the weight of `flow_risk` ($0.35 + 0.25 + 0.15 = 0.75$), masking missing modality uncertainty instead of renormalizing available evidence weights.

---

## 4. The Corrected Risk Formulation

To resolve these issues, the Hierarchical Risk Engine must decouple **Instantaneous Event Threat ($S_{\text{event}}$)** from **Accumulated Device Posture ($R_{\text{device}}$)**, and employ a **Non-Dilutive Dominant-Signal Architecture with Corroboration Amplification**:

### 4.1 Non-Dilutive Event Threat Fusion
1. **Anchor Threat**:
   $$S_{\text{base}} = \max(R_{\text{flow}}, R_{\text{novelty}})$$
2. **Corroborating Amplification**:
   $$S_{\text{secondary}} = \frac{w_{\text{temp}} R_{\text{temporal}} + w_{\text{graph}} R_{\text{graph}}}{w_{\text{temp}} + w_{\text{graph}}}$$
3. **Fused Event Threat**:
   $$S_{\text{event}} = S_{\text{base}} + (1.0 - S_{\text{base}}) \cdot \kappa \cdot S_{\text{secondary}}$$
   where $\kappa \in [0, 1]$ (default $0.50$) governs the corroboration bonus.

### 4.2 Mathematical Guarantees
- **Non-Dilution**: $S_{\text{event}} \ge S_{\text{base}}$. A 99% flow risk is guaranteed to yield $S_{\text{event}} \ge 0.99$.
- **Corroboration Elevation**: If secondary temporal or graph anomalies are also observed, $S_{\text{event}}$ increases toward 1.0.
- **Low-and-Slow Attack Catching**: If flow risk is borderline ($0.40$), strong temporal sequence confidence ($0.90$) elevates event threat:
  $$0.40 + 0.60 \cdot 0.5 \cdot 0.90 = 0.67$$
- **Benign Stability**: If flow is benign ($0.02$) and secondary signals are low ($0.01$), event threat remains $< 0.03$.

### 4.3 Dynamic Missing-Modality Normalization
If a modality is unavailable (e.g. cold start with $< 3$ flows or uninitialized graph tracker), weights are dynamically renormalized over strictly available modalities:
$$w_m' = \frac{w_m}{\sum_{k \in \mathcal{M}_{\text{available}}} w_k}$$

### 4.4 Decoupled Output Schema
`evaluate_risk()` returns:
- `fused_event_threat`: Normalized event threat $\in [0, 100]$ (for per-flow alerting & ROC calibration).
- `composite_device_risk`: Stateful decayed threat posture $\in [0, 100]$ (for SOC device inventory).
