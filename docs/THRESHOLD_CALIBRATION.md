# Pahredaar-IoT — Score Calibration & Operational Thresholding
**Document Version:** 1.0 (Phase 3 Specification)  
**Authors:** Senior Machine Learning Engineer & Cybersecurity Architect  

---

## 1. The Anomaly Score Calibration Problem

Raw outputs from unsupervised anomaly detection algorithms (such as Isolation Forest's `decision_function` or opposite score samples) lack probabilistic interpretation:
- Raw scores depend heavily on sample dimension, tree depth, and contamination hyperparameters.
- An arbitrary cutoff (e.g. `raw_score > 0.5`) cannot guarantee bounded false positive rates across diverse networks.
- In multi-device IoT environments, traffic variability across heterogeneous device classes (e.g., cameras producing megabytes vs. temperature sensors producing bytes) distorts unnormalized distance metrics.

---

## 2. Empirical CDF Percentile Calibration

To transform raw unbounded scores into well-behaved probabilities in $[0.0, 1.0]$, Pahredaar-IoT implements an **Empirical Cumulative Distribution Function (ECDF)** calibrator (`AnomalyCalibrator`):

1. **Reference Fitting:** A set of $N_{val}$ benign flows from the validation split $\mathcal{X}_{val\_benign}$ is evaluated against the trained Isolation Forest to compute raw anomaly scores $\mathcal{S}_{benign} = \{s_1, s_2, \dots, s_{N_{val}}\}$.
2. **Quantile Mapping:** Scores are sorted in ascending order.
3. **Inference Calibration:** For any incoming flow with raw anomaly score $s_{raw}$, the calibrated anomaly percentile $S_{cal}$ is determined via:
   $$S_{cal}(s_{raw}) = \frac{1}{N_{val}} \sum_{i=1}^{N_{val}} \mathbf{1}(s_i \le s_{raw})$$
4. **Interpretation:**
   - $S_{cal} \in [0.0, 0.50]$: Normal benign behavior, well within median training volume.
   - $S_{cal} \in [0.90, 0.95]$: Elevated anomaly (top 5-10% tail); transitions to `UNCERTAIN` review state.
   - $S_{cal} \ge 0.95$: Severe behavioral deviation; triggers `UNKNOWN_SUSPICIOUS` triage if unsupported by multiclass confidence.

---

## 3. ROC-Constrained Gate Threshold Calibration ($\text{FPR} \le 2.0\%$)

The Binary Gate (Stage 1b) enforces a strict operational ceiling of **$\le 2.0\%$ False Positive Rate** on benign traffic.

### Calibration Procedure (`calibrate_gate_threshold`):
1. Compute the Receiver Operating Characteristic (ROC) curve over validation ground truth $y_{val} \in \{0, 1\}$ and gate probabilities $P(\text{attack} \mid \mathbf{x})$.
2. Filter the parameter space to the valid subset where $\text{FPR}(\tau) \le 0.02$.
3. Among candidates achieving maximum True Positive Rate ($\text{TPR} = 1.0000$), select the threshold targeting optimal operational balance ($\text{FPR} \approx 0.01$).
4. Clamp the operational threshold $\tau_{gate} \le 0.30$ to prevent high-threshold brittleness against unseen zero-day attacks.

### Achieved Operating Point:
- **Calibrated Gate Threshold:** $\tau_{gate} = 0.3000$
- **Validation False Positive Rate:** $\text{FPR}_{val} = 0.26\%$ (0.0026) — significantly below the $2.0\%$ ceiling.
- **Validation True Positive Rate (Recall):** $\text{TPR}_{val} = 100.0\%$ (1.0000).
