# Pahredaar-IoT — Empirical Unknown Attack Evaluation & Benchmark Report
**Document Version:** 1.0 (Phase 3 Benchmark)  
**Authors:** Senior Machine Learning Engineer & Network Security Researcher  

---

## 1. Experimental Protocol: Zero-Leakage Unknown Attack Evaluation

To rigorously evaluate open-set recognition without synthetic illusions or data leakage, the evaluation strictly followed an experimental protocol where attack classes were **completely partitioned**:

- **Known Training Classes (Train & Val Splits):**
  - `benign`
  - `port_scan`
  - `ddos`
  - `mirai_beacon`
- **Genuinely Held-Out Unknown Attack (Test Split ONLY):**
  - `brute_force` (0 instances in Train, 0 instances in Val; 80 instances in held-out Test split)
- **Leakage Safeguard:**
  - `StandardScaler`, `IsolationForest`, `RandomForestClassifier` (gate and multiclass), and `CentroidGeometry` were fitted exclusively on Train data containing no instances of `brute_force`.
  - Score calibration was performed strictly on Validation benign data.
  - The held-out test split of 2,250 samples was evaluated only once at the conclusion of training.

---

## 2. Quantitative Performance Metrics

### Summary Table

| Metric Category | Metric Name | Measured Value | Standard / Target | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Known-Class Performance** | Accuracy on Known Traffic | **91.47%** | $\ge 90\%$ | **PASS** |
| | Macro F1 Score | **0.7785** | $\ge 0.75$ | **PASS** |
| | Port Scan F1 Score | **1.0000** | $\ge 0.95$ | **PASS** |
| | Mirai Beacon F1 Score | **0.9744** | $\ge 0.95$ | **PASS** |
| | DDoS F1 Score | **0.9673** | $\ge 0.90$ | **PASS** |
| | Benign Precision | **1.0000** | $\ge 0.98$ | **PASS** |
| **Unknown Attack Detection** | **Unknown Detection Rate (Recall)** | **100.0% (1.0000)** | $\ge 80\%$ | **EXCEEDS** |
| | Unknown Attack Precision | **30.42%** | $\ge 25\%$ | **PASS** |
| | **Novelty AUROC** | **0.8828** | $\ge 0.85$ | **PASS** |
| | Novelty AUPRC | **0.3211** | $\ge 0.25$ | **PASS** |
| **Operational Reliability** | False Unknown Rate (on Benign) | **9.23%** | $\le 10\%$ | **PASS** |
| | False Rejection Rate (on Known) | **2.66%** | $\le 5\%$ | **PASS** |
| | Gate Validation FPR Ceiling | **0.26% (0.0026)** | $\le 2.0\%$ | **PASS** |
| | Mean Per-Sample Latency | **146 ms / sample** | $< 250$ ms | **PASS** |
| | Vectorized Batch Throughput | **> 1,500 samples/sec** | $> 1,000$ | **PASS** |

---

## 3. Confusion Matrix Breakdown

Test Partition Size: **2,250 samples**  
- Known Samples: 2,170 (1,907 Benign, 106 Port Scan, 79 DDoS, 78 Mirai Beacon)
- Held-Out Unknown Samples: 80 (`brute_force`)

### Ground Truth vs Predicted Outcome:

| Ground Truth Class | Triage Outcome: BENIGN | Triage Outcome: KNOWN_ATTACK | Triage Outcome: UNKNOWN_SUSPICIOUS | Triage Outcome: UNCERTAIN |
| :--- | :---: | :---: | :---: | :---: |
| **Benign** (1,907) | **1,729** (90.7%) | **2** (0.10%) | **82** (4.30%) | **94** (4.93%) |
| **Port Scan** (106) | 0 (0.0%) | **106** (100.0%) | 0 (0.0%) | 0 (0.0%) |
| **DDoS** (79) | 0 (0.0%) | **74** (93.7%) | **5** (6.3%) | 0 (0.0%) |
| **Mirai Beacon** (78) | 0 (0.0%) | **76** (97.4%) | **2** (2.6%) | 0 (0.0%) |
| **Brute Force (UNKNOWN)** (80) | **0** (0.0%) | **0** (0.0%) | **80** (100.0%) | **0** (0.0%) |

### Key Observations:
1. **Zero False Rejections of Unknown Attacks to Benign:** Exactly 0 out of 80 unknown brute force attacks were misclassified as benign ($0.0\%$ escape rate).
2. **Zero Forced Misclassifications:** Zero unknown brute force attacks were forced into known attack categories (`ddos`, `port_scan`, `mirai_beacon`).
3. **Ultra-Low Known Attack False Alarms on Benign:** Only 2 out of 1,907 benign flows ($0.10\%$) triggered a known attack alert.
4. **Transparent Reason Coding:** Unknown attacks were rejected with clear machine-readable codes: `GATE_FLAG_MULTICLASS_BENIGN_DISAGREEMENT` and `AMBIGUOUS_CLASS_MARGIN`.
