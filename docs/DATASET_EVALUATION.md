# Pahredaar-IoT — Dataset Evaluation & Benchmark Report
**Document Version:** 2.0 (Phase 2 Release)  

---

## 1. Evaluation Methodology

In accordance with Section 10 of the Master Implementation Plan:
1. Model performance is evaluated strictly on **held-out chronological test sets**.
2. Detection performance is reported on a **per-class basis** (never blended global accuracy alone).
3. The $\le 2\%$ Operational False-Positive Rate (FPR) ceiling is evaluated as a strict constraint.

---

## 2. Real Dataset Feature Compatibility Summary

Evaluated using `canonical_contract.evaluate_dataset_compatibility()`:

| Dataset | Format | Feature Compatibility | Compatible Dimensions | Notes |
|---|---|---|---|---|
| **IoT-23** | Zeek `conn.log` TSV/JSON | **100% Fully Compatible** | 20 / 20 Features | Native flow tuples map 1:1 into `DeviceState` engine. |
| **TON_IoT** | Network Flow CSV | **100% Fully Compatible** | 20 / 20 Features | Zeek-derived flow records map 1:1 into `DeviceState` engine. |
| **CICIoT2023** | Statistical Aggregates CSV | **Specialized 46-Feature Contract** | 46 / 46 Features | Tabular statistical aggregates match `real_feature_columns.json`. |

---

## 3. Class Diversity & Shannon Entropy

| Dataset | Major Classes Available | Imbalance Ratio | Shannon Entropy |
|---|---|---|---|
| **IoT-23** | `BENIGN`, `PORT_SCAN`, `DDOS`, `BOTNET`, `MIRAI_BEACON`, `OTHER_ATTACK` | 14.2:1 | 2.15 bits |
| **CICIoT2023** | `BENIGN`, `DDOS`, `PORT_SCAN`, `BRUTE_FORCE`, `MIRAI_BEACON`, `OTHER_ATTACK` | 8.6:1 | 2.48 bits |
| **TON_IoT** | `BENIGN`, `PORT_SCAN`, `DDOS`, `BRUTE_FORCE`, `OTHER_ATTACK` | 6.4:1 | 1.95 bits |

---

## 4. Evaluation Constraints & Caveats

1. **No Mixed Global Accuracy:** Blended accuracy masks rare attack failures (e.g. Brute Force or Botnet C2 with small sample sizes). Always inspect per-class recall and precision.
2. **FPR Constraint:** Any model exhibiting an FPR $> 2.0\%$ on the validation partition is rejected before promotion to the test phase.
3. **Cross-Dataset Gap:** When models trained on IoT-23 are evaluated on TON_IoT, a performance gap is observed (Macro F1 decreases from ~0.98 to ~0.45). This drop reflects genuine domain shift (different testbed topologies and capture tools) rather than pipeline defect.
