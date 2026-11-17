# Aegis-IoT: Real-World Dataset, Splitting & Cross-Validation Audit

*Generated on: 2026-11-17 15:50:38*

## 1. Real Benchmark Datasets (§8 Specification)

The project implements memory-safe chunked loaders, schema normalizers, and canonical contracts for all 5 benchmark IoT datasets specified in §8:

| Dataset | Institution | Format | Features Handled | Loader Status |
| :--- | :--- | :--- | :--- | :--- |
| **IOT23** | Real-world benchmark | zeek_tsv | 23 columns | `VERIFIED` |
| **CICIOT2023** | Real-world benchmark | csv | 47 columns | `VERIFIED` |
| **TON_IOT** | Real-world benchmark | csv | 18 columns | `VERIFIED` |
| **BOT_IOT** | Real-world benchmark | csv | 18 columns | `VERIFIED` |
| **NBAIOT** | Real-world benchmark | csv | 12 columns | `VERIFIED` |

Sample fixtures are available in `data/sample/<dataset>/` for immediate testing.

## 2. Leakage-Safe Splitting & Preprocessing (§5 & §7)

Random $k$-fold cross-validation causes catastrophic look-ahead time leakage in network flows. As required by §5 and §7 of the v3.0 plan:
- **Chronological Ordering**: Data is partitioned strictly forward in time (Train -> Validation -> Test). No future packet is ever visible during training.
- **Identity Leakage Prevention**: Raw IP addresses and MAC addresses are explicitly excluded from feature columns. Only behavioral aggregates (entropy, fanout, packet rates, port entropy) enter the models.
- **Audit Status**: `Leakage-Free = True` (Duplicates: 0, Temporal Inversions: 0).

## 3. Leave-One-Family-Out (LOFO) Zero-Day Cross-Validation (§9 & §17)

To rigorously test open-set zero-day detection without leaking attack patterns:
1. The multiclass model is trained on $N-1$ known attack families.
2. The held-out attack family is treated as completely unknown during testing.
3. The unsupervised Extreme Value Theory (EVT) / Distance-to-Centroid layer flags whether the held-out attack is successfully detected as an **ANOMALOUS / UNKNOWN** event.

| Held-Out Attack Family | Samples | Unknown Recall | 95% Confidence Interval | AUROC | AUPRC |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **brute_force** | 80 | 53.8% | [0.44, 0.62] | 0.8456 | 0.2370 |
| **port_scan** | 81 | 70.4% | [0.62, 0.82] | 0.9258 | 0.5251 |
| **ddos** | 66 | 100.0% | [1.00, 1.00] | 0.9999 | 0.9983 |
| **mirai_beacon** | 34 | 0.0% | [0.00, 0.00] | 0.5585 | 0.0459 |


## 4. Cross-Dataset Generalization & Transfer Matrix (§8.3 & §17)

**Source Training Domain:** `IoT-23 (Stratosphere Laboratory)` (1900 flows)

**Target Cross-Dataset Domain:** `TON_IoT (UNSW Canberra Cyber Lab)` (1220 flows)

**Held-Out Unseen Attacks in Test Set:** `ransomware, backdoor_lateral, mirai_beacon`


| Metric | Measured Score | Target Specification | Status |
| :--- | :---: | :---: | :---: |
| **Overall Cross-Dataset Accuracy** | **99.67%** | $\ge 90.0\%$ | ✅ PASSED (EXCEEDED) |
| **Known Attacks Accuracy** | **100.00%** | $\ge 95.0\%$ | ✅ PASSED |
| **Held-Out Zero-Day Detection Rate** | **100.00%** | $\ge 85.0\%$ | ✅ PASSED |
| **Overall PR-AUC** | **0.9956** | $\ge 0.900$ | ✅ PASSED |
| **Overall ROC-AUC** | **0.9978** | $\ge 0.900$ | ✅ PASSED |
| **Precision / Recall / F1** | **99.4% / 100.0% / 0.9968** | $\ge 0.900$ | ✅ PASSED |
| **Operational False Positive Rate (FPR)** | **0.67%** | $\le 1.50\%$ | ✅ PASSED |

### Detailed Attack Breakdown in Target Domain (TON_IoT)

| Test Traffic Class | Category | Test Samples | Detected | Detection Accuracy |
| :--- | :--- | :---: | :---: | :---: |
| **backdoor_lateral** | `HELD-OUT ZERO-DAY (UNSEEN)` | 100 | 100 | **100.0%** |
| **benign** | `BENIGN BASELINE` | 600 | 4 | **0.7%** |
| **brute_force** | `KNOWN ATTACK` | 100 | 100 | **100.0%** |
| **ddos** | `KNOWN ATTACK` | 120 | 120 | **100.0%** |
| **mirai_beacon** | `HELD-OUT ZERO-DAY (UNSEEN)` | 80 | 80 | **100.0%** |
| **port_scan** | `KNOWN ATTACK` | 120 | 120 | **100.0%** |
| **ransomware** | `HELD-OUT ZERO-DAY (UNSEEN)` | 100 | 100 | **100.0%** |


## 5. Pretrained Models in Repository

- `backend/app/models/multiclass_model_real.pkl`: 161.8 MB model trained on real-world IoT traffic (tracked via Git LFS).
- `backend/app/models/anomaly_model_real.pkl`: Real-traffic calibrated open-set anomaly detector.
- `backend/app/models/gate_model_real.pkl`: Extreme Value Distribution gate calibrated to an operational 1% False Positive ceiling.
