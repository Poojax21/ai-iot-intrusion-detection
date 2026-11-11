# Pahredaar-IoT — Data Leakage Prevention & Partitioning Standards
**Document Version:** 2.0  
**Authority:** `training/splitting/`  

---

## 1. Why Random Splitting Is Prohibited in Network IDS

A common flaw in academic literature is applying `train_test_split(shuffle=True)` to network traffic. In an intrusion detection context, random row splitting causes catastrophic feature leakage:
1. **Flow Overlap:** TCP connections spanning multiple seconds get packets/records placed in both train and test sets, artificially inflating recall to ~99.9%.
2. **IP / Port Memorization:** The model learns that specific attacker IPs (e.g. `192.168.1.195`) or ephemeral ports represent attacks, failing immediately when evaluated on a different subnet.
3. **Temporal Lookahead Bias:** The model is trained on events that occurred *after* events in the test set, violating physical operational causality.

---

## 2. Partitioning Strategies Implemented in Pahredaar-IoT

### A. Chronological Splitting (`chronological_split.py`)
- All records are sorted by their floating-point Unix timestamp (`ts`).
- Earliest 70% of traffic $\rightarrow$ Training set.
- Next 15% $\rightarrow$ Validation set (used for FPR threshold selection and early stopping).
- Final 15% $\rightarrow$ Held-out test set.
- **Guarantee:** $\max(\text{train}_{ts}) \le \min(\text{val}_{ts}) \le \min(\text{test}_{ts})$.

### B. Group-Based Splitting (`group_split.py`)
- Partitions by `scenario_id` or `capture_id`.
- Entire capture sessions (e.g. `CTU-IoT-Malware-Capture-1-1`) are kept strictly within a single partition.
- **Guarantee:** $\text{train}_{\text{scenarios}} \cap \text{test}_{\text{scenarios}} = \emptyset$.

### C. Cross-Dataset Transfer Evaluation
- Train model exclusively on Dataset A (e.g. IoT-23).
- Evaluate on Dataset B (e.g. TON_IoT) with zero fine-tuning.
- Measures real-world generalizability across different lab environments and capture tools.

---

## 3. Automated Leakage Audit (`leakage_detection.py`)

Before training any model, `check_leakage(train, test)` runs four automated integrity checks:
1. **Duplicate 5-Tuple & Timestamp:** Flags identical flows in both splits.
2. **Group Bleed:** Flags shared scenarios or capture IDs between train and test.
3. **Temporal Inversion:** Detects test events occurring before training cutoff.
4. **Target Leakage:** Verifies no static IP or MAC tokens are passed into model feature vectors.
