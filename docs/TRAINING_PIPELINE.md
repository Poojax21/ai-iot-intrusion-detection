# Pahredaar-IoT — Reproducible ML Training Pipeline
**Document Version:** 2.0  

---

## 1. Principles of Reproducibility

1. **Fixed Random Seeds:** All stochastic components (`RandomForestClassifier`, `IsolationForest`, data splitters) use explicit seeds (`seed=42`).
2. **Versioned Preprocessing:** Feature scaling and imputations are fit **only** on the training set and serialized alongside model weights.
3. **Immutability of Baseline Models:** Pre-existing V1 model artifacts (`backend/app/models/`) are never overwritten automatically. New experiment models are saved into versioned artifact directories.
4. **Decoupled Training & Serving:** Training utilities reside strictly in `training/`, ensuring inference engines in `backend/` do not require training dependencies.

---

## 2. Experiment Artifact Directory Structure

All new research-grade training runs output structured artifacts to:
```text
training/artifacts/
  └── <dataset_name>/
      └── <experiment_name>/
          ├── feature_schema.json     # Ordered list of features used
          ├── preprocessing.json      # Scaler parameters and missing-value rules
          ├── split_metadata.json     # Timestamps, scenario groups, and sample counts
          ├── metrics.json            # Precision, Recall, F1, FPR, PR-AUC per class
          ├── confusion_matrix.csv    # Evaluated confusion matrix
          └── model.pkl               # Serialized model pipeline
```

---

## 3. End-to-End Training Workflow

1. **Dataset Ingestion:**
   ```powershell
   py -3.14 -m training.datasets prepare --dataset iot23 --path data/iot23/conn.log.labeled --limit 50000
   ```
2. **Leakage Audit Verification:** Confirms `is_leakage_free == True`.
3. **Feature Vectorization:** Uses `batch_align_features` to compute canonical features with `DeviceState` rolling baselines.
4. **Model Fitting & Calibration:**
   - Stage 1a: IsolationForest on benign training flows.
   - Stage 1b: RandomForest Binary Gate tuned on validation set for $\text{FPR} \le 2\%$.
   - Stage 2: RandomForest Multiclass Classifier on flagged flows.
5. **Independent Evaluation:** Scored on held-out test partition with per-class metrics reporting.
