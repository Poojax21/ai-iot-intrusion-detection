# Pahredaar-IoT — Comprehensive Codebase Audit
**Author:** Principal Cybersecurity Architect & Senior Engineering Team  
**Date:** November 2026  
**Repository:** `iot-ids-project` (Root: `C:\Users\Hi\Projects\iot-ids-project`)  
**Baseline Version:** V1 Working Slice

---

## 1. Executive Summary

A comprehensive, line-by-line inspection of the repository was completed across all subsystem modules: backend (`FastAPI`), detection pipeline (`scikit-learn`), feature engineering, data storage (`SQLite`), simulation engine, Zeek adapter, model artifacts, and the frontend dashboard.

The existing V1 implementation successfully demonstrates a lightweight, end-to-end working proof-of-concept:
- Models are trained on synthetic IoT flows and pre-serialized in `backend/app/models/`.
- The FastAPI service ingests flows via `/api/ingest`, applies a two-stage detection pipeline (IsolationForest unsupervised anomaly + tuned RandomForest binary gate, followed by a multiclass RandomForest classifier), logs to SQLite, and broadcasts alerts over WebSockets.
- The single-page frontend (`frontend/index.html`) displays real-time alerts, device risk cards, MITRE ATT&CK tags, and an in-browser Traffic Lab.
- An edge bridge (`simulator/zeek_adapter.py`) tails Zeek `conn.log` and maps fields to the `FlowRecord` schema.

However, moving from this working demo to a **research-grade, production-hardened IoT intrusion detection platform** reveals critical architectural gaps, security liabilities, missing evaluation components, and technical debt.

---

## 2. Inventory & Feature Status Matrix

| Module / Feature | Status | Analysis & Deficiencies |
|---|---|---|
| **FastAPI Backend Core** (`backend/app/main.py`) | **Partially Implemented** | Working endpoints for `/api/health`, `/api/ingest`, `/api/alerts`, `/api/devices`, `/api/stats`, `/ws/alerts`. <br/>*Issues:* Wide-open CORS (`allow_origins=["*"]`), no authentication/authorization (JWT/API Keys), no rate limiting, no structured JSON logging, thread concurrency risks with global `DetectionEngine` state. |
| **Detection Engine** (`backend/app/detection.py`) | **Partially Implemented** | Two-stage detection (IsolationForest + RF Binary Gate + RF Multiclass) works with 15-flow grace period. <br/>*Issues:* Closed-set classification (forced to pick among 4 known classes), pseudo-SHAP (simple ablation vs scaler mean, not true Shapley values), no uncertainty estimation, no out-of-distribution (OOD) score calibration, hardcoded `GRACE_PERIOD_FLOWS=15`. |
| **Feature Engineering** (`backend/app/features.py`, `simulator/features.py`, `training/features.py`) | **Partially Implemented** | 20 features computed in-memory per flow. Code duplicated identically in 3 separate directories. <br/>*Issues:* Redundant file copies create drift risk; features lack deep temporal and graph context; device state history kept in non-persistent Python memory. |
| **Data Storage** (`backend/app/storage.py`) | **Partially Implemented** | SQLite database `iot_ids.db` with thread-locking. <br/>*Issues:* SQLite lacks time-series hypertable optimization for high-throughput flows; no schema migration tool; unbounded growth without retention/partitioning policies; risk score formula is a hardcoded heuristic. |
| **Schemas** (`backend/app/schemas.py`) | **Partially Implemented** | Pydantic v2 schemas for `FlowRecord`, `AlertOut`, `DeviceOut`. <br/>*Issues:* Missing request validation for sensor registration, authentication, incident management, user management, and configuration. |
| **Simulator** (`simulator/simulate_devices.py`, `synthetic_traffic.py`) | **Fully Implemented (V1 Scope)** | 5 device types (`camera`, `smart_plug`, `temp_sensor`, `thermostat`, `smart_bulb`), 4 attack patterns (`port_scan`, `ddos`, `brute_force`, `mirai_beacon`). Functional for local synthetic tests. |
| **Zeek Network Bridge** (`simulator/zeek_adapter.py`) | **Partially Implemented** | Tails TSV `conn.log`, buffers during disconnects. <br/>*Issues:* `resolve_device_id` falls back to `sha256(src_ip)` which breaks across DHCP lease renewals; lacks log rotation detection, JSON log parsing, and PCAP direct ingestion. |
| **Frontend SOC Dashboard** (`frontend/index.html`) | **Partially Implemented** | Clean single-file UI with WebSocket stream, risk cards, MITRE ATT&CK mapping, Traffic Lab. <br/>*Issues:* Single massive 1500-line file; lacks network topology graph, incident investigation workflows, sensor management, user management, and multi-tenant authentication. |
| **Model Training & Notebook** (`training/train_model.ipynb`) | **Partially Implemented** | Working synthetic training pipeline with chronological split. <br/>*Issues:* `load_real_dataset()` raises `NotImplementedError`; no open-set evaluation; no cross-dataset generalization harness; notebook execution count metadata had broken kernel reference (`Python 2.7.18`). |
| **Pretrained Models** (`backend/app/models/`) | **Fully Implemented (V1 Scope)** | Contains functional V1 models (`anomaly_model.pkl`, `gate_model.pkl`, `multiclass_model.pkl`, `feature_scaler.pkl`, `gate_threshold.json`) plus latent real-dataset experiment files (`anomaly_model_real.pkl`, `gate_model_real.pkl`, `multiclass_model_real.pkl`, `real_feature_columns.json`, `cross_dataset_results.json`). |
| **Testing Suite** (`tests/`) | **Missing** | Zero automated unit tests, integration tests, or regression tests existed prior to Phase 1. |
| **Configuration & Secrets** | **Missing** | Hardcoded constants throughout codebase; no `.env` validation or settings management via `pydantic-settings`. |
| **Advanced ML (GraphSAGE, LSTM, Exact SHAP)** | **Missing / Deferred** | Outlined in design docs but omitted in V1 implementation. |

---

## 3. Detailed Technical Deficiencies

### 3.1 Security & Ingestion Vulnerabilities
1. **Unauthenticated Ingestion:** Anyone able to reach port 8000 can POST arbitrary flows to `/api/ingest`, skewing device statistics or flooding the alerts database (CWE-306).
2. **Permissive CORS:** `allow_origins=["*"]` on all endpoints allows cross-origin requests from any website visited by the user.
3. **No Rate Limiting:** High-frequency malicious bursts could exhaust backend memory and saturate SQLite write locks.
4. **Opaque Device Identity Spoofing:** In `zeek_adapter.py`, device identity relies on IP hashing when ARP is missing. An attacker spoofing an internal IP immediately pollutes another device's baseline profile.

### 3.2 Machine Learning & Statistical Integrity
1. **Closed-Set Overconfidence:** `multiclass_model.predict_proba()` produces normalized probabilities that sum to 1. When an unknown zero-day or novel protocol attack is detected by the gate, the multiclass classifier is forced to label it as one of the 4 known training classes.
2. **Pseudo-SHAP vs. Exact Shapley Values:** `_shap_explain()` calculates single-feature ablation against a zeroed-out scaled vector. While computationally cheap ($O(F)$ calls to `predict_proba`), it ignores feature correlations and interaction effects, and mislabels the metric as SHAP.
3. **Duplicated Code & Skew Risk:** `features.py` and `synthetic_traffic.py` exist in three distinct folders (`backend/app/`, `simulator/`, `training/`). Any modification in one without synchronizing the others introduces immediate training-serving skew.
4. **Data Leakage in Public Benchmarks:** Public datasets (IoT-23, TON_IoT, CICIoT2023) contain static IP/MAC indicators. Without behavioral feature transformation, classifiers memorize source addresses rather than traffic mechanics.

### 3.3 Storage & Concurrency Bottlenecks
1. **SQLite Write Lock Contention:** Python's `threading.Lock()` serializes all database writes. At high flow ingestion rates (>500 flows/sec), thread contention increases event latency.
2. **No Data Retention / Partitioning:** Table `flows` stores every single raw flow record indefinitely. A small IoT gateway generates millions of flows weekly, rapidly degrading SQLite performance.
3. **Volatile In-Memory Device State:** The `DeviceState` objects in `DetectionEngine.device_states` are in-memory Python dictionaries. If the backend restarts, all device baselines, edge caches, and grace-period counters are erased, re-triggering false positives on established devices.

---

## 4. Remediation Strategy by Phase

1. **Phase 1 (Foundation):** Establish testing infrastructure (`pytest`, fixtures, coverage), structured configuration (`pydantic-settings`), logging, and modular architecture without breaking V1 APIs.
2. **Phase 2 (Datasets):** Implement unified, leakage-safe dataset loaders for IoT-23, CICIoT2023, and TON_IoT with feature normalization and chronological/device-aware splits.
3. **Phase 3 (Open-Set Detection):** Build open-set rejection, calibrated anomaly fusion, uncertainty estimation, and 4-way triage (`NORMAL`, `KNOWN_ATTACK`, `UNKNOWN_ATTACK`, `NEEDS_INVESTIGATION`).
4. **Phase 4 (Hybrid AI Engine):** Add GraphSAGE topology detection, LSTM sequence anomaly detection, exact TreeSHAP explainability, and multi-sensor risk fusion.
5. **Phase 5 (Network Integration):** Harden Zeek adapter (rotation handling, JSON parsing, ARP/DHCP lease table tracking) and add PCAP ingestion.
6. **Phase 6 (Secure Production Backend):** Introduce JWT authentication, API key sensor validation, rate limiting, and PostgreSQL/TimescaleDB migration support.
7. **Phase 7 (SOC Dashboard):** Upgrade frontend with interactive topology, incident triage, SHAP waterfalls, and sensor monitoring.
8. **Phase 8 (Validation & Release):** End-to-end integration tests, security audit, Docker Compose packaging, and performance benchmarks.
