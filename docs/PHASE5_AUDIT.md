# Pahredaar-IoT — Phase 5 Comprehensive System Audit

**Date:** 2026-11-11  
**Baseline Commit:** `9843183`  
**Regression Test Baseline:** 88 passing tests  

---

## 1. Executive Summary

Pahredaar-IoT has evolved across four developmental phases from a baseline dual-stage detector into a multi-modal hybrid platform integrating canonical dataset loaders (IoT-23, CICIoT2023, TON_IoT), calibrated open-set anomaly recognition, exact TreeSHAP local explanations, temporal sequence modeling (LSTM), communication topology analysis, and hierarchical multi-signal risk aggregation.

While the individual modular components have demonstrated strong statistical validation on isolated unit tests and benchmark datasets, this comprehensive audit reveals significant operational gaps, measurement inconsistencies, and production vulnerabilities that must be addressed to transform this research prototype into an enterprise-grade IoT security appliance.

---

## 2. Risk-Scoring Inconsistencies (Highest Priority Issue)

### 2.1 The Spearman $\rho$ Collapse Paradox
In Phase 4 evaluation (`docs/HYBRID_EVALUATION.md`), risk-alignment correlation plummeted:
- **Baseline V1 alone:** $\rho = 0.6922$
- **V1 + Phase 3 Open-Set:** $\rho = 0.7196$
- **Full Hybrid w/o Risk Engine:** $\rho = 0.7196$
- **Full Hybrid Engine (with Risk Engine):** $\rho = 0.2106$

### 2.2 Root Causes Identified
1. **Mismatched Target Semantics (Device State vs. Instantaneous Flow Ground Truth):**
   - The ablation benchmark defined ground-truth severity as a per-flow property: `benign: 0.0`, `unknown_attack: 60.0`, `known_attack: 85.0`.
   - When the risk engine was disabled, the benchmark fell back to `100.0 if is_flagged else 0.0`, an instantaneous binary step function that trivially correlates with flow attack status.
   - When the hierarchical risk engine was enabled, it updated a persistent, decaying **device-level** risk state. When an attack occurred, the device risk jumped to 35-70 points. Subsequent benign flows from that same device (with true flow severity = 0.0) arrived while the device risk slowly decayed ($T_{\text{half}} = 120$s). Comparing a decaying device security posture against instantaneous flow labels artificially penalized the stateful engine.
2. **State Leakage Across Benchmark Runs:**
   - In `training/evaluation/ablation_study.py`, the teardown logic checked `hasattr(engine.risk_engine, "device_profiles")` and `recent_alerts`. However, `HierarchicalRiskEngine` stores state in `self._device_records`! As a result, device risk was never reset between ablation configurations, poisoning subsequent configurations with stale historical risk.
3. **Additive Point Accumulation & Scale Disparity:**
   - In `backend/app/risk/risk_engine.py`, the risk increment added arbitrary points (`base_impact = 25.0` or `35.0`) scaled by `fused_signal`. Because benign traffic could occasionally trigger high calibrated anomaly percentiles or novel graph edges, device risk could drift upward without an upper bound other than `min(100.0, ...)`.
4. **Missing Signal Imputation Fallacy:**
   - When temporal or graph detectors were absent or failed, `risk_engine.py` defaulted: `temporal_risk = flow_risk` and `graph_risk = flow_risk`. This effectively duplicated the weight of flow risk to $0.35 + 0.25 + 0.15 = 0.75$, masking missing modality uncertainty rather than recalculating normalized evidence weights.

---

## 3. Inference Bottlenecks & Benchmark Flaws

### 3.1 Benchmark Latency Anomalies
Phase 4 reported:
- **V1 Baseline:** 234.1 ms
- **Full Hybrid Engine:** 229.9 ms
- **Without Risk Engine:** 334.6 ms
- **Without Graph:** 279.5 ms

These numbers contradict physical reality: adding PyTorch LSTM inference, graph edge updates, and TreeSHAP calculations cannot reduce execution time below a single Scikit-Learn tree traversal.

### 3.2 Root Causes Identified
1. **Benchmark Measurement Contamination:**
   - `run_single_ablation` measured `t_elapsed = (time.perf_counter() - t_start) * 1000.0` over individual flows in a sequence of 350 flows. However, the first configuration tested suffered from Python JIT/PyTorch warm-up, module import latencies, and initial database initialization penalties.
2. **Global Feature Extraction vs Component Profiling:**
   - Feature extraction (`build_feature_vector`) was timed together with model inference rather than separately isolating:
     - Rolling device state feature extraction (`~0.05 ms`)
     - Model inference (V1 Scikit-Learn RF / PyTorch LSTM / Graph tracker)
     - TreeSHAP attribution (`_shap_explain`)
     - SQLite synchronous write operations
3. **No Percentile Latency Distribution:**
   - Prior benchmarks only reported arithmetic mean latency, hiding tail latencies (p95, p99) driven by garbage collection, SQLite disk lock contention, and cache misses.

---

## 4. Missing Real-World Network Validation

### 4.1 Limitations of Existing Zeek Integration
1. **Rigid Positional Parsing in `simulator/zeek_adapter.py`:**
   - The adapter uses hardcoded column offsets (`dict(zip(CONN_LOG_FIELDS, parts))`). In standard Zeek deployments, `conn.log` column ordering varies based on Zeek scripts and site-specific policy configurations. Headers (`#fields`) must be dynamically parsed.
2. **Missing Ingest Reconnection & Offline PCAP Replay:**
   - `tail_file()` runs `f.seek(0, 2)` (seeking to EOF). This prevents replaying historical captures or processing pre-recorded PCAPs/logs.
   - Lacks deduplication tracking: if Zeek restarts or rotates logs, duplicate records could flood `/api/ingest`.
3. **Absence of Real Packet & Log Replay Testing:**
   - Prior phases tested solely on synthetic traffic generators (`synthetic_traffic.py`) and tabular CSV fixtures. No end-to-end replay of actual PCAP/Zeek network captures has been validated in the test suite.

---

## 5. Multi-Family Unknown Attack Detection Gaps

1. **Single Held-Out Class Evaluation:**
   - Phase 3 evaluated unknown attack detection exclusively by holding out `brute_force` flows.
   - An intrusion detection engine cannot be deemed "open-set verified" based on a single attack category.
2. **OOD Generalization Across Families:**
   - Must evaluate leave-one-family-out (LOFO) experiments across all primary IoT attack families:
     - `port_scan` (reconnaissance)
     - `ddos` (volumetric denial of service)
     - `mirai_beacon` (C2 communication / botnet staging)
     - `brute_force` (credential abuse)
3. **Cross-Dataset Validation:**
   - The open-set boundary must be tested on cross-dataset transfers (e.g. training on IoT-23 and testing on TON_IoT or CICIoT2023) to measure domain shift resilience.

---

## 6. Operational Intelligence & Alert Fatigue

1. **Alert Flooding in Fast Bursts:**
   - Although `should_suppress_alert` suppresses identical `(device_id, attack_type)` within 5 seconds, it does not aggregate alerts into cohesive **Security Incidents**.
   - A distributed scan produces hundreds of individual alerts in `storage.py`, overwhelming SOC operators.
2. **Lack of Incident Lifecycle:**
   - Alerts currently have no lifecycle states (`OPEN`, `ACKNOWLEDGED`, `RESOLVED`, `FALSE_POSITIVE`).
   - Operators cannot track mitigation progress or annotate true positive vs benign noise.

---

## 7. Security Hardening & Deployment Vulnerabilities

1. **Unclosed SQLite Database Connections (Test Warning):**
   - In `backend/app/storage.py`, `with get_conn() as conn:` manages transactions but does not close the underlying connection, causing `ResourceWarning: unclosed database` and intermittent Windows file-locking failures.
2. **Missing Ingestion Authentication & Rate Limiting:**
   - `/api/ingest` accepts unbounded HTTP POST requests with no API key or sensor authorization. A rogue device on the LAN could forge telemetry or cause denial of service.
3. **WebSocket Vulnerability:**
   - `/ws/alerts` is unauthenticated and accepts arbitrary connections without origin verification or rate limiting.
4. **CORS Defaulting to Wildcard in Development:**
   - Need clear production `.env` configuration separating local development from hardened network deployment.

---

## 8. Audit Remediation Action Plan

| Priority | Component | Action Item | Target Artifacts |
|:---|:---|:---|:---|
| **P0** | **Component A: Risk Engine** | Disentangle flow risk from device posture; calibrate multi-signal weights on validation split; implement probabilistic OR / calibrated max aggregation; verify Spearman $\rho > \text{baseline}$. | `docs/RISK_ENGINE_AUDIT.md`, `docs/RISK_ENGINE_VALIDATION.md`, `backend/app/risk/` |
| **P1** | **Component B: Benchmarking** | Isolate each pipeline stage; warm up execution; record p50, p90, p95, p99, throughput, and memory. | `training/benchmarking/`, `docs/PERFORMANCE_BENCHMARKS.md` |
| **P2** | **Component C: Zeek Integration** | Implement dynamic `#fields` header parser, offline replay, deduplication cache, and PCAP conversion. | `simulator/zeek_adapter.py`, `docs/REAL_NETWORK_VALIDATION.md` |
| **P3** | **Component D: Multi-Family OOD** | Perform leave-one-family-out (LOFO) evaluation across 4 attack categories + cross-dataset transfer. | `docs/MULTI_FAMILY_UNKNOWN_VALIDATION.md` |
| **P4** | **Component E & F: Temporal & Graph** | Measure operational early-warning lead time and lateral movement detection metrics. | `docs/TEMPORAL_VALIDATION.md`, `docs/GRAPH_VALIDATION.md` |
| **P5** | **Component G: Alert Quality** | Implement incident grouping, lifecycle states (`ACKNOWLEDGED`), and alert rate metrics. | `backend/app/storage.py`, `docs/ALERT_QUALITY.md` |
| **P6** | **Component H & I: Hardening & Deploy** | Fix SQLite connection leaks, add sensor API key auth, rate limiting, and startup health diagnostics. | `backend/app/`, `docs/SECURITY_HARDENING.md`, `docs/INSTALLATION.md` |
