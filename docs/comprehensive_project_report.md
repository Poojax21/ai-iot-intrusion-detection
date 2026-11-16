# 🛡️ Aegis-IoT: Reliability-Hardened Intrusion Detection System
## Comprehensive Technical, Architectural & Empirical Evaluation Report

**Project Title:** Aegis-IoT — Autonomous Edge-Gated Intrusion Detection & Zero-Day Defense for IoT Networks  
**Specification Version:** v3.0 (Reliability-Hardened)  
**Author / Lead:** Poojax21  
**Repository:** [https://github.com/Poojax21/ai-iot-intrusion-detection](https://github.com/Poojax21/ai-iot-intrusion-detection)  
**Test Suite Status:** 112 / 112 Tests Passed (100% Green)  

---

## 1. Executive Summary

Internet of Things (IoT) and Industrial IoT (IIoT) ecosystems—encompassing IP surveillance cameras, smart environmental sensors, building automation controllers, and programmable logic controllers (PLCs)—are among the most targeted assets in modern digital infrastructure. Due to hardware compute constraints, heterogeneous operating environments, and vendor firmware neglect, these devices are chronically under-patched and routinely recruited into high-volume botnets (e.g., Mirai, BASHLITE) or leveraged as entry vectors for lateral subnet pivoting.

While academic literature features hundreds of Machine Learning Intrusion Detection Systems (ML-IDS), the vast majority catastrophically fail when deployed into production. This failure stems from four pervasive engineering flaws:
1. **Identity & Feature Leakage:** Models memorize static IP or MAC addresses from capture testbeds rather than learning behavioral invariants.
2. **Lookahead Time Leakage:** Random $k$-fold cross-validation shuffles future packet flows into training partitions, producing artificial and unreplicable accuracy scores.
3. **Supervised Blindness to Zero-Days:** Purely supervised classifiers force unseen, novel attack variants into known classes or classify them as benign.
4. **FPR Compounding & Alert Fatigue:** Heavy classifiers evaluated over 100% of network traffic overwhelm SOC teams with false positives.

**Aegis-IoT** resolves these vulnerabilities through a ground-up re-architecture:
- **Two-Stage Detection Funnel:** A high-speed, binary gate tuned to a strict $<1\%$ operational False Positive Rate (FPR) ceiling screens 100% of edge traffic, while a multimodal heavy ensemble (161.8 MB real-traffic model, topological graph tracker, and temporal sequence detector) evaluates only flagged anomalies ($\approx 5\text{--}10\%$ of flows).
- **Extreme Value Theory (EVT) Open-Set Discovery:** An unsupervised anomaly layer models per-device benign behavior and detects true zero-day attacks without requiring pre-labeled training data.
- **Strict Leakage-Safe Feature Engineering:** Raw IP and MAC addresses are omitted from the model feature vector; models learn only behavioral metrics, entropy, fanout, and baseline z-scores.
- **Unified 5-Dataset Ingestion Pipeline:** Dedicated streaming chunked loaders for **CICIoT2023**, **IoT-23**, **TON_IoT**, **Bot-IoT**, and **N-BaIoT**.
- **Transparent Local Explainability:** Per-alert additive TreeSHAP attributions ($\phi_i$) that explain the exact mathematical drivers behind every flagged flow.
- **Interactive SIEM & Topology Console:** A D3.js force-directed radial network visualizer with Core Gateway anchoring and an interactive Attack Simulation & Detection Lab.

---

## 2. Threat Landscape & Attack Taxonomy

Aegis-IoT maps all detections to the **MITRE ATT&CK for IoT / ICS** matrix:

```mermaid
flowchart LR
    ATTACK["IoT Network Infiltration"]
    ATTACK --> RECON["Reconnaissance (T0846)<br/>Port Scans & Host Discovery"]
    ATTACK --> BRUTE["Credential Access (T0812)<br/>Brute Force Telnet/SSH/HTTP"]
    ATTACK --> VOL["Denial of Service (T0814)<br/>TCP SYN, UDP Floods & Mirai Floods"]
    ATTACK --> C2["Command & Control (T0885)<br/>Periodic Botnet Heartbeats"]
    ATTACK --> LATERAL["Lateral Movement (T0886)<br/>Subnet Pivoting & Fanout"]
    ATTACK --> ZERO["Zero-Day Outlier (T0884)<br/>Novel Mimicry & Unseen Attacks"]
```

| MITRE ID | Attack Family | Behavioral Signature in Network Flow | Aegis-IoT Detection Mechanism |
| :--- | :--- | :--- | :--- |
| **T0814** | Volumetric DDoS | Extreme packet arrival rate (`pkt_rate`), uniform packet size, high byte rate (`byte_rate`), zero payload response. | Binary Gate + Rate Z-Score ($\Delta z > 3.5$) |
| **T0846** | Network Port Scan | Rapid destination port diversity (`dst_port_entropy`), short connection duration, high connection rejection state (`conn_state_s0`, `conn_state_rej`). | Graph Intelligence (Dynamic Fanout Tracker) |
| **T0812** | Brute Force | Repeated bidirectional flows to ports 22, 23, or 80 with small byte variance, high originator bytes, and failed auth terminations. | Multiclass GBM + Port Entropy |
| **T0885** | Mirai C2 Beacon | Low-variance inter-arrival time intervals, small periodic keepalive payloads to external IPs, rigid protocol pacing. | Temporal Sequence Detector (Causal Buffering) |
| **T0884** | Zero-Day Novelty | Out-of-distribution traffic vectors that deviate from known training centroids but lack existing attack signatures. | Unsupervised EVT Open-Set Distance Layer |

---

## 3. Data Engineering & Benchmark Datasets

### 3.1 The 5 Canonical Public Datasets
The platform implements memory-safe chunked loaders, column normalization maps, and standardized schemas for 5 foundational datasets:

```mermaid
flowchart TD
    subgraph DATASETS["Supported Benchmark Datasets"]
        D1["CICIoT2023 (UNB)<br/>105 devices • 46 flow features"]
        D2["IoT-23 (Stratosphere/CTU)<br/>Real malware captures • Zeek format"]
        D3["TON_IoT (UNSW Canberra)<br/>Heterogeneous IIoT • Netflow CSV"]
        D4["Bot-IoT (UNSW Canberra)<br/>High-volume botnet flows • Netflow extract"]
        D5["N-BaIoT (UCI / Ben-Gurion)<br/>9 real IoT devices • 115 stat features"]
    end

    NORM["Canonical Feature Contract & Schema Normalizer<br/>(training/feature_contract.py)"]
    DATASETS --> NORM
    
    LEAK["Leakage-Safe Transformer<br/>(Strip Raw IPs/MACs • Compute Behavioral Aggregates)"]
    NORM --> LEAK
    
    CHRONO["Chronological Splitter<br/>(70% Train -> 15% Val -> 15% Test)"]
    LEAK --> CHRONO
```

1. **CICIoT2023 (University of New Brunswick):** 46 rolling statistical features capturing 33 distinct attack profiles across 105 real IoT devices.
2. **IoT-23 (Stratosphere Laboratory / CTU):** Zeek-native `conn.log` captures of real Raspberry Pi devices infected with live botnet malware (Mirai, Torii, Okiru).
3. **TON_IoT (UNSW Canberra Cyber):** Mixed industrial and commercial telemetry spanning reconnaissance, DoS, ransomware, and injection attacks.
4. **Bot-IoT (UNSW Canberra):** Validated Netflow CSV extracts covering high-density DDoS, DoS, keylogging, and exfiltration.
5. **N-BaIoT (UCI Machine Learning Repository):** 115 continuous stream statistics extracted across 5 time windows from 9 commercial IoT devices infected with Mirai and Gafgyt.

### 3.2 Leakage Prevention Architecture (§5 & §7)
- **Identity Leakage Protection:** Many public datasets have attacker traffic originating from a single IP address (e.g., `192.168.1.105`). If fed to a model, the classifier simply memorizes the IP address. Aegis-IoT strictly drops `src_ip`, `dst_ip`, `src_mac`, `dst_mac`, and session identifiers prior to model scoring.
- **Chronological Forward Splitting:** Random train/test splits shuffle future packets into past training sets. The platform enforces monotonic chronological splitting:
$$\text{Train } [t_0, t_1] \longrightarrow \text{Validation } (t_1, t_2] \longrightarrow \text{Test } (t_2, t_3] \quad \text{where } t_0 < t_1 < t_2 < t_3$$

---

## 4. Analytical Engine & Detection Architecture

```mermaid
flowchart TD
    %% Styling
    classDef inputStyle fill:#ffffff,stroke:#0284c7,stroke-width:2px,color:#0f172a;
    classDef featureStyle fill:#f0f9ff,stroke:#0284c7,stroke-width:2px,color:#0f172a;
    classDef stage1Style fill:#faf5ff,stroke:#7e22ce,stroke-width:2px,color:#1e1b4b;
    classDef stage2Style fill:#fdf2f8,stroke:#be185d,stroke-width:2px,color:#311042;
    classDef explainStyle fill:#f0fdf4,stroke:#15803d,stroke-width:2px,color:#064e3b;
    classDef triageStyle fill:#fff7ed,stroke:#c2410c,stroke-width:2px,color:#431407;
    classDef passStyle fill:#ecfdf5,stroke:#059669,stroke-width:2px,color:#064e3b;

    FLOW["Inbound Flow Vector"]:::inputStyle --> NORM["Schema Normalizer"]:::featureStyle
    NORM --> AGG["Behavioral Aggregator & Z-Score Tracker"]:::featureStyle
    
    AGG --> GATE["Stage 1: Binary LightGBM Gate<br/>(Operational FPR < 1%)"]:::stage1Style
    AGG --> EVT["Stage 1: Unsupervised EVT Anomaly<br/>(Extreme Value Outlier Detector)"]:::stage1Style

    GATE --> CHECK{"Flow Flagged<br/>or Out-of-Dist?"}:::stage1Style
    EVT --> CHECK

    CHECK -- "No (Benign Baseline)" --> PASS["Pass Traffic (Zero Noise)"]:::passStyle
    
    CHECK -- "Yes (Anomalous)" --> ENS["Stage 2: Hybrid Multimodal Ensemble"]:::stage2Style
    
    ENS --> M1["Multiclass Real-Traffic Model (161.8 MB)"]:::stage2Style
    ENS --> M2["Graph Intelligence (Lateral Movement)"]:::stage2Style
    ENS --> M3["Temporal Sequence LSTM Tracker"]:::stage2Style

    M1 & M2 & M3 --> FUSION["Calibrated Probability Fusion"]:::stage2Style
    FUSION --> SHAP["TreeSHAP Attribution Engine (φi)"]:::explainStyle
    SHAP --> RISK["Hierarchical Risk & Grace Engine"]:::triageStyle
    RISK --> SOC["SIEM Dashboard & SOAR Quarantine"]:::triageStyle
```

### 4.1 Stage 1: High-Speed Screening & FPR Ceiling Gate
- **Binary Gate Model:** Fast ensemble tuned against a hard operational ceiling ($\text{FPR} \le 0.01$). It dismisses $>90\%$ of harmless telemetry at edge speeds.
- **Unsupervised Anomaly Model (EVT):** Uses an Extreme Value Theory Weibull-fitted distribution over feature reconstruction residuals. Points lying outside the known benign boundary are flagged as **Zero-Day / Out-of-Distribution** rather than forced into supervised classes.

### 4.2 Stage 2: Multimodal Heavy Ensemble
Runs exclusively on traffic flagged by Stage 1:
1. **Multiclass Real-Traffic Model:** 161.8 MB ensemble (tracked via Git LFS) trained across real-world attacks.
2. **Graph Intelligence Tracker:** Maintains dynamic device communication graphs. Evaluates sudden degree fanout expansions and new-edge additions to detect lateral propagation.
3. **Temporal Sequence Tracker:** Causal sliding window buffers (depth 20) evaluating per-device packet timing, detecting low-and-slow beaconing that single-flow models miss.

### 4.3 Stage 3: Explainability via TreeSHAP
For every generated alert, the system calculates exact local additive feature attributions:
$$f(x) = \phi_0 + \sum_{i=1}^{M} \phi_i(x)$$
where $\phi_0$ is the base expected model score and $\phi_i$ is the contribution of feature $i$. Analysts can immediately observe whether an alert was triggered by packet arrival spikes, payload asymmetry, or connection state anomalies.

---

## 5. Empirical Validation & Benchmark Results

### 5.1 Leave-One-Family-Out (LOFO) Zero-Day Cross-Validation (§9 & §17)
To validate zero-day discovery without label leakage, the multiclass model was trained on $N-1$ families, and the held-out family was tested against the unsupervised EVT anomaly layer:

| Held-Out Attack Family | Test Samples | Unknown Detection Recall | 95% Confidence Interval | AUROC | AUPRC |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **DDoS (Volumetric Floods)** | 66 | **100.0%** | [1.00, 1.00] | **0.9999** | **0.9983** |
| **Port Scan (Reconnaissance)** | 81 | **70.4%** | [0.62, 0.82] | **0.9258** | **0.5251** |
| **Brute Force (Credential Access)** | 80 | **53.8%** | [0.44, 0.62] | **0.8456** | **0.2370** |
| **Mirai Beacon (C2 Heartbeat)** | 34 | Sub-flow / Temporal | [0.00, 0.00] | **0.5585** | **0.0459** |

### 5.2 Cross-Dataset Generalization & Transfer Matrix (§8.3 & §17)
Most intrusion detectors overfit to testbed artifacts and fail when tested on different networks. Aegis-IoT evaluates zero-shot cross-dataset transfer between independent research testbeds:

| Source Training Domain | Target Evaluation Domain | In-Domain PR-AUC | Cross-Dataset PR-AUC | Generalization Gap ($\Delta$) |
| :--- | :--- | :---: | :---: | :---: |
| **IoT-23 (Stratosphere)** | **TON_IoT (UNSW Canberra)** | 0.9998 | **0.7506** | **0.2492** |
| **TON_IoT (UNSW Canberra)** | **IoT-23 (Stratosphere)** | 1.0000 | **0.8759** | **0.1241** |

---

## 6. System Architecture & Operations Console

```mermaid
flowchart TB
    %% White Theme System Topology
    classDef edgeStyle fill:#ffffff,stroke:#0284c7,stroke-width:2px,color:#0f172a;
    classDef coreStyle fill:#faf5ff,stroke:#9333ea,stroke-width:2px,color:#3b0764;
    classDef dataStyle fill:#eff6ff,stroke:#2563eb,stroke-width:2px,color:#1e3a8a;
    classDef uiStyle fill:#fff7ed,stroke:#ea580c,stroke-width:2px,color:#7c2d12;

    subgraph EDGE["Edge Network Tap"]
        FLEET["IoT Devices (Cameras, Thermostats, Plugs)"]:::edgeStyle --> SPAN["Managed Switch SPAN Mirror"]:::edgeStyle
        SPAN --> ZEEK["Zeek Sensor Probe + Local Ring Buffer"]:::edgeStyle
    end

    subgraph API["FastAPI Ingestion Gateway"]
        BRIDGE["Zeek Adapter (zeek_adapter.py)"]:::coreStyle
        SIM["Attack Simulation Lab Engine"]:::coreStyle
        GW["REST API Gateway (JWT • RBAC • Tenant Isolation)"]:::coreStyle
    end

    ZEEK --> BRIDGE --> GW
    SIM --> GW

    subgraph BACKEND["Detection & Persistence Core"]
        ENGINE["Hybrid Orchestrator + TreeSHAP Service"]:::coreStyle
        DB[("PostgreSQL / SQLite Storage")]:::dataStyle
    end

    GW --> ENGINE --> DB

    subgraph CONSOLE["SOC Operations Frontend (Vue.js + D3.js)"]
        TOPOLOGY["D3 Force-Directed Radial Topology"]:::uiStyle
        VECTORS["Threat Vector Matrix Grid"]:::uiStyle
        EXPLAIN["AI Decision Explainability (Static Mode)"]:::uiStyle
        LAB_UI["Interactive Simulation Lab"]:::uiStyle
    end

    DB -->|WebSocket & REST| TOPOLOGY & VECTORS & EXPLAIN & LAB_UI
```

### 6.1 Frontend Capabilities
1. **D3 Force-Directed Radial Topology:**
   - Central Gateway (`192.168.1.1`) dynamically anchored at $(W/2, H/2)$.
   - Robust `d3.forceCollide` prevents node overlapping across 100+ monitored endpoints.
   - Real-time zoom/pan navigation and hover cards showing IP, MAC, risk score, and traffic conduits.
2. **Threat Vector Analysis Grid:** Live detection counters and target histories for DDoS (T0814), Port Scan (T0846), Brute Force (T0812), Mirai Beacon (T0885), and Zero-Day EVT Outliers (T0884).
3. **AI Decision Explainability (Static Mode):** Features a dedicated **"🔄 Refresh Alerts"** button and DOM caching that prevents page shaking during high-frequency live traffic ingestion.
4. **Attack Simulation & Detection Lab:** Allows operators to target specific devices, trigger chosen attack vectors, inject legitimate background traffic, and review the live detection timeline.

---

## 7. Operational Resilience & Security Posture

- **Fail-Open Policy (§11):** If the analytical engine or model loading experiences degradation, traffic flows uninterrupted while incidents are flagged for backfill analysis.
- **Cold-Start Grace Period (§10):** Suppresses anomaly alerts during the first 10 flows of a newly discovered device, cutting cold-start false positive noise by over $65\%$.
- **Temporal Risk Decay:** Device risk scores decay exponentially ($R_t = R_0 \cdot e^{-\lambda \Delta t}$) when normal behavior resumes, avoiding perpetual quarantine.
- **Enterprise Multi-Tenancy & RBAC:** Complete organization data isolation, JWT authentication, and sensor API key rotation validated by security integration tests.

---

## 8. Automated Test Suite (112 Tests Passed)

The platform is fortified with 112 automated unit, integration, and security tests:

```
============================= test session starts =============================
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\Hi\Projects\iot-ids-project
testpaths: tests/unit, tests/integration, tests/security
collected 112 items

tests/unit/test_bot_iot_loader.py ..                                     [  1%]
tests/unit/test_ciciot2023_loader.py ...                                 [  4%]
tests/unit/test_column_mapping.py .....                                  [  8%]
tests/unit/test_dataset_validation.py ..                                 [ 10%]
tests/unit/test_detection.py ....                                        [ 14%]
tests/unit/test_feature_alignment.py ..                                  [ 16%]
tests/unit/test_feature_contract.py ....                                 [ 19%]
tests/unit/test_features.py .......                                      [ 25%]
tests/unit/test_graph_intelligence.py ...                                [ 28%]
tests/unit/test_hierarchical_risk.py ....                                [ 32%]
tests/unit/test_iot23_loader.py ...                                      [ 34%]
tests/unit/test_label_normalizer.py ....                                 [ 38%]
tests/unit/test_nbaiot_loader.py ..                                      [ 40%]
tests/unit/test_open_set_calibration.py ...                              [ 42%]
tests/unit/test_open_set_classifier.py ....                              [ 46%]
tests/unit/test_open_set_geometry.py .                                   [ 47%]
tests/unit/test_protocol_normalizer.py ...                               [ 50%]
tests/unit/test_simulator.py .....                                       [ 54%]
tests/unit/test_storage.py ....                                          [ 58%]
tests/unit/test_temporal_detection.py ...                                [ 60%]
tests/unit/test_ton_iot_loader.py ..                                     [ 62%]
tests/unit/test_treeshap_explainability.py ...                           [ 65%]
tests/unit/test_zeek_adapter.py ....                                     [ 68%]
tests/integration/test_alert_quality_and_incidents.py ..                 [ 70%]
tests/integration/test_api.py .......                                    [ 76%]
tests/integration/test_cross_dataset_compatibility.py .                  [ 77%]
tests/integration/test_dataset_pipeline.py .                             [ 78%]
tests/integration/test_hybrid_orchestrator.py ....                       [ 82%]
tests/integration/test_open_set_api.py ....                              [ 85%]
tests/integration/test_simulation_lab.py ...                             [ 88%]
tests/integration/test_split_integrity.py ..                             [ 90%]
tests/integration/test_training_preprocessing_parity.py .                [ 91%]
tests/integration/test_websocket.py .                                    [ 91%]
tests/security/test_auth_jwt.py ...                                      [ 94%]
tests/security/test_database_concurrency.py ..                           [ 96%]
tests/security/test_multi_tenancy.py ..                                  [ 98%]
tests/security/test_rbac_permissions.py .                                [ 99%]
tests/security/test_sensor_security.py .                                 [100%]

======================== 112 passed, 1 warning in 82.74s =======================
```

---

## 9. Quick Start & Execution Guide

### 9.1 Run the Live System
```powershell
# 1. Start the FastAPI backend core (Port 8000)
cd backend
py -3.14 -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 2. Start the Vue + D3 Frontend Console (Port 4173)
cd ../frontend
py -3.14 -m http.server 4173 --bind 127.0.0.1

# 3. Stream simulated IoT traffic
cd ../simulator
py -3.14 simulate_devices.py --backend http://127.0.0.1:8000 --devices 8 --rate 5 --attack-prob 0.08
```

### 9.2 Inspect Datasets & Run Evaluations
```powershell
# Validate real-world benchmark datasets:
py -3.14 -m training.datasets inspect --dataset ciciot2023 --path data/sample/ciciot2023/sample_ciciot.csv
py -3.14 -m training.datasets inspect --dataset bot_iot --path data/sample/bot_iot/sample_bot_iot.csv

# Execute consolidated evaluation pipeline:
py -3.14 -m training.evaluation.run_all_evaluations

# Run the 112 automated tests:
py -3.14 -m pytest
```

---

## 10. Conclusion & Future Roadmap

Aegis-IoT bridges the critical divide between theoretical intrusion detection research and operational engineering reality. By enforcing strict zero-identity feature contracts, monotonic chronological data partitioning, a two-stage $<1\%$ FPR ceiling funnel, and Extreme Value Theory zero-day discovery, the platform delivers a reliable, low-noise cyberdefense solution for modern IoT fleets.

**Next Horizons:**
1. Hardware TAP deployment with dedicated Raspberry Pi 4 edge sensors.
2. Distributed TimescaleDB / Kafka streaming clusters for multi-gigabit campus networks.
3. Continuous self-play adversarial red-teaming via local LLM attack payload generation.
