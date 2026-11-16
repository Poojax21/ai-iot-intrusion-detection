# Aegis-IoT: Technical Architecture & Algorithm Reference (Light / White Theme)

This document provides formal, publication-ready visual representations for both the **Detection Algorithm Flow** and the **System Architecture** of Aegis-IoT styled in a clean, high-contrast white / light theme.

---

## 1. Algorithm Flowchart: Two-Stage Detection & Explainability Pipeline

```mermaid
flowchart TD
    %% White / Light Theme Styling
    classDef inputStyle fill:#ffffff,stroke:#0284c7,stroke-width:2px,color:#0f172a;
    classDef featureStyle fill:#f0f9ff,stroke:#0284c7,stroke-width:2px,color:#0f172a;
    classDef stage1Style fill:#faf5ff,stroke:#7e22ce,stroke-width:2px,color:#1e1b4b;
    classDef stage2Style fill:#fdf2f8,stroke:#be185d,stroke-width:2px,color:#311042;
    classDef explainStyle fill:#f0fdf4,stroke:#15803d,stroke-width:2px,color:#064e3b;
    classDef triageStyle fill:#fff7ed,stroke:#c2410c,stroke-width:2px,color:#431407;
    classDef passStyle fill:#ecfdf5,stroke:#059669,stroke-width:2px,color:#064e3b;

    %% Ingestion & Feature Engineering
    subgraph INGESTION["1. Ingestion & Leakage-Safe Feature Construction"]
        FLOW["Inbound Network Flow Record<br/>(Duration, Bytes, Packets, TCP Flags, Protocol)"]:::inputStyle
        NORM["Protocol & State Normalizer<br/>(Map to Canonical Schema)"]:::featureStyle
        DROP["Identity Leakage Prevention<br/>(Omit raw IP / MAC addresses from ML feature vector)"]:::featureStyle
        CALC["Behavioral Feature Extraction<br/>(Packet Rate, Byte Entropy, Port Fanout, Flow Duration)"]:::featureStyle
        BASE["Per-Device Rolling State Update<br/>(Update μ, σ, and calculate dynamic Z-score)"]:::featureStyle
    end

    FLOW --> NORM --> DROP --> CALC --> BASE

    %% Stage 1: Filtering Funnel
    subgraph STAGE1["2. Stage 1: High-Speed Screening & Outlier Discovery"]
        GATE["FPR-Calibrated Binary Gate<br/>(Tuned to strict &lt; 1% False Positive Ceiling)"]:::stage1Style
        EVT["Unsupervised Anomaly Detector<br/>(Extreme Value Theory & Centroid Distance)"]:::stage1Style
        DEC1{"Is Flow Suspicious<br/>or Out-of-Distribution?"}:::stage1Style
        PASS["Update Benign Baseline<br/>(Safe Traffic Passed • Zero SOC Noise)"]:::passStyle
    end

    BASE --> GATE
    BASE --> EVT
    GATE --> DEC1
    EVT --> DEC1
    DEC1 -- "No (Score &lt; Threshold)" --> PASS

    %% Stage 2: Heavy Ensemble
    subgraph STAGE2["3. Stage 2: Multimodal Ensemble Classification"]
        DEC1 -- "Yes (Score &gt;= Threshold)" --> FORK["Flagged Traffic Dispatcher"]:::stage2Style
        MULTI["Supervised Multiclass GBM<br/>(161 MB Model: DDoS, Port Scan, Brute Force, Mirai)"]:::stage2Style
        GRAPH["Graph Intelligence Module<br/>(Topological Fanout & Lateral Movement Detection)"]:::stage2Style
        TEMP["Temporal Sequence Tracker<br/>(Causal Sliding Window & Periodic Beaconing)"]:::stage2Style
        FUSION["Hierarchical Hybrid Fusion Head<br/>(Calibrated Probability Matrix + Threat Taxonomy)"]:::stage2Style
    end

    FORK --> MULTI --> FUSION
    FORK --> GRAPH --> FUSION
    FORK --> TEMP --> FUSION

    %% Stage 3: Attribution & Risk
    subgraph STAGE3["4. Explainability & Triage Engine"]
        SHAP["TreeSHAP Attribution Engine<br/>(Compute Exact Local Additive Shapley Values)"]:::explainStyle
        GRACE{"Device Grace Period<br/>Active (&lt; 10 flows)?"}:::triageStyle
        SUPPRESS["Suppress Cold-Start Noise<br/>(Prevent False Alarms on New IoT Nodes)"]:::passStyle
        RISK["Hierarchical Risk Scorer<br/>(Severity Weighting + Deduplication + Exponential Decay)"]:::triageStyle
    end

    FUSION --> SHAP --> GRACE
    GRACE -- "Yes" --> SUPPRESS
    GRACE -- "No" --> RISK

    %% Stage 4: SOC Output
    subgraph OUTPUT["5. Incident Response & SOC Operations"]
        ALERT["Generate Security Alert<br/>(MITRE ATT&CK Tagging + SHAP Feature Breakdown)"]:::triageStyle
        TOPO["Live Dynamic Topology Update<br/>(Mark Target Node Red • Pulse Attack Conduit)"]:::triageStyle
        SOAR["Automated SOAR Action<br/>(High-Confidence Quarantine • Switch ACL Hook)"]:::triageStyle
    end

    RISK --> ALERT
    RISK --> TOPO
    RISK --> SOAR
```

---

## 2. System Architecture Diagram: End-to-End Enterprise Deployment

```mermaid
flowchart TB
    %% White / Light Theme Styling
    classDef edgeStyle fill:#ffffff,stroke:#0284c7,stroke-width:2px,color:#0f172a;
    classDef ingestStyle fill:#f0fdf4,stroke:#16a34a,stroke-width:2px,color:#064e3b;
    classDef coreStyle fill:#faf5ff,stroke:#9333ea,stroke-width:2px,color:#3b0764;
    classDef dataStyle fill:#eff6ff,stroke:#2563eb,stroke-width:2px,color:#1e3a8a;
    classDef uiStyle fill:#fff7ed,stroke:#ea580c,stroke-width:2px,color:#7c2d12;

    %% Edge Layer
    subgraph EDGE["Physical Edge & Network Tap Layer"]
        subgraph IOT_FLEET["Monitored IoT Fleet"]
            CAM["IP Cameras"]:::edgeStyle
            THERM["Smart Thermostats"]:::edgeStyle
            PLUG["Smart Plugs"]:::edgeStyle
            SENS["Environmental Sensors"]:::edgeStyle
            GW["Subnet Gateways"]:::edgeStyle
        end
        SWITCH["Managed Network Switch<br/>(Port Mirroring / SPAN / TAP)"]:::edgeStyle
        PROBE["Edge Sensor Probe<br/>(Raspberry Pi 4 / Linux VM with Zeek Engine)"]:::edgeStyle
        BUFFER[("Local Edge Ring Buffer<br/>(Backpressure & Outage Safe)")]:::edgeStyle
    end

    CAM & THERM & PLUG & SENS & GW --> SWITCH
    SWITCH -->|Mirrored Raw Traffic| PROBE
    PROBE -->|conn.log / dns.log| BUFFER

    %% Ingestion Layer
    subgraph INGEST["Ingestion & Integration Layer"]
        BRIDGE["Zeek Adapter Bridge<br/>(zeek_adapter.py)"]:::ingestStyle
        ARP["ARP / DHCP Resolution Table<br/>(Maps Ephemeral IPs to Stable Hardware IDs)"]:::ingestStyle
        SIM["Traffic & Attack Simulation Lab<br/>(Target Device & Vector Injection)"]:::ingestStyle
        API_GATEWAY["FastAPI REST & Ingestion Gateway<br/>(Rate Limiting • JWT Auth • Multi-Tenant RBAC)"]:::ingestStyle
    end

    BUFFER --> BRIDGE
    ARP --> BRIDGE
    BRIDGE -->|POST /api/ingest| API_GATEWAY
    SIM -->|Simulated Flows| API_GATEWAY

    %% Core Detection Engine
    subgraph ENGINE["Aegis-IoT Analytical Core"]
        ORCH["Hybrid Orchestrator Service"]:::coreStyle
        
        subgraph MODELS["Model & Intelligence Layer"]
            M_GATE["Stage 1: Binary Gate Model<br/>(gate_model_real.pkl)"]:::coreStyle
            M_EVT["Stage 1: EVT Anomaly Model<br/>(anomaly_model_real.pkl)"]:::coreStyle
            M_MULTI["Stage 2: Multiclass Model<br/>(multiclass_model_real.pkl • 161 MB)"]:::coreStyle
            M_GRAPH["Graph Intelligence Engine<br/>(Topological Adjacency Matrix)"]:::coreStyle
            M_TEMP["Temporal Sequence Tracker<br/>(Causal Sequence Buffers)"]:::coreStyle
        end

        SHAP_SRV["TreeSHAP Explainability Service"]:::coreStyle
        RISK_SRV["Hierarchical Risk & Incident Manager"]:::coreStyle
    end

    API_GATEWAY --> ORCH
    ORCH --> M_GATE & M_EVT
    M_GATE & M_EVT --> M_MULTI & M_GRAPH & M_TEMP
    M_MULTI & M_GRAPH & M_TEMP --> SHAP_SRV --> RISK_SRV

    %% Storage Layer
    subgraph STORAGE["Persistence & Telemetry Store"]
        DB[("Relational & Time-Series DB<br/>(SQLite / PostgreSQL / TimescaleDB)")]:::dataStyle
        AUDIT[("Audit & Security Logs")]:::dataStyle
    end

    RISK_SRV --> DB & AUDIT

    %% Presentation Layer
    subgraph PRESENTATION["SOC Operations Center (Vue.js + D3.js)"]
        TOPOLOGY["D3 Force-Directed Radial Topology<br/>(Gateway Centered • Collision Physics • Tooltips)"]:::uiStyle
        VECTORS["Threat Vector Analysis Grid<br/>(DDoS, Scan, Brute Force, Mirai, Zero-Day)"]:::uiStyle
        SIM_UI["Attack Simulation Lab Console<br/>(Select Target Device, Vector & Safe Traffic)"]:::uiStyle
        INCIDENTS["Incident & Alert Triage Queue<br/>(MITRE Tags • TreeSHAP Pills • SOAR Quarantine)"]:::uiStyle
    end

    DB -->|WebSocket /ws/alerts & REST| TOPOLOGY & VECTORS & INCIDENTS
    SIM_UI -->|Trigger Simulation Run| SIM
```
