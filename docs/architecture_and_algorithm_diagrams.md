# Pahredaar-IoT: Technical Architecture & Algorithm Reference

This document provides formal visual representations for both the **Detection Algorithm Flow** and the **System Architecture** of Pahredaar-IoT.

---

## 1. Algorithm Flowchart: Two-Stage Detection & Explainability Pipeline

This diagram explains the mathematical and algorithmic progression of every network flow through the system: from raw packet ingestion and leakage-safe feature construction, through the two-stage detection funnel (with Extreme Value Theory for zero-day discovery), to TreeSHAP attribution and hierarchical alert triage.

```mermaid
flowchart TD
    %% Styling
    classDef inputStyle fill:#1e293b,stroke:#38bdf8,stroke-width:2px,color:#f8fafc;
    classDef featureStyle fill:#0f172a,stroke:#818cf8,stroke-width:2px,color:#f8fafc;
    classDef stage1Style fill:#1e1b4b,stroke:#a855f7,stroke-width:2px,color:#f8fafc;
    classDef stage2Style fill:#311042,stroke:#ec4899,stroke-width:2px,color:#f8fafc;
    classDef explainStyle fill:#064e3b,stroke:#34d399,stroke-width:2px,color:#f8fafc;
    classDef triageStyle fill:#451a03,stroke:#f97316,stroke-width:2px,color:#f8fafc;
    classDef passStyle fill:#064e3b,stroke:#10b981,stroke-width:2px,color:#f8fafc;

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

### Key Algorithmic Steps:
1. **Zero-Identity Leakage Extraction**: Network flows pass through a filter that strips raw IP and MAC identities. Only statistical rates, entropy, port fanouts, and rolling deviations enter the models.
2. **Two-Stage Funnel**: 
   - **Stage 1 (Binary Gate + EVT)** processes 100% of network traffic at high speed. It enforces an operational False Positive Rate ceiling of $<1\%$ while Extreme Value Theory (EVT) detects novel out-of-distribution behaviors (zero-days).
   - **Stage 2 (Heavy Ensemble)** only fires on flagged traffic ($\approx 5-10\%$ of total flows). It combines multiclass supervised predictions with graph topological lateral-movement tracking and temporal sequence analysis.
3. **Local Explainability (TreeSHAP)**: Every generated alert includes exact Shapley attributions, highlighting the exact feature spikes that caused the alert.
4. **Hierarchical Risk & Triage**: Alerts are filtered by a new-device grace period, deduplicated across time windows, and decayed exponentially to eliminate alert fatigue.

---

## 2. System Architecture Diagram: End-to-End Enterprise Deployment

This diagram shows how the system deploys across physical network hardware, the ingestion pipeline, the analytical engine, and the frontend SOC operations console.

```mermaid
flowchart TB
    %% Styling
    classDef edgeStyle fill:#0f172a,stroke:#38bdf8,stroke-width:2px,color:#f8fafc;
    classDef ingestStyle fill:#1e293b,stroke:#818cf8,stroke-width:2px,color:#f8fafc;
    classDef coreStyle fill:#1e1b4b,stroke:#a855f7,stroke-width:2px,color:#f8fafc;
    classDef dataStyle fill:#172554,stroke:#60a5fa,stroke-width:2px,color:#f8fafc;
    classDef uiStyle fill:#064e3b,stroke:#34d399,stroke-width:2px,color:#f8fafc;

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
    subgraph ENGINE["Pahredaar-IoT Analytical Core"]
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

### Architectural Highlights:
1. **Edge Tap Non-Invasiveness**: Passive monitoring via SPAN/TAP mirror ports ensures zero latency impact on IoT devices.
2. **Resilience & Local Buffering**: Edge sensor probes buffer packets locally to handle network disconnects or collector maintenance without flow loss.
3. **Decoupled Ingestion**: The REST ingestion contract accepts standard `FlowRecord` JSON from both live physical Zeek probes and the interactive Simulation Lab.
4. **Multi-Tenant Security**: Full JWT authentication, role-based access control (RBAC), and strict organization isolation at the database and WebSocket layers.
5. **Real-Time Interactive SOC Interface**: D3.js force-directed topology visualizer with real-time WebSocket feeds and automated SOAR response hooks.
