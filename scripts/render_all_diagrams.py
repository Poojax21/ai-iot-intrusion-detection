"""
Render all 4 diagrams from comprehensive_project_report.md to ultra-high-resolution PNGs.
Uses Playwright with device_scale_factor=3 for 300+ DPI razor-sharp print and document clarity.
"""

import time
from pathlib import Path
from playwright.sync_api import sync_playwright

PROJECT_ROOT = Path(__file__).resolve().parent.parent
IMG_DIR = PROJECT_ROOT / "docs" / "images"
IMG_DIR.mkdir(parents=True, exist_ok=True)

HTML_PAGE = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Aegis-IoT Report Diagrams</title>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
  <style>
    body {
      background-color: #ffffff;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      margin: 0;
      padding: 40px;
    }
    .diagram-card {
      background: #ffffff;
      padding: 30px;
      margin-bottom: 50px;
      border: 1.5px solid #cbd5e1;
      border-radius: 12px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
      display: inline-block;
      box-sizing: border-box;
    }
    .card-title {
      font-size: 20px;
      font-weight: 700;
      color: #1e3a8a;
      margin-bottom: 20px;
      font-family: 'Segoe UI', Calibri, sans-serif;
    }
    .mermaid {
      background: #ffffff;
    }
    .mermaid svg {
      max-width: none !important;
      height: auto !important;
    }
  </style>
</head>
<body>

  <!-- Figure 1: Threat Landscape & MITRE ATT&CK Matrix -->
  <div id="card-threat" class="diagram-card" style="min-width: 1300px;">
    <div class="card-title">Figure 1: MITRE ATT&CK for IoT Threat Landscape & Vector Mapping</div>
    <div class="mermaid" id="diag-threat">
flowchart LR
    classDef mainStyle fill:#1e3a8a,stroke:#172554,stroke-width:2.5px,color:#ffffff,font-weight:bold,font-size:16px;
    classDef nodeStyle fill:#f0f9ff,stroke:#0284c7,stroke-width:2px,color:#0f172a,font-size:15px;

    ATTACK["🛡️ IoT Network Infiltration<br/>(Targeted Edge Assets)"]:::mainStyle
    ATTACK --> RECON["🔍 Reconnaissance (T0846)<br/>Port Scans & Host Discovery"]:::nodeStyle
    ATTACK --> BRUTE["🔑 Credential Access (T0812)<br/>Brute Force Telnet / SSH / HTTP"]:::nodeStyle
    ATTACK --> VOL["💥 Denial of Service (T0814)<br/>TCP SYN, UDP Floods & Mirai Floods"]:::nodeStyle
    ATTACK --> C2["📡 Command & Control (T0885)<br/>Periodic Botnet C2 Heartbeats"]:::nodeStyle
    ATTACK --> LATERAL["🔀 Lateral Movement (T0886)<br/>Subnet Pivoting & Host Fanout"]:::nodeStyle
    ATTACK --> ZERO["☣️ Zero-Day Outlier (T0884)<br/>Novel Mimicry & Unseen Zero-Days"]:::nodeStyle
    </div>
  </div>

  <br/>

  <!-- Figure 2: Data Pipeline & 5 Datasets -->
  <div id="card-data" class="diagram-card" style="min-width: 1200px;">
    <div class="card-title">Figure 2: Unified 5-Dataset Ingestion & Leakage-Safe Feature Pipeline</div>
    <div class="mermaid" id="diag-data">
flowchart TD
    classDef dsStyle fill:#f8fafc,stroke:#475569,stroke-width:2px,color:#0f172a,font-size:14px;
    classDef normStyle fill:#eff6ff,stroke:#2563eb,stroke-width:2px,color:#1e3a8a,font-size:15px,font-weight:bold;
    classDef leakStyle fill:#fef2f2,stroke:#dc2626,stroke-width:2px,color:#7f1d1d,font-size:15px,font-weight:bold;
    classDef splitStyle fill:#f0fdf4,stroke:#16a34a,stroke-width:2px,color:#14532d,font-size:15px,font-weight:bold;

    subgraph DATASETS["Supported Public Benchmark Datasets (§8)"]
        D1["CICIoT2023 (UNB)<br/>105 IoT Devices • 33 Attack Classes • 46 Features"]:::dsStyle
        D2["IoT-23 (Stratosphere / CTU)<br/>Real Malware Traffic on Raspberry Pi • Zeek Logs"]:::dsStyle
        D3["TON_IoT (UNSW Canberra)<br/>Heterogeneous IIoT & Telemetry • Netflow CSV"]:::dsStyle
        D4["Bot-IoT (UNSW Canberra)<br/>High-Volume Botnet Floods & Keylogging"]:::dsStyle
        D5["N-BaIoT (UCI / Ben-Gurion)<br/>9 Commercial IoT Devices • 115 Behavioral Stats"]:::dsStyle
    end

    NORM["Canonical Feature Contract & Schema Normalizer<br/>(Standardize protocols, state flags, byte/pkt units)"]:::normStyle
    DATASETS --> NORM
    
    LEAK["Strict Identity & Time Leakage Prevention Protocol<br/>(Strip raw IPs & MACs • Compute rolling rates, entropy & fanout)"]:::leakStyle
    NORM --> LEAK
    
    CHRONO["Chronological Monotonic Partitioning<br/>(70% Train [t0, t1] ➔ 15% Val (t1, t2] ➔ 15% Test (t2, t3])"]:::splitStyle
    LEAK --> CHRONO
    </div>
  </div>

  <br/>

  <!-- Figure 3: Two-Stage Detection Funnel -->
  <div id="card-funnel" class="diagram-card" style="min-width: 1200px;">
    <div class="card-title">Figure 3: Aegis-IoT Two-Stage Detection Funnel & Explainability Flowchart</div>
    <div class="mermaid" id="diag-funnel">
flowchart TD
    classDef inputStyle fill:#ffffff,stroke:#0284c7,stroke-width:2.5px,color:#0f172a,font-size:14px;
    classDef featureStyle fill:#f0f9ff,stroke:#0284c7,stroke-width:2px,color:#0f172a,font-size:14px;
    classDef stage1Style fill:#faf5ff,stroke:#7e22ce,stroke-width:2px,color:#1e1b4b,font-size:14px;
    classDef stage2Style fill:#fdf2f8,stroke:#be185d,stroke-width:2px,color:#311042,font-size:14px;
    classDef explainStyle fill:#f0fdf4,stroke:#15803d,stroke-width:2px,color:#064e3b,font-size:14px;
    classDef triageStyle fill:#fff7ed,stroke:#c2410c,stroke-width:2px,color:#431407,font-size:14px;
    classDef passStyle fill:#ecfdf5,stroke:#059669,stroke-width:2px,color:#064e3b,font-size:14px;

    FLOW["Inbound Network Flow Vector<br/>(Dur, Bytes, Pkts, Flags, State, Protocol)"]:::inputStyle --> NORM["Schema Normalizer & Feature Contract"]:::featureStyle
    NORM --> AGG["Behavioral Aggregator & Rolling Z-Score Tracker"]:::featureStyle
    
    AGG --> GATE["Stage 1: Binary LightGBM Gate<br/>(Operational FPR &lt; 1% Ceiling)"]:::stage1Style
    AGG --> EVT["Stage 1: Unsupervised EVT Anomaly<br/>(Extreme Value Weibull Outlier Detector)"]:::stage1Style

    GATE --> CHECK{"Flow Flagged<br/>or Out-of-Distribution?"}:::stage1Style
    EVT --> CHECK

    CHECK -- "No (Benign Baseline)" --> PASS["Pass Safe Traffic (Zero SOC Noise)"]:::passStyle
    
    CHECK -- "Yes (Anomalous Flow)" --> ENS["Stage 2: Hybrid Multimodal Ensemble"]:::stage2Style
    
    ENS --> M1["Multiclass Real-Traffic Model (161.8 MB)"]:::stage2Style
    ENS --> M2["Graph Intelligence (Lateral Expansion)"]:::stage2Style
    ENS --> M3["Temporal Sequence Tracker (Causal Buffering)"]:::stage2Style

    M1 & M2 & M3 --> FUSION["Calibrated Probability Fusion Head"]:::stage2Style
    FUSION --> SHAP["TreeSHAP Attribution Engine (Local φi Values)"]:::explainStyle
    SHAP --> RISK["Hierarchical Risk Scorer & Grace Period"]:::triageStyle
    RISK --> SOC["SIEM Dashboard & SOAR Quarantine"]:::triageStyle
    </div>
  </div>

  <br/>

  <!-- Figure 4: System Architecture -->
  <div id="card-arch" class="diagram-card" style="min-width: 1200px;">
    <div class="card-title">Figure 4: Aegis-IoT End-to-End Enterprise Deployment Architecture</div>
    <div class="mermaid" id="diag-arch">
flowchart TB
    classDef edgeStyle fill:#ffffff,stroke:#0284c7,stroke-width:2px,color:#0f172a,font-size:14px;
    classDef ingestStyle fill:#f0fdf4,stroke:#16a34a,stroke-width:2px,color:#064e3b,font-size:14px;
    classDef coreStyle fill:#faf5ff,stroke:#9333ea,stroke-width:2px,color:#3b0764,font-size:14px;
    classDef dataStyle fill:#eff6ff,stroke:#2563eb,stroke-width:2px,color:#1e3a8a,font-size:14px;
    classDef uiStyle fill:#fff7ed,stroke:#ea580c,stroke-width:2px,color:#7c2d12,font-size:14px;

    subgraph EDGE["Physical Edge & Network Tap Layer"]
        subgraph FLEET["Monitored IoT Fleet"]
            CAM["IP Cameras"]:::edgeStyle
            THERM["Smart Thermostats"]:::edgeStyle
            PLUG["Smart Plugs"]:::edgeStyle
            SENS["Sensors & PLCs"]:::edgeStyle
        end
        SPAN["Managed Switch SPAN / TAP Mirror"]:::edgeStyle
        ZEEK["Zeek Sensor Probe + Local Edge Ring Buffer"]:::edgeStyle
    end

    CAM & THERM & PLUG & SENS --> SPAN --> ZEEK

    subgraph INGEST["Ingestion & Integration Layer"]
        BRIDGE["Zeek Adapter Bridge (zeek_adapter.py)"]:::ingestStyle
        SIM["Simulation Lab Engine (Attack Injection)"]:::ingestStyle
        GW["FastAPI Ingestion Gateway (JWT • RBAC • Multi-Tenant)"]:::ingestStyle
    end

    ZEEK -->|conn.log / dns.log| BRIDGE -->|POST /api/ingest| GW
    SIM -->|Synthetic Flows| GW

    subgraph CORE["Aegis-IoT Analytical Core"]
        ORCH["Hybrid Orchestrator Service"]:::coreStyle
        MODELS["Model Registry (Binary Gate • EVT • 161.8 MB Multiclass • Graph • Temporal)"]:::coreStyle
        SHAP["TreeSHAP Explainability Engine"]:::coreStyle
        RISK["Hierarchical Risk & Incident Engine"]:::coreStyle
    end

    GW --> ORCH --> MODELS --> SHAP --> RISK

    subgraph STORE["Persistence & Storage Layer"]
        DB[("SQLite / PostgreSQL TimeSeries Store")]:::dataStyle
        AUDIT[("Audit Logs & Model Artifacts")]:::dataStyle
    end

    RISK --> DB & AUDIT

    subgraph UI["SOC Operations Console (Vue.js + D3.js)"]
        TOPOLOGY["D3 Force-Directed Radial Topology (Gateway Anchor)"]:::uiStyle
        VECTORS["Threat Vector Matrix Grid (MITRE Tags)"]:::uiStyle
        EXPLAIN["AI Decision Explainability (Static Mode)"]:::uiStyle
        LAB_UI["Interactive Attack Simulation Console"]:::uiStyle
    end

    DB -->|WebSocket & REST API| TOPOLOGY & VECTORS & EXPLAIN & LAB_UI
    </div>
  </div>

  <script>
    mermaid.initialize({
      startOnLoad: true,
      theme: 'neutral',
      themeVariables: {
        fontSize: '15px',
        fontFamily: '-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif',
        primaryColor: '#ffffff',
        primaryBorderColor: '#0284c7',
        primaryTextColor: '#0f172a',
        lineColor: '#0284c7'
      },
      flowchart: {
        curve: 'linear',
        htmlLabels: true,
        nodeSpacing: 40,
        rankSpacing: 40
      }
    });
  </script>
</body>
</html>
"""

def render_all():
    html_file = IMG_DIR / "temp_render_all.html"
    html_file.write_text(HTML_PAGE, encoding="utf-8")
    
    file_url = f"file:///{html_file.as_posix()}"
    print(f"[INFO] Opening {file_url} in Playwright (Edge/Chromium, Scale Factor: 3)...")
    
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)
        context = browser.new_context(viewport={"width": 2600, "height": 3800}, device_scale_factor=3)
        page = context.new_page()
        page.goto(file_url)
        
        # Wait for all 4 SVGs to render
        page.wait_for_selector("#diag-threat svg", timeout=20000)
        page.wait_for_selector("#diag-data svg", timeout=20000)
        page.wait_for_selector("#diag-funnel svg", timeout=20000)
        page.wait_for_selector("#diag-arch svg", timeout=20000)
        time.sleep(2)
        
        targets = [
            ("#card-threat", IMG_DIR / "figure1_threat_taxonomy.png", "Figure 1 (Threat Taxonomy)"),
            ("#card-data", IMG_DIR / "figure2_data_pipeline.png", "Figure 2 (Data Pipeline)"),
            ("#card-funnel", IMG_DIR / "figure3_detection_funnel.png", "Figure 3 (Detection Funnel)"),
            ("#card-arch", IMG_DIR / "figure4_system_architecture.png", "Figure 4 (System Architecture)"),
        ]
        
        for selector, out_path, label in targets:
            el = page.query_selector(selector)
            if el:
                el.screenshot(path=str(out_path))
                print(f"[SUCCESS] Saved {label} to: {out_path}")
            else:
                print(f"[ERROR] Selector {selector} not found")
                
        browser.close()
        
    if html_file.exists():
        html_file.unlink()

if __name__ == "__main__":
    render_all()
