"""
Render Model-by-Model Execution Flowchart to Ultra-High-Resolution PNG.
Shows exactly how Random Forest, Isolation Forest, EVT, Multiclass GBM, Graph,
Temporal, and TreeSHAP execute in Aegis-IoT.
"""

import time
from pathlib import Path
from playwright.sync_api import sync_playwright

PROJECT_ROOT = Path(__file__).resolve().parent.parent
IMG_DIR = PROJECT_ROOT / "docs" / "images"
IMG_DIR.mkdir(parents=True, exist_ok=True)

HTML_CONTENT = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Aegis-IoT Model-by-Model Execution Flow</title>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
  <style>
    body {
      background-color: #ffffff;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      margin: 0;
      padding: 30px;
    }
    .diagram-container {
      background: #ffffff;
      padding: 30px;
      border: 1.5px solid #cbd5e1;
      border-radius: 12px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
      display: inline-block;
      min-width: 1350px;
      box-sizing: border-box;
    }
    .title-box {
      margin-bottom: 25px;
      border-bottom: 2px solid #0284c7;
      padding-bottom: 12px;
    }
    .title-box h1 {
      margin: 0 0 6px 0;
      font-size: 22px;
      color: #1e3a8a;
      font-weight: 700;
    }
    .title-box p {
      margin: 0;
      font-size: 14px;
      color: #64748b;
    }
    .mermaid svg {
      max-width: none !important;
      height: auto !important;
    }
  </style>
</head>
<body>

  <div id="wrapper-models" class="diagram-container">
    <div class="title-box">
      <h1>Aegis-IoT: Model-by-Model Detailed Execution Pipeline</h1>
      <p>Step-by-step execution path for every machine learning model and analytical algorithm in Aegis-IoT</p>
    </div>
    <div class="mermaid" id="diagram-models">
flowchart TD
    %% Styling Classes
    classDef inputStyle fill:#ffffff,stroke:#0284c7,stroke-width:2.5px,color:#0f172a,font-size:14px;
    classDef prepStyle fill:#f0f9ff,stroke:#0284c7,stroke-width:2px,color:#0f172a,font-size:13px;
    classDef gateStyle fill:#eff6ff,stroke:#1d4ed8,stroke-width:2.5px,color:#1e3a8a,font-size:13px;
    classDef iforestStyle fill:#faf5ff,stroke:#7e22ce,stroke-width:2.5px,color:#3b0764,font-size:13px;
    classDef evtStyle fill:#fdf4ff,stroke:#c026d3,stroke-width:2.5px,color:#701a75,font-size:13px;
    classDef multiStyle fill:#fdf2f8,stroke:#be185d,stroke-width:2.5px,color:#831843,font-size:13px;
    classDef graphStyle fill:#fff7ed,stroke:#c2410c,stroke-width:2.5px,color:#7c2d12,font-size:13px;
    classDef tempStyle fill:#fefce8,stroke:#ca8a04,stroke-width:2.5px,color:#713f12,font-size:13px;
    classDef shapStyle fill:#f0fdf4,stroke:#15803d,stroke-width:2.5px,color:#14532d,font-size:13px;
    classDef passStyle fill:#ecfdf5,stroke:#059669,stroke-width:2.5px,color:#064e3b,font-size:13px,font-weight:bold;
    classDef alertStyle fill:#fef2f2,stroke:#dc2626,stroke-width:2.5px,color:#7f1d1d,font-size:13px,font-weight:bold;

    %% Raw Input
    INBOUND["1. Inbound Flow Packet<br/>(dur, orig_bytes, resp_bytes, proto, state, flags)"]:::inputStyle

    %% Preprocessing
    subgraph PREP["PREPROCESSING & ONLINE BASELINE TRACKING"]
        NORM["Canonical Contract Normalizer<br/>(Strip raw IP / MAC to prevent identity leakage)"]:::prepStyle
        EMA["DeviceState EMA Tracker<br/>(Update running μ and σ; compute Δz rolling score)"]:::prepStyle
        SCALER["StandardScaler Transformation<br/>(Standardize features: X_s = (X - μ) / σ)"]:::prepStyle
    end

    INBOUND --> NORM --> EMA --> SCALER

    %% Stage 1 Parallel Screening
    subgraph STAGE1["STAGE 1: HIGH-SPEED SCREENING (100% OF TRAFFIC • &lt; 0.5 ms)"]
        direction LR
        RF_GATE["MODEL 1: Random Forest Binary Gate<br/>(gate_model.pkl)<br/>• Traverses 100 Decision Trees<br/>• Predicts P(Attack)<br/>• Threshold τ = 0.30 (FPR &lt; 1%)"]:::gateStyle
        
        IFOREST["MODEL 2: Isolation Forest<br/>(anomaly_model.pkl)<br/>• Recursive random partition trees<br/>• Calculates path length h(x)<br/>• Flags isolated outliers: s(x) &gt; 0.5"]:::iforestStyle
        
        EVT["MODEL 3: Extreme Value Theory (EVT)<br/>(anomaly_calibrator.pkl + geometry.pkl)<br/>• Euclidean distance to benign centroids<br/>• Weibull tail extreme distribution<br/>• Tags Zero-Day Novelty (T0884)"]:::evtStyle
    end

    SCALER --> RF_GATE
    SCALER --> IFOREST
    SCALER --> EVT

    %% Decision Node 1
    DEC1{"Are any Stage 1 Models<br/>Triggered?"}:::inputStyle
    RF_GATE --> DEC1
    IFOREST --> DEC1
    EVT --> DEC1

    %% Safe Pass
    BENIGN_PASS["PASS AS SAFE TRAFFIC<br/>• Sub-millisecond pass-through<br/>• Updates clean baseline<br/>• Zero SOC alert fatigue"]:::passStyle
    DEC1 -- "No (All Below Threshold)" --> BENIGN_PASS

    %% Stage 2 Ensemble
    subgraph STAGE2["STAGE 2: MULTIMODAL FORENSIC ENSEMBLE (FLAGGED TRAFFIC ONLY • ~5-10%)"]
        direction TB
        RF_MULTI["MODEL 4: Multiclass Random Forest<br/>(multiclass_model.pkl)<br/>• Multi-tree majority vote<br/>• Outputs probability per attack family<br/>• Classifies DDoS, Port Scan, Brute Force, Mirai"]:::multiStyle
        
        GRAPH["MODEL 5: Graph Intelligence Detector<br/>(graph_detector.py)<br/>• Real-time bipartite communication graph<br/>• Evaluates out-degree surge (Δdeg_out &gt; 5)<br/>• Uncovers Lateral Movement (T0886)"]:::graphStyle
        
        TEMPORAL["MODEL 6: Temporal Sequence Tracker<br/>(temporal_detector.py)<br/>• Causal FIFO sliding buffer (depth 20)<br/>• Computes inter-arrival timing variance Var(Δt)<br/>• Identifies low-and-slow C2 Beacons (T0885)"]:::tempStyle
    end

    DEC1 -- "Yes (Flagged as Suspicious)" --> RF_MULTI
    DEC1 -- "Yes (Flagged as Suspicious)" --> GRAPH
    DEC1 -- "Yes (Flagged as Suspicious)" --> TEMPORAL

    %% Fusion
    FUSION["Calibrated Probability Fusion Head<br/>(Platt Temperature Scaling & Confidence Tiering)"]:::inputStyle
    RF_MULTI --> FUSION
    GRAPH --> FUSION
    TEMPORAL --> FUSION

    %% Stage 3: Explainability
    subgraph STAGE3["STAGE 3: LOCAL EXPLAINABILITY & TRIAGE"]
        SHAP["MODEL 7: TreeSHAP Attribution Engine<br/>(shap_explainer.py)<br/>• Evaluates tree feature split paths<br/>• Computes local Shapley values: f(x) = φ0 + Σ φi<br/>• Assigns mathematical reason per feature"]:::shapStyle
        
        GRACE{"Cold-Start Grace Check<br/>(flow_count &le; 10?)"}:::prepStyle
        
        RISK["Hierarchical Risk Engine<br/>(HierarchicalRiskEngine)<br/>• Deduplicates alerts in 30s window<br/>• Applies exponential decay: R_t = R_0 * e^(-λt)"]:::prepStyle
    end

    FUSION --> SHAP --> GRACE
    GRACE -- "Yes (New Device)" --> SUPPRESS["Suppress Alert (Prevent Startup Noise)"]:::passStyle
    GRACE -- "No" --> RISK

    %% Output
    SOC_ALERT["DISPATCH ACTIONABLE SOC ALERT<br/>• MITRE ATT&CK Tagged Alert<br/>• TreeSHAP Feature Breakdown Bar<br/>• D3.js Topology Red Node & Pulsing Conduit<br/>• Automated SOAR Switch ACL Quarantine"]:::alertStyle
    RISK --> SOC_ALERT
    </div>
  </div>

  <script>
    mermaid.initialize({
      startOnLoad: true,
      theme: 'neutral',
      themeVariables: {
        fontSize: '15px',
        fontFamily: '-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif',
        primaryColor: '#ffffff',
        primaryBorderColor: '#0284c7',
        primaryTextColor: '#0f172a',
        lineColor: '#0284c7'
      },
      flowchart: {
        curve: 'linear',
        htmlLabels: true,
        nodeSpacing: 45,
        rankSpacing: 45
      }
    });
  </script>
</body>
</html>
"""

def render_diagram():
    html_file = IMG_DIR / "temp_model_exec.html"
    html_file.write_text(HTML_CONTENT, encoding="utf-8")
    
    file_url = f"file:///{html_file.as_posix()}"
    print(f"[INFO] Opening {file_url} in Playwright (Edge/Chromium, Scale Factor: 3)...")
    
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)
        context = browser.new_context(viewport={"width": 2600, "height": 3800}, device_scale_factor=3)
        page = context.new_page()
        page.goto(file_url)
        
        page.wait_for_selector("#diagram-models svg", timeout=20000)
        time.sleep(2)
        
        el = page.query_selector("#wrapper-models")
        out_path = IMG_DIR / "model_execution_architecture.png"
        if el:
            el.screenshot(path=str(out_path))
            print(f"[SUCCESS] Saved Model Execution Architecture Diagram to: {out_path}")
        else:
            print("[ERROR] Selector #wrapper-models not found")
            
        browser.close()
        
    if html_file.exists():
        html_file.unlink()

if __name__ == "__main__":
    render_diagram()
