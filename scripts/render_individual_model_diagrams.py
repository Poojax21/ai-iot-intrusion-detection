"""
Render 8 individual, high-resolution diagrams for each model in Aegis-IoT.
Uses Playwright with device_scale_factor=3 for razor-sharp vector-grade quality.
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
  <title>Aegis-IoT Individual Model Diagrams</title>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
  <style>
    body {
      background-color: #ffffff;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      margin: 0;
      padding: 30px;
    }
    .diagram-card {
      background: #ffffff;
      padding: 24px;
      margin-bottom: 40px;
      border: 1.5px solid #cbd5e1;
      border-radius: 10px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
      display: inline-block;
      box-sizing: border-box;
      min-width: 1100px;
    }
    .card-header {
      font-size: 18px;
      font-weight: 700;
      color: #1e3a8a;
      margin-bottom: 16px;
      border-bottom: 1.5px solid #e2e8f0;
      padding-bottom: 8px;
    }
    .mermaid svg {
      max-width: none !important;
      height: auto !important;
    }
  </style>
</head>
<body>

  <!-- Model 1: Random Forest Binary Gate -->
  <div id="card-m1" class="diagram-card">
    <div class="card-header">Model 1: Random Forest Binary Gate (gate_model.pkl) — Execution Flow</div>
    <div class="mermaid" id="diag-m1">
flowchart TD
    classDef inStyle fill:#ffffff,stroke:#0284c7,stroke-width:2px,color:#0f172a,font-size:13px;
    classDef treeStyle fill:#eff6ff,stroke:#2563eb,stroke-width:2px,color:#1e3a8a,font-size:13px;
    classDef voteStyle fill:#faf5ff,stroke:#7e22ce,stroke-width:2px,color:#3b0764,font-size:13px;
    classDef passStyle fill:#ecfdf5,stroke:#059669,stroke-width:2px,color:#064e3b,font-size:13px,font-weight:bold;
    classDef flagStyle fill:#fef2f2,stroke:#dc2626,stroke-width:2px,color:#7f1d1d,font-size:13px,font-weight:bold;

    VEC["Standardized Feature Vector X_s<br/>(pkt_rate, byte_rate, port_entropy, duration, flags)"]:::inStyle

    subgraph ENSEMBLE["100 Independent Decision Trees (Parallel Evaluation)"]
        T1["Decision Tree #1<br/>• Split: pkt_rate &gt; 1520<br/>• Split: duration &lt; 0.02<br/>➔ Vote: Attack"]:::treeStyle
        T2["Decision Tree #2<br/>• Split: byte_rate &gt; 8500<br/>• Split: conn_state == S0<br/>➔ Vote: Attack"]:::treeStyle
        T3["Decision Tree #3<br/>• Split: port_entropy &gt; 2.4<br/>• Split: orig_bytes &gt; 400<br/>➔ Vote: Benign"]:::treeStyle
        T100["Decision Tree #100<br/>• Split: z_score &gt; 3.5<br/>• Split: resp_pkts == 0<br/>➔ Vote: Attack"]:::treeStyle
    end

    VEC --> T1 & T2 & T3 & T100

    AGG["Probability Aggregator<br/>P(Attack) = (1 / 100) * Σ I(t_k == Attack)<br/>Result: P(Attack) = 0.84"]:::voteStyle
    T1 & T2 & T3 & T100 --> AGG

    THRESH{"FPR-Calibrated Threshold<br/>Is P(Attack) &gt;= 0.30?<br/>(Operational FPR &lt; 1%)"}:::inStyle
    AGG --> THRESH

    THRESH -- "No: Score &lt; 0.30" --> PASS["CERTIFY BENIGN &amp; PASS<br/>• Pass immediately in 0.18 ms<br/>• Zero SOC alert fatigue"]:::passStyle
    THRESH -- "Yes: Score &gt;= 0.30" --> FLAG["FLAG ANOMALY &amp; DISPATCH<br/>• Escalate to Stage 2 Heavy Ensemble<br/>• Invoke Multiclass &amp; Explainability"]:::flagStyle
    </div>
  </div>

  <br/>

  <!-- Model 2: Isolation Forest Anomaly Detector -->
  <div id="card-m2" class="diagram-card">
    <div class="card-header">Model 2: Isolation Forest Anomaly Detector (anomaly_model.pkl) — Execution Flow</div>
    <div class="mermaid" id="diag-m2">
flowchart TD
    classDef inStyle fill:#ffffff,stroke:#0284c7,stroke-width:2px,color:#0f172a,font-size:13px;
    classDef splitStyle fill:#faf5ff,stroke:#9333ea,stroke-width:2px,color:#3b0764,font-size:13px;
    classDef scoreStyle fill:#fdf2f8,stroke:#be185d,stroke-width:2px,color:#831843,font-size:13px;
    classDef normStyle fill:#ecfdf5,stroke:#059669,stroke-width:2px,color:#064e3b,font-size:13px,font-weight:bold;
    classDef outStyle fill:#fef2f2,stroke:#dc2626,stroke-width:2px,color:#7f1d1d,font-size:13px,font-weight:bold;

    SAMPLE["Continuous Feature Vector X_s<br/>(Trained exclusively on Benign Baseline Telemetry)"]:::inStyle

    subgraph ITREES["Ensemble of 100 Random Isolation Trees (iTrees)"]
        direction LR
        IT1["iTree #1<br/>Random split on feature f_k<br/>Path Length: h_1(x)"]:::splitStyle
        IT2["iTree #2<br/>Random split on feature f_j<br/>Path Length: h_2(x)"]:::splitStyle
        IT3["iTree #100<br/>Random split on feature f_m<br/>Path Length: h_100(x)"]:::splitStyle
    end

    SAMPLE --> IT1 & IT2 & IT3

    CALC["Average Path Length Evaluator<br/>E(h(x)) = (1 / 100) * Σ h_k(x)<br/>Compute c(n) = 2(ln(n - 1) + 0.5772) - 2(n - 1) / n"]:::scoreStyle
    IT1 & IT2 & IT3 --> CALC

    SCORE["Anomaly Score Formula<br/>s(x, n) = 2 ^ ( - E(h(x)) / c(n) )"]:::scoreStyle
    CALC --> SCORE

    CHECK{"Anomaly Decision<br/>Is s(x) &gt; 0.50?<br/>(Prediction == -1)"}:::inStyle
    SCORE --> CHECK

    CHECK -- "No: Deep Path (s &lt;= 0.5)" --> BENIGN["NORMAL CLUSTER DATA (Label: +1)<br/>• Required many splits to isolate<br/>• Consistent with known baseline"]:::normStyle
    CHECK -- "Yes: Short Path (s &gt; 0.5)" --> OUTLIER["STRUCTURAL ANOMALY (Label: -1)<br/>• Isolated in very few random cuts<br/>• Out-of-Distribution trigger to Stage 2"]:::outStyle
    </div>
  </div>

  <br/>

  <!-- Model 3: Extreme Value Theory (EVT) & Centroid Geometry -->
  <div id="card-m3" class="diagram-card">
    <div class="card-header">Model 3: Extreme Value Theory (EVT) & Centroid Geometry — Execution Flow</div>
    <div class="mermaid" id="diag-m3">
flowchart TD
    classDef inStyle fill:#ffffff,stroke:#0284c7,stroke-width:2px,color:#0f172a,font-size:13px;
    classDef geoStyle fill:#fdf4ff,stroke:#c026d3,stroke-width:2px,color:#701a75,font-size:13px;
    classDef evtStyle fill:#eff6ff,stroke:#1d4ed8,stroke-width:2px,color:#1e3a8a,font-size:13px;
    classDef knownStyle fill:#fefce8,stroke:#ca8a04,stroke-width:2px,color:#713f12,font-size:13px,font-weight:bold;
    classDef zeroStyle fill:#fef2f2,stroke:#dc2626,stroke-width:2px,color:#7f1d1d,font-size:13px,font-weight:bold;

    SAMPLE["Flow Sample Vector X_s<br/>(Flagged by Stage 1 Gate)"]:::inStyle

    subgraph CENTROIDS["Hyperspherical Centroid Geometry (centroid_geometry.pkl)"]
        C_BENIGN["Benign Centroid (c_0)<br/>Radius r_95 = 5.72"]:::geoStyle
        C_DDOS["DDoS Centroid (c_1)<br/>Radius r_95 = 11.27"]:::geoStyle
        C_SCAN["PortScan Centroid (c_2)<br/>Radius r_95 = 5.72"]:::geoStyle
        C_MIRAI["Mirai Centroid (c_3)<br/>Radius r_95 = 2.05"]:::geoStyle
    end

    SAMPLE --> DIST["Distance Calculator<br/>Compute Euclidean Distance to all centroids:<br/>d(x) = min_k || X_s - c_k ||_2"]:::geoStyle
    C_BENIGN & C_DDOS & C_SCAN & C_MIRAI --> DIST

    EVT["EVT Calibrator (anomaly_calibrator.pkl)<br/>• Fit extreme distance tail to Weibull GPD<br/>• Compute tail probability: P(D &gt; d | D &gt; μ)<br/>• Calibrated Anomaly Score S_cal"]:::evtStyle
    DIST --> EVT

    DEC{"Open-Set Boundary Check<br/>Is S_cal &gt; r_99 and d(x) &gt; r_95?"}:::inStyle
    EVT --> DEC

    DEC -- "No (Inside Known Convex Hull)" --> KNOWN["KNOWN CLASS MATCH (Outcome: KNOWN_ATTACK)<br/>• Dispatched to Multiclass Random Forest<br/>• Map to supervised taxonomy (DDoS, Scan, Mirai)"]:::knownStyle
    DEC -- "Yes (Beyond Extreme Hull)" --> ZERO["GENUINE ZERO-DAY OUTLIER (Outcome: UNKNOWN_SUSPICIOUS)<br/>• Tagged as MITRE T0884 Novel Outlier<br/>• True Zero-Day discovery with zero signature leakage"]:::zeroStyle
    </div>
  </div>

  <br/>

  <!-- Model 4: Multiclass Random Forest Classifier -->
  <div id="card-m4" class="diagram-card">
    <div class="card-header">Model 4: Multiclass Random Forest Classifier (multiclass_model.pkl) — Execution Flow</div>
    <div class="mermaid" id="diag-m4">
flowchart TD
    classDef inStyle fill:#ffffff,stroke:#0284c7,stroke-width:2px,color:#0f172a,font-size:13px;
    classDef treeStyle fill:#fdf2f8,stroke:#be185d,stroke-width:2px,color:#831843,font-size:13px;
    classDef tallyStyle fill:#eff6ff,stroke:#2563eb,stroke-width:2px,color:#1e3a8a,font-size:13px;
    classDef tagStyle fill:#fff7ed,stroke:#ea580c,stroke-width:2px,color:#7c2d12,font-size:13px,font-weight:bold;

    X_FLAG["Flagged Feature Vector X_s<br/>(Verified anomalous by Stage 1 screening)"]:::inStyle

    subgraph TREES["100 Multiclass Decision Trees (Multi-Branch Voting)"]
        MT1["Tree #1 Split Matrix<br/>➔ Class Vote: DDoS"]:::treeStyle
        MT2["Tree #2 Split Matrix<br/>➔ Class Vote: DDoS"]:::treeStyle
        MT3["Tree #3 Split Matrix<br/>➔ Class Vote: Port Scan"]:::treeStyle
        MT100["Tree #100 Split Matrix<br/>➔ Class Vote: DDoS"]:::treeStyle
    end

    X_FLAG --> MT1 & MT2 & MT3 & MT100

    VOTES["Posterior Probability Tally<br/>P(y = c | X_s) = (1 / 100) * Σ I(t_k == c)<br/>• P(DDoS) = 0.92<br/>• P(PortScan) = 0.05<br/>• P(BruteForce) = 0.02<br/>• P(Mirai) = 0.01<br/>• P(Benign) = 0.00"]:::tallyStyle
    MT1 & MT2 & MT3 & MT100 --> VOTES

    ARGMAX["Winning Class Selector<br/>c* = argmax P(y = c) ➔ DDoS<br/>Confidence = 0.92"]:::tallyStyle
    VOTES --> ARGMAX

    TIER{"Confidence Tiering Logic<br/>Conf &gt;= 0.85 &amp; Gate &gt;= 0.90?"}:::inStyle
    ARGMAX --> TIER

    TIER -- "Yes" --> CRIT["CRITICAL SEVERITY INCIDENT<br/>• Attack: Volumetric Flood (DDoS)<br/>• MITRE ATT&CK: T0814<br/>• Trigger automated SOAR isolation"]:::tagStyle
    TIER -- "No" --> WARN["WARNING / INFO INCIDENT<br/>• Attack: Medium-confidence anomaly<br/>• Escalated to SOC analyst queue"]:::tagStyle
    </div>
  </div>

  <br/>

  <!-- Model 5: Graph Intelligence Detector -->
  <div id="card-m5" class="diagram-card">
    <div class="card-header">Model 5: Graph Intelligence Detector (graph_detector.py) — Execution Flow</div>
    <div class="mermaid" id="diag-m5">
flowchart TD
    classDef inStyle fill:#ffffff,stroke:#0284c7,stroke-width:2px,color:#0f172a,font-size:13px;
    classDef graphStyle fill:#fff7ed,stroke:#c2410c,stroke-width:2px,color:#7c2d12,font-size:13px;
    classDef entropyStyle fill:#eff6ff,stroke:#2563eb,stroke-width:2px,color:#1e3a8a,font-size:13px;
    classDef passStyle fill:#ecfdf5,stroke:#059669,stroke-width:2px,color:#064e3b,font-size:13px,font-weight:bold;
    classDef lateralStyle fill:#fef2f2,stroke:#dc2626,stroke-width:2px,color:#7f1d1d,font-size:13px,font-weight:bold;

    FLOW["Inbound Flow Tuple<br/>(src_ip, dst_ip, dst_port, timestamp, protocol)"]:::inStyle

    GRAPH["Update Dynamic Directed Graph G = (V, E)<br/>Add edge: (src_ip ➔ dst_ip) with metadata port=dst_port"]:::graphStyle
    FLOW --> GRAPH

    subgraph METRICS["Graph Centrality & Topology Metrics"]
        DEG["Out-Degree Fanout Tracker<br/>deg_out(src) = count(unique dst_ip)<br/>Compute 60-second surge: Δdeg_out"]:::graphStyle
        ENTROPY["Destination Port Shannon Entropy<br/>H(P) = - Σ P(p) * log2(P(p))<br/>Measures target port diversity"]:::entropyStyle
    end

    GRAPH --> DEG
    GRAPH --> ENTROPY

    FUSION["Graph Anomaly Score Head<br/>S_graph = w_1 * (Δdeg_out / max_fanout) + w_2 * (H(P) / max_H)"]:::graphStyle
    DEG & ENTROPY --> FUSION

    CHECK{"Lateral Movement Trigger<br/>Is Δdeg_out &gt;= 5 OR H(P) &gt; threshold?"}:::inStyle
    FUSION --> CHECK

    CHECK -- "No (Normal Star Topology)" --> SAFE["EXPECTED PEER TRAFFIC<br/>• Device communicates only with Gateway / Cloud<br/>• Graph anomaly score S_graph remains low"]:::passStyle
    CHECK -- "Yes (Fanout Surge)" --> LATERAL["LATERAL MOVEMENT DETECTED (T0886)<br/>• Compromised IoT node scanning subnet peers<br/>• Dispatched as High Severity Reconnaissance Alert"]:::lateralStyle
    </div>
  </div>

  <br/>

  <!-- Model 6: Temporal Sequence Tracker -->
  <div id="card-m6" class="diagram-card">
    <div class="card-header">Model 6: Temporal Sequence Tracker (temporal_detector.py) — Execution Flow</div>
    <div class="mermaid" id="diag-m6">
flowchart TD
    classDef inStyle fill:#ffffff,stroke:#0284c7,stroke-width:2px,color:#0f172a,font-size:13px;
    classDef bufStyle fill:#fefce8,stroke:#ca8a04,stroke-width:2px,color:#713f12,font-size:13px;
    classDef statStyle fill:#eff6ff,stroke:#2563eb,stroke-width:2px,color:#1e3a8a,font-size:13px;
    classDef stochStyle fill:#ecfdf5,stroke:#059669,stroke-width:2px,color:#064e3b,font-size:13px,font-weight:bold;
    classDef beaconStyle fill:#fef2f2,stroke:#dc2626,stroke-width:2px,color:#7f1d1d,font-size:13px,font-weight:bold;

    FLOW["Packet Flow Event (device_id, timestamp t_i)"]:::inStyle

    FIFO["Causal FIFO Sliding Window Buffer<br/>Maintain rolling queue of last k = 20 flow timestamps for device_id<br/>Queue: [t_1, t_2, ..., t_20]"]:::bufStyle
    FLOW --> FIFO

    DIFF["Inter-Arrival Time Calculation (Δt)<br/>Compute pairwise differences:<br/>Δt_i = t_i - t_{i-1} for i in [1..k]"]:::statStyle
    FIFO --> DIFF

    STATS["Statistical Dispersion Analyzer<br/>• Mean: μ(Δt) = (1 / k) * Σ Δt_i<br/>• Variance: σ^2(Δt) = (1 / k) * Σ (Δt_i - μ)^2<br/>• Coefficient of Variation: CV = σ(Δt) / μ(Δt)"]:::statStyle
    DIFF --> STATS

    CHECK{"Beaconing Pacing Check<br/>Is queue full (k &gt;= 10) AND CV &lt; 0.15?<br/>(Rigid clock-cycle periodicity)"}:::inStyle
    STATS --> CHECK

    CHECK -- "No (Stochastic Pacing: CV &gt;= 0.15)" --> STOCH["NORMAL SENSOR TELEMETRY<br/>• Variable inter-arrival timing<br/>• Burst &amp; idle patterns confirmed benign"]:::stochStyle
    CHECK -- "Yes (Near-Zero Variance: CV &lt; 0.15)" --> BEACON["MIRAI C2 BEACON DETECTED (T0885)<br/>• Uncovers periodic botnet keepalive heartbeat<br/>• Bypasses evasion attempts in single-packet models"]:::beaconStyle
    </div>
  </div>

  <br/>

  <!-- Model 7: TreeSHAP Attribution Engine -->
  <div id="card-m7" class="diagram-card">
    <div class="card-header">Model 7: TreeSHAP Attribution Engine (shap_explainer.py) — Execution Flow</div>
    <div class="mermaid" id="diag-m7">
flowchart TD
    classDef inStyle fill:#ffffff,stroke:#0284c7,stroke-width:2px,color:#0f172a,font-size:13px;
    classDef shapStyle fill:#f0fdf4,stroke:#15803d,stroke-width:2px,color:#14532d,font-size:13px;
    classDef decompStyle fill:#eff6ff,stroke:#2563eb,stroke-width:2px,color:#1e3a8a,font-size:13px;
    classDef socStyle fill:#fff7ed,stroke:#c2410c,stroke-width:2px,color:#7c2d12,font-size:13px,font-weight:bold;

    ALERT["Flagged Flow Event X_s + Random Forest Ensemble Model"]:::inStyle

    TRAVERSE["Tree Ensemble Path Traversal (O(TLD^2) Algorithm)<br/>For each tree in the forest, track decision path conditions<br/>Evaluate conditional feature expectations: E[f(x) | S]"]:::shapStyle
    ALERT --> TRAVERSE

    SHAP["Exact Shapley Value Formula<br/>φ_i(x) = Σ [ |S|!(|F| - |S| - 1)! / |F|! ] * [ f(S ∪ {i}) - f(S) ]<br/>Computes exact marginal attribution φ_i for all 46 features"]:::shapStyle
    TRAVERSE --> SHAP

    ADDITIVE["Additive Local Attribution Verification<br/>f(x) = φ_0 + Σ φ_i(x)<br/>Where φ_0 = Base expected score (0.08), f(x) = Predicted score (0.92)"]:::decompStyle
    SHAP --> ADDITIVE

    RANK["Feature Driver Ranking & Extraction<br/>Sort features by absolute contribution |φ_i|:<br/>1. pkt_rate: +0.42 (DDoS packet surge)<br/>2. dst_port_entropy: +0.28 (Scanning diversity)<br/>3. conn_state_s0: +0.15 (SYN without ACK)<br/>4. duration: -0.05 (Mitigating factor)"]:::decompStyle
    ADDITIVE --> RANK

    SOC["SOC OPERATOR WATERFALL DISPLAY<br/>• Transparent, non-black-box evidence card<br/>• Eliminates analyst ambiguity and alert confusion"]:::socStyle
    RANK --> SOC
    </div>
  </div>

  <br/>

  <!-- Model 8: Online EMA Baseline & Hierarchical Risk Engine -->
  <div id="card-m8" class="diagram-card">
    <div class="card-header">Model 8: Online EMA Baseline & Risk Engine (DeviceState &amp; RiskEngine) — Execution Flow</div>
    <div class="mermaid" id="diag-m8">
flowchart TD
    classDef inStyle fill:#ffffff,stroke:#0284c7,stroke-width:2px,color:#0f172a,font-size:13px;
    classDef emaStyle fill:#f0f9ff,stroke:#0284c7,stroke-width:2px,color:#0f172a,font-size:13px;
    classDef graceStyle fill:#fefce8,stroke:#ca8a04,stroke-width:2px,color:#713f12,font-size:13px;
    classDef decayStyle fill:#eff6ff,stroke:#2563eb,stroke-width:2px,color:#1e3a8a,font-size:13px;
    classDef actionStyle fill:#fef2f2,stroke:#dc2626,stroke-width:2px,color:#7f1d1d,font-size:13px,font-weight:bold;

    FLOW["Continuous Device Packet Stream (device_id, flow_t)"]:::inStyle

    EMA["Online Exponential Moving Average (EMA) Update<br/>• μ_t = α * x_t + (1 - α) * μ_{t-1}<br/>• σ^2_t = β * (x_t - μ_t)^2 + (1 - β) * σ^2_{t-1}<br/>• Dynamic Z-Score: z = (x_t - μ_t) / (σ_t + ε)"]:::emaStyle
    FLOW --> EMA

    GRACE{"Cold-Start Grace Period Check<br/>Is state.flow_count &lt;= 10 flows?"}:::graceStyle
    EMA --> GRACE

    GRACE -- "Yes (New Onboarded Device)" --> SUPPRESS["SUPPRESS STARTUP NOISE<br/>• Discard anomaly alerts during first 10 flows<br/>• Cuts onboarding false alarms by &gt; 65%"]:::emaStyle
    GRACE -- "No (Established Device)" --> RISK["Alert Queue Ingestion &amp; Severity Weighting<br/>Base Severity Weight: Critical (100), Warning (50), Info (20)"]:::decayStyle

    DEDUP["Sliding-Window Deduplication (30s Window)<br/>Aggregate repeated alerts from same device into incident count"]:::decayStyle
    RISK --> DEDUP

    DECAY["Exponential Temporal Risk Decay Formula<br/>R_t = R_0 * e ^ ( - λ * Δt )<br/>Smoothly reduces risk back to clean state when attacks halt"]:::decayStyle
    DEDUP --> DECAY

    ACTION["FINAL INCIDENT DISPATCH<br/>• D3.js Radial Topology Node turns Red<br/>• Real-time WebSocket event sent to UI<br/>• Automated SOAR webhook to switch port ACL"]:::actionStyle
    DECAY --> ACTION
    </div>
  </div>

  <script>
    mermaid.initialize({
      startOnLoad: true,
      theme: 'neutral',
      themeVariables: {
        fontSize: '14px',
        fontFamily: '-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif',
        primaryColor: '#ffffff',
        primaryBorderColor: '#0284c7',
        primaryTextColor: '#0f172a',
        lineColor: '#0284c7'
      },
      flowchart: {
        curve: 'linear',
        htmlLabels: true,
        nodeSpacing: 35,
        rankSpacing: 35
      }
    });
  </script>
</body>
</html>
"""

def render_all_models():
    html_file = IMG_DIR / "temp_individual_models.html"
    html_file.write_text(HTML_CONTENT, encoding="utf-8")
    
    file_url = f"file:///{html_file.as_posix()}"
    print(f"[INFO] Opening {file_url} in Playwright (Scale Factor: 3)...")
    
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)
        context = browser.new_context(viewport={"width": 2600, "height": 4200}, device_scale_factor=3)
        page = context.new_page()
        page.goto(file_url)
        
        targets = [
            ("#card-m1", IMG_DIR / "model1_random_forest_gate.png", "Model 1: Random Forest Binary Gate"),
            ("#card-m2", IMG_DIR / "model2_isolation_forest.png", "Model 2: Isolation Forest Anomaly"),
            ("#card-m3", IMG_DIR / "model3_evt_geometry.png", "Model 3: EVT Centroid Geometry"),
            ("#card-m4", IMG_DIR / "model4_multiclass_ensemble.png", "Model 4: Multiclass Ensemble"),
            ("#card-m5", IMG_DIR / "model5_graph_intelligence.png", "Model 5: Graph Intelligence"),
            ("#card-m6", IMG_DIR / "model6_temporal_tracker.png", "Model 6: Temporal Tracker"),
            ("#card-m7", IMG_DIR / "model7_treeshap_explainer.png", "Model 7: TreeSHAP Explainer"),
            ("#card-m8", IMG_DIR / "model8_risk_engine.png", "Model 8: EMA Risk Engine"),
        ]
        
        # Wait for first and last SVG
        page.wait_for_selector("#diag-m1 svg", timeout=20000)
        page.wait_for_selector("#diag-m8 svg", timeout=20000)
        time.sleep(2)
        
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
    render_all_models()
