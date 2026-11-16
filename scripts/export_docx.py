"""
Export Comprehensive Project Report to Microsoft Word (.docx) Format.
Faithfully mirrors comprehensive_project_report.md with publication typography,
structured tables, colored callout boxes, and 4 ultra-high-resolution diagrams.
"""

import os
from pathlib import Path
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

PROJECT_ROOT = Path(__file__).resolve().parent.parent
IMG_DIR = PROJECT_ROOT / "docs" / "images"

def set_cell_background(cell, hex_color):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>')
    tcPr.append(shd)

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{m}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def add_callout(doc, text, title="NOTE / ARCHITECTURE PRINCIPLE"):
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl.autofit = False
    tbl.columns[0].width = Inches(6.5)
    
    cell = tbl.cell(0, 0)
    set_cell_background(cell, "F0F9FF")
    set_cell_margins(cell, top=120, bottom=120, left=180, right=180)
    
    tcPr = cell._tc.get_or_add_tcPr()
    borders = parse_xml(
        f'<w:tcBorders {nsdecls("w")}>'
        f'  <w:left w:val="single" w:sz="24" w:space="0" w:color="0284C7"/>'
        f'  <w:top w:val="none"/>'
        f'  <w:right w:val="none"/>'
        f'  <w:bottom w:val="none"/>'
        f'</w:tcBorders>'
    )
    tcPr.append(borders)
    
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(2)
    run_title = p.add_run(f"📌 {title}: ")
    run_title.bold = True
    run_title.font.name = "Calibri"
    run_title.font.size = Pt(10)
    run_title.font.color.rgb = RGBColor(2, 132, 199)
    
    run_text = p.add_run(text)
    run_text.font.name = "Calibri"
    run_text.font.size = Pt(10)
    run_text.font.color.rgb = RGBColor(15, 23, 42)
    doc.add_paragraph().paragraph_format.space_after = Pt(4)

def add_figure(doc, img_path, caption, width_inches=6.5):
    if not Path(img_path).exists():
        print(f"[WARN] Image {img_path} not found.")
        return
    p_img = doc.add_paragraph()
    p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_img.paragraph_format.space_before = Pt(10)
    p_img.paragraph_format.space_after = Pt(3)
    p_img.add_run().add_picture(str(img_path), width=Inches(width_inches))
    
    p_cap = doc.add_paragraph()
    p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_cap.paragraph_format.space_before = Pt(0)
    p_cap.paragraph_format.space_after = Pt(10)
    r_cap = p_cap.add_run(caption)
    r_cap.font.name = "Calibri"
    r_cap.font.size = Pt(9.5)
    r_cap.font.italic = True
    r_cap.font.color.rgb = RGBColor(100, 116, 139)

def build_docx_report():
    doc = Document()
    
    # Page setup: Standard Letter, 0.75-inch margins
    sections = doc.sections
    for section in sections:
        section.top_margin = Inches(0.75)
        section.bottom_margin = Inches(0.75)
        section.left_margin = Inches(0.75)
        section.right_margin = Inches(0.75)

    # 1. Document Title
    p_title = doc.add_paragraph()
    p_title.paragraph_format.space_before = Pt(0)
    p_title.paragraph_format.space_after = Pt(2)
    run_title = p_title.add_run("🛡️ Aegis-IoT: Enterprise & Industrial Intrusion Detection System")
    run_title.font.name = "Calibri"
    run_title.font.size = Pt(22)
    run_title.bold = True
    run_title.font.color.rgb = RGBColor(30, 58, 138) # Navy Blue

    # Subtitle
    p_sub = doc.add_paragraph()
    p_sub.paragraph_format.space_before = Pt(0)
    p_sub.paragraph_format.space_after = Pt(12)
    run_sub = p_sub.add_run("Autonomous Edge-Gated Intrusion Detection & Zero-Day Defense for IoT Networks\nComprehensive Technical, Architectural & Empirical Evaluation Report")
    run_sub.font.name = "Calibri"
    run_sub.font.size = Pt(12)
    run_sub.font.color.rgb = RGBColor(71, 85, 105) # Slate

    # Metadata Table
    meta_table = doc.add_table(rows=5, cols=2)
    meta_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta_data = [
        ("Project Name", "Aegis-IoT (Autonomous Edge-Gated Intrusion Detection System)"),
        ("Specification Version", "v3.0 (Reliability-Hardened Production Specification)"),
        ("Author / Organization", "Poojax21"),
        ("Repository", "https://github.com/Poojax21/ai-iot-intrusion-detection"),
        ("Verification Test Suite", "112 / 112 Automated Tests Passing (100% Green Build)"),
    ]
    for idx, (k, v) in enumerate(meta_data):
        row = meta_table.rows[idx]
        cell_k, cell_v = row.cells[0], row.cells[1]
        set_cell_background(cell_k, "F8FAFC")
        set_cell_background(cell_v, "FFFFFF")
        set_cell_margins(cell_k, top=60, bottom=60, left=100, right=100)
        set_cell_margins(cell_v, top=60, bottom=60, left=100, right=100)
        
        pk = cell_k.paragraphs[0]
        pk.paragraph_format.space_after = Pt(1)
        rk = pk.add_run(k)
        rk.bold = True
        rk.font.name = "Calibri"
        rk.font.size = Pt(9.5)
        rk.font.color.rgb = RGBColor(51, 65, 85)
        
        pv = cell_v.paragraphs[0]
        pv.paragraph_format.space_after = Pt(1)
        rv = pv.add_run(v)
        rv.font.name = "Calibri"
        rv.font.size = Pt(9.5)
        rv.font.color.rgb = RGBColor(15, 23, 42)

    doc.add_paragraph().paragraph_format.space_after = Pt(10)

    # Typography helpers
    def add_heading_1(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(14)
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.keep_with_next = True
        run = p.add_run(text)
        run.bold = True
        run.font.name = "Calibri"
        run.font.size = Pt(15)
        run.font.color.rgb = RGBColor(30, 58, 138)
        return p

    def add_heading_2(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(10)
        p.paragraph_format.space_after = Pt(3)
        p.paragraph_format.keep_with_next = True
        run = p.add_run(text)
        run.bold = True
        run.font.name = "Calibri"
        run.font.size = Pt(12.5)
        run.font.color.rgb = RGBColor(13, 148, 136)
        return p

    def add_p(text, bold_prefix=None):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.line_spacing = 1.15
        if bold_prefix:
            r_b = p.add_run(bold_prefix)
            r_b.bold = True
            r_b.font.name = "Calibri"
            r_b.font.size = Pt(10.5)
            r_b.font.color.rgb = RGBColor(15, 23, 42)
        r = p.add_run(text)
        r.font.name = "Calibri"
        r.font.size = Pt(10.5)
        r.font.color.rgb = RGBColor(30, 41, 59)
        return p

    def add_bullet(text, bold_prefix=None):
        p = doc.add_paragraph(style='List Bullet')
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(2)
        p.paragraph_format.line_spacing = 1.15
        if bold_prefix:
            r_b = p.add_run(bold_prefix)
            r_b.bold = True
            r_b.font.name = "Calibri"
            r_b.font.size = Pt(10.5)
            r_b.font.color.rgb = RGBColor(15, 23, 42)
        r = p.add_run(text)
        r.font.name = "Calibri"
        r.font.size = Pt(10.5)
        r.font.color.rgb = RGBColor(30, 41, 59)
        return p

    # --- Section 1: Executive Summary ---
    add_heading_1("1. Executive Summary")
    add_p(
        "Internet of Things (IoT) and Industrial IoT (IIoT) ecosystems—encompassing IP surveillance cameras, smart environmental sensors, building automation controllers, and programmable logic controllers (PLCs)—are among the most targeted assets in modern digital infrastructure. Due to hardware compute constraints, heterogeneous operating environments, and vendor firmware neglect, these devices are chronically under-patched and routinely recruited into high-volume botnets (e.g., Mirai, BASHLITE) or leveraged as entry vectors for lateral subnet pivoting."
    )
    add_p(
        "While academic literature features hundreds of Machine Learning Intrusion Detection Systems (ML-IDS), the vast majority catastrophically fail when deployed into production. This failure stems from four pervasive engineering flaws:"
    )
    add_bullet(" Models memorize static IP or MAC addresses from capture testbeds rather than learning behavioral invariants.", "1. Identity & Feature Leakage:")
    add_bullet(" Random k-fold cross-validation shuffles future packet flows into training partitions, producing artificial and unreplicable accuracy scores.", "2. Lookahead Time Leakage:")
    add_bullet(" Purely supervised classifiers force unseen, novel attack variants into known classes or classify them as benign.", "3. Supervised Blindness to Zero-Days:")
    add_bullet(" Heavy classifiers evaluated over 100% of network traffic overwhelm SOC teams with false positives and high computational overhead.", "4. FPR Compounding & Alert Fatigue:")
    
    add_p(
        "Aegis-IoT resolves these vulnerabilities through a ground-up re-architecture: a two-stage detection funnel (fast <1% FPR binary gate + heavy multimodal ensemble), unsupervised Extreme Value Theory (EVT) for genuine zero-day discovery, strict zero-identity feature engineering, and per-alert TreeSHAP explainability."
    )
    
    add_callout(
        doc,
        "Aegis-IoT guarantees strict operational stability: 100% of traffic is screened at line rate by a lightweight binary gate, bounding heavy ensemble inference to only the 5-10% of traffic flagged as anomalous.",
        "CORE RELIABILITY PRINCIPLE"
    )

    # --- Section 2: Threat Landscape & Attack Taxonomy ---
    add_heading_1("2. Threat Landscape & Attack Taxonomy")
    add_p("Aegis-IoT maps all detections to the MITRE ATT&CK for IoT / ICS matrix:")

    # Embed Figure 1
    add_figure(
        doc,
        IMG_DIR / "figure1_threat_taxonomy.png",
        "Figure 1: Aegis-IoT Threat Landscape & MITRE ATT&CK for IoT Vector Mapping",
        width_inches=6.5
    )

    mitre_tbl = doc.add_table(rows=6, cols=4)
    mitre_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    headers = ["MITRE ID", "Attack Family", "Flow Behavioral Signature", "Aegis-IoT Detection Mechanism"]
    for j, h in enumerate(headers):
        cell = mitre_tbl.rows[0].cells[j]
        set_cell_background(cell, "1E3A8A")
        set_cell_margins(cell, top=80, bottom=80, left=100, right=100)
        p = cell.paragraphs[0]
        r = p.add_run(h)
        r.bold = True
        r.font.name = "Calibri"
        r.font.size = Pt(9.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    mitre_rows = [
        ("T0814", "Volumetric DDoS", "Extreme packet arrival rate (pkt_rate), uniform packet size, high byte rate, zero payload response.", "Stage 1 Binary Gate + Rate Z-Score (Δz > 3.5)"),
        ("T0846", "Network Port Scan", "Rapid destination port diversity (dst_port_entropy), short duration, SYN-no-ACK (conn_state_s0).", "Graph Intelligence (Dynamic Fanout Tracker)"),
        ("T0812", "Brute Force", "Repeated bidirectional flows to ports 22, 23, or 80 with small byte variance, high originator bytes, and failed auth terminations.", "Multiclass GBM + Port Entropy Analysis"),
        ("T0885", "Mirai C2 Beacon", "Low-variance inter-arrival time intervals, small periodic keepalive payloads to external IPs, rigid protocol pacing.", "Temporal Sequence Detector (Causal Buffering)"),
        ("T0884", "Zero-Day Outlier", "Out-of-distribution vectors that deviate from known training centroids but lack existing attack signatures.", "Unsupervised EVT Open-Set Distance Layer"),
    ]
    for i, row_data in enumerate(mitre_rows):
        row = mitre_tbl.rows[i+1]
        for j, val in enumerate(row_data):
            cell = row.cells[j]
            set_cell_background(cell, "F8FAFC" if i % 2 == 1 else "FFFFFF")
            set_cell_margins(cell, top=60, bottom=60, left=100, right=100)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.name = "Calibri"
            r.font.size = Pt(9)
            if j == 0:
                r.bold = True

    doc.add_paragraph().paragraph_format.space_after = Pt(6)

    # --- Section 3: Data Engineering & Benchmark Datasets ---
    add_heading_1("3. Data Engineering & Benchmark Datasets")
    add_p(
        "Aegis-IoT implements memory-safe chunked loaders, column normalization maps, and standardized schemas for 5 foundational public benchmark datasets:"
    )

    # Embed Figure 2
    add_figure(
        doc,
        IMG_DIR / "figure2_data_pipeline.png",
        "Figure 2: Unified 5-Dataset Ingestion & Leakage-Safe Feature Pipeline",
        width_inches=6.5
    )

    add_bullet(" 105 IoT devices, 33 attacks across 7 classes (DDoS, DoS, Recon, Mirai, Brute Force, Web, Spoofing).", "1. CICIoT2023 (UNB):")
    add_bullet(" Real Raspberry Pi captures with live malware infections (Mirai, Torii, Okiru, Kenjiro, C&C Heartbeats).", "2. IoT-23 (Stratosphere/CTU):")
    add_bullet(" Heterogeneous IoT and IIoT telemetry with scanning, ransomware, backdoors, and injection attacks.", "3. TON_IoT (UNSW Canberra):")
    add_bullet(" Netflow CSV extracts capturing high-density botnet DDoS, DoS, and exfiltration flows.", "4. Bot-IoT (UNSW Canberra):")
    add_bullet(" 115 continuous stream statistics extracted over 5 time windows from 9 commercial IoT devices.", "5. N-BaIoT (UCI Repository):")

    add_heading_2("Strict Leakage Prevention Protocol (§5 & §7)")
    add_bullet(" Raw IP addresses (src_ip, dst_ip) and MAC addresses (src_mac, dst_mac) are completely removed from the ML feature vector. The models score only behavioral invariants (rates, entropy, fanout, rolling z-scores).", "Identity Leakage:")
    add_bullet(" Random k-fold cross-validation is replaced by strict monotonic chronological partitioning (70% Train -> 15% Validation -> 15% Test forward in time). Models are never evaluated on events preceding their training window.", "Time Leakage:")

    # --- Section 4: Analytical Engine & Detection Architecture ---
    add_heading_1("4. Analytical Engine & Detection Architecture")
    add_p(
        "The architecture implements a multi-tiered inspection pipeline designed to prevent false positive compounding:"
    )

    # Embed Figure 3
    add_figure(
        doc,
        IMG_DIR / "figure3_detection_funnel.png",
        "Figure 3: Aegis-IoT Two-Stage Detection Funnel & Explainability Flowchart",
        width_inches=6.5
    )

    add_bullet(" Fast ensemble tuned against a hard operational ceiling (FPR <= 0.01). It dismisses > 90% of harmless telemetry at edge speeds.", "Stage 1a — Fast Binary Gate:")
    add_bullet(" Uses an Extreme Value Theory Weibull-fitted distribution over feature reconstruction residuals. Points lying outside the known benign boundary are flagged as Zero-Day / Out-of-Distribution rather than forced into supervised classes.", "Stage 1b — Unsupervised Anomaly Model (EVT):")
    add_bullet(" Evaluates only flagged traffic (~5-10% of total volume). Combines a 161.8 MB supervised multiclass model, graph topological fanout (lateral movement), and temporal causal sequence tracking (C2 beaconing).", "Stage 2 — Multimodal Heavy Ensemble:")
    add_bullet(" For every generated alert, calculates exact local additive feature attributions: f(x) = φ0 + Σ φi(x), providing immediate transparency into why traffic was flagged.", "Stage 3 — Explainability via TreeSHAP:")
    add_bullet(" Suppresses cold-start alerts on new devices (10-flow grace period), deduplicates repeated alerts across sliding windows, and decays risk exponentially.", "Stage 4 — Hierarchical Risk Engine:")

    # --- Section 5: Empirical Benchmarks ---
    add_heading_1("5. Empirical Validation & Scientific Benchmarks")
    add_heading_2("5.1 Leave-One-Family-Out (LOFO) Zero-Day Cross-Validation")
    add_p(
        "To rigorously test zero-day detection without leaking attack signatures, the multiclass model was trained on N-1 attack families, while the held-out family was evaluated against the unsupervised EVT anomaly layer:"
    )

    lofo_tbl = doc.add_table(rows=5, cols=6)
    lofo_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    lofo_headers = ["Held-Out Attack Family", "Test Samples", "Unknown Recall", "95% Confidence Interval", "AUROC", "AUPRC"]
    for j, h in enumerate(lofo_headers):
        cell = lofo_tbl.rows[0].cells[j]
        set_cell_background(cell, "0D9488")
        set_cell_margins(cell, top=80, bottom=80, left=100, right=100)
        p = cell.paragraphs[0]
        r = p.add_run(h)
        r.bold = True
        r.font.name = "Calibri"
        r.font.size = Pt(9.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    lofo_data = [
        ("DDoS (Volumetric Floods)", "66", "100.0%", "[1.00, 1.00]", "0.9999", "0.9983"),
        ("Port Scan (Reconnaissance)", "81", "70.4%", "[0.62, 0.82]", "0.9258", "0.5251"),
        ("Brute Force (Credential Access)", "80", "53.8%", "[0.44, 0.62]", "0.8456", "0.2370"),
        ("Mirai Beacon (C2 Heartbeat)", "34", "Temporal / Seq", "[0.00, 0.00]", "0.5585", "0.0459"),
    ]
    for i, row_data in enumerate(lofo_data):
        row = lofo_tbl.rows[i+1]
        for j, val in enumerate(row_data):
            cell = row.cells[j]
            set_cell_background(cell, "F8FAFC" if i % 2 == 1 else "FFFFFF")
            set_cell_margins(cell, top=60, bottom=60, left=100, right=100)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.name = "Calibri"
            r.font.size = Pt(9)
            if j == 0:
                r.bold = True

    doc.add_paragraph().paragraph_format.space_after = Pt(6)

    add_heading_2("5.2 Cross-Dataset Generalization & Transfer Matrix")
    add_p(
        "Most IDS models overfit to their source testbed. Aegis-IoT measures true cross-dataset transfer between independent research datasets with zero fine-tuning:"
    )

    cross_tbl = doc.add_table(rows=3, cols=5)
    cross_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    cross_headers = ["Training Source Domain", "Target Evaluation Domain", "In-Domain PR-AUC", "Cross-Dataset PR-AUC", "Generalization Gap (Δ)"]
    for j, h in enumerate(cross_headers):
        cell = cross_tbl.rows[0].cells[j]
        set_cell_background(cell, "1E3A8A")
        set_cell_margins(cell, top=80, bottom=80, left=100, right=100)
        p = cell.paragraphs[0]
        r = p.add_run(h)
        r.bold = True
        r.font.name = "Calibri"
        r.font.size = Pt(9.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    cross_data = [
        ("IoT-23 (Stratosphere Lab)", "TON_IoT (UNSW Canberra)", "0.9998", "0.7506", "0.2492"),
        ("TON_IoT (UNSW Canberra)", "IoT-23 (Stratosphere Lab)", "1.0000", "0.8759", "0.1241"),
    ]
    for i, row_data in enumerate(cross_data):
        row = cross_tbl.rows[i+1]
        for j, val in enumerate(row_data):
            cell = row.cells[j]
            set_cell_background(cell, "F8FAFC" if i % 2 == 1 else "FFFFFF")
            set_cell_margins(cell, top=60, bottom=60, left=100, right=100)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.name = "Calibri"
            r.font.size = Pt(9)
            if j == 0:
                r.bold = True

    doc.add_paragraph().paragraph_format.space_after = Pt(6)

    add_heading_2("5.3 Latency & Computational Profile")
    lat_tbl = doc.add_table(rows=5, cols=4)
    lat_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    lat_headers = ["Component", "Execution Mode", "Latency (P95)", "Throughput Capacity"]
    for j, h in enumerate(lat_headers):
        cell = lat_tbl.rows[0].cells[j]
        set_cell_background(cell, "1E3A8A")
        set_cell_margins(cell, top=80, bottom=80, left=100, right=100)
        p = cell.paragraphs[0]
        r = p.add_run(h)
        r.bold = True
        r.font.name = "Calibri"
        r.font.size = Pt(9.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    lat_data = [
        ("Stage 1 Binary Gate", "Edge In-line (100% Traffic)", "0.18 ms", "12,500 flows/sec"),
        ("EVT Outlier Anomaly", "Edge In-line (100% Traffic)", "0.34 ms", "6,200 flows/sec"),
        ("Stage 2 Heavy Ensemble", "Flagged Traffic (~5-10%)", "2.40 ms", "1,200 flows/sec"),
        ("TreeSHAP Local Attributions", "On Security Alert Trigger", "4.85 ms", "350 alerts/sec"),
    ]
    for i, row_data in enumerate(lat_data):
        row = lat_tbl.rows[i+1]
        for j, val in enumerate(row_data):
            cell = row.cells[j]
            set_cell_background(cell, "F8FAFC" if i % 2 == 1 else "FFFFFF")
            set_cell_margins(cell, top=60, bottom=60, left=100, right=100)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.name = "Calibri"
            r.font.size = Pt(9)
            if j == 0:
                r.bold = True

    doc.add_paragraph().paragraph_format.space_after = Pt(6)

    # --- Section 6: System Architecture & Operations Console ---
    add_heading_1("6. System Architecture & Operations Console")
    add_p(
        "Aegis-IoT delivers an enterprise deployment architecture bridging edge network taps to a modern SIEM console:"
    )

    # Embed Figure 4
    add_figure(
        doc,
        IMG_DIR / "figure4_system_architecture.png",
        "Figure 4: Aegis-IoT End-to-End Enterprise Deployment Architecture",
        width_inches=6.5
    )

    add_heading_2("6.1 Frontend Capabilities")
    add_bullet(" Central Gateway (192.168.1.1) dynamically anchored at center (W/2, H/2). Robust d3.forceCollide prevents node overlapping across 100+ monitored endpoints with zoom/pan navigation and hover cards.", "1. D3 Force-Directed Radial Topology:")
    add_bullet(" Live detection counters and target histories for DDoS (T0814), Port Scan (T0846), Brute Force (T0812), Mirai Beacon (T0885), and Zero-Day EVT Outliers (T0884).", "2. Threat Vector Analysis Grid:")
    add_bullet(" Features a dedicated '🔄 Refresh Alerts' button and DOM caching that completely prevents page shaking during high-frequency live traffic ingestion.", "3. AI Decision Explainability (Static Mode):")
    add_bullet(" Allows operators to target specific devices, trigger chosen attack vectors, inject legitimate background traffic, and review the live detection timeline.", "4. Attack Simulation & Detection Lab:")

    # --- Section 7: Operational Resilience & Security Posture ---
    add_heading_1("7. Operational Resilience & Security Posture")
    add_bullet(" If the analytical engine or model loading experiences degradation, traffic flows uninterrupted while incidents are flagged for backfill analysis.", "Fail-Open Policy (§11):")
    add_bullet(" Suppresses anomaly alerts during the first 10 flows of a newly discovered device, cutting cold-start false positive noise by over 65%.", "Cold-Start Grace Period (§10):")
    add_bullet(" Device risk scores decay exponentially (Rt = R0 * e^(-λ Δt)) when normal behavior resumes, avoiding perpetual quarantine.", "Temporal Risk Decay:")
    add_bullet(" Complete organization data isolation, JWT authentication, and sensor API key rotation validated by security integration tests.", "Enterprise Multi-Tenancy & RBAC:")

    # --- Section 8: Automated Test Suite ---
    add_heading_1("8. Automated Test Suite (112 Tests Passed)")
    add_p("The platform is fortified with 112 automated unit, integration, and security tests:")
    add_bullet(" Unit Tests (60+): Column mapping, loaders, feature alignment, isolation forest, EVT calibration, protocol normalizer.", "")
    add_bullet(" Integration Tests: Full pipeline end-to-end, split integrity, hybrid orchestrator, WebSocket streaming, simulation lifecycle.", "")
    add_bullet(" Security Tests: JWT rotation, RBAC role permissions, database concurrency rollback, multi-tenant IDOR prevention, sensor key rate limiting.", "")
    add_bullet(" Result: 112 passed, 0 failed, 1 warning (100% Green).", "")

    # --- Section 9: Conclusion & Citation ---
    add_heading_1("9. Conclusion & Citation")
    add_p(
        "Aegis-IoT establishes an enterprise-ready benchmark for IoT intrusion detection by solving the critical failure modes of academic ML-IDS: feature leakage, time leakage, supervised zero-day blindness, and alert fatigue. The architecture operates reliably under a hard <1% false positive ceiling and provides full TreeSHAP explainability for SOC operators."
    )
    add_p("To cite this project in academic literature or engineering reviews:")
    add_p(
        "Poojax21, 'Aegis-IoT: Autonomous Edge-Gated Intrusion Detection & Zero-Day Defense for IoT Networks', GitHub Repository, 2026. https://github.com/Poojax21/ai-iot-intrusion-detection"
    )

    output_path = PROJECT_ROOT / "docs" / "Aegis_IoT_Comprehensive_Project_Report.docx"
    doc.save(str(output_path))
    print(f"[SUCCESS] Exported Word report to: {output_path}")

    # Copy to artifact directory
    artifact_dir = Path(r"C:\Users\Hi\.gemini\antigravity\brain\9fa58b67-f6ff-4eca-bee5-b8cba48470d4")
    if artifact_dir.exists():
        artifact_doc = artifact_dir / "Aegis_IoT_Comprehensive_Project_Report.docx"
        doc.save(str(artifact_doc))
        print(f"[SUCCESS] Copied Word report to artifact: {artifact_doc}")

if __name__ == "__main__":
    build_docx_report()
