# Frontend Usability Audit & Functional Gap Analysis

**Date:** 2026-11-13  
**Platform:** Pahredaar-IoT Intrusion Detection Platform  
**Target:** `frontend/index.html` & Frontend Subsystems

---

## 1. Executive Summary

A comprehensive end-to-end audit of the Pahredaar-IoT frontend was conducted across layout, terminology, interactivity, backend API coverage, visual hierarchy, and usability. 

While the underlying AI detection engines (TreeSHAP, LSTM, Graph, Open-Set) and Phase 6 Enterprise Backend (SQLAlchemy 2.x, PostgreSQL/SQLite, JWT, RBAC, Sensors, Audit Logs) are fully functional, the existing frontend was implemented as a single, overwhelming vertical page with steep cognitive friction, missing explanations, non-functional buttons, and disconnected enterprise capabilities.

---

## 2. Identified Usability & Information Architecture Deficiencies

### A. Layout & Cognitive Overload
1. **Monolithic Vertical Stacking:** The entire interface (Hero banner, connection form, engine telemetry strip, 5 metric cards, traffic simulation controls, fleet cards, attack mix chart, graph canvas, live alerts table, and incident response table) was packed onto one continuous page with no tabbed views or workflow segmentation.
2. **Missing Application Context & Onboarding:** A first-time user opening the dashboard had no clear understanding of what Pahredaar-IoT does, how traffic flows into the AI pipeline, or what their role as a security operator entails.
3. **Overly Technical, Unexplained Acronyms:**
   - "Gate: V1 (RF)" — unexplained that this is the frontline Random Forest binary classifier distinguishing benign traffic from cyber attacks.
   - "Open-Set: v1" — unexplained that this engine identifies zero-day, novel, and out-of-distribution attacks unseen in training data.
   - "Temporal: LSTM v1" — unexplained that this analyzes consecutive flow sequences to detect stealthy multi-pulse reconnaissance and C2 beacons.
   - "Graph: Topology v1" — unexplained that this monitors communication graph entropy to detect lateral movement between IoT devices.
   - "Hierarchical v2" — unexplained non-dilutive multi-factor risk scoring algorithm ($R_{flow}, R_{novelty}, R_{temporal}, R_{graph}$).
   - "MTTA / MTTR" — no tooltips defining Mean Time to Acknowledge and Mean Time to Resolve.
   - "SHAP Bars" — tiny color bars without explicit labels indicating feature names, baseline expectations, or directional impact (red = push towards attack, blue = push towards benign).

---

## 3. Interaction & Functionality Audit (Broken / Incomplete Elements)

| Component / Button | Current State | Defect / Gap | Required Remediation |
| :--- | :--- | :--- | :--- |
| **Device Risk Cards** | Static cards | Clicking a device does nothing; cannot inspect per-device traffic history, flow volume, or IP info. | Add interactive Device Inspection Drawer/Modal with real-time statistics and filter alerts by device. |
| **Live Alert Rows** | Static table rows | Clicking a row does nothing; no way to view raw network headers (IPs, ports, flags, byte counters) or full SHAP waterfall breakdown. | Add Alert Detail Modal with complete network flow inspection and full TreeSHAP explainability chart. |
| **Incident Response (Ack/Resolve)** | Raw buttons | Calls API without confirmation dialogs, loading indicators, or visible toast feedback. | Add confirmation prompts, instant status badges, and professional toast notification system. |
| **Alert Filtering & Search** | Completely missing | No way to search by IP or filter alerts by severity (CRITICAL, HIGH, MEDIUM, LOW) or attack type. | Implement real-time client-side and API search/filtering controls with badge counts. |
| **Incident Filtering** | Completely missing | Incidents table shows all states without status filter tabs (`ALL`, `OPEN`, `ACKNOWLEDGED`, `RESOLVED`). | Implement incident status filter tabs and priority sorting. |
| **Authentication & User Profile** | Text badge only | No UI modal to sign in with username/password, register, switch tenants, or log out. | Implement Enterprise Auth Modal (Sign In, Register, Current User Profile, Org Switcher). |
| **Sensor Management UI** | Non-existent | Backend supports `/api/sensors`, but frontend has zero interface to provision, view, rotate, or deactivate edge sensors. | Implement dedicated Sensors Tab with sensor provisioning modal, API key reveal, and rotation dialog. |
| **Security Audit Logs UI** | Non-existent | Backend supports `/api/audit-logs`, but frontend has zero interface to inspect compliance logs. | Implement dedicated Compliance & Audit Logs Tab with real-time log viewer. |
| **Traffic Simulator Panel** | Basic controls | Only shows counters; lacks visual feedback on what device is transmitting and test run progress. | Add live pulse activity indicators, progress visualizer, and clear preset descriptions. |
| **Error & Toast Feedback** | Missing | Errors are logged to console `console.error`; user gets no feedback if an action succeeds or fails. | Build universal Toast Notification System (`success`, `warning`, `error`, `info`). |

---

## 4. Remediation Blueprint

1. **Tabbed Navigation Architecture:**
   -  **Tab 1: SOC Live Console** (Top-level KPI metrics, real-time alert feed with SHAP bars, attack distribution, fleet posture, and network topology).
   - 🛡️ **Tab 2: Incident Response Center** (Dedicated triage console, MTTA/MTTR metrics, incident lifecycle actions, status filters, and root-cause summaries).
   - 💻 **Tab 3: Device Fleet & Topology** (Comprehensive IoT inventory, risk sub-scores, device detail drawer, and interactive topology map).
   - 🧪 **Tab 4: Traffic Lab & Simulator** (Step-by-step traffic injection, normal vs attack modes, burst controls, and live pulse stream).
   - 📡 **Tab 5: Edge Sensors & Ingestion** (Sensor provisioning, API key generation with one-time copy, key rotation, and rate-limit configuration).
   - 📜 **Tab 6: Security Audit Trail** (Immutable compliance ledger, filtering by action, tenant, and actor).
   - ⚙️ **Tab 7: System Settings & Connection** (Backend URL configuration, JWT credentials, AI engine health, and system diagnostics).

2. **Understandability & Context System:**
   - Every tab features a clear, human-readable introduction explaining:
     - **What is this section?**
     - **Why is it important?**
     - **What actions can you take?**
   - Metric cards feature info tooltips explaining definitions and thresholds.
   - Interactive modals for deep inspection of Alerts, Devices, Incidents, and Sensors.
   - Standardized toast alerts for every user action.
