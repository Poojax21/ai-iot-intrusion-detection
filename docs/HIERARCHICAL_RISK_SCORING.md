# Pahredaar-IoT — Hierarchical Risk Scoring & Evidence Synthesis
**Document Version:** 1.0 (Phase 4 Specification)  
**Authors:** Senior Machine Learning Engineer & Cybersecurity Architect  

---

## 1. Problem Formulation: Beyond Arbitrary Alert Counts

In naive intrusion detection systems, device risk is often calculated as a crude count of alerts or by linearly averaging uncalibrated model outputs:
$$R_{naive} = \frac{1}{M} \sum_{m=1}^M S_m$$
This approach has fatal weaknesses:
1. **Uncalibrated Distortion:** A raw anomaly score of 0.65 from an Isolation Forest is not a probability and cannot be averaged with a calibrated gate probability.
2. **Alert Storm Distortion:** A fast port scan producing 200 alerts in 2 seconds artificially inflates risk by 200x compared to a stealthy multi-hour reconnaissance campaign producing 2 alerts.
3. **No Temporal Memory or Recovery:** Without decay, a device compromised 30 days ago remains permanently labeled critical even after remediation.

---

## 2. Hierarchical Formulation: Flow $\to$ Temporal $\to$ Graph $\to$ Device

Pahredaar-IoT synthesizes threat evidence across four orthogonal operational layers:

$$\Delta R(t) = w_{flow} \cdot S_{flow} + w_{novelty} \cdot S_{novelty} + w_{temporal} \cdot S_{temporal} + w_{graph} \cdot S_{graph}$$

Where:
- $S_{flow} = \max(S_{gate}, \mathbf{1}(S_{cal} \ge 0.90) \cdot S_{cal})$: Verified Stage 1 flow anomaly probability.
- $S_{novelty} = \mathbf{1}(\text{is\_unknown}) \cdot \min(1.0, \frac{\text{dist}}{2 \rho})$: Out-of-distribution zero-day distance penalty.
- $S_{temporal} \in [0, 1]$: Sequential LSTM/GRU attack probability over rolling window $W$.
- $S_{graph} \in [0, 1]$: Topological degree, fan-out anomaly, and internal lateral movement penalty.
- Default Calibrated Weights: $w_{flow} = 0.35, \, w_{novelty} = 0.25, \, w_{temporal} = 0.25, \, w_{graph} = 0.15$ ($\sum w_i = 1.0$).

---

## 3. Continuous Exponential Half-Life Decay

Device risk decays continuously following exponential half-life kinetics:
$$R_{decayed}(t) = R(t_{prev}) \cdot \exp\left( - \frac{\Delta t \cdot \ln(2)}{T_{half}} \right)$$
- Default Half-Life: $T_{half} = 120.0$ seconds (configurable).
- After 2 minutes of quiet normal traffic without attacks, device risk naturally decays by 50%.
- After 4 minutes, risk decays to 25%, reflecting restored fleet health.

---

## 4. Multi-Tier Risk Classification

| Risk Score Range | Severity Tier | Operational Meaning & Recommended SOC Action |
| :---: | :---: | :--- |
| **0.0 – 24.9** | **`LOW`** | Normal fleet baseline activity. Routine periodic telemetry. |
| **25.0 – 54.9** | **`ELEVATED`** | Borderline flow tail, isolated anomaly, or single suppressed event. |
| **55.0 – 79.9** | **`HIGH`** | Confirmed attack, persistent temporal burst, or novel zero-day pattern. Automated quarantine alert issued. |
| **80.0 – 100.0** | **`CRITICAL`** | Multi-modal convergence (flow attack + temporal burst + internal lateral movement). Immediate node isolation. |
