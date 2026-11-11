# Pahredaar-IoT — Open-Set Recognition API & Integration Specification
**Document Version:** 1.0 (Phase 3 API Contract)  
**Authors:** Backend Engineer & Distributed Systems Architect  

---

## 1. Updated Endpoints & Wire Schemas

### `POST /api/ingest`
Submits a single network flow record for real-time inference and triage.

#### Request Body (`FlowRecord`):
```json
{
  "ts": 1794387056.12,
  "device_id": "camera-a1b2c3d4",
  "device_type": "camera",
  "src_ip": "192.168.1.10",
  "dst_ip": "203.0.113.88",
  "src_port": 51234,
  "dst_port": 2222,
  "proto": "tcp",
  "duration": 0.002,
  "orig_bytes": 48,
  "resp_bytes": 0,
  "orig_pkts": 1,
  "resp_pkts": 0,
  "conn_state": "S0",
  "mac_unstable": false
}
```

#### Response Body:
```json
{
  "flagged": true,
  "gate_score": 0.998,
  "anomaly_score": 0.654,
  "calibrated_anomaly_score": 0.985,
  "novelty_score": 1.42,
  "decision": "UNKNOWN_SUSPICIOUS",
  "is_unknown": true,
  "reason_codes": [
    "GATE_FLAG_MULTICLASS_BENIGN_DISAGREEMENT",
    "FEATURE_SPACE_OOD_DISTANCE"
  ],
  "alert": {
    "id": 142,
    "ts": 1794387056.12,
    "device_id": "camera-a1b2c3d4",
    "device_type": "camera",
    "src_ip": "192.168.1.10",
    "dst_ip": "203.0.113.88",
    "attack_type": "unknown_suspicious",
    "mitre": "T1204 (Zero-Day / Novel Vector - Open-Set Anomaly)",
    "severity": "warning",
    "gate_score": 0.998,
    "confidence_tier": "medium",
    "decision": "UNKNOWN_SUSPICIOUS",
    "is_unknown": true,
    "novelty_score": 1.42,
    "calibrated_anomaly_score": 0.985,
    "reason_codes": [
      "GATE_FLAG_MULTICLASS_BENIGN_DISAGREEMENT",
      "FEATURE_SPACE_OOD_DISTANCE"
    ],
    "top_features": [
      ["device_zscore", -2.21],
      ["is_new_edge", 1.0]
    ],
    "shap_values": [ ... ]
  },
  "warning": null
}
```

---

## 2. Health Endpoint (`GET /api/health`)
Returns service and model status:
```json
{
  "status": "ok",
  "models_loaded": true,
  "open_set_enabled": true,
  "open_set_version": "open_set_v1",
  "hint": null
}
```

---

## 3. Alerts Endpoint (`GET /api/alerts`)
Returns recent alerts with open-set triage metadata:
```json
[
  {
    "id": 142,
    "ts": 1794387056.12,
    "device_id": "camera-a1b2c3d4",
    "attack_type": "unknown_suspicious",
    "is_unknown": true,
    "decision": "UNKNOWN_SUSPICIOUS",
    "novelty_score": 1.42,
    "calibrated_anomaly_score": 0.985,
    "reason_codes": ["GATE_FLAG_MULTICLASS_BENIGN_DISAGREEMENT"]
  }
]
```

---

## 4. Operational Alert Storm Suppression

To prevent alert flooding in real networks during sustained port scans or DDoS bursts, Pahredaar-IoT features a sliding-window alert deduplicator (`should_suppress_alert`):
- **Window:** 5.0 seconds (configurable via `ALERT_SUPPRESSION_WINDOW_SEC`).
- **Scope:** Per `(device_id, attack_type)`.
- **Behavior:** The initial attack flow triggers full alert broadcast and database persistence. Immediate subsequent flows with the same signature update the device flow count and rolling baseline without spawning redundant alert records.
