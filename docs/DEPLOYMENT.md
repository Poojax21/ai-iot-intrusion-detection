# Pahredaar-IoT — Production Deployment & Operations Architecture

**Date:** 2026-11-11  
**Architecture:** Edge Security Gateway / Central SOC Collector  

---

## 1. Deployment Topologies

Pahredaar-IoT supports two deployment topologies:

### Topology 1: Standalone Smart Gateway (Edge Deployment)
Ideal for branch offices, smart homes, or isolated OT/ICS environments:
```
[IoT Devices: Cameras / Plugs / Sensors]
                 │
                 ▼
       [Local Router / Switch]
                 │ (SPAN / Mirror Port)
                 ▼
       [Zeek Network Sensor]
                 │ (Local pipe / conn.log)
                 ▼
    [Pahredaar-IoT Edge Box]
    ├── Ingestion API (FastAPI)
    ├── Multi-Modal AI Engine
    ├── Local Storage (SQLite WAL)
    └── Dashboard UI (Port 4173)
```

### Topology 2: Distributed Multi-Sensor Collector
Ideal for enterprise campus networks:
```
[Subnet A Sensor] ──┐
[Subnet B Sensor] ──┼──> [Pahredaar-IoT Central Appliance]
[Subnet C Sensor] ──┘         │
                              ├── Token-Authenticated /api/ingest
                              ├── Hybrid ML Evaluation
                              └── Live WebSocket Broadcast to SOC
```

---

## 2. Health & Diagnostic Diagnostics

The `/api/health` endpoint provides comprehensive diagnostic state:
```json
{
  "status": "ok",
  "api_health": "healthy",
  "database_health": "healthy",
  "models_loaded": true,
  "open_set_enabled": true,
  "open_set_version": "open_set_v1",
  "temporal_enabled": true,
  "temporal_version": "temporal_v1",
  "graph_enabled": true,
  "graph_version": "graph_v1",
  "risk_engine_enabled": true,
  "risk_engine_version": "hierarchical_v2",
  "active_features": {
    "treeshap": true,
    "temporal": true,
    "graph": true,
    "hierarchical_risk": true
  }
}
```

---

## 3. Production Hardening Checklist

1. **Explicit CORS**: Update `CORS_ORIGINS` in `.env` from `["*"]` to exact host domains.
2. **Sensor Authentication**: Set `ENABLE_INGEST_AUTH=true` and issue distinct `API_KEY` secrets.
3. **Database Maintenance**: SQLite runs in WAL (Write-Ahead Logging) mode. Automate daily vacuuming and online backups.
4. **Log Retention**: Implement a log rotation schedule on `storage.py` flows table (prune flows $> 30$ days old).
