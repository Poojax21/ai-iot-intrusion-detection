# Pahredaar-IoT — Component H: Production Security & Reliability Audit

**Date:** 2026-11-11  
**Scope:** `backend/app/` (API Ingestion, Storage, WebSockets, Environment, Concurrency)  

---

## 1. Security Architecture & Threat Model

Pahredaar-IoT functions as an edge network security appliance, ingesting telemetry from IoT sensors and Zeek packet monitors, evaluating AI inference models, and delivering alerts to an administrative SOC interface. 

The threat model identifies five primary attack vectors:
1. **Sensor Ingestion Spoofing / DoS:** Rogue LAN hosts forging telemetry or flooding `/api/ingest` to exhaust CPU/memory.
2. **Database Concurrency & Locking:** Multi-threaded writes corrupting or locking the SQLite database.
3. **Model Tampering:** Unauthorized modification or overwrite of serialized model weights (`.pkl`, `.pt`).
4. **WebSocket Unauthorized Monitoring:** Unauthorized eavesdropping on live network alert feeds.
5. **Secret Exposure & Credential Leakage:** Hardcoded tokens or database credentials committed to version control.

---

## 2. Hardening Measures Implemented

### 2.1 Sensor Authentication & Ingestion Authorization
- Configurable sensor API key protection via `ENABLE_INGEST_AUTH=true`.
- Accepts standard `X-API-Key` headers or `Authorization: Bearer <token>`.
- Unauthorized requests receive HTTP 401 Unauthorized before triggering model inference.

### 2.2 Volumetric Rate Limiting
- In-memory sliding window rate limiter enforcing `RATE_LIMIT_INGEST_PER_SEC` (default: 500 requests/sec).
- High-frequency flood attempts receive HTTP 429 Too Many Requests, protecting the Scikit-Learn and PyTorch pipelines from CPU starvation.

### 2.3 Concurrency & Database Connection Safety
- Replaced naked SQLite connections with a context-managed `db_session()` pattern with a 10.0-second busy timeout and explicit connection teardown.
- Completely resolved all `ResourceWarning: unclosed database` issues and Windows file-lock contentions.
- Database operations are wrapped with re-entrant thread locks (`threading.Lock()`).

### 2.4 Model Immutability & Safe Deserialization
- Model weights (`.pkl`, `.pt`, `.json`) are stored in read-only application directories (`backend/app/models/`).
- No API endpoints accept model uploads, weight updates, or arbitrary pickled objects.
- Model loading enforces strict schema validation matching `FEATURE_COLUMNS`.

### 2.5 Input Sanitization & Privacy Preservation
- Inbound flow records are strictly validated via Pydantic v2 schemas (`schemas.FlowRecord`).
- Payloads are never captured, stored, or transmitted—only L3/L4 network metadata.
- Source and destination IPs are converted to opaque SHA-256 hashed device IDs at the ingestion boundary.

### 2.6 WebSocket Protection
- Origin checking aligned with `CORS_ORIGINS`.
- Connection manager automatically prunes dead sockets on network disconnection, preventing socket descriptor leaks.

---

## 3. Database Backup & Disaster Recovery Procedures

To create a consistent, point-in-time backup of the active database while the backend is running:

```powershell
# Windows PowerShell safe backup using SQLite online backup API
py -3.14 -c "import sqlite3; src = sqlite3.connect('backend/app/iot_ids.db'); dst = sqlite3.connect('backend/app/backup_iot_ids.db'); src.backup(dst); dst.close(); src.close(); print('Backup complete!')"
```
