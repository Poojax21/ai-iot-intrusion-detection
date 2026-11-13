# API Security & Authorization Matrix

This document provides a comprehensive security and RBAC access matrix across all HTTP and WebSocket endpoints in Pahredaar-IoT.

---

## 1. Authentication Schemes

- **`Bearer <JWT>`**: Standard HTTP `Authorization: Bearer <access_token>` header.
- **`X-Sensor-Key: <key>`**: API key header for network traffic collectors.
- **`Query: ?token=<JWT>`**: Query parameter for WebSocket initial handshake.

---

## 2. Comprehensive Endpoint Matrix

| Method | Endpoint | Allowed Roles / Auth | Rate Limit (Tier) | Description | Response Codes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/health` | Public / Anonymous | None | Engine and DB status | `200` |
| `POST` | `/api/auth/register` | Public / Admin | 10 / min | Register new user | `201`, `400`, `422` |
| `POST` | `/api/auth/login` | Public | 10 / min | Login with username/password | `200`, `401`, `422` |
| `POST` | `/api/auth/refresh` | Public | 30 / min | Refresh token rotation | `200`, `401`, `422` |
| `POST` | `/api/auth/logout` | `admin`, `analyst`, `viewer` | Standard | Invalidate active refresh token | `200`, `401` |
| `GET` | `/api/auth/me` | `admin`, `analyst`, `viewer` | Standard | Current user profile & roles | `200`, `401` |
| `POST` | `/api/ingest` | `sensor`, `admin`, Valid API Key | Sensor Config (e.g. 100/s) | Real-time network flow ingestion | `200`, `400`, `401`, `429` |
| `POST` | `/api/ingest/batch` | `sensor`, `admin`, Valid API Key | Sensor Config | Bulk flow ingestion | `200`, `400`, `401`, `429` |
| `GET` | `/api/alerts` | `admin`, `analyst`, `viewer` | Standard | Query alert stream (org-scoped) | `200`, `401`, `403` |
| `GET` | `/api/devices` | `admin`, `analyst`, `viewer` | Standard | Device posture list (org-scoped) | `200`, `401`, `403` |
| `GET` | `/api/devices/{id}` | `admin`, `analyst`, `viewer` | Standard | Single device details (IDOR safe)| `200`, `401`, `404` |
| `GET` | `/api/incidents` | `admin`, `analyst`, `viewer` | Standard | Incident list & lifecycle metrics| `200`, `401`, `403` |
| `POST` | `/api/incidents/{id}/acknowledge` | `admin`, `analyst` | Standard | Transition status to ACKNOWLEDGED| `200`, `401`, `403`, `404` |
| `POST` | `/api/incidents/{id}/resolve` | `admin`, `analyst` | Standard | Transition status to RESOLVED | `200`, `401`, `403`, `404` |
| `GET` | `/api/stats` | `admin`, `analyst`, `viewer` | Standard | Ingestion & threat statistics | `200`, `401`, `403` |
| `POST` | `/api/sensors` | `admin` | Admin Tier | Provision a new edge sensor | `201`, `401`, `403` |
| `GET` | `/api/sensors` | `admin` | Admin Tier | List all registered sensors | `200`, `401`, `403` |
| `POST` | `/api/sensors/{id}/rotate-key` | `admin` | Admin Tier | Rotate sensor API key | `200`, `401`, `403`, `404` |
| `POST` | `/api/sensors/{id}/deactivate`| `admin` | Admin Tier | Deactivate sensor immediately | `200`, `401`, `403`, `404` |
| `GET` | `/api/audit-logs` | `admin` | Admin Tier | Query immutable security audit log| `200`, `401`, `403` |
| `WS` | `/ws/alerts` | `admin`, `analyst`, `viewer` | WebSocket Max | Real-time WebSocket alerts | `101`, `1008` (Unauthorized) |

---

## 3. Defense-in-Depth Measures

1. **Strict Input Validation**: All payloads validated with Pydantic schemas; unexpected fields stripped.
2. **Security Headers**: Standard secure HTTP response headers applied.
3. **Audit Trails**: Security-sensitive operations (sensor rotation, incident resolution, token reuse) trigger immutable audit log entries.
4. **Tenant Scoping**: All resource identifiers checked against caller's `organization_id`.
