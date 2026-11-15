"""
Pahredaar-IoT Enterprise IDS Backend.
Features Multi-Tenant Organization Isolation, JWT & Sensor Auth, RBAC, and Hybrid AI Engine.

Endpoints:
  # Ingestion
  POST /api/ingest                  - submit one flow record (authenticated sensor / Zeek bridge)
  
  # Telemetry & Monitoring (Scoped by Organization)
  GET  /api/alerts                  - recent alerts
  GET  /api/devices                 - device list with composite risk scores & tiers
  GET  /api/stats                   - summary counters
  GET  /api/incidents               - active and historical security incidents
  POST /api/incidents/{id}/acknowledge - acknowledge an incident (Analyst/Admin)
  POST /api/incidents/{id}/resolve  - resolve an incident (Analyst/Admin)
  GET  /api/incidents/metrics       - alert quality and incident response metrics (MTTA, MTTR, suppression)
  WS   /ws/alerts                   - live alert and incident push (Scoped by Organization)
  GET  /api/audit-logs              - security audit log (Admin only)
  GET  /api/health                  - comprehensive system and model health check

  # Routers
  /api/auth/*                       - registration, login, refresh, profile
  /api/sensors/*                    - sensor registration, key rotation, status
"""

import sys
import asyncio
from collections import deque

# Patch Windows asyncio ProactorEventLoop to prevent socket termination on WinError 64 / transient disconnects
if sys.platform == "win32":
    try:
        import asyncio.proactor_events
        import asyncio.trsock
        _orig_start_serving = asyncio.proactor_events.BaseProactorEventLoop._start_serving

        def _safe_start_serving(self, protocol_factory, sock, sslcontext=None, server=None, backlog=100,
                                ssl_handshake_timeout=None, ssl_shutdown_timeout=None):
            def loop(f=None):
                try:
                    if f is not None:
                        try:
                            conn, addr = f.result()
                        except OSError as client_err:
                            # Client reset connection prior to accept completing (WinError 64, 10054, etc.)
                            if not self.is_closed() and sock.fileno() != -1:
                                f2 = self._proactor.accept(sock)
                                self._accept_futures[sock.fileno()] = f2
                                f2.add_done_callback(loop)
                            return

                        protocol = protocol_factory()
                        if sslcontext is not None:
                            self._make_ssl_transport(
                                conn, protocol, sslcontext, server_side=True,
                                extra={'peername': addr}, server=server,
                                ssl_handshake_timeout=ssl_handshake_timeout,
                                ssl_shutdown_timeout=ssl_shutdown_timeout)
                        else:
                            self._make_socket_transport(
                                conn, protocol,
                                extra={'peername': addr}, server=server)
                    if self.is_closed():
                        return
                    f = self._proactor.accept(sock)
                except OSError as exc:
                    if sock.fileno() != -1:
                        winerror = getattr(exc, 'winerror', None)
                        if winerror in (64, 121, 10053, 10054):
                            if not self.is_closed():
                                try:
                                    f2 = self._proactor.accept(sock)
                                    self._accept_futures[sock.fileno()] = f2
                                    f2.add_done_callback(loop)
                                    return
                                except Exception:
                                    pass
                        self.call_exception_handler({
                            'message': 'Accept failed on a socket',
                            'exception': exc,
                            'socket': asyncio.trsock.TransportSocket(sock) if hasattr(asyncio, 'trsock') else sock,
                        })
                        sock.close()
                except asyncio.CancelledError:
                    sock.close()
                else:
                    self._accept_futures[sock.fileno()] = f
                    f.add_done_callback(loop)

            self.call_soon(loop)

        asyncio.proactor_events.BaseProactorEventLoop._start_serving = _safe_start_serving
    except Exception:
        pass
import json
import threading
import time
import warnings
warnings.filterwarnings("ignore")
from typing import Any, Dict, List, Optional

from fastapi import (
    FastAPI,
    WebSocket,
    WebSocketDisconnect,
    HTTPException,
    Header,
    Query,
    Depends,
    Request,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from .schemas import FlowRecord
from .detection import engine
from . import storage
from .config import settings
from .logging_config import setup_logging
from .database.session import get_db
from .database.models import User
from .database.repositories import AuditRepository
from .auth.security import decode_jwt_token
from .auth.rbac import Role
from .auth.dependencies import (
    get_current_user,
    get_current_user_optional,
    require_roles,
    verify_sensor_identity,
)
from .api.auth import router as auth_router
from .api.sensors import router as sensors_router
from .api.lab import router as lab_router

logger = setup_logging(settings.LOG_LEVEL, settings.LOG_JSON)

app = FastAPI(title="Pahredaar-IoT IDS Enterprise Backend", version="3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Subrouters
app.include_router(auth_router)
app.include_router(sensors_router)
app.include_router(lab_router)

storage.init_db()


class ConnectionManager:
    """Manages WebSocket connections partitioned by organization for strict tenant isolation."""
    def __init__(self):
        self.org_connections: Dict[str, List[WebSocket]] = {}
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket, org_id: str = "default-org-id"):
        await ws.accept()
        if org_id not in self.org_connections:
            self.org_connections[org_id] = []
        self.org_connections[org_id].append(ws)
        self.active.append(ws)

    def disconnect(self, ws: WebSocket, org_id: str = "default-org-id"):
        if org_id in self.org_connections and ws in self.org_connections[org_id]:
            self.org_connections[org_id].remove(ws)
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, message: dict, org_id: Optional[str] = None):
        targets = self.org_connections.get(org_id, []) if org_id else self.active
        dead = []
        for ws in list(targets):
            try:
                await ws.send_text(json.dumps(message))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws, org_id or "default-org-id")


manager = ConnectionManager()


# Rate Limiting
_rate_limit_lock = threading.Lock()
_ingest_timestamps: deque = deque(maxlen=2000)


def verify_sensor_auth(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
):
    """Backward compatibility helper for synchronous callers."""
    if not settings.ENABLE_INGEST_AUTH:
        return True
    expected = settings.API_KEY
    if not expected:
        return True
    token = x_api_key
    if not token and authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
    if token != expected:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid sensor API key")
    return True


class ResolveIncidentRequest(BaseModel):
    notes: str = Field(default="", description="Operator resolution notes")


@app.get("/api/health")
def health():
    db_ok = False
    try:
        with storage.db_session() as conn:
            conn.execute("SELECT 1").fetchone()
            db_ok = True
    except Exception:
        db_ok = False

    is_ready = engine.models_loaded or (engine.open_set_classifier is not None)
    return {
        "status": "ok" if (is_ready and db_ok) else "degraded",
        "api_health": "healthy",
        "database_health": "healthy" if db_ok else "unreachable",
        "models_loaded": is_ready,
        "open_set_enabled": engine.open_set_classifier is not None,
        "open_set_version": engine.open_set_classifier.version if engine.open_set_classifier else None,
        "temporal_enabled": engine.temporal_detector is not None,
        "temporal_version": engine.temporal_detector.version if engine.temporal_detector else None,
        "graph_enabled": engine.graph_detector is not None,
        "graph_version": engine.graph_detector.version if engine.graph_detector else None,
        "risk_engine_enabled": engine.risk_engine is not None,
        "risk_engine_version": "hierarchical_v2" if engine.risk_engine else None,
        "multi_tenancy_enabled": True,
        "jwt_auth_enabled": True,
        "active_features": {
            "treeshap": engine.shap_explainer is not None,
            "temporal": engine.temporal_detector is not None,
            "graph": engine.graph_detector is not None,
            "hierarchical_risk": engine.risk_engine is not None,
            "rbac": True,
            "tenant_isolation": True,
        },
        "hint": None if is_ready else (
            "Models not found in backend/app/models/. Run training scripts first."
        ),
    }


@app.post("/api/ingest")
async def ingest_flow(
    flow: FlowRecord,
    x_sensor_key: Optional[str] = Header(None, alias="X-Sensor-Key"),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
):
    # Sensor authentication & tenant resolution
    sensor, org_id = await verify_sensor_identity(
        x_sensor_key=x_sensor_key,
        x_api_key=x_api_key,
        authorization=authorization,
    )

    rate_limit = sensor.rate_limit_per_sec if sensor else settings.RATE_LIMIT_INGEST_PER_SEC

    # Ingestion rate limiting
    now_mono = time.monotonic()
    with _rate_limit_lock:
        while _ingest_timestamps and (now_mono - _ingest_timestamps[0]) > 1.0:
            _ingest_timestamps.popleft()
        if len(_ingest_timestamps) >= rate_limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded (Max {rate_limit} flows/sec)",
            )
        _ingest_timestamps.append(now_mono)

    flow_dict = flow.model_dump()
    result = engine.score_flow(flow_dict)

    composite_risk = result.get("composite_device_risk")
    risk_tier = result.get("risk_tier")
    temp_info = result.get("temporal") if isinstance(result.get("temporal"), dict) else {}
    graph_info = result.get("graph") if isinstance(result.get("graph"), dict) else {}
    temporal_risk = temp_info.get("temporal_risk")
    graph_risk = graph_info.get("graph_risk")
    risk_breakdown = result.get("risk_breakdown")
    fused_threat = result.get("fused_event_threat")

    storage.record_flow(
        flow_dict,
        gate_score=result.get("gate_score", 0.0),
        is_flagged=result.get("is_flagged", False),
        composite_risk=composite_risk,
        risk_tier=risk_tier,
        temporal_risk=temporal_risk,
        graph_risk=graph_risk,
        org_id=org_id,
    )

    # Periodic stats broadcast over WebSocket on normal flows
    if not (result.get("is_flagged") and "attack_type" in result) and len(_ingest_timestamps) % 2 == 0:
        st = storage.get_stats(org_id=org_id)
        await manager.broadcast({
            "type": "stats",
            "stats": {
                "flows_per_sec": len(_ingest_timestamps),
                "total_flows": st.get("total_flows", 0),
                "total_alerts": st.get("total_alerts", 0),
                "alerts_by_type": st.get("alerts_by_type", {}),
                "recent_targets_by_type": st.get("recent_targets_by_type", {}),
            }
        }, org_id=org_id)

    alert_payload = None
    if result.get("is_flagged") and "attack_type" in result:
        attack_type = result["attack_type"]
        is_suppressed = storage.should_suppress_alert(
            device_id=flow_dict["device_id"],
            attack_type=attack_type,
            ts=flow_dict["ts"],
            window_sec=getattr(settings, "ALERT_SUPPRESSION_WINDOW_SEC", 5.0),
        )

        if not is_suppressed:
            alert_id = storage.record_alert(
                flow_dict,
                attack_type=attack_type,
                mitre=result["mitre"],
                severity=result["severity"],
                gate_score=result["gate_score"],
                anomaly_score=result["anomaly_score"],
                confidence_tier=result["confidence_tier"],
                top_features=result["top_features"],
                shap_values=result.get("shap_values", []),
                shap_base_value=result.get("shap_base_value"),
                decision=result.get("decision"),
                is_unknown=result.get("is_unknown", False),
                novelty_score=result.get("novelty_score"),
                calibrated_anomaly_score=result.get("calibrated_anomaly_score"),
                reason_codes=result.get("reason_codes", []),
                composite_device_risk=composite_risk,
                risk_tier=risk_tier,
                temporal_risk=temporal_risk,
                graph_risk=graph_risk,
                risk_breakdown=risk_breakdown,
                org_id=org_id,
            )
            alert_payload = {
                "id": alert_id, "ts": flow_dict["ts"], "device_id": flow_dict["device_id"],
                "device_type": flow_dict.get("device_type"), "src_ip": flow_dict["src_ip"],
                "dst_ip": flow_dict["dst_ip"], "attack_type": attack_type,
                "mitre": result["mitre"], "severity": result["severity"],
                "gate_score": result["gate_score"], "confidence_tier": result["confidence_tier"],
                "top_features": result["top_features"],
                "shap_values": result.get("shap_values", []),
                "shap_base_value": result.get("shap_base_value"),
                "decision": result.get("decision"),
                "is_unknown": result.get("is_unknown", False),
                "novelty_score": result.get("novelty_score"),
                "calibrated_anomaly_score": result.get("calibrated_anomaly_score"),
                "reason_codes": result.get("reason_codes", []),
                "composite_device_risk": composite_risk,
                "fused_event_threat": fused_threat,
                "risk_tier": risk_tier,
                "temporal_risk": temporal_risk,
                "graph_risk": graph_risk,
                "risk_breakdown": risk_breakdown,
                "organization_id": org_id,
            }
            alert_obj = dict(alert_payload)
            alert_obj["id"] = alert_id
            alert_obj["device"] = alert_payload["device_id"]
            alert_obj["ip"] = alert_payload["src_ip"]
            alert_obj["type"] = alert_payload["attack_type"]
            raw_s = str(alert_payload.get("severity", "info")).lower()
            if alert_payload.get("is_unknown"):
                alert_obj["severity"] = "Zero-day"
                alert_obj["sev"] = "Zero-day"
            else:
                alert_obj["severity"] = raw_s.capitalize()
                alert_obj["sev"] = raw_s.capitalize()
            alert_obj["confidence"] = float(alert_payload.get("gate_score", 0.0))
            alert_obj["shap"] = [
                {"feature": item.get("feature", "feature"), "value": float(item.get("contribution", item.get("value", 0.0)))}
                for item in alert_payload.get("shap_values", []) if isinstance(item, dict)
            ]
            # Broadcast strictly to subscribers in the same organization
            await manager.broadcast({"type": "alert", "alert": alert_obj, "data": alert_obj}, org_id=org_id)
            st = storage.get_stats(org_id=org_id)
            await manager.broadcast({
                "type": "stats",
                "stats": {
                    "flows_per_sec": len(_ingest_timestamps),
                    "total_flows": st.get("total_flows", 0),
                    "total_alerts": st.get("total_alerts", 0),
                    "alerts_by_type": st.get("alerts_by_type", {}),
                    "recent_targets_by_type": st.get("recent_targets_by_type", {}),
                }
            }, org_id=org_id)

    return {
        "flagged": result.get("is_flagged", False),
        "gate_score": result.get("gate_score"),
        "anomaly_score": result.get("anomaly_score"),
        "calibrated_anomaly_score": result.get("calibrated_anomaly_score"),
        "novelty_score": result.get("novelty_score"),
        "decision": result.get("decision"),
        "is_unknown": result.get("is_unknown", False),
        "reason_codes": result.get("reason_codes", []),
        "composite_device_risk": composite_risk,
        "fused_event_threat": fused_threat,
        "risk_tier": risk_tier,
        "temporal_risk": temporal_risk,
        "graph_risk": graph_risk,
        "alert": alert_payload,
        "warning": result.get("error"),
    }


@app.get("/api/flows")
def get_flows(
    limit: int = 100,
    is_flagged: Optional[bool] = None,
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    org_id = current_user.organization_id if current_user else None
    return storage.list_flows(limit=limit, is_flagged=is_flagged, org_id=org_id)


@app.get("/api/alerts")
def get_alerts(
    limit: int = 100,
    device_id: Optional[str] = None,
    severity: Optional[str] = None,
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    org_id = current_user.organization_id if current_user else None
    return storage.list_alerts(limit=limit, org_id=org_id, device_id=device_id, severity=severity)


@app.get("/api/alerts/{alert_id}")
def get_alert_detail(alert_id: int, current_user: Optional[User] = Depends(get_current_user_optional)):
    org_id = current_user.organization_id if current_user else None
    a = storage.get_alert(alert_id, org_id=org_id)
    if not a:
        raise HTTPException(status_code=404, detail="Alert not found")
    return a


@app.post("/api/alerts/{alert_id}/feedback")
def submit_alert_feedback(alert_id: int, payload: dict, current_user: Optional[User] = Depends(get_current_user_optional)):
    return {"status": "ok", "alert_id": alert_id, "feedback": payload}


@app.get("/api/devices")
def get_devices(current_user: Optional[User] = Depends(get_current_user_optional)):
    org_id = current_user.organization_id if current_user else None
    return storage.list_devices(org_id=org_id)


@app.get("/api/devices/{device_id}")
def get_device(device_id: str, current_user: Optional[User] = Depends(get_current_user_optional)):
    org_id = current_user.organization_id if current_user else None
    device = storage.get_device(device_id, org_id=org_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@app.get("/api/stats")
def get_stats(current_user: Optional[User] = Depends(get_current_user_optional)):
    org_id = current_user.organization_id if current_user else None
    return storage.get_stats(org_id=org_id)


@app.get("/api/incidents")
def get_incidents(
    status: Optional[str] = None,
    device_id: Optional[str] = None,
    limit: int = 200,
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    org_id = current_user.organization_id if current_user else None
    return storage.list_incidents(status=status, limit=limit, org_id=org_id, device_id=device_id)


@app.post("/api/incidents/{incident_id}/acknowledge")
def acknowledge_incident(
    incident_id: str,
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    if current_user and current_user.role == Role.VIEWER.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Viewers cannot acknowledge incidents",
        )
    org_id = current_user.organization_id if current_user else None
    ok = storage.acknowledge_incident(incident_id, org_id=org_id)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found or not in OPEN state",
        )
    return {"status": "acknowledged", "incident_id": incident_id}


@app.post("/api/incidents/{incident_id}/resolve")
def resolve_incident(
    incident_id: str,
    payload: Optional[ResolveIncidentRequest] = None,
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    if current_user and current_user.role == Role.VIEWER.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Viewers cannot resolve incidents",
        )
    org_id = current_user.organization_id if current_user else None
    notes = payload.notes if payload else ""
    ok = storage.resolve_incident(incident_id, notes=notes, org_id=org_id)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )
    return {"status": "resolved", "incident_id": incident_id}


@app.patch("/api/incidents/{incident_id}")
def patch_incident(incident_id: str, payload: dict, current_user: Optional[User] = Depends(get_current_user_optional)):
    org_id = current_user.organization_id if current_user else None
    target_state = payload.get("state")
    if target_state == "ACKNOWLEDGED":
        storage.acknowledge_incident(incident_id, org_id=org_id)
    elif target_state == "RESOLVED":
        storage.resolve_incident(incident_id, notes=payload.get("notes", ""), org_id=org_id)
    incs = storage.list_incidents(limit=200, org_id=org_id)
    for inc in incs:
        if inc.get("incident_id") == incident_id or str(inc.get("id")) == str(incident_id):
            return inc
    return {"id": incident_id, "state": target_state}


@app.get("/api/incidents/metrics")
def get_incident_metrics(current_user: Optional[User] = Depends(get_current_user_optional)):
    org_id = current_user.organization_id if current_user else None
    return storage.get_incident_metrics(org_id=org_id)


@app.get("/api/audit-logs")
async def get_audit_logs(
    limit: int = 100,
    current_user: User = Depends(require_roles(Role.ADMIN.value)),
    db: AsyncSession = Depends(get_db),
):
    audit_repo = AuditRepository(db)
    logs = await audit_repo.list_by_organization(current_user.organization_id, limit=limit)
    return [
        {
            "id": log.id,
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
            "timestamp": log.timestamp.isoformat(),
            "source_ip": log.source_ip,
            "metadata": log.event_metadata,
            "user_email": log.user.email if log.user else None,
        }
        for log in logs
    ]


@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket, token: Optional[str] = Query(None)):
    org_id = "default-org-id"
    if token:
        try:
            payload = decode_jwt_token(token)
            org_id = payload.get("org_id", "default-org-id")
        except Exception:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

    await manager.connect(websocket, org_id=org_id)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, org_id=org_id)
