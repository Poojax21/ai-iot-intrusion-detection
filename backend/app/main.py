"""
IoT IDS backend with Multi-Modal Hybrid Engine, Security Hardening & Incident Tracking.

Endpoints:
  POST /api/ingest                  - submit one flow record (sensor / Zeek bridge)
  GET  /api/alerts                  - recent alerts
  GET  /api/devices                 - device list with composite risk scores & tiers
  GET  /api/stats                   - summary counters
  GET  /api/incidents               - active and historical security incidents
  POST /api/incidents/{id}/acknowledge - acknowledge an incident
  POST /api/incidents/{id}/resolve  - resolve an incident
  GET  /api/incidents/metrics       - alert quality and incident response metrics (MTTA, MTTR, suppression)
  WS   /ws/alerts                   - live alert and incident push
  GET  /api/health                  - comprehensive system and model health check
"""

import asyncio
from collections import deque
import json
import threading
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Header, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .schemas import FlowRecord
from .detection import engine
from . import storage
from .config import settings
from .logging_config import setup_logging

logger = setup_logging(settings.LOG_LEVEL, settings.LOG_JSON)

app = FastAPI(title="Pahredaar-IoT IDS Backend", version="2.5")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

storage.init_db()


class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(json.dumps(message))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


# Rate Limiting & Sensor Auth
_rate_limit_lock = threading.Lock()
_ingest_timestamps: deque = deque(maxlen=2000)


def verify_sensor_auth(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
):
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
        "active_features": {
            "treeshap": engine.shap_explainer is not None,
            "temporal": engine.temporal_detector is not None,
            "graph": engine.graph_detector is not None,
            "hierarchical_risk": engine.risk_engine is not None,
        },
        "hint": None if is_ready else (
            "Models not found in backend/app/models/. Run training scripts first."
        ),
    }


@app.post("/api/ingest")
async def ingest_flow(
    flow: FlowRecord,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
):
    # Sensor authentication check
    verify_sensor_auth(x_api_key=x_api_key, authorization=authorization)

    # Ingestion rate limiting
    now_mono = time.monotonic()
    with _rate_limit_lock:
        while _ingest_timestamps and (now_mono - _ingest_timestamps[0]) > 1.0:
            _ingest_timestamps.popleft()
        if len(_ingest_timestamps) >= settings.RATE_LIMIT_INGEST_PER_SEC:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded (Max {settings.RATE_LIMIT_INGEST_PER_SEC} flows/sec)",
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
    )

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
            }
            await manager.broadcast({"type": "alert", "data": alert_payload})

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


@app.get("/api/alerts")
def get_alerts(limit: int = 100):
    return storage.list_alerts(limit=limit)


@app.get("/api/devices")
def get_devices():
    return storage.list_devices()


@app.get("/api/stats")
def get_stats():
    return storage.get_stats()


@app.get("/api/incidents")
def get_incidents(status: Optional[str] = None, limit: int = 50):
    return storage.list_incidents(status=status, limit=limit)


@app.post("/api/incidents/{incident_id}/acknowledge")
def acknowledge_incident(incident_id: str):
    ok = storage.acknowledge_incident(incident_id)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found or not in OPEN state",
        )
    return {"status": "acknowledged", "incident_id": incident_id}


@app.post("/api/incidents/{incident_id}/resolve")
def resolve_incident(incident_id: str, payload: Optional[ResolveIncidentRequest] = None):
    notes = payload.notes if payload else ""
    ok = storage.resolve_incident(incident_id, notes=notes)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )
    return {"status": "resolved", "incident_id": incident_id}


@app.get("/api/incidents/metrics")
def get_incident_metrics():
    return storage.get_incident_metrics()


@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
