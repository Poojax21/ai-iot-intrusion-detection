"""
IoT IDS backend.

Endpoints:
  POST /api/ingest        - submit one flow record (simulator OR real hardware sensor)
  GET  /api/alerts        - recent alerts
  GET  /api/devices       - device list with risk scores
  GET  /api/stats         - summary counters
  WS   /ws/alerts         - live alert push for the dashboard
  GET  /api/health        - are models loaded, is the service healthy

Fail-open note (plan §11): if models aren't loaded yet (notebook not run),
/api/ingest still accepts and stores flows, just without scoring — it never
blocks traffic ingestion because the ML layer is unavailable.
"""

import asyncio
import json
from typing import List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .schemas import FlowRecord
from .detection import engine
from . import storage
from .config import settings
from .logging_config import setup_logging

logger = setup_logging(settings.LOG_LEVEL, settings.LOG_JSON)

app = FastAPI(title="Pahredaar-IoT IDS Backend", version="2.0")

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


@app.get("/api/health")
def health():
    is_ready = engine.models_loaded or (engine.open_set_classifier is not None)
    return {
        "status": "ok",
        "models_loaded": is_ready,
        "open_set_enabled": engine.open_set_classifier is not None,
        "open_set_version": engine.open_set_classifier.version if engine.open_set_classifier else None,
        "hint": None if is_ready else (
            "Models not found in backend/app/models/. Run training/train_model.ipynb or train_open_set first."
        ),
    }


@app.post("/api/ingest")
async def ingest_flow(flow: FlowRecord):
    flow_dict = flow.model_dump()

    result = engine.score_flow(flow_dict)

    storage.record_flow(flow_dict, gate_score=result.get("gate_score", 0.0),
                         is_flagged=result.get("is_flagged", False))

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


@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # We don't expect client messages; just keep the connection alive.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
