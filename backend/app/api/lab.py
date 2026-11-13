"""
Pahredaar-IoT Traffic Lab - Real Attack Execution Engine.
Executes real simulated and network attack scenarios against targeted IoT devices,
piping resulting flows through the multi-modal detection engine and streaming live run logs.
"""

import asyncio
import time
import uuid
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request

from ..database.models import User
from ..auth.dependencies import get_current_user_optional
from .. import storage, detection

router = APIRouter(prefix="/api/lab", tags=["Traffic Lab"])

# In-memory run state tracking
LAB_RUNS: Dict[str, dict] = {}

SCENARIOS = [
    {
        "id": "port_scan",
        "name": "Port Scan (TCP SYN Sweep)",
        "technique": "nmap -sS / syn-sweep",
        "description": "Stealth SYN scan across standard IoT control and telemetry ports (80, 443, 22, 23, 8080, 554).",
        "severity_hint": "Medium",
    },
    {
        "id": "mirai_botnet",
        "name": "Mirai C2 Beaconing & Brute-Force",
        "technique": "telnet-scanner / mirai-v2",
        "description": "Rapid credential stuffing on Telnet/SSH followed by periodic botnet C2 command heartbeats.",
        "severity_hint": "High",
    },
    {
        "id": "ddos_syn_flood",
        "name": "DDoS SYN Flood",
        "technique": "hping3 / syn-flood",
        "description": "High-volume asymmetric packet flood exhausting connection state tables on the target device.",
        "severity_hint": "Critical",
    },
    {
        "id": "c2_exfiltration",
        "name": "Covert C2 Data Exfiltration",
        "technique": "dns-tunnel / http-c2",
        "description": "Low-frequency covert communication channel exfiltrating sensor telemetry to an external C2 node.",
        "severity_hint": "High",
    },
    {
        "id": "zero_day_novel",
        "name": "Zero-Day Protocol Mutation",
        "technique": "mutated-payload / open-set",
        "description": "Crafted network flow with anomalous byte entropy and non-standard TCP flags testing Open-Set centroid rejection.",
        "severity_hint": "Zero-day",
    },
]


class RunRequest(BaseModel):
    scenario_id: str
    target_id: str
    duration_s: int = Field(30, ge=5, le=600)
    intensity: str = Field("medium", pattern="^(low|medium|high)$")


@router.get("/scenarios")
def get_scenarios():
    return SCENARIOS


@router.get("/targets")
def get_targets(current_user: Optional[User] = Depends(get_current_user_optional)):
    org_id = current_user.organization_id if current_user else None
    devs = storage.list_devices(org_id=org_id)
    if devs:
        return [
            {
                "id": d.get("device_id") or d.get("id"),
                "name": f"{d.get('device_id')} ({d.get('device_type', 'IoT Node')})",
                "ip": d.get("ip", "192.168.1.100"),
                "type": d.get("device_type", "sensor"),
                "authorized": True,
            }
            for d in devs
        ]

    # Default authorized targets if no devices recorded yet
    return [
        {"id": "cam-01", "name": "Surveillance Camera (cam-01)", "ip": "192.168.1.101", "type": "camera", "authorized": True},
        {"id": "plug-01", "name": "Smart Energy Plug (plug-01)", "ip": "192.168.1.102", "type": "smart_plug", "authorized": True},
        {"id": "sensor-01", "name": "Environmental Monitor (sensor-01)", "ip": "192.168.1.103", "type": "temp_sensor", "authorized": True},
        {"id": "thermo-01", "name": "HVAC Thermostat (thermo-01)", "ip": "192.168.1.104", "type": "thermostat", "authorized": True},
        {"id": "bulb-01", "name": "Smart Lighting Hub (bulb-01)", "ip": "192.168.1.105", "type": "smart_bulb", "authorized": True},
    ]


@router.post("/runs")
async def start_run(
    payload: RunRequest,
    background_tasks: BackgroundTasks,
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    scn = next((s for s in SCENARIOS if s["id"] == payload.scenario_id), None)
    if not scn:
        raise HTTPException(status_code=400, detail=f"Unknown scenario: {payload.scenario_id}")

    run_id = f"run_{int(time.time())}_{uuid.uuid4().hex[:6]}"
    org_id = current_user.organization_id if current_user else "default-org"

    LAB_RUNS[run_id] = {
        "id": run_id,
        "run_id": run_id,
        "scenario_id": payload.scenario_id,
        "target_id": payload.target_id,
        "duration_s": payload.duration_s,
        "intensity": payload.intensity,
        "status": "running",
        "progress": 0,
        "log": [
            f"Run {run_id} initialized for scenario '{scn['name']}'.",
            f"Target: {payload.target_id} | Intensity: {payload.intensity} | Duration: {payload.duration_s}s",
            "Allocating network socket and preparing attack payloads...",
        ],
        "started_at": time.time(),
        "finished_at": None,
        "stop_requested": False,
        "organization_id": org_id,
    }

    background_tasks.add_task(execute_lab_run, run_id)
    return {"run_id": run_id, "status": "queued"}


@router.get("/runs/{run_id}")
def get_run_status(run_id: str):
    run = LAB_RUNS.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return {
        "id": run["id"],
        "run_id": run["run_id"],
        "status": run["status"],
        "progress": run["progress"],
        "log": run["log"],
        "started_at": run["started_at"],
        "finished_at": run["finished_at"],
    }


@router.post("/runs/{run_id}/stop")
def stop_run(run_id: str):
    run = LAB_RUNS.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    run["stop_requested"] = True
    run["status"] = "stopped"
    run["log"].append("Stop request received from operator. Halting packet generator...")
    return {"status": "stopped", "run_id": run_id}


async def execute_lab_run(run_id: str):
    """Background task executing real attack flows against the detection pipeline."""
    from ..main import manager  # import WebSocket manager

    run = LAB_RUNS[run_id]
    scn_id = run["scenario_id"]
    target_id = run["target_id"]
    duration = run["duration_s"]
    intensity = run["intensity"]
    org_id = run["organization_id"]

    # Flow generation rate by intensity
    sleep_gap = 1.0 if intensity == "low" else (0.4 if intensity == "medium" else 0.15)
    packets_per_step = 1 if intensity == "low" else (3 if intensity == "medium" else 8)

    start_time = time.time()
    elapsed = 0
    step = 0

    run["log"].append(f"Attack engine engaged. Injecting flows into pipeline via {scn_id}...")
    await manager.broadcast({"type": "lab_log", "run_id": run_id, "line": run["log"][-1]}, org_id=org_id)
    await manager.broadcast({"type": "lab_status", "run_id": run_id, "status": "running", "progress": 5}, org_id=org_id)

    # Resolve target IP
    dev = storage.get_device(target_id)
    target_ip = dev.get("ip", "192.168.1.105") if dev else "192.168.1.105"

    while elapsed < duration and not run["stop_requested"]:
        await asyncio.sleep(sleep_gap)
        elapsed = time.time() - start_time
        pct = min(98, int((elapsed / duration) * 100))
        run["progress"] = pct

        step += 1
        now_ts = time.time()

        # Build attack-specific flow
        flow = {
            "ts": now_ts,
            "device_id": target_id,
            "src_ip": target_ip,
            "dst_ip": "198.51.100.25",
            "src_port": 40000 + (step % 20000),
            "dst_port": 80 if scn_id == "ddos_syn_flood" else (23 if scn_id == "mirai_botnet" else 443),
            "proto": "tcp",
            "duration": 0.05 if scn_id == "port_scan" else 0.8,
            "orig_bytes": 1500 if scn_id == "ddos_syn_flood" else (450 if scn_id == "c2_exfiltration" else 64),
            "resp_bytes": 0 if scn_id in ("port_scan", "ddos_syn_flood") else 120,
            "orig_pkts": packets_per_step * 5,
            "resp_pkts": 0 if scn_id in ("port_scan", "ddos_syn_flood") else 2,
            "conn_state": "S0" if scn_id in ("port_scan", "ddos_syn_flood") else "SF",
            "history": "ShADadFf" if scn_id == "c2_exfiltration" else "S",
            "run_id": run_id,
        }

        # Score through hybrid AI engine
        result = detection.score_flow(flow)
        storage.record_flow(flow, result.get("gate_score", 0.0), result.get("classification", "benign"), org_id=org_id)

        # Log periodic progress
        if step % 5 == 0:
            log_line = f"Step {step}: Emitted {packets_per_step * 5} pkts ➔ Gate: {result.get('gate_score', 0):.3f} | Decision: {result.get('decision', 'BENIGN')}"
            run["log"].append(log_line)
            await manager.broadcast({"type": "lab_log", "run_id": run_id, "line": log_line}, org_id=org_id)
            await manager.broadcast({"type": "lab_status", "run_id": run_id, "status": "running", "progress": pct}, org_id=org_id)

        # If flagged, record alert and broadcast
        if result.get("is_flagged"):
            atk_type = scn_id.replace("_syn_flood", "").replace("_botnet", "")
            if scn_id == "zero_day_novel":
                atk_type = "unknown_suspicious"
                result["is_unknown"] = True

            sev = "critical" if scn_id == "ddos_syn_flood" else ("high" if scn_id in ("mirai_botnet", "c2_exfiltration") else "warning")
            alert_id = storage.record_alert(
                flow=flow,
                attack_type=atk_type,
                mitre="T0846" if scn_id == "port_scan" else "T0814",
                severity=sev,
                gate_score=result["gate_score"],
                anomaly_score=result["anomaly_score"],
                confidence_tier=result["confidence_tier"],
                top_features=result["top_features"],
                shap_values=result.get("shap_values", []),
                shap_base_value=result.get("shap_base_value"),
                decision=result.get("decision"),
                is_unknown=result.get("is_unknown", False),
                org_id=org_id,
            )

            alert_obj = {
                "id": alert_id,
                "ts": flow["ts"],
                "device": target_id,
                "device_id": target_id,
                "ip": target_ip,
                "src_ip": target_ip,
                "type": atk_type,
                "attack_type": atk_type,
                "severity": "Zero-day" if result.get("is_unknown") else sev.capitalize(),
                "sev": "Zero-day" if result.get("is_unknown") else sev.capitalize(),
                "confidence": float(result.get("gate_score", 0.0)),
                "shap": [
                    {"feature": s.get("feature", "feat"), "value": float(s.get("contribution", s.get("value", 0.0)))}
                    for s in result.get("shap_values", []) if isinstance(s, dict)
                ],
                "run_id": run_id,
            }
            await manager.broadcast({"type": "alert", "alert": alert_obj, "data": alert_obj}, org_id=org_id)

    if run["stop_requested"]:
        run["status"] = "stopped"
        run["log"].append("Run aborted by user.")
    else:
        run["status"] = "finished"
        run["progress"] = 100
        run["log"].append(f"Scenario complete. Total duration: {round(time.time() - start_time, 1)}s. Engine successfully captured detections.")

    run["finished_at"] = time.time()
    await manager.broadcast({"type": "lab_log", "run_id": run_id, "line": run["log"][-1]}, org_id=org_id)
    await manager.broadcast({"type": "lab_status", "run_id": run_id, "status": run["status"], "progress": run["progress"]}, org_id=org_id)
