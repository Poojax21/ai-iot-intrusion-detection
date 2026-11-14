"""
Pahredaar-IoT Attack Simulation & Detection Engine.
Interactive real-time IoT cybersecurity simulation environment:
- Multi-attack generation (DDoS, DoS, Brute Force, Port Scan, Mirai C2, Zero-Day).
- Legitimate traffic generation (HTTP, Heartbeat, Sensor updates, Temp, Humidity, Status, API).
- Real-time dual terminal streaming (Attack Generator & Target IoT Device).
- Real-time AI detection pipeline integration with live metrics & alert dispatch.
"""

import asyncio
import random
import time
import uuid
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request

from ..database.models import User
from ..auth.dependencies import get_current_user_optional
from .. import storage
from ..detection import engine

router = APIRouter(prefix="/api/lab", tags=["Attack Simulation & Detection"])

# In-memory simulation session registry
LAB_RUNS: Dict[str, dict] = {}

# Device security status cache (device_id -> status: normal | monitoring | suspicious | attack_detected)
DEVICE_SECURITY_STATUS: Dict[str, str] = {}

ATTACK_SCENARIOS = [
    {
        "id": "ddos_syn_flood",
        "name": "DDoS Attack (Distributed SYN Flood)",
        "category": "Denial of Service",
        "description": "High-volume distributed packet flood exhausting network bandwidth and connection state tables.",
        "severity": "Critical",
        "mitre": "T0814",
        "default_port": 80,
    },
    {
        "id": "dos_conn_exhaust",
        "name": "DoS Connection Exhaustion",
        "category": "Denial of Service",
        "description": "Persistent TCP half-open connection spam depleting available socket handles on target service.",
        "severity": "High",
        "mitre": "T0814",
        "default_port": 80,
    },
    {
        "id": "brute_force_cred",
        "name": "Brute Force Simulation",
        "category": "Credential Access",
        "description": "Rapid credential stuffing and dictionary authentication attempts targeting Telnet/SSH/HTTP login ports.",
        "severity": "High",
        "mitre": "T0812",
        "default_port": 22,
    },
    {
        "id": "port_scan_syn",
        "name": "Port Scanning (TCP SYN Sweep)",
        "category": "Discovery",
        "description": "Stealth horizontal and vertical TCP SYN sweep mapping open IoT control and telemetry services.",
        "severity": "Medium",
        "mitre": "T0846",
        "default_port": 8080,
    },
    {
        "id": "mirai_c2_flood",
        "name": "Suspicious Traffic Flooding (Mirai C2)",
        "category": "Command & Control",
        "description": "Rapid periodic botnet command-and-control beaconing and anomalous burst communication.",
        "severity": "High",
        "mitre": "T0885",
        "default_port": 6667,
    },
    {
        "id": "zero_day_payload",
        "name": "Unauthorized Access / Zero-Day Mutation",
        "category": "Exploit",
        "description": "Out-of-distribution protocol mutations and anomalous byte entropy testing Open-Set centroid detection.",
        "severity": "Zero-day",
        "mitre": "T0855",
        "default_port": 49152,
    },
]

LEGITIMATE_TYPES = [
    {
        "id": "http_telemetry",
        "name": "Normal HTTP Requests",
        "category": "Web / REST",
        "description": "REST API queries and web interface telemetry pulls (/api/v1/telemetry, 200 OK).",
        "proto": "tcp",
        "port": 80,
    },
    {
        "id": "device_heartbeat",
        "name": "Device Heartbeat Requests",
        "category": "Diagnostics",
        "description": "Periodic keepalive ping to cloud IoT gateway confirming node connectivity and operational readiness.",
        "proto": "tcp",
        "port": 8883,
    },
    {
        "id": "sensor_updates",
        "name": "Sensor Data Updates",
        "category": "Telemetry",
        "description": "Periodic telemetry reports published over MQTT broker (temperature, humidity, voltage).",
        "proto": "tcp",
        "port": 8883,
    },
    {
        "id": "temp_readings",
        "name": "Temperature Readings",
        "category": "Environmental",
        "description": "Continuous ambient temperature telemetry stream from calibrated thermal probes.",
        "proto": "tcp",
        "port": 8883,
    },
    {
        "id": "humidity_readings",
        "name": "Humidity Readings",
        "category": "Environmental",
        "description": "Relative humidity sensor telemetry updates emitted to building climate control automation.",
        "proto": "tcp",
        "port": 8883,
    },
    {
        "id": "status_updates",
        "name": "Device Status Updates",
        "category": "System Health",
        "description": "Device runtime status synchronisation including battery level, CPU utilization, and heap metrics.",
        "proto": "tcp",
        "port": 443,
    },
    {
        "id": "api_requests",
        "name": "Normal API Requests",
        "category": "Cloud Services",
        "description": "Cloud configuration synchronization, remote policy verification, and NTP clock synchronization.",
        "proto": "tcp",
        "port": 443,
    },
]

# Backward-compatible SCENARIOS alias
SCENARIOS = [
    {
        "id": s["id"],
        "name": s["name"],
        "technique": s["category"],
        "description": s["description"],
        "severity_hint": s["severity"],
    }
    for s in ATTACK_SCENARIOS
]


class RunRequest(BaseModel):
    # Backward compatibility with existing single scenario
    scenario_id: Optional[str] = None
    target_id: Optional[str] = None
    duration_s: int = Field(60, ge=5, le=1800)
    intensity: str = Field("medium", pattern="^(low|medium|high)$")

    # Enhanced multi-selection fields
    attack_types: List[str] = Field(default_factory=list)
    legitimate_types: List[str] = Field(default_factory=list)
    target_ids: List[str] = Field(default_factory=list)


def _fmt_ts() -> str:
    return time.strftime("%H:%M:%S")


def _get_target_pool(org_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve all simulated IoT devices with connection & security status."""
    devs = storage.list_devices(org_id=org_id)
    out = []

    # Map existing devices from DB
    for d in devs:
        dev_id = d.get("device_id") or d.get("id")
        sec_status = DEVICE_SECURITY_STATUS.get(dev_id)
        if not sec_status:
            # Derive from risk score
            r = float(d.get("risk_score", 0.0))
            if r >= 75.0:
                sec_status = "Attack Detected"
            elif r >= 40.0:
                sec_status = "Suspicious Activity"
            else:
                sec_status = "Normal"

        dtype = d.get("device_type") or "sensor"
        name = f"Smart {dtype.replace('_', ' ').title()} ({dev_id})"
        out.append({
            "id": dev_id,
            "device_id": dev_id,
            "name": name,
            "device_type": dtype,
            "type": dtype,
            "ip": d.get("ip") or "192.168.1.10",
            "mac": d.get("mac") or "b8:27:eb:3d:4a:10",
            "connection_status": "Online",
            "status": "Online",
            "security_status": sec_status,
            "risk_score": round(float(d.get("risk_score", 0.0)), 1),
            "flow_count": d.get("flow_count", 0),
            "alert_count": d.get("alert_count", 0),
            "authorized": True,
        })

    # If DB has fewer than 5 devices, supplement with standard simulated fleet
    if len(out) < 5:
        defaults = [
            ("camera-bdd640fb", "camera", "Smart Security Camera", "192.168.1.10", "b8:27:eb:11:22:33"),
            ("smart_plug-23b8c1e9", "smart_plug", "Smart Power Outlet", "192.168.1.11", "b8:27:eb:44:55:66"),
            ("temp_sensor-6b65a6a4", "temp_sensor", "Environmental Temp Monitor", "192.168.1.12", "b8:27:eb:77:88:99"),
            ("thermostat-972a8469", "thermostat", "HVAC Smart Thermostat", "192.168.1.13", "b8:27:eb:aa:bb:cc"),
            ("smart_bulb-4f2a1b9c", "smart_bulb", "Smart LED Luminaire", "192.168.1.14", "b8:27:eb:dd:ee:ff"),
        ]
        existing_ids = {d["id"] for d in out}
        for did, dtype, dname, dip, dmac in defaults:
            if did not in existing_ids:
                out.append({
                    "id": did,
                    "device_id": did,
                    "name": f"{dname} ({did})",
                    "device_type": dtype,
                    "type": dtype,
                    "ip": dip,
                    "mac": dmac,
                    "connection_status": "Online",
                    "status": "Online",
                    "security_status": DEVICE_SECURITY_STATUS.get(did, "Normal"),
                    "risk_score": 0.0,
                    "flow_count": 0,
                    "alert_count": 0,
                    "authorized": True,
                })

    return out


@router.get("/scenarios")
def get_scenarios():
    return SCENARIOS


@router.get("/attacks")
def get_attacks():
    return ATTACK_SCENARIOS


@router.get("/legitimate_types")
def get_legitimate_types():
    return LEGITIMATE_TYPES


@router.get("/targets")
def get_targets(current_user: Optional[User] = Depends(get_current_user_optional)):
    org_id = current_user.organization_id if current_user else None
    return _get_target_pool(org_id)


@router.post("/runs")
async def start_run(
    payload: RunRequest,
    background_tasks: BackgroundTasks,
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    org_id = current_user.organization_id if current_user else "default-org-id"

    # Normalize attacks list
    attack_types = list(payload.attack_types)
    if not attack_types and payload.scenario_id:
        attack_types = [payload.scenario_id]

    # Normalize legitimate types
    legitimate_types = list(payload.legitimate_types)

    # Normalize target devices
    target_ids = list(payload.target_ids)
    if not target_ids and payload.target_id:
        target_ids = [payload.target_id]

    if not target_ids:
        # Fall back to first available device
        pool = _get_target_pool(org_id)
        if pool:
            target_ids = [pool[0]["id"]]
        else:
            raise HTTPException(status_code=400, detail="No target device selected or available.")

    # Validate that at least one attack or legitimate traffic generator is selected
    if not attack_types and not legitimate_types:
        raise HTTPException(
            status_code=400,
            detail="Select at least one attack simulation or legitimate traffic generator."
        )

    run_id = f"sim_{int(time.time())}_{uuid.uuid4().hex[:6]}"
    primary_target = target_ids[0]

    # Resolve target device details
    target_pool = {d["id"]: d for d in _get_target_pool(org_id)}
    target_info = target_pool.get(primary_target, {
        "id": primary_target,
        "name": primary_target,
        "device_type": "camera",
        "ip": "192.168.1.10",
    })

    # Set initial device status to Monitoring
    DEVICE_SECURITY_STATUS[primary_target] = "Monitoring"

    LAB_RUNS[run_id] = {
        "id": run_id,
        "run_id": run_id,
        "status": "running",
        "is_paused": False,
        "stop_requested": False,
        "progress": 0,
        "started_at": time.time(),
        "finished_at": None,
        "duration_s": payload.duration_s,
        "intensity": payload.intensity,
        "target_id": primary_target,
        "target_ids": target_ids,
        "target_info": target_info,
        "attack_types": attack_types,
        "legitimate_types": legitimate_types,
        "scenario_id": attack_types[0] if attack_types else "benign_only",
        "organization_id": org_id,
        # Metrics
        "metrics": {
            "total_requests": 0,
            "legitimate_requests": 0,
            "malicious_requests": 0,
            "suspicious_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "requests_per_sec": 0.0,
        },
        # Terminals and Feeds
        "attack_terminal": [],
        "device_terminal": [],
        "detections": [],
        "activity_feed": [],
        # Backward-compatible log
        "log": [],
    }

    background_tasks.add_task(orchestrate_simulation_session, run_id)
    return {
        "run_id": run_id,
        "status": "running",
        "target_id": primary_target,
        "active_attacks": attack_types,
        "active_legitimate": legitimate_types,
    }


@router.get("/runs/{run_id}")
def get_run_status(run_id: str):
    run = LAB_RUNS.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Simulation run not found")
    elapsed = (run["finished_at"] or time.time()) - run["started_at"]
    return {
        "id": run["id"],
        "run_id": run["run_id"],
        "status": run["status"],
        "is_paused": run["is_paused"],
        "progress": run["progress"],
        "elapsed_s": round(elapsed, 1),
        "target_id": run["target_id"],
        "target_info": run["target_info"],
        "attack_types": run["attack_types"],
        "legitimate_types": run["legitimate_types"],
        "metrics": run["metrics"],
        "detections": run["detections"],
        "attack_terminal": run["attack_terminal"][-50:],
        "device_terminal": run["device_terminal"][-50:],
        "activity_feed": run["activity_feed"][-30:],
        "log": run["log"][-50:],
        "started_at": run["started_at"],
        "finished_at": run["finished_at"],
    }


@router.post("/runs/{run_id}/pause")
async def pause_run(run_id: str):
    from ..main import manager
    run = LAB_RUNS.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Simulation run not found")
    if run["status"] == "running":
        run["is_paused"] = True
        run["status"] = "paused"
        pause_line = f"[{_fmt_ts()}] Simulation PAUSED by security operator."
        run["attack_terminal"].append({"ts": _fmt_ts(), "line": pause_line, "tag": "SIM-CONTROL"})
        run["device_terminal"].append({"ts": _fmt_ts(), "line": pause_line, "type": "info"})
        await manager.broadcast({
            "type": "sim_status",
            "run_id": run_id,
            "status": "paused",
            "progress": run["progress"]
        }, org_id=run["organization_id"])
    return {"status": "paused", "run_id": run_id}


@router.post("/runs/{run_id}/resume")
async def resume_run(run_id: str):
    from ..main import manager
    run = LAB_RUNS.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Simulation run not found")
    if run["status"] == "paused":
        run["is_paused"] = False
        run["status"] = "running"
        resume_line = f"[{_fmt_ts()}] Simulation RESUMED by security operator."
        run["attack_terminal"].append({"ts": _fmt_ts(), "line": resume_line, "tag": "SIM-CONTROL"})
        run["device_terminal"].append({"ts": _fmt_ts(), "line": resume_line, "type": "info"})
        await manager.broadcast({
            "type": "sim_status",
            "run_id": run_id,
            "status": "running",
            "progress": run["progress"]
        }, org_id=run["organization_id"])
    return {"status": "running", "run_id": run_id}


@router.post("/runs/{run_id}/stop")
async def stop_run(run_id: str):
    from ..main import manager
    run = LAB_RUNS.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Simulation run not found")
    run["stop_requested"] = True
    run["status"] = "stopped"
    target_id = run["target_id"]
    DEVICE_SECURITY_STATUS[target_id] = "Normal"

    stop_line = f"[{_fmt_ts()}] Operator aborted simulation session. Terminating generator workers..."
    run["attack_terminal"].append({"ts": _fmt_ts(), "line": stop_line, "tag": "ABORT"})
    run["device_terminal"].append({"ts": _fmt_ts(), "line": f"[{_fmt_ts()}] Traffic ceased. Target device recovered to normal state.", "type": "ok"})
    run["log"].append("Simulation stopped by operator.")

    await manager.broadcast({
        "type": "sim_device_status",
        "device_id": target_id,
        "security_status": "Normal"
    }, org_id=run["organization_id"])

    await manager.broadcast({
        "type": "sim_feed_event",
        "run_id": run_id,
        "ts": _fmt_ts(),
        "event": "Device recovered",
        "detail": f"{target_id} returned to normal operations",
        "badge": "ok"
    }, org_id=run["organization_id"])

    await manager.broadcast({
        "type": "sim_status",
        "run_id": run_id,
        "status": "stopped",
        "progress": run["progress"]
    }, org_id=run["organization_id"])

    return {"status": "stopped", "run_id": run_id}


@router.post("/runs/{run_id}/reset")
async def reset_run(run_id: str):
    from ..main import manager
    run = LAB_RUNS.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Simulation run not found")
    run["stop_requested"] = True
    run["status"] = "idle"
    target_id = run["target_id"]
    DEVICE_SECURITY_STATUS[target_id] = "Normal"
    run["metrics"] = {
        "total_requests": 0, "legitimate_requests": 0, "malicious_requests": 0,
        "suspicious_requests": 0, "successful_requests": 0, "failed_requests": 0,
        "requests_per_sec": 0.0,
    }
    run["attack_terminal"].clear()
    run["device_terminal"].clear()
    run["detections"].clear()
    run["activity_feed"].clear()
    run["log"].clear()

    await manager.broadcast({
        "type": "sim_device_status",
        "device_id": target_id,
        "security_status": "Normal"
    }, org_id=run["organization_id"])

    return {"status": "idle", "run_id": run_id}


# Flow Crafting Generators for Attack Scenarios
def _craft_attack_flow(attack_id: str, target_id: str, target_ip: str, step: int) -> Dict[str, Any]:
    now_ts = time.time()
    attacker_ip = f"198.51.100.{(step % 50) + 1}"

    if attack_id == "ddos_syn_flood":
        return {
            "ts": now_ts, "device_id": target_id, "src_ip": attacker_ip, "dst_ip": target_ip,
            "src_port": 10000 + (step % 50000), "dst_port": 80, "proto": "tcp",
            "duration": 0.005, "orig_bytes": 1400, "resp_bytes": 0,
            "orig_pkts": 40, "resp_pkts": 0, "conn_state": "S0", "history": "S",
            "attack_type": "ddos", "label": "ddos"
        }
    elif attack_id == "dos_conn_exhaust":
        return {
            "ts": now_ts, "device_id": target_id, "src_ip": attacker_ip, "dst_ip": target_ip,
            "src_port": 20000 + (step % 40000), "dst_port": 80, "proto": "tcp",
            "duration": 0.015, "orig_bytes": 900, "resp_bytes": 0,
            "orig_pkts": 25, "resp_pkts": 0, "conn_state": "S0", "history": "S",
            "attack_type": "ddos", "label": "ddos"
        }
    elif attack_id == "brute_force_cred":
        target_port = 22 if (step % 2 == 0) else 23
        return {
            "ts": now_ts, "device_id": target_id, "src_ip": attacker_ip, "dst_ip": target_ip,
            "src_port": 40000 + (step % 20000), "dst_port": target_port, "proto": "tcp",
            "duration": 0.25, "orig_bytes": 180, "resp_bytes": 45,
            "orig_pkts": 4, "resp_pkts": 2, "conn_state": "REJ", "history": "ShR",
            "attack_type": "brute_force", "label": "brute_force"
        }
    elif attack_id == "port_scan_syn":
        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 554, 1883, 3389, 8080, 8883, 49152]
        scan_port = common_ports[step % len(common_ports)]
        return {
            "ts": now_ts, "device_id": target_id, "src_ip": attacker_ip, "dst_ip": target_ip,
            "src_port": 50000 + (step % 10000), "dst_port": scan_port, "proto": "tcp",
            "duration": 0.002, "orig_bytes": 60, "resp_bytes": 0,
            "orig_pkts": 1, "resp_pkts": 0, "conn_state": "S0", "history": "S",
            "attack_type": "port_scan", "label": "port_scan"
        }
    elif attack_id == "mirai_c2_flood":
        return {
            "ts": now_ts, "device_id": target_id, "src_ip": target_ip, "dst_ip": "203.0.113.88",
            "src_port": 45000 + (step % 15000), "dst_port": 6667, "proto": "tcp",
            "duration": 0.150, "orig_bytes": 84, "resp_bytes": 64,
            "orig_pkts": 2, "resp_pkts": 2, "conn_state": "SF", "history": "ShADdfFa",
            "attack_type": "mirai_beacon", "label": "mirai_beacon"
        }
    else:  # zero_day_payload
        return {
            "ts": now_ts, "device_id": target_id, "src_ip": attacker_ip, "dst_ip": target_ip,
            "src_port": 61000 + (step % 4000), "dst_port": 49152, "proto": "tcp",
            "duration": 0.08, "orig_bytes": 2400, "resp_bytes": 0,
            "orig_pkts": 12, "resp_pkts": 0, "conn_state": "OTH", "history": "S",
            "attack_type": "unknown_suspicious", "label": "unknown_suspicious"
        }


# Flow Crafting Generators for Legitimate Traffic
def _craft_legitimate_flow(legit_id: str, target_id: str, target_ip: str, step: int) -> Dict[str, Any]:
    now_ts = time.time()
    cloud_gw = f"203.0.113.{(step % 8) + 1}"

    if legit_id == "http_telemetry":
        return {
            "ts": now_ts, "device_id": target_id, "src_ip": target_ip, "dst_ip": cloud_gw,
            "src_port": 48000 + (step % 10000), "dst_port": 80, "proto": "tcp",
            "duration": 0.18, "orig_bytes": 450, "resp_bytes": 680,
            "orig_pkts": 4, "resp_pkts": 5, "conn_state": "SF", "history": "ShADadfF",
            "label": "benign"
        }
    elif legit_id == "device_heartbeat":
        return {
            "ts": now_ts, "device_id": target_id, "src_ip": target_ip, "dst_ip": cloud_gw,
            "src_port": 49000 + (step % 8000), "dst_port": 8883, "proto": "tcp",
            "duration": 0.06, "orig_bytes": 88, "resp_bytes": 96,
            "orig_pkts": 2, "resp_pkts": 2, "conn_state": "SF", "history": "ShADdf",
            "label": "benign"
        }
    elif legit_id == "sensor_updates":
        return {
            "ts": now_ts, "device_id": target_id, "src_ip": target_ip, "dst_ip": cloud_gw,
            "src_port": 50000 + (step % 12000), "dst_port": 8883, "proto": "tcp",
            "duration": 0.12, "orig_bytes": 280, "resp_bytes": 340,
            "orig_pkts": 3, "resp_pkts": 4, "conn_state": "SF", "history": "ShADadf",
            "label": "benign"
        }
    elif legit_id == "temp_readings":
        return {
            "ts": now_ts, "device_id": target_id, "src_ip": target_ip, "dst_ip": cloud_gw,
            "src_port": 51000 + (step % 9000), "dst_port": 8883, "proto": "tcp",
            "duration": 0.08, "orig_bytes": 160, "resp_bytes": 180,
            "orig_pkts": 2, "resp_pkts": 3, "conn_state": "SF", "history": "ShADdf",
            "label": "benign"
        }
    elif legit_id == "humidity_readings":
        return {
            "ts": now_ts, "device_id": target_id, "src_ip": target_ip, "dst_ip": cloud_gw,
            "src_port": 52000 + (step % 9000), "dst_port": 8883, "proto": "tcp",
            "duration": 0.09, "orig_bytes": 175, "resp_bytes": 190,
            "orig_pkts": 2, "resp_pkts": 3, "conn_state": "SF", "history": "ShADdf",
            "label": "benign"
        }
    elif legit_id == "status_updates":
        return {
            "ts": now_ts, "device_id": target_id, "src_ip": target_ip, "dst_ip": cloud_gw,
            "src_port": 53000 + (step % 7000), "dst_port": 443, "proto": "tcp",
            "duration": 0.22, "orig_bytes": 620, "resp_bytes": 850,
            "orig_pkts": 6, "resp_pkts": 7, "conn_state": "SF", "history": "ShADadfF",
            "label": "benign"
        }
    else:  # api_requests
        return {
            "ts": now_ts, "device_id": target_id, "src_ip": target_ip, "dst_ip": cloud_gw,
            "src_port": 54000 + (step % 8000), "dst_port": 443, "proto": "tcp",
            "duration": 0.14, "orig_bytes": 390, "resp_bytes": 510,
            "orig_pkts": 3, "resp_pkts": 4, "conn_state": "SF", "history": "ShADadf",
            "label": "benign"
        }


async def orchestrate_simulation_session(run_id: str):
    """
    Main simulation orchestration loop:
    - Runs concurrent generator loops for all selected attacks and legitimate traffic types.
    - Pipes flows directly through the real AI scoring engine.
    - Streams live outputs to Terminal 1 (Attack Generator) & Terminal 2 (Device).
    - Triggers detection events and updates UI dashboards.
    """
    from ..main import manager

    run = LAB_RUNS[run_id]
    target_id = run["target_id"]
    target_info = run["target_info"]
    target_ip = target_info.get("ip", "192.168.1.10")
    target_name = target_info.get("name", target_id)
    org_id = run["organization_id"]
    duration = run["duration_s"]
    intensity = run["intensity"]

    # Sleep cadence based on intensity
    base_sleep = 0.5 if intensity == "low" else (0.22 if intensity == "medium" else 0.08)

    # Initial session announcements
    init_attack_msg = f"[{_fmt_ts()}] Initializing Attack Generator for {target_name} ({target_ip})..."
    init_dev_msg = f"[{_fmt_ts()}] {target_name} is online. Ingress interfaces UP on {target_ip}."

    run["attack_terminal"].append({"ts": _fmt_ts(), "line": init_attack_msg, "tag": "INIT"})
    run["device_terminal"].append({"ts": _fmt_ts(), "line": init_dev_msg, "type": "info"})
    run["activity_feed"].append({
        "ts": _fmt_ts(),
        "event": "Simulation started",
        "detail": f"Target: {target_name} | Attacks: {len(run['attack_types'])} | Legitimate: {len(run['legitimate_types'])}",
        "badge": "info",
    })

    await manager.broadcast({
        "type": "sim_attack_log",
        "run_id": run_id,
        "ts": _fmt_ts(),
        "tag": "INIT",
        "line": init_attack_msg,
    }, org_id=org_id)

    await manager.broadcast({
        "type": "sim_device_log",
        "run_id": run_id,
        "device_id": target_id,
        "ts": _fmt_ts(),
        "type": "info",
        "line": init_dev_msg,
    }, org_id=org_id)

    await manager.broadcast({
        "type": "sim_feed_event",
        "run_id": run_id,
        "ts": _fmt_ts(),
        "event": "Simulation started",
        "detail": f"Target: {target_name} | Attacks: {len(run['attack_types'])} | Legitimate: {len(run['legitimate_types'])}",
        "badge": "info",
    }, org_id=org_id)

    start_time = time.time()
    step = 0
    attack_index = 0
    legit_index = 0

    attack_types = run["attack_types"]
    legit_types = run["legitimate_types"]

    while (time.time() - start_time) < duration and not run["stop_requested"]:
        # Handle pause
        if run["is_paused"]:
            await asyncio.sleep(0.5)
            continue

        step += 1
        elapsed = time.time() - start_time
        pct = min(99, int((elapsed / duration) * 100))
        run["progress"] = pct

        # 1. GENERATE LEGITIMATE TRAFFIC IF CONFIGURED
        if legit_types:
            curr_legit = legit_types[legit_index % len(legit_types)]
            legit_index += 1
            l_flow = _craft_legitimate_flow(curr_legit, target_id, target_ip, step)
            l_res = engine.score_flow(l_flow)

            # Record flow in persistent storage
            storage.record_flow(l_flow, l_res.get("gate_score", 0.0), False, org_id=org_id)

            # Update metrics
            run["metrics"]["total_requests"] += 1
            run["metrics"]["legitimate_requests"] += 1
            run["metrics"]["successful_requests"] += 1
            run["metrics"]["requests_per_sec"] = round(run["metrics"]["total_requests"] / max(elapsed, 0.5), 1)

            # Emit Device Terminal event for legitimate ingress
            legit_name = curr_legit.replace("_", " ").title()
            dev_line = f"[{_fmt_ts()}] [Legitimate {legit_name}] INGRESS from {l_flow['dst_ip']}:{l_flow['dst_port']} (proto={l_flow['proto']}, {l_flow['orig_bytes']}B) -> 200 OK"
            run["device_terminal"].append({"ts": _fmt_ts(), "line": dev_line, "type": "legitimate"})

            await manager.broadcast({
                "type": "sim_device_log",
                "run_id": run_id,
                "device_id": target_id,
                "ts": _fmt_ts(),
                "type": "legitimate",
                "line": dev_line,
            }, org_id=org_id)

        # 2. GENERATE ATTACK TRAFFIC IF CONFIGURED
        if attack_types:
            curr_atk = attack_types[attack_index % len(attack_types)]
            attack_index += 1
            atk_flow = _craft_attack_flow(curr_atk, target_id, target_ip, step)
            atk_res = engine.score_flow(atk_flow)

            # Gate score / decision from AI pipeline
            gate_score = float(atk_res.get("gate_score", 0.95))
            is_flagged = bool(atk_res.get("is_flagged", True))

            # Record in storage
            storage.record_flow(atk_flow, gate_score, is_flagged, org_id=org_id)

            # Update metrics
            run["metrics"]["total_requests"] += 1
            run["metrics"]["malicious_requests"] += 1
            if is_flagged:
                run["metrics"]["suspicious_requests"] += 1
                # Under heavy attack, some connections fail
                if curr_atk in ("ddos_syn_flood", "dos_conn_exhaust") and (step % 3 == 0):
                    run["metrics"]["failed_requests"] += 1
                else:
                    run["metrics"]["successful_requests"] += 1
            else:
                run["metrics"]["successful_requests"] += 1

            run["metrics"]["requests_per_sec"] = round(run["metrics"]["total_requests"] / max(elapsed, 0.5), 1)

            # Attack Terminal emission
            atk_meta = next((a for a in ATTACK_SCENARIOS if a["id"] == curr_atk), None)
            atk_name = atk_meta["name"] if atk_meta else curr_atk
            atk_tag = curr_atk.split("_")[0].upper()

            atk_line = f"[{_fmt_ts()}] [{atk_tag}-Worker] Emitting {atk_flow['orig_pkts']} pkts -> {target_ip}:{atk_flow['dst_port']} ({atk_flow['proto'].upper()} {atk_flow['conn_state']}) | {atk_flow['orig_bytes']} B"
            run["attack_terminal"].append({"ts": _fmt_ts(), "line": atk_line, "tag": atk_tag})

            await manager.broadcast({
                "type": "sim_attack_log",
                "run_id": run_id,
                "ts": _fmt_ts(),
                "tag": atk_tag,
                "line": atk_line,
            }, org_id=org_id)

            # Device Terminal emission for malicious packet ingress
            dev_atk_line = f"[{_fmt_ts()}] [MALICIOUS INGRESS] Alert on port {atk_flow['dst_port']} from {atk_flow['src_ip']} (flags={atk_flow['conn_state']}, pkts={atk_flow['orig_pkts']}, bytes={atk_flow['orig_bytes']})"
            run["device_terminal"].append({"ts": _fmt_ts(), "line": dev_atk_line, "type": "malicious"})

            await manager.broadcast({
                "type": "sim_device_log",
                "run_id": run_id,
                "device_id": target_id,
                "ts": _fmt_ts(),
                "type": "malicious",
                "line": dev_atk_line,
            }, org_id=org_id)

            # 3. REAL-TIME ATTACK DETECTION TRIGGER
            if is_flagged:
                # Update device security status to Attack Detected
                DEVICE_SECURITY_STATUS[target_id] = "Attack Detected"

                sev = atk_meta["severity"] if atk_meta else "High"
                mitre_code = atk_meta.get("mitre", "T0814") if atk_meta else "T0814"

                # Record alert in storage database
                alert_id = storage.record_alert(
                    flow=atk_flow,
                    attack_type=atk_flow.get("attack_type", "anomaly"),
                    mitre=mitre_code,
                    severity=sev.lower(),
                    gate_score=gate_score,
                    anomaly_score=atk_res.get("anomaly_score", 0.90),
                    confidence_tier=atk_res.get("confidence_tier", "high"),
                    top_features=atk_res.get("top_features", []),
                    shap_values=atk_res.get("shap_values", []),
                    shap_base_value=atk_res.get("shap_base_value"),
                    decision=atk_res.get("decision", "ATTACK"),
                    is_unknown=atk_res.get("is_unknown", False),
                    org_id=org_id,
                )

                detection_item = {
                    "alert_id": alert_id,
                    "target_id": target_id,
                    "target_name": target_name,
                    "attack_type": atk_name,
                    "raw_type": atk_flow.get("attack_type", "ddos"),
                    "severity": sev,
                    "mitre": mitre_code,
                    "confidence": gate_score,
                    "confidence_pct": round(gate_score * 100, 1),
                    "timestamp": _fmt_ts(),
                    "reason": f"Anomalous {atk_flow['proto'].upper()} traffic burst on port {atk_flow['dst_port']} (SHAP score: {gate_score:.3f})",
                    "affected_requests": atk_flow["orig_pkts"],
                }
                run["detections"].append(detection_item)

                # Output to Device Terminal
                det_dev_line = f"[SECURITY DETECTION] [{_fmt_ts()}] Suspicious activity detected on {target_name}! Attack: {atk_name} | Severity: {sev.upper()} | Confidence: {gate_score:.1%} | Action: SOC Alert Dispatched"
                run["device_terminal"].append({"ts": _fmt_ts(), "line": det_dev_line, "type": "detection"})

                # Output to Attack Generator Terminal
                det_atk_line = f"[{_fmt_ts()}] [DETECTION CONFIRMED] Target IDS defense flagged malicious pattern! Attack: {atk_name} | Score: {gate_score:.3f}"
                run["attack_terminal"].append({"ts": _fmt_ts(), "line": det_atk_line, "tag": "DETECTED"})

                # Broadcast live detection event
                await manager.broadcast({
                    "type": "sim_detection",
                    "run_id": run_id,
                    "detection": detection_item,
                }, org_id=org_id)

                await manager.broadcast({
                    "type": "sim_device_log",
                    "run_id": run_id,
                    "device_id": target_id,
                    "ts": _fmt_ts(),
                    "type": "detection",
                    "line": det_dev_line,
                }, org_id=org_id)

                await manager.broadcast({
                    "type": "sim_attack_log",
                    "run_id": run_id,
                    "ts": _fmt_ts(),
                    "tag": "DETECTED",
                    "line": det_atk_line,
                }, org_id=org_id)

                await manager.broadcast({
                    "type": "sim_device_status",
                    "device_id": target_id,
                    "security_status": "Attack Detected",
                }, org_id=org_id)

                # Update activity feed if this is a newly detected attack
                if len(run["detections"]) <= 10:
                    feed_item = {
                        "ts": _fmt_ts(),
                        "event": "Attack detected",
                        "detail": f"{atk_name} identified on {target_name} ({sev})",
                        "badge": "crit" if sev == "Critical" else "high",
                    }
                    run["activity_feed"].append(feed_item)
                    await manager.broadcast({
                        "type": "sim_feed_event",
                        "run_id": run_id,
                        **feed_item,
                    }, org_id=org_id)

                # Also broadcast to main SOC alert channel
                alert_obj = {
                    "id": alert_id,
                    "ts": atk_flow["ts"],
                    "device": target_id,
                    "device_id": target_id,
                    "ip": target_ip,
                    "src_ip": atk_flow["src_ip"],
                    "type": atk_flow.get("attack_type", "anomaly"),
                    "attack_type": atk_flow.get("attack_type", "anomaly"),
                    "severity": sev,
                    "sev": sev,
                    "confidence": gate_score,
                    "run_id": run_id,
                }
                await manager.broadcast({"type": "alert", "alert": alert_obj, "data": alert_obj}, org_id=org_id)

        # Broadcast periodic simulation metrics
        if step % 2 == 0:
            await manager.broadcast({
                "type": "sim_metrics",
                "run_id": run_id,
                "metrics": run["metrics"],
                "progress": pct,
            }, org_id=org_id)
            # Backward-compatible status broadcast
            await manager.broadcast({
                "type": "lab_status",
                "run_id": run_id,
                "status": "running",
                "progress": pct,
            }, org_id=org_id)

        # Sleep between generation steps
        await asyncio.sleep(base_sleep)

    # Wrap up simulation session
    run["finished_at"] = time.time()
    if run["stop_requested"]:
        run["status"] = "stopped"
        end_msg = f"[{_fmt_ts()}] Simulation session stopped by operator."
    else:
        run["status"] = "finished"
        run["progress"] = 100
        end_msg = f"[{_fmt_ts()}] Simulation completed successfully. Total requests: {run['metrics']['total_requests']} | Detections: {len(run['detections'])}"

    # Recover device security status
    DEVICE_SECURITY_STATUS[target_id] = "Normal"

    run["attack_terminal"].append({"ts": _fmt_ts(), "line": end_msg, "tag": "FINISH"})
    run["device_terminal"].append({"ts": _fmt_ts(), "line": f"[{_fmt_ts()}] Ingress idle. Device health normal.", "type": "ok"})
    run["activity_feed"].append({
        "ts": _fmt_ts(),
        "event": "Attack stopped",
        "detail": f"Simulation session concluded on {target_name}",
        "badge": "ok",
    })

    await manager.broadcast({
        "type": "sim_status",
        "run_id": run_id,
        "status": run["status"],
        "progress": run["progress"],
    }, org_id=org_id)

    await manager.broadcast({
        "type": "sim_device_status",
        "device_id": target_id,
        "security_status": "Normal",
    }, org_id=org_id)

    await manager.broadcast({
        "type": "sim_feed_event",
        "run_id": run_id,
        "ts": _fmt_ts(),
        "event": "Attack stopped",
        "detail": f"Simulation session concluded on {target_name}",
        "badge": "ok",
    }, org_id=org_id)

    await manager.broadcast({
        "type": "lab_status",
        "run_id": run_id,
        "status": run["status"],
        "progress": run["progress"],
    }, org_id=org_id)
