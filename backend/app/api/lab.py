"""
Pahredaar-IoT Attack Simulation & Detection Engine.
Interactive real-time IoT cybersecurity simulation environment:
- Real separate native operating-system terminal windows (Windows Terminal / Command Prompt).
- Dedicated Live Feed Terminal for every selected target IoT device.
- Dedicated Individual Attack Execution Terminal for every selected attack.
- Dedicated Legitimate Traffic Generation Terminal for normal background operations.
- Real-time multi-modal AI detection pipeline integration with live metrics & alert dispatch.
"""

import asyncio
import json
import os
from pathlib import Path
import random
import subprocess
import sys
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

REPO_ROOT = str(Path(__file__).resolve().parents[3])

# In-memory simulation session registry
LAB_RUNS: Dict[str, dict] = {}

# Process registry: run_id -> list of spawned OS processes and their metadata
ACTIVE_SIM_PROCESSES: Dict[str, List[Dict[str, Any]]] = {}

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

    # Multi-selection and Native Terminal fields
    attack_types: List[str] = Field(default_factory=list)
    legitimate_types: List[str] = Field(default_factory=list)
    target_ids: List[str] = Field(default_factory=list)
    launch_native_terminals: bool = Field(True)


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

    # Supplement standard fleet if fewer than 5
    if len(out) < 5:
        defaults = [
            ("camera-bdd640fb", "camera", "Smart Security Camera 01", "192.168.1.10", "b8:27:eb:11:22:33"),
            ("smart_plug-23b8c1e9", "smart_plug", "Smart Energy Plug 02", "192.168.1.11", "b8:27:eb:44:55:66"),
            ("temp_sensor-6b65a6a4", "temp_sensor", "Environmental Temp Sensor 03", "192.168.1.12", "b8:27:eb:77:88:99"),
            ("thermostat-972a8469", "thermostat", "HVAC Thermostat 04", "192.168.1.13", "b8:27:eb:aa:bb:cc"),
            ("smart_bulb-4f2a1b9c", "smart_bulb", "Smart Light Hub 05", "192.168.1.14", "b8:27:eb:dd:ee:ff"),
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


def _spawn_native_console(cmd_args: List[str]) -> Optional[subprocess.Popen]:
    """
    Launches an actual, separate operating-system terminal window on Windows.
    Uses CREATE_NEW_CONSOLE to guarantee a dedicated visible Command Prompt / Terminal window.
    """
    try:
        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NEW_CONSOLE

        proc = subprocess.Popen(
            cmd_args,
            creationflags=creationflags,
            cwd=REPO_ROOT
        )
        return proc
    except Exception as e:
        print(f"Warning: Failed to launch native terminal process: {e}")
        return None


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
        pool = _get_target_pool(org_id)
        if pool:
            target_ids = [pool[0]["id"]]
        else:
            raise HTTPException(status_code=400, detail="No target device selected or available.")

    if not attack_types and not legitimate_types:
        raise HTTPException(
            status_code=400,
            detail="Select at least one attack simulation or legitimate traffic generator."
        )

    run_id = f"sim_{int(time.time())}_{uuid.uuid4().hex[:6]}"
    target_pool = {d["id"]: d for d in _get_target_pool(org_id)}

    for tid in target_ids:
        DEVICE_SECURITY_STATUS[tid] = "Monitoring"

    primary_target = target_ids[0]
    primary_info = target_pool.get(primary_target, {
        "id": primary_target,
        "name": primary_target,
        "device_type": "camera",
        "ip": "192.168.1.10",
    })

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
        "target_info": primary_info,
        "attack_types": attack_types,
        "legitimate_types": legitimate_types,
        "scenario_id": attack_types[0] if attack_types else "benign_only",
        "organization_id": org_id,
        "launch_native_terminals": payload.launch_native_terminals,
        "metrics": {
            "total_requests": 0,
            "legitimate_requests": 0,
            "malicious_requests": 0,
            "suspicious_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "requests_per_sec": 0.0,
        },
        "attack_terminal": [],
        "device_terminal": [],
        "detections": [],
        "activity_feed": [],
        "log": [],
    }

    # LAUNCH REAL OPERATING-SYSTEM NATIVE TERMINAL WINDOWS
    spawned_processes: List[Dict[str, Any]] = []

    if payload.launch_native_terminals:
        backend_url = "http://127.0.0.1:8000"

        # 1. Spawn a dedicated visible native terminal window for EVERY selected IoT device
        for tid in target_ids:
            dev_info = target_pool.get(tid, {"id": tid, "name": tid, "type": "sensor", "ip": "192.168.1.10"})
            d_name = dev_info.get("name", tid)
            d_type = dev_info.get("type") or dev_info.get("device_type", "sensor")
            d_ip = dev_info.get("ip", "192.168.1.10")

            dev_cmd = [
                sys.executable, "-m", "simulator.runners.device_runner",
                "--session-id", run_id,
                "--device-id", tid,
                "--device-name", d_name,
                "--device-type", d_type,
                "--device-ip", d_ip,
                "--backend-url", backend_url
            ]
            proc = _spawn_native_console(dev_cmd)
            if proc:
                spawned_processes.append({
                    "pid": proc.pid,
                    "type": "device_monitor",
                    "title": f"IOT DEVICE - {d_name.upper()} - LIVE MONITOR",
                    "target_id": tid,
                    "target_name": d_name,
                    "process": proc,
                    "started_at": time.time(),
                })

        # 2. Spawn a dedicated visible native terminal window for EVERY selected attack
        for tid in target_ids:
            dev_info = target_pool.get(tid, {"id": tid, "name": tid, "ip": "192.168.1.10"})
            d_name = dev_info.get("name", tid)
            d_ip = dev_info.get("ip", "192.168.1.10")

            for atk_id in attack_types:
                atk_meta = next((a for a in ATTACK_SCENARIOS if a["id"] == atk_id), None)
                atk_tag = atk_meta["name"].split()[0].upper() if atk_meta else atk_id.upper()

                atk_cmd = [
                    sys.executable, "-m", "simulator.runners.attack_runner",
                    "--session-id", run_id,
                    "--device-id", tid,
                    "--device-name", d_name,
                    "--device-ip", d_ip,
                    "--attack-type", atk_id,
                    "--intensity", payload.intensity,
                    "--duration", str(payload.duration_s),
                    "--backend-url", backend_url
                ]
                proc = _spawn_native_console(atk_cmd)
                if proc:
                    spawned_processes.append({
                        "pid": proc.pid,
                        "type": "attack_worker",
                        "title": f"ATTACK - {atk_tag} - {d_name.upper()}",
                        "target_id": tid,
                        "target_name": d_name,
                        "attack_type": atk_id,
                        "process": proc,
                        "started_at": time.time(),
                    })

        # 3. Spawn a dedicated visible native terminal window for Legitimate Traffic Generation
        if legitimate_types:
            dev_list_minimal = [
                {"id": tid, "name": target_pool[tid]["name"], "ip": target_pool[tid]["ip"]}
                for tid in target_ids if tid in target_pool
            ]
            legit_cmd = [
                sys.executable, "-m", "simulator.runners.legitimate_runner",
                "--session-id", run_id,
                "--devices-json", json.dumps(dev_list_minimal),
                "--types-csv", ",".join(legitimate_types),
                "--intensity", payload.intensity,
                "--duration", str(payload.duration_s),
                "--backend-url", backend_url
            ]
            proc = _spawn_native_console(legit_cmd)
            if proc:
                spawned_processes.append({
                    "pid": proc.pid,
                    "type": "legitimate_generator",
                    "title": "LEGITIMATE TRAFFIC GENERATOR - MULTI-DEVICE",
                    "target_id": "all",
                    "target_name": "Multi-Device Fleet",
                    "process": proc,
                    "started_at": time.time(),
                })

    ACTIVE_SIM_PROCESSES[run_id] = spawned_processes

    # Also launch background orchestrator for frontend live state syncing & metrics
    background_tasks.add_task(orchestrate_simulation_session, run_id)

    return {
        "run_id": run_id,
        "status": "running",
        "target_id": primary_target,
        "target_ids": target_ids,
        "active_attacks": attack_types,
        "active_legitimate": legitimate_types,
        "native_processes_launched": len(spawned_processes),
        "processes": [
            {
                "pid": p["pid"],
                "type": p["type"],
                "title": p["title"],
                "target_name": p["target_name"]
            }
            for p in spawned_processes
        ]
    }


@router.get("/runs/{run_id}")
def get_run_status(run_id: str):
    run = LAB_RUNS.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Simulation run not found")
    elapsed = (run["finished_at"] or time.time()) - run["started_at"]

    procs = ACTIVE_SIM_PROCESSES.get(run_id, [])
    live_procs = [
        {
            "pid": p["pid"],
            "type": p["type"],
            "title": p["title"],
            "target_name": p["target_name"],
            "status": "running" if (p["process"].poll() is None) else "exited",
        }
        for p in procs
    ]

    return {
        "id": run["id"],
        "run_id": run["run_id"],
        "status": run["status"],
        "is_paused": run["is_paused"],
        "progress": run["progress"],
        "elapsed_s": round(elapsed, 1),
        "target_id": run["target_id"],
        "target_ids": run["target_ids"],
        "target_info": run["target_info"],
        "attack_types": run["attack_types"],
        "legitimate_types": run["legitimate_types"],
        "metrics": run["metrics"],
        "detections": run["detections"],
        "process_count": len(live_procs),
        "processes": live_procs,
        "attack_terminal": run["attack_terminal"][-50:],
        "device_terminal": run["device_terminal"][-50:],
        "activity_feed": run["activity_feed"][-30:],
        "log": run["log"][-50:],
        "started_at": run["started_at"],
        "finished_at": run["finished_at"],
    }


@router.get("/runs/{run_id}/processes")
def get_run_processes(run_id: str):
    procs = ACTIVE_SIM_PROCESSES.get(run_id, [])
    return [
        {
            "pid": p["pid"],
            "type": p["type"],
            "title": p["title"],
            "target_id": p.get("target_id"),
            "target_name": p["target_name"],
            "status": "running" if (p["process"].poll() is None) else "exited",
            "started_at": p.get("started_at"),
        }
        for p in procs
    ]


@router.post("/runs/{run_id}/pause")
async def pause_run(run_id: str):
    from ..main import manager
    run = LAB_RUNS.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Simulation run not found")
    if run["status"] == "running":
        run["is_paused"] = True
        run["status"] = "paused"
        pause_line = f"[{_fmt_ts()}] Simulation PAUSED by operator."
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
        resume_line = f"[{_fmt_ts()}] Simulation RESUMED by operator."
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

    # TERMINATE AND CLEAN UP ALL SPAWNED NATIVE OS TERMINAL WINDOW PROCESSES
    procs = ACTIVE_SIM_PROCESSES.get(run_id, [])
    active_pids = []
    for p_info in procs:
        proc: subprocess.Popen = p_info.get("process")
        if proc and proc.poll() is None:
            try:
                proc.kill()
                active_pids.append(str(proc.pid))
            except Exception:
                pass
            p_info["status"] = "exited"

    if active_pids and sys.platform == "win32":
        try:
            cmd = ["taskkill", "/F", "/T"]
            for pid in active_pids:
                cmd.extend(["/PID", pid])
            subprocess.run(cmd, capture_output=True, timeout=2.0)
        except Exception:
            pass

    # Recover all target device statuses
    for tid in run.get("target_ids", [run["target_id"]]):
        DEVICE_SECURITY_STATUS[tid] = "Normal"
        await manager.broadcast({
            "type": "sim_device_status",
            "device_id": tid,
            "security_status": "Normal"
        }, org_id=run["organization_id"])

    stop_line = f"[{_fmt_ts()}] Operator stopped simulation. All {len(procs)} native terminal processes terminated."
    run["attack_terminal"].append({"ts": _fmt_ts(), "line": stop_line, "tag": "ABORT"})
    run["device_terminal"].append({"ts": _fmt_ts(), "line": f"[{_fmt_ts()}] Traffic ceased. Target devices recovered to normal state.", "type": "ok"})
    run["log"].append(stop_line)

    await manager.broadcast({
        "type": "sim_feed_event",
        "run_id": run_id,
        "ts": _fmt_ts(),
        "event": "Simulation stopped",
        "detail": f"Terminated {len(procs)} OS terminal processes",
        "badge": "ok"
    }, org_id=run["organization_id"])

    await manager.broadcast({
        "type": "sim_status",
        "run_id": run_id,
        "status": "stopped",
        "progress": run["progress"]
    }, org_id=run["organization_id"])

    return {
        "status": "stopped",
        "run_id": run_id,
        "terminated_processes": len(procs)
    }


@router.post("/runs/{run_id}/reset")
async def reset_run(run_id: str):
    from ..main import manager
    run = LAB_RUNS.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Simulation run not found")
    run["stop_requested"] = True
    run["status"] = "idle"

    # Terminate any remaining processes
    procs = ACTIVE_SIM_PROCESSES.get(run_id, [])
    for p_info in procs:
        proc = p_info.get("process")
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass
    ACTIVE_SIM_PROCESSES[run_id] = []

    for tid in run.get("target_ids", [run["target_id"]]):
        DEVICE_SECURITY_STATUS[tid] = "Normal"
        await manager.broadcast({
            "type": "sim_device_status",
            "device_id": tid,
            "security_status": "Normal"
        }, org_id=run["organization_id"])

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

    return {"status": "idle", "run_id": run_id}


# Flow Crafting Generators for Internal Simulation Loop
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
    Background orchestrator updating dashboard metrics and dispatches.
    Keeps frontend in sync while real OS terminal windows execute.
    """
    from ..main import manager

    run = LAB_RUNS[run_id]
    target_ids = run.get("target_ids", [run["target_id"]])
    target_info = run["target_info"]
    target_ip = target_info.get("ip", "192.168.1.10")
    target_name = target_info.get("name", target_ids[0])
    org_id = run["organization_id"]
    duration = run["duration_s"]
    intensity = run["intensity"]

    base_sleep = 0.5 if intensity == "low" else (0.22 if intensity == "medium" else 0.08)

    init_attack_msg = f"[{_fmt_ts()}] Attack Generator initialized for {target_name} ({target_ip})."
    init_dev_msg = f"[{_fmt_ts()}] {target_name} is online. Ingress interfaces UP on {target_ip}."

    run["attack_terminal"].append({"ts": _fmt_ts(), "line": init_attack_msg, "tag": "INIT"})
    run["device_terminal"].append({"ts": _fmt_ts(), "line": init_dev_msg, "type": "info"})
    run["activity_feed"].append({
        "ts": _fmt_ts(),
        "event": "Simulation started",
        "detail": f"Targets: {len(target_ids)} | Attacks: {len(run['attack_types'])} | Legitimate: {len(run['legitimate_types'])}",
        "badge": "info",
    })

    await manager.broadcast({
        "type": "sim_feed_event",
        "run_id": run_id,
        "ts": _fmt_ts(),
        "event": "Simulation started",
        "detail": f"Launched native OS terminals for {len(target_ids)} device(s)",
        "badge": "info",
    }, org_id=org_id)

    start_time = time.time()
    step = 0
    attack_index = 0
    legit_index = 0

    attack_types = run["attack_types"]
    legit_types = run["legitimate_types"]

    while (time.time() - start_time) < duration and not run["stop_requested"]:
        if run["is_paused"]:
            await asyncio.sleep(0.5)
            continue

        step += 1
        elapsed = time.time() - start_time
        pct = min(99, int((elapsed / duration) * 100))
        run["progress"] = pct

        curr_target_id = target_ids[step % len(target_ids)]

        # 1. GENERATE LEGITIMATE TRAFFIC IF CONFIGURED
        if legit_types:
            curr_legit = legit_types[legit_index % len(legit_types)]
            legit_index += 1
            l_flow = _craft_legitimate_flow(curr_legit, curr_target_id, target_ip, step)
            l_res = engine.score_flow(l_flow)

            storage.record_flow(l_flow, l_res.get("gate_score", 0.0), False, org_id=org_id)

            run["metrics"]["total_requests"] += 1
            run["metrics"]["legitimate_requests"] += 1
            run["metrics"]["successful_requests"] += 1
            run["metrics"]["requests_per_sec"] = round(run["metrics"]["total_requests"] / max(elapsed, 0.5), 1)

            legit_name = curr_legit.replace("_", " ").title()
            dev_line = f"[{_fmt_ts()}] [Legitimate {legit_name}] INGRESS from {l_flow['dst_ip']}:{l_flow['dst_port']} -> 200 OK"
            run["device_terminal"].append({"ts": _fmt_ts(), "line": dev_line, "type": "legitimate"})

            await manager.broadcast({
                "type": "sim_device_log",
                "run_id": run_id,
                "device_id": curr_target_id,
                "ts": _fmt_ts(),
                "type": "legitimate",
                "line": dev_line,
            }, org_id=org_id)

        # 2. GENERATE ATTACK TRAFFIC IF CONFIGURED
        if attack_types:
            curr_atk = attack_types[attack_index % len(attack_types)]
            attack_index += 1
            atk_flow = _craft_attack_flow(curr_atk, curr_target_id, target_ip, step)
            atk_res = engine.score_flow(atk_flow)

            gate_score = float(atk_res.get("gate_score", 0.95))
            is_flagged = bool(atk_res.get("is_flagged", True))

            storage.record_flow(atk_flow, gate_score, is_flagged, org_id=org_id)

            run["metrics"]["total_requests"] += 1
            run["metrics"]["malicious_requests"] += 1
            if is_flagged:
                run["metrics"]["suspicious_requests"] += 1
                if curr_atk in ("ddos_syn_flood", "dos_conn_exhaust") and (step % 3 == 0):
                    run["metrics"]["failed_requests"] += 1
                else:
                    run["metrics"]["successful_requests"] += 1
            else:
                run["metrics"]["successful_requests"] += 1

            run["metrics"]["requests_per_sec"] = round(run["metrics"]["total_requests"] / max(elapsed, 0.5), 1)

            atk_meta = next((a for a in ATTACK_SCENARIOS if a["id"] == curr_atk), None)
            atk_name = atk_meta["name"] if atk_meta else curr_atk
            atk_tag = curr_atk.split("_")[0].upper()

            atk_line = f"[{_fmt_ts()}] [{atk_tag}-Worker] Emitting {atk_flow['orig_pkts']} pkts -> {target_ip}:{atk_flow['dst_port']} | {atk_flow['orig_bytes']} B"
            run["attack_terminal"].append({"ts": _fmt_ts(), "line": atk_line, "tag": atk_tag})

            await manager.broadcast({
                "type": "sim_attack_log",
                "run_id": run_id,
                "ts": _fmt_ts(),
                "tag": atk_tag,
                "line": atk_line,
            }, org_id=org_id)

            # 3. REAL-TIME ATTACK DETECTION TRIGGER
            if is_flagged:
                DEVICE_SECURITY_STATUS[curr_target_id] = "Attack Detected"
                sev = atk_meta["severity"] if atk_meta else "High"
                mitre_code = atk_meta.get("mitre", "T0814") if atk_meta else "T0814"

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
                    "target_id": curr_target_id,
                    "target_name": target_name,
                    "attack_type": atk_name,
                    "raw_type": atk_flow.get("attack_type", "ddos"),
                    "severity": sev,
                    "mitre": mitre_code,
                    "confidence": gate_score,
                    "confidence_pct": round(gate_score * 100, 1),
                    "timestamp": _fmt_ts(),
                    "reason": f"Anomalous {atk_flow['proto'].upper()} burst on port {atk_flow['dst_port']} (SHAP: {gate_score:.3f})",
                    "affected_requests": atk_flow["orig_pkts"],
                }
                run["detections"].append(detection_item)

                det_dev_line = f"[SECURITY DETECTION] [{_fmt_ts()}] Suspicious activity detected on {target_name}! Attack: {atk_name} | Severity: {sev.upper()} | Confidence: {gate_score:.1%}"
                run["device_terminal"].append({"ts": _fmt_ts(), "line": det_dev_line, "type": "detection"})

                await manager.broadcast({
                    "type": "sim_detection",
                    "run_id": run_id,
                    "detection": detection_item,
                }, org_id=org_id)

                await manager.broadcast({
                    "type": "sim_device_status",
                    "device_id": curr_target_id,
                    "security_status": "Attack Detected",
                }, org_id=org_id)

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

        # Broadcast periodic simulation metrics
        if step % 2 == 0:
            await manager.broadcast({
                "type": "sim_metrics",
                "run_id": run_id,
                "metrics": run["metrics"],
                "progress": pct,
            }, org_id=org_id)

        await asyncio.sleep(base_sleep)

    run["finished_at"] = time.time()
    if run["stop_requested"]:
        run["status"] = "stopped"
    else:
        run["status"] = "finished"
        run["progress"] = 100

    for tid in target_ids:
        DEVICE_SECURITY_STATUS[tid] = "Normal"

    # Terminate spawned processes on normal completion
    procs = ACTIVE_SIM_PROCESSES.get(run_id, [])
    for p_info in procs:
        proc = p_info.get("process")
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass

    await manager.broadcast({
        "type": "sim_status",
        "run_id": run_id,
        "status": run["status"],
        "progress": run["progress"],
    }, org_id=org_id)
