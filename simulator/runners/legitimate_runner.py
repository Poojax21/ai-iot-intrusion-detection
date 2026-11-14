"""
Native Windows Terminal Runner: Legitimate Traffic Generator.
Generates normal background operations for simulated IoT devices:
HTTP telemetry requests, temperature updates, device heartbeats, sensor data updates,
humidity readings, status updates, and normal API calls.
"""

import argparse
import asyncio
import ctypes
import json
import os
import random
import sys
import time
import urllib.request

# Enable Windows virtual terminal sequences for ANSI colors
if os.name == "nt":
    os.system("")

# ANSI Color Codes
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


def set_terminal_title(title: str):
    """Sets the title of the native Windows terminal window."""
    if os.name == "nt":
        try:
            ctypes.windll.kernel32.SetConsoleTitleW(title)
        except Exception:
            pass


def fmt_time() -> str:
    return time.strftime("%H:%M:%S")


def send_flow(backend_url: str, flow: dict):
    try:
        url = f"{backend_url}/api/ingest"
        data = json.dumps(flow).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def print_banner(devices: list, legit_types: list, intensity: str):
    print(f"{GREEN}{BOLD}╔════════════════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{GREEN}{BOLD}║                 LEGITIMATE TRAFFIC GENERATOR (NORMAL REQUESTS)             ║{RESET}")
    print(f"{GREEN}{BOLD}╚════════════════════════════════════════════════════════════════════════════╝{RESET}")
    print(f"  {BOLD}Target Devices:{RESET} {', '.join(d['name'] for d in devices)}")
    print(f"  {BOLD}Request Types :{RESET} {', '.join(t.replace('_', ' ').title() for t in legit_types)}")
    print(f"  {BOLD}Traffic Profile:{RESET} Normal Operational Ingress (HTTP, MQTT, Heartbeats, Temp)")
    print(f"  {BOLD}Intensity     :{RESET} {intensity.upper()}")
    print(f"{GREEN}──────────────────────────────────────────────────────────────────────────────{RESET}")
    print(f"[{fmt_time()}] Initializing Legitimate Traffic Generator...")
    print(f"[{fmt_time()}] Delivering safe background operations to target device network interfaces...")
    print(f"{GREEN}──────────────────────────────────────────────────────────────────────────────{RESET}\n")


async def run_legitimate_loop(devices: list, legit_types: list, intensity: str, duration_s: int, backend_url: str):
    sleep_gap = 1.0 if intensity == "low" else (0.45 if intensity == "medium" else 0.2)
    start_time = time.time()
    step = 0
    total_reqs = 0

    while (time.time() - start_time) < duration_s:
        step += 1
        now_ts = time.time()
        dev = devices[step % len(devices)]
        dev_id = dev["id"]
        dev_name = dev["name"]
        dev_ip = dev["ip"]

        req_type = legit_types[step % len(legit_types)]
        cloud_gw = f"203.0.113.{(step % 8) + 1}"

        if req_type == "http_telemetry":
            flow = {
                "ts": now_ts, "device_id": dev_id, "src_ip": dev_ip, "dst_ip": cloud_gw,
                "src_port": 48000 + (step % 10000), "dst_port": 80, "proto": "tcp",
                "duration": 0.18, "orig_bytes": 450, "resp_bytes": 680,
                "orig_pkts": 4, "resp_pkts": 5, "conn_state": "SF", "history": "ShADadfF",
            }
            desc = f"HTTP REST Query GET /api/telemetry (200 OK, 450 B)"
        elif req_type in ("temp_readings", "humidity_readings"):
            flow = {
                "ts": now_ts, "device_id": dev_id, "src_ip": dev_ip, "dst_ip": cloud_gw,
                "src_port": 51000 + (step % 9000), "dst_port": 8883, "proto": "tcp",
                "duration": 0.08, "orig_bytes": 160, "resp_bytes": 180,
                "orig_pkts": 2, "resp_pkts": 3, "conn_state": "SF", "history": "ShADdf",
            }
            temp_val = round(21.5 + (random.random() * 3.5), 1)
            desc = f"Climate Probe Telemetry: {temp_val}°C to MQTT broker ({cloud_gw}:8883)"
        elif req_type == "device_heartbeat":
            flow = {
                "ts": now_ts, "device_id": dev_id, "src_ip": dev_ip, "dst_ip": cloud_gw,
                "src_port": 49000 + (step % 8000), "dst_port": 8883, "proto": "tcp",
                "duration": 0.06, "orig_bytes": 88, "resp_bytes": 96,
                "orig_pkts": 2, "resp_pkts": 2, "conn_state": "SF", "history": "ShADdf",
            }
            desc = f"Heartbeat PINGREQ to gateway ({cloud_gw}) -> PINGRESP OK"
        elif req_type == "sensor_updates":
            flow = {
                "ts": now_ts, "device_id": dev_id, "src_ip": dev_ip, "dst_ip": cloud_gw,
                "src_port": 50000 + (step % 12000), "dst_port": 8883, "proto": "tcp",
                "duration": 0.12, "orig_bytes": 280, "resp_bytes": 340,
                "orig_pkts": 3, "resp_pkts": 4, "conn_state": "SF", "history": "ShADadf",
            }
            desc = f"Sensor Data Publish (lux, battery=98%, heap=42KB)"
        else:
            flow = {
                "ts": now_ts, "device_id": dev_id, "src_ip": dev_ip, "dst_ip": cloud_gw,
                "src_port": 53000 + (step % 7000), "dst_port": 443, "proto": "tcp",
                "duration": 0.22, "orig_bytes": 620, "resp_bytes": 850,
                "orig_pkts": 6, "resp_pkts": 7, "conn_state": "SF", "history": "ShADadfF",
            }
            desc = f"Status Synchronization API sync with cloud endpoint"

        send_flow(backend_url, flow)
        total_reqs += 1

        print(f"[{fmt_time()}] Target: {GREEN}{dev_name}{RESET} ({dev_ip})")
        print(f"[{fmt_time()}] Type  : {req_type.replace('_', ' ').title()}")
        print(f"[{fmt_time()}] Detail: {desc}")
        print(f"[{fmt_time()}] Status: {GREEN}DELIVERED (Classification: LEGITIMATE){RESET}\n")

        await asyncio.sleep(sleep_gap)

    print(f"\n{GREEN}{BOLD}[{fmt_time()}] Legitimate traffic generator finished. Total requests: {total_reqs}{RESET}")


def main():
    parser = argparse.ArgumentParser(description="Pahredaar-IoT Legitimate Traffic Generator")
    parser.add_argument("--session-id", default="sim_live")
    parser.add_argument("--devices-json", required=True, help="JSON encoded list of device objects")
    parser.add_argument("--types-csv", default="http_telemetry,device_heartbeat")
    parser.add_argument("--intensity", default="medium")
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--backend-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()

    set_terminal_title("LEGITIMATE TRAFFIC GENERATOR - MULTI-DEVICE")

    try:
        devices = json.loads(args.devices_json)
    except Exception:
        devices = [{"id": "cam-01", "name": "Camera 01", "ip": "192.168.1.10"}]

    legit_types = [t.strip() for t in args.types_csv.split(",") if t.strip()]
    if not legit_types:
        legit_types = ["http_telemetry"]

    print_banner(devices, legit_types, args.intensity)

    try:
        asyncio.run(run_legitimate_loop(
            devices,
            legit_types,
            args.intensity,
            args.duration,
            args.backend_url
        ))
    except KeyboardInterrupt:
        print(f"\n[{fmt_time()}] Legitimate traffic generator stopped by operator.")


if __name__ == "__main__":
    main()
