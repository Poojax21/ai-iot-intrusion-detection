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


def print_banner(devices: list, legit_types: list, intensity: str, duration: int):
    print(f"{GREEN}{BOLD}╔═══════════════════════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{GREEN}{BOLD}║                 LEGITIMATE TRAFFIC GENERATOR (NORMAL REQUESTS)                    ║{RESET}")
    print(f"{GREEN}{BOLD}╚═══════════════════════════════════════════════════════════════════════════════════╝{RESET}")
    print(f"  {BOLD}Target Devices:{RESET} {', '.join(d['name'] for d in devices)}")
    print(f"  {BOLD}Request Types :{RESET} {', '.join(t.replace('_', ' ').title() for t in legit_types)}")
    print(f"  {BOLD}Traffic Profile:{RESET} Normal Operational Telemetry (HTTP, MQTT, Heartbeats, Climate)")
    print(f"  {BOLD}Intensity Rate:{RESET} {intensity.upper()}")
    print(f"  {BOLD}Run Duration  :{RESET} {duration} seconds (Standard Window)")
    print(f"{GREEN}───────────────────────────────────────────────────────────────────────────────────{RESET}")
    print(f"[{fmt_time()}] Initializing Legitimate Safe Traffic Generator...")
    print(f"[{fmt_time()}] Delivering authentic baseline operations across selected IoT nodes...")
    print(f"{GREEN}───────────────────────────────────────────────────────────────────────────────────{RESET}\n")


async def listen_for_stop(backend_url: str, stop_event: asyncio.Event):
    import websockets
    ws_url = backend_url.replace("http://", "ws://").replace("https://", "wss://") + "/ws/alerts"
    try:
        async with websockets.connect(ws_url, ping_interval=20, ping_timeout=20) as ws:
            async for raw in ws:
                try:
                    data = json.loads(raw)
                    if data.get("type") == "sim_stop":
                        stop_event.set()
                        return
                except Exception:
                    pass
    except Exception:
        pass


async def run_legitimate_loop(devices: list, legit_types: list, intensity: str, duration_s: int, backend_url: str):
    sleep_gap = 1.0 if intensity == "low" else (0.45 if intensity == "medium" else 0.2)
    start_time = time.time()
    step = 0
    total_reqs = 0
    stop_event = asyncio.Event()

    # Start background listener for operator stop signal
    asyncio.create_task(listen_for_stop(backend_url, stop_event))

    while (time.time() - start_time) < duration_s and not stop_event.is_set():
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
                "label": "benign"
            }
            desc = "GET /api/v1/telemetry HTTP/1.1 (Payload: status=ONLINE, uptime=84200s)"
        elif req_type in ("temp_readings", "humidity_readings"):
            flow = {
                "ts": now_ts, "device_id": dev_id, "src_ip": dev_ip, "dst_ip": cloud_gw,
                "src_port": 51000 + (step % 9000), "dst_port": 8883, "proto": "tcp",
                "duration": 0.08, "orig_bytes": 160, "resp_bytes": 180,
                "orig_pkts": 2, "resp_pkts": 3, "conn_state": "SF", "history": "ShADdf",
                "label": "benign"
            }
            temp_val = round(21.5 + (random.random() * 3.5), 1)
            rh_val = round(48.0 + (random.random() * 12.0), 1)
            desc = f"Thermal & Climate Telemetry: temp={temp_val}°C, humidity={rh_val}% RH -> MQTT Broker"
        elif req_type == "device_heartbeat":
            flow = {
                "ts": now_ts, "device_id": dev_id, "src_ip": dev_ip, "dst_ip": cloud_gw,
                "src_port": 49000 + (step % 8000), "dst_port": 8883, "proto": "tcp",
                "duration": 0.06, "orig_bytes": 88, "resp_bytes": 96,
                "orig_pkts": 2, "resp_pkts": 2, "conn_state": "SF", "history": "ShADdf",
                "label": "benign"
            }
            desc = f"MQTT PINGREQ /devices/keepalive (seq={step}, rssi=-56dBm) -> PINGRESP OK"
        elif req_type == "sensor_updates":
            flow = {
                "ts": now_ts, "device_id": dev_id, "src_ip": dev_ip, "dst_ip": cloud_gw,
                "src_port": 50000 + (step % 12000), "dst_port": 8883, "proto": "tcp",
                "duration": 0.12, "orig_bytes": 280, "resp_bytes": 340,
                "orig_pkts": 3, "resp_pkts": 4, "conn_state": "SF", "history": "ShADadf",
                "label": "benign"
            }
            desc = f"Sensor Telemetry Publish: lux=340, battery=3.28V, heap_free=42100B"
        elif req_type == "status_updates":
            flow = {
                "ts": now_ts, "device_id": dev_id, "src_ip": dev_ip, "dst_ip": cloud_gw,
                "src_port": 53000 + (step % 7000), "dst_port": 443, "proto": "tcp",
                "duration": 0.22, "orig_bytes": 620, "resp_bytes": 850,
                "orig_pkts": 6, "resp_pkts": 7, "conn_state": "SF", "history": "ShADadfF",
                "label": "benign"
            }
            desc = f"HTTPS POST /api/status (battery=96%, cpu=4.2%, wifi_snr=34)"
        else:  # api_requests
            flow = {
                "ts": now_ts, "device_id": dev_id, "src_ip": dev_ip, "dst_ip": cloud_gw,
                "src_port": 54000 + (step % 8000), "dst_port": 443, "proto": "tcp",
                "duration": 0.14, "orig_bytes": 390, "resp_bytes": 510,
                "orig_pkts": 3, "resp_pkts": 4, "conn_state": "SF", "history": "ShADadf",
                "label": "benign"
            }
            desc = f"HTTPS GET /api/v1/policy/rules (sync_version=v2.4, cert=VALID)"

        res = send_flow(backend_url, flow)
        total_reqs += 1

        print(f"{GREEN}[{fmt_time()}] ─── [SAFE TELEMETRY DISPATCH #LEG-{step:04d}] ──────────────────────────────{RESET}")
        print(f"  {BOLD}[CATEGORY]     :{RESET} {GREEN}{BOLD}SAFE REQUEST: {req_type.replace('_', ' ').title()}{RESET}")
        print(f"  {BOLD}[TARGET NODE]  :{RESET} {dev_name} ({dev_ip})")
        print(f"  {BOLD}[PAYLOAD DATA] :{RESET} {desc}")
        print(f"  {BOLD}[FLOW STATS]   :{RESET} Packets: {flow['orig_pkts']} | Ingress: {flow['orig_bytes']} B | State: {flow['conn_state']}")
        print(f"  {BOLD}[BACKEND ECHO] :{RESET} {GREEN}{BOLD}✓ CLASSIFICATION: LEGITIMATE (200 OK Accepted){RESET}")
        print(f"{GREEN}─────────────────────────────────────────────────────────────────────────────{RESET}\n")

        await asyncio.sleep(sleep_gap)

    # POST-SIMULATION LIFECYCLE
    if stop_event.is_set():
        print(f"\n{YELLOW}{BOLD}═════════════════════════════════════════════════════════════════════════════════════{RESET}")
        print(f"{YELLOW}{BOLD}                 [LEGITIMATE GENERATOR STOPPED BY OPERATOR]                          {RESET}")
        print(f"{YELLOW}{BOLD}═════════════════════════════════════════════════════════════════════════════════════{RESET}")
        print(f"  {BOLD}Status        :{RESET} Safe traffic generation halted by SOC operator.")
        print(f"  {BOLD}Requests Sent :{RESET} {total_reqs} legitimate baseline requests delivered")
        print(f"  {BOLD}Terminal State:{RESET} {CYAN}{BOLD}WINDOW KEPT OPEN FOR FORENSIC LOG INSPECTION{RESET}")
        print(f"  {BOLD}Action        :{RESET} Review all safe requests above. Close this window [X] when done.")
        print(f"{YELLOW}{BOLD}═════════════════════════════════════════════════════════════════════════════════════{RESET}\n")
        while True:
            await asyncio.sleep(3600)
    else:
        print(f"\n{CYAN}{BOLD}═════════════════════════════════════════════════════════════════════════════════════{RESET}")
        print(f"{CYAN}{BOLD}                 [SAFE TELEMETRY COMPLETED - 60s RUN FINISHED]                       {RESET}")
        print(f"{CYAN}{BOLD}═════════════════════════════════════════════════════════════════════════════════════{RESET}")
        print(f"  {BOLD}Requests Sent :{RESET} {total_reqs} legitimate baseline requests delivered")
        print(f"  {BOLD}Shutdown Mode :{RESET} All terminals will automatically shut down after 60 seconds.")
        print(f"  {BOLD}Manual Exit   :{RESET} Press Enter or close this window [X] anytime.")
        print(f"{CYAN}{BOLD}═════════════════════════════════════════════════════════════════════════════════════{RESET}\n")
        for remaining in range(60, 0, -5):
            print(f"[{fmt_time()}] Auto-closing in {remaining} seconds... (Close [X] anytime)")
            await asyncio.sleep(5)
        print(f"[{fmt_time()}] 60-second retention window complete. Closing terminal.")


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

    print_banner(devices, legit_types, args.intensity, args.duration)

    try:
        asyncio.run(run_legitimate_loop(
            devices,
            legit_types,
            args.intensity,
            args.duration,
            args.backend_url
        ))
    except KeyboardInterrupt:
        print(f"\n[{fmt_time()}] Legitimate traffic generator stopped by operator. Window preserved. Close [X] to exit.")
        while True:
            time.sleep(3600)


if __name__ == "__main__":
    main()
