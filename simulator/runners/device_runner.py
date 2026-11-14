"""
Native Windows Terminal Runner: IoT Device Live Ingress Monitor.
Represents a standalone simulated IoT device terminal window running in real time.
Displays incoming legitimate, suspicious, and malicious traffic received by this specific device.
"""

import argparse
import asyncio
import ctypes
import json
import os
import sys
import time

# Enable Windows virtual terminal sequences for ANSI colors
if os.name == "nt":
    os.system("")

# ANSI Color Codes
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
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


def fmt_now_precise() -> str:
    t = time.time()
    ms = int((t % 1) * 1000)
    return time.strftime("%H:%M:%S", time.localtime(t)) + f".{ms:03d}"


def print_banner(device_name: str, device_id: str, device_type: str, device_ip: str, duration_s: int):
    print(f"{CYAN}{BOLD}╔═══════════════════════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{CYAN}{BOLD}║                 IOT DEVICE LIVE INGRESS & SECURITY MONITOR                        ║{RESET}")
    print(f"{CYAN}{BOLD}╚═══════════════════════════════════════════════════════════════════════════════════╝{RESET}")
    print(f"  {BOLD}Device Name   :{RESET} {GREEN}{device_name}{RESET}")
    print(f"  {BOLD}Device ID     :{RESET} {CYAN}{device_id}{RESET}")
    print(f"  {BOLD}Device Type   :{RESET} {device_type.replace('_', ' ').title()}")
    print(f"  {BOLD}IPv4 Address  :{RESET} {GREEN}{device_ip}{RESET}")
    print(f"  {BOLD}Interfaces    :{RESET} eth0, wlan0 {GREEN}● UP{RESET}")
    print(f"  {BOLD}Defense Sensor:{RESET} Multi-Modal AI IDS Hook Active (Hybrid RF + Isolation Forest)")
    print(f"  {BOLD}Session Budget:{RESET} {duration_s}s active simulation")
    print(f"{CYAN}───────────────────────────────────────────────────────────────────────────────────{RESET}")
    print(f"[{fmt_time()}] Device {device_name} online. Ingress sockets bound to {device_ip}.")
    print(f"[{fmt_time()}] Awaiting incoming legitimate requests and attack vectors...")
    print(f"{CYAN}───────────────────────────────────────────────────────────────────────────────────{RESET}\n")


async def monitor_device_events(device_id: str, device_name: str, device_ip: str, session_id: str, duration_s: int, backend_url: str):
    import websockets

    ws_url = backend_url.replace("http://", "ws://").replace("https://", "wss://") + "/ws/alerts"
    start_time = time.time()
    legit_count = 0
    mal_count = 0
    stopped_by_operator = False

    try:
        async with websockets.connect(ws_url, ping_interval=20, ping_timeout=20) as ws:
            print(f"[{fmt_time()}] {GREEN}Connected to Pahredaar-IoT backend telemetry bus.{RESET}\n")

            while True:
                elapsed = time.time() - start_time
                if elapsed >= duration_s:
                    break

                try:
                    raw_msg = await asyncio.wait_for(ws.recv(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue

                try:
                    msg = json.loads(raw_msg)
                except Exception:
                    continue

                msg_type = msg.get("type")

                # Check if operator stopped simulation early
                if msg_type == "sim_stop":
                    stopped_by_operator = True
                    break

                # 1. Device Ingress Log Event (Timeline)
                if msg_type == "sim_device_log":
                    target_dev = msg.get("device_id")
                    if target_dev != device_id:
                        continue

                    log_type = msg.get("log_type") or msg.get("type", "legitimate")
                    ts = msg.get("ts", fmt_time())
                    event_id = msg.get("event_id", f"EVT-{int(time.time()*1000)%100000:05d}")
                    name = msg.get("name") or "Network Ingress"
                    src = msg.get("src", "203.0.113.1:443")
                    dst = msg.get("dst", f"{device_ip}:80")
                    proto = msg.get("proto", "TCP").upper()
                    payload = msg.get("payload", "Standard Data Packet")
                    stats = msg.get("stats", "Packets: 4 | Ingress: 450 B")
                    verdict = msg.get("verdict", "Evaluated by AI Engine")

                    if log_type == "legitimate":
                        legit_count += 1
                        print(f"{GREEN}[{ts}] ─── [INGRESS TIMELINE EVENT #{event_id}] ──────────────────────────────────────────{RESET}")
                        print(f"  {BOLD}[CATEGORY]    :{RESET} {GREEN}{BOLD}SAFE REQUEST: {name}{RESET}")
                        print(f"  {BOLD}[TIMELINE]    :{RESET} Received: {ts} (Processing Latency: +1.4ms)")
                        print(f"  {BOLD}[FLOW 5-TUPLE]:{RESET} {src} -> {dst} [{proto}]")
                        print(f"  {BOLD}[PAYLOAD DATA]:{RESET} {payload}")
                        print(f"  {BOLD}[FLOW STATS]  :{RESET} {stats}")
                        print(f"  {BOLD}[AI VERDICT]  :{RESET} {GREEN}{BOLD}✓ {verdict} -> Status: 200 OK{RESET}")
                        print(f"{GREEN}───────────────────────────────────────────────────────────────────────────────────{RESET}\n")

                    elif log_type == "malicious":
                        mal_count += 1
                        print(f"{RED}[{ts}] ─── [INGRESS TIMELINE EVENT #{event_id}] ──────────────────────────────────────────{RESET}")
                        print(f"  {BOLD}[CATEGORY]    :{RESET} {RED}{BOLD}🚨 THREAT DETECTED: {name}{RESET}")
                        print(f"  {BOLD}[TIMELINE]    :{RESET} Received: {ts} (AI Detection Latency: +2.1ms)")
                        print(f"  {BOLD}[FLOW 5-TUPLE]:{RESET} {RED}{src} -> {dst} [{proto}]{RESET}")
                        print(f"  {BOLD}[PAYLOAD DATA]:{RESET} {payload}")
                        print(f"  {BOLD}[FLOW STATS]  :{RESET} {stats}")
                        print(f"  {BOLD}[AI DECISION] :{RESET} {RED}{BOLD}{verdict}{RESET}")
                        print(f"  {BOLD}[ACTION TAKEN]:{RESET} {YELLOW}{BOLD}INGRESS ISOLATED & DISPATCHED TO INCIDENT RESPONSE{RESET}")
                        print(f"{RED}───────────────────────────────────────────────────────────────────────────────────{RESET}\n")

                # 2. High-Severity Security Detection Alert Box
                elif msg_type == "sim_detection":
                    det = msg.get("detection", {})
                    if det.get("target_id") != device_id:
                        continue

                    ts = det.get("timestamp", fmt_time())
                    atk_name = det.get("attack_type", "Suspicious Activity")
                    sev = det.get("severity", "HIGH").upper()
                    conf = det.get("confidence_pct", 98)
                    reason = det.get("reason", "Anomalous traffic burst")

                    print(f"{RED}{BOLD}╔═══════════════════════════════════════════════════════════════════════════════════╗{RESET}")
                    print(f"{RED}{BOLD}║                         [SIEM DEFENSE ALERT DISPATCH]                             ║{RESET}")
                    print(f"{RED}{BOLD}╚═══════════════════════════════════════════════════════════════════════════════════╝{RESET}")
                    print(f"  {BOLD}Victim Node   :{RESET} {device_name} ({device_ip})")
                    print(f"  {BOLD}Threat Vector :{RESET} {RED}{BOLD}{atk_name}{RESET}")
                    print(f"  {BOLD}Classification:{RESET} {RED}{BOLD}MALICIOUS (Ingress Attack Blocked){RESET}")
                    print(f"  {BOLD}Severity Tier :{RESET} {RED if sev in ('CRITICAL', 'HIGH') else YELLOW}{sev}{RESET}")
                    print(f"  {BOLD}AI Confidence :{RESET} {conf}%")
                    print(f"  {BOLD}Attribution   :{RESET} {reason}")
                    print(f"  {BOLD}SOC Mitigation:{RESET} Ingress Dropped, Port Quarantined, Alert Synced to SOAR")
                    print(f"{RED}{BOLD}╚═══════════════════════════════════════════════════════════════════════════════════╝{RESET}\n")

    except Exception as e:
        print(f"[{fmt_time()}] Telemetry stream notice: {e}")

    # POST-SIMULATION LIFECYCLE
    if stopped_by_operator:
        print(f"\n{YELLOW}{BOLD}═════════════════════════════════════════════════════════════════════════════════════{RESET}")
        print(f"{YELLOW}{BOLD}                 [SIMULATION STOPPED BY SOC OPERATOR]                                {RESET}")
        print(f"{YELLOW}{BOLD}═════════════════════════════════════════════════════════════════════════════════════{RESET}")
        print(f"  {BOLD}Status        :{RESET} Traffic generation halted by SOC Console operator.")
        print(f"  {BOLD}Safe Requests :{RESET} {GREEN}{legit_count} processed successfully (200 OK){RESET}")
        print(f"  {BOLD}Attacks Caught:{RESET} {RED}{mal_count} identified, mitigated, and isolated{RESET}")
        print(f"  {BOLD}Terminal State:{RESET} {CYAN}{BOLD}WINDOW KEPT OPEN FOR FORENSIC LOG INSPECTION{RESET}")
        print(f"  {BOLD}Action        :{RESET} Review all requests above. Close this window [X] whenever you are done.")
        print(f"{YELLOW}{BOLD}═════════════════════════════════════════════════════════════════════════════════════{RESET}\n")
        # Keep open permanently so user cuts it themselves
        while True:
            await asyncio.sleep(3600)
    else:
        # Completed naturally after duration (e.g. 1 minute)
        print(f"\n{CYAN}{BOLD}═════════════════════════════════════════════════════════════════════════════════════{RESET}")
        print(f"{CYAN}{BOLD}                 [SIMULATION COMPLETED - 60s RUN FINISHED]                           {RESET}")
        print(f"{CYAN}{BOLD}═════════════════════════════════════════════════════════════════════════════════════{RESET}")
        print(f"  {BOLD}Safe Requests :{RESET} {GREEN}{legit_count} processed successfully (200 OK){RESET}")
        print(f"  {BOLD}Attacks Caught:{RESET} {RED}{mal_count} identified, mitigated, and isolated{RESET}")
        print(f"  {BOLD}Shutdown Mode :{RESET} All terminals will automatically shut down after 60 seconds.")
        print(f"  {BOLD}Manual Exit   :{RESET} Press Enter or close this window [X] anytime.")
        print(f"{CYAN}{BOLD}═════════════════════════════════════════════════════════════════════════════════════{RESET}\n")
        for remaining in range(60, 0, -5):
            print(f"[{fmt_time()}] Auto-closing in {remaining} seconds... (Close [X] anytime)")
            await asyncio.sleep(5)
        print(f"[{fmt_time()}] 60-second retention window complete. Closing terminal.")


def main():
    parser = argparse.ArgumentParser(description="Pahredaar-IoT Device Ingress Monitor")
    parser.add_argument("--session-id", default="sim_live")
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--device-name", default="IoT Device")
    parser.add_argument("--device-type", default="sensor")
    parser.add_argument("--device-ip", default="192.168.1.10")
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--backend-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()

    title = f"IOT DEVICE - {args.device_name.upper()} - LIVE MONITOR"
    set_terminal_title(title)
    print_banner(args.device_name, args.device_id, args.device_type, args.device_ip, args.duration)

    try:
        asyncio.run(monitor_device_events(
            args.device_id,
            args.device_name,
            args.device_ip,
            args.session_id,
            args.duration,
            args.backend_url
        ))
    except KeyboardInterrupt:
        print(f"\n[{fmt_time()}] Device monitor stopped by operator. Window preserved. Close [X] to exit.")
        while True:
            time.sleep(3600)


if __name__ == "__main__":
    main()
