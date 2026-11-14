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


def print_banner(device_name: str, device_id: str, device_type: str, device_ip: str):
    print(f"{CYAN}{BOLD}╔════════════════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{CYAN}{BOLD}║                 IOT DEVICE LIVE INGRESS & SECURITY MONITOR                 ║{RESET}")
    print(f"{CYAN}{BOLD}╚════════════════════════════════════════════════════════════════════════════╝{RESET}")
    print(f"  {BOLD}Device Name   :{RESET} {GREEN}{device_name}{RESET}")
    print(f"  {BOLD}Device ID     :{RESET} {CYAN}{device_id}{RESET}")
    print(f"  {BOLD}Device Type   :{RESET} {device_type.replace('_', ' ').title()}")
    print(f"  {BOLD}IPv4 Address  :{RESET} {GREEN}{device_ip}{RESET}")
    print(f"  {BOLD}Status        :{RESET} {GREEN}● ONLINE (Interfaces eth0, wlan0 UP){RESET}")
    print(f"  {BOLD}Defenses      :{RESET} Multi-Modal AI IDS Ingress Hook Active")
    print(f"{CYAN}──────────────────────────────────────────────────────────────────────────────{RESET}")
    print(f"[{fmt_time()}] Device {device_name} initialized.")
    print(f"[{fmt_time()}] Device status: {GREEN}ONLINE{RESET}. Listening for incoming traffic...")
    print(f"{CYAN}──────────────────────────────────────────────────────────────────────────────{RESET}\n")


async def monitor_device_events(device_id: str, device_name: str, device_ip: str, session_id: str, backend_url: str):
    import websockets

    ws_url = backend_url.replace("http://", "ws://").replace("https://", "wss://") + "/ws/alerts"

    while True:
        try:
            async with websockets.connect(ws_url, ping_interval=20, ping_timeout=20) as ws:
                print(f"[{fmt_time()}] {GREEN}Connected to Pahredaar-IoT backend message bus.{RESET}")
                print(f"[{fmt_time()}] Ingress socket active on {device_ip}. Awaiting network flows...\n")

                async for raw_msg in ws:
                    try:
                        msg = json.loads(raw_msg)
                    except Exception:
                        continue

                    msg_type = msg.get("type")

                    # 1. Device Ingress Log Event
                    if msg_type == "sim_device_log":
                        target_dev = msg.get("device_id")
                        if target_dev != device_id:
                            continue

                        line_type = msg.get("type", "info")
                        ts = msg.get("ts", fmt_time())
                        line = msg.get("line", "")

                        if line_type == "legitimate":
                            print(f"{GREEN}[{ts}] {line}{RESET}")
                            print(f"{GREEN}[{ts}] Classification: LEGITIMATE.{RESET}\n")
                        elif line_type == "malicious":
                            print(f"{RED}[{ts}] {line}{RESET}")
                            print(f"{RED}[{ts}] Classification: MALICIOUS.{RESET}\n")
                        elif line_type == "detection":
                            # Security detection box
                            print(f"{YELLOW}{BOLD}{'═' * 76}{RESET}")
                            print(f"{YELLOW}{BOLD}[SECURITY ALERT DETECTED]{RESET}")
                            print(f"  {BOLD}Device        :{RESET} {device_name} ({device_ip})")
                            print(f"  {BOLD}Alert Detail  :{RESET} {line}")
                            print(f"  {BOLD}Action        :{RESET} Flow Flagged -> Dispatched to SOC Defense Center")
                            print(f"{YELLOW}{BOLD}{'═' * 76}{RESET}\n")
                        else:
                            print(f"[{ts}] {line}")

                    # 2. Specific Security Detection Event
                    elif msg_type == "sim_detection":
                        det = msg.get("detection", {})
                        if det.get("target_id") != device_id:
                            continue

                        ts = det.get("timestamp", fmt_time())
                        atk_name = det.get("attack_type", "Suspicious Activity")
                        sev = det.get("severity", "HIGH").upper()
                        conf = det.get("confidence_pct", 98)
                        reason = det.get("reason", "Anomalous traffic burst")

                        print(f"{RED}{BOLD}╔══════════════════════════════════════════════════════════════════════╗{RESET}")
                        print(f"{RED}{BOLD}║                         [SECURITY ALERT]                             ║{RESET}")
                        print(f"{RED}{BOLD}╚══════════════════════════════════════════════════════════════════════╝{RESET}")
                        print(f"  {BOLD}Device         :{RESET} {device_name} ({device_ip})")
                        print(f"  {BOLD}Attack Detected:{RESET} {RED}{BOLD}{atk_name}{RESET}")
                        print(f"  {BOLD}Classification :{RESET} {RED}{BOLD}MALICIOUS{RESET}")
                        print(f"  {BOLD}Severity       :{RESET} {RED if sev in ('CRITICAL', 'HIGH') else YELLOW}{sev}{RESET}")
                        print(f"  {BOLD}Confidence     :{RESET} {conf}%")
                        print(f"  {BOLD}Reason         :{RESET} {reason}")
                        print(f"  {BOLD}Status         :{RESET} {RED}{BOLD}DETECTED - Ingress Isolated{RESET}")
                        print(f"{RED}{BOLD}╚══════════════════════════════════════════════════════════════════════╝{RESET}\n")

                    # 3. Native Flow Ingress Event
                    elif msg_type == "flow":
                        flow = msg.get("flow", {})
                        if flow.get("device_id") != device_id:
                            continue

                        proto = flow.get("proto", "tcp").upper()
                        src = f"{flow.get('src_ip')}:{flow.get('src_port')}"
                        dst = f"{flow.get('dst_ip')}:{flow.get('dst_port')}"
                        bytes_cnt = flow.get("orig_bytes", 0) + flow.get("resp_bytes", 0)
                        is_flagged = flow.get("is_flagged", False)

                        if is_flagged:
                            print(f"{RED}[{fmt_time()}] Incoming suspicious traffic from {src} -> {dst}{RESET}")
                            print(f"{RED}[{fmt_time()}] Proto: {proto} | Bytes: {bytes_cnt} | Classification: MALICIOUS.{RESET}\n")
                        else:
                            print(f"{GREEN}[{fmt_time()}] Incoming request from {src} -> {dst}{RESET}")
                            print(f"{GREEN}[{fmt_time()}] Proto: {proto} | Bytes: {bytes_cnt} | Classification: LEGITIMATE.{RESET}\n")

        except (websockets.exceptions.ConnectionClosed, OSError) as e:
            print(f"[{fmt_time()}] {YELLOW}Connection to backend interrupted. Reconnecting in 2s...{RESET}")
            await asyncio.sleep(2.0)
        except Exception as e:
            print(f"[{fmt_time()}] {RED}Error in monitor stream: {e}. Retrying...{RESET}")
            await asyncio.sleep(2.0)


def main():
    parser = argparse.ArgumentParser(description="Pahredaar-IoT Device Ingress Monitor")
    parser.add_argument("--session-id", default="sim_live")
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--device-name", default="IoT Device")
    parser.add_argument("--device-type", default="sensor")
    parser.add_argument("--device-ip", default="192.168.1.10")
    parser.add_argument("--backend-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()

    title = f"IOT DEVICE - {args.device_name.upper()} - LIVE MONITOR"
    set_terminal_title(title)
    print_banner(args.device_name, args.device_id, args.device_type, args.device_ip)

    try:
        asyncio.run(monitor_device_events(
            args.device_id,
            args.device_name,
            args.device_ip,
            args.session_id,
            args.backend_url
        ))
    except KeyboardInterrupt:
        print(f"\n[{fmt_time()}] Device monitor stopped by operator. Goodbye.")


if __name__ == "__main__":
    main()
