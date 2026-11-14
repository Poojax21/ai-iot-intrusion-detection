"""
Native Windows Terminal Runner: Individual Attack Execution Generator.
Represents an independent attack simulation process running in its own native console window.
Generates controlled traffic flows for a specific attack vector targeting an IoT device.
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


ATTACK_META = {
    "ddos_syn_flood": {
        "title": "DDOS",
        "name": "DDoS Simulation (Distributed SYN Flood)",
        "mitre": "T0814",
        "severity": "CRITICAL",
        "port": 80,
    },
    "dos_conn_exhaust": {
        "title": "DOS",
        "name": "DoS Connection Exhaustion",
        "mitre": "T0814",
        "severity": "HIGH",
        "port": 80,
    },
    "brute_force_cred": {
        "title": "BRUTE FORCE",
        "name": "Brute Force Authentication Simulation",
        "mitre": "T0812",
        "severity": "HIGH",
        "port": 22,
    },
    "port_scan_syn": {
        "title": "PORT SCANNING",
        "name": "Port Scanning Simulation (TCP SYN Sweep)",
        "mitre": "T0846",
        "severity": "MEDIUM",
        "port": 8080,
    },
    "mirai_c2_flood": {
        "title": "MIRAI C2",
        "name": "Mirai C2 Botnet Beaconing",
        "mitre": "T0885",
        "severity": "HIGH",
        "port": 6667,
    },
    "zero_day_payload": {
        "title": "ZERO-DAY NOVELTY",
        "name": "Unauthorized Zero-Day Protocol Mutation",
        "mitre": "T0855",
        "severity": "ZERO-DAY",
        "port": 49152,
    },
}


def print_banner(attack_key: str, device_name: str, device_ip: str, intensity: str):
    meta = ATTACK_META.get(attack_key, {
        "title": attack_key.upper(),
        "name": attack_key.replace("_", " ").title(),
        "mitre": "T0814",
        "severity": "HIGH",
        "port": 80,
    })

    print(f"{RED}{BOLD}╔════════════════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{RED}{BOLD}║                 INDIVIDUAL ATTACK SIMULATION EXECUTION TERMINAL             ║{RESET}")
    print(f"{RED}{BOLD}╚════════════════════════════════════════════════════════════════════════════╝{RESET}")
    print(f"  {BOLD}Attack Name   :{RESET} {YELLOW}{BOLD}{meta['name']}{RESET}")
    print(f"  {BOLD}Target Device :{RESET} {GREEN}{device_name}{RESET} ({device_ip})")
    print(f"  {BOLD}MITRE ATT&CK  :{RESET} {CYAN}{meta['mitre']}{RESET} | Severity: {RED if meta['severity'] in ('CRITICAL', 'HIGH') else YELLOW}{meta['severity']}{RESET}")
    print(f"  {BOLD}Intensity     :{RESET} {intensity.upper()} | Target Port: {meta['port']}")
    print(f"  {BOLD}Environment   :{RESET} {GREEN}Controlled Local Sandbox (Zero external egress){RESET}")
    print(f"{RED}──────────────────────────────────────────────────────────────────────────────{RESET}")
    print(f"[{fmt_time()}] Initializing {meta['name']} engine...")
    print(f"[{fmt_time()}] Target: {device_name} ({device_ip}).")
    print(f"[{fmt_time()}] Starting controlled traffic generation...")
    print(f"{RED}──────────────────────────────────────────────────────────────────────────────{RESET}\n")


def send_flow(backend_url: str, flow: dict):
    """Sends a flow record to backend ingestion endpoint."""
    try:
        url = f"{backend_url}/api/ingest"
        data = json.dumps(flow).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


async def run_attack_loop(attack_key: str, device_id: str, device_name: str, device_ip: str, intensity: str, duration_s: int, backend_url: str, session_id: str):
    meta = ATTACK_META.get(attack_key, ATTACK_META["ddos_syn_flood"])
    sleep_gap = 0.5 if intensity == "low" else (0.22 if intensity == "medium" else 0.08)

    sample_creds = [
        ("admin", "admin123"), ("root", "toor"), ("user", "123456"),
        ("support", "support"), ("guest", "guest"), ("service", "operator")
    ]
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 443, 554, 1883, 3389, 8080, 8883, 49152]

    start_time = time.time()
    step = 0
    total_pkts = 0
    total_bytes = 0

    while (time.time() - start_time) < duration_s:
        step += 1
        now_ts = time.time()
        attacker_ip = f"198.51.100.{(step % 50) + 1}"

        if attack_key in ("ddos_syn_flood", "dos_conn_exhaust"):
            pkts = 40 if intensity == "medium" else (20 if intensity == "low" else 80)
            bytes_sent = pkts * 40
            total_pkts += pkts
            total_bytes += bytes_sent
            flow = {
                "ts": now_ts, "device_id": device_id, "src_ip": attacker_ip, "dst_ip": device_ip,
                "src_port": 10000 + (step % 50000), "dst_port": meta["port"], "proto": "tcp",
                "duration": 0.005, "orig_bytes": bytes_sent, "resp_bytes": 0,
                "orig_pkts": pkts, "resp_pkts": 0, "conn_state": "S0", "history": "S",
            }
            res = send_flow(backend_url, flow)
            print(f"[{fmt_time()}] Generating simulated requests -> {device_ip}:{meta['port']} (TCP S0)")
            print(f"[{fmt_time()}] Requests generated: {total_pkts} | Emitted: {round(total_bytes / 1024, 1)} KB.")
            if res and res.get("flagged"):
                print(f"{YELLOW}[{fmt_time()}] >>> [DETECTION EVENT] Defense engine flagged DDoS traffic pattern!{RESET}\n")
            else:
                print(f"[{fmt_time()}] Simulation active.\n")

        elif attack_key == "brute_force_cred":
            user, pwd = sample_creds[step % len(sample_creds)]
            target_port = 22 if (step % 2 == 0) else 23
            proto_name = "SSH" if target_port == 22 else "Telnet"
            total_pkts += 4
            total_bytes += 180
            flow = {
                "ts": now_ts, "device_id": device_id, "src_ip": attacker_ip, "dst_ip": device_ip,
                "src_port": 40000 + (step % 20000), "dst_port": target_port, "proto": "tcp",
                "duration": 0.25, "orig_bytes": 180, "resp_bytes": 45,
                "orig_pkts": 4, "resp_pkts": 2, "conn_state": "REJ", "history": "ShR",
            }
            res = send_flow(backend_url, flow)
            print(f"[{fmt_time()}] Attempt {step}: Simulated credentials '{user}:{pwd}' on {proto_name} (port {target_port})")
            if res and res.get("flagged"):
                print(f"{YELLOW}[{fmt_time()}] >>> [DETECTION EVENT] Authentication testing flagged by IDS!{RESET}\n")
            else:
                print(f"[{fmt_time()}] Authentication challenge failed (REJ). Testing next credential set.\n")

        elif attack_key == "port_scan_syn":
            scan_port = scan_ports[step % len(scan_ports)]
            total_pkts += 1
            total_bytes += 60
            flow = {
                "ts": now_ts, "device_id": device_id, "src_ip": attacker_ip, "dst_ip": device_ip,
                "src_port": 50000 + (step % 10000), "dst_port": scan_port, "proto": "tcp",
                "duration": 0.002, "orig_bytes": 60, "resp_bytes": 0,
                "orig_pkts": 1, "resp_pkts": 0, "conn_state": "S0", "history": "S",
            }
            res = send_flow(backend_url, flow)
            state_str = "OPEN" if scan_port in (80, 443, 22) else "REJ"
            print(f"[{fmt_time()}] Checking simulated port {scan_port} -> TCP SYN sent ({state_str})")
            if res and res.get("flagged"):
                print(f"{YELLOW}[{fmt_time()}] >>> [DETECTION EVENT] Port sweep pattern detected by IDS!{RESET}\n")
            else:
                print(f"[{fmt_time()}] Probe recorded. Moving to next service boundary.\n")

        elif attack_key == "mirai_c2_flood":
            total_pkts += 2
            total_bytes += 84
            flow = {
                "ts": now_ts, "device_id": device_id, "src_ip": device_ip, "dst_ip": "203.0.113.88",
                "src_port": 45000 + (step % 15000), "dst_port": 6667, "proto": "tcp",
                "duration": 0.150, "orig_bytes": 84, "resp_bytes": 64,
                "orig_pkts": 2, "resp_pkts": 2, "conn_state": "SF", "history": "ShADdfFa",
            }
            res = send_flow(backend_url, flow)
            print(f"[{fmt_time()}] Emitting botnet C2 heartbeat beacon to 203.0.113.88:6667 (TCP SF)")
            if res and res.get("flagged"):
                print(f"{YELLOW}[{fmt_time()}] >>> [DETECTION EVENT] C2 beaconing anomaly identified!{RESET}\n")
            else:
                print(f"[{fmt_time()}] Heartbeat acknowledged by remote mock C2 node.\n")

        else:  # zero_day_payload
            total_pkts += 12
            total_bytes += 2400
            flow = {
                "ts": now_ts, "device_id": device_id, "src_ip": attacker_ip, "dst_ip": device_ip,
                "src_port": 61000 + (step % 4000), "dst_port": 49152, "proto": "tcp",
                "duration": 0.08, "orig_bytes": 2400, "resp_bytes": 0,
                "orig_pkts": 12, "resp_pkts": 0, "conn_state": "OTH", "history": "S",
            }
            res = send_flow(backend_url, flow)
            print(f"[{fmt_time()}] Injecting mutated payload into port 49152 (entropy anomaly)")
            if res and res.get("flagged"):
                print(f"{YELLOW}[{fmt_time()}] >>> [DETECTION EVENT] Open-Set novel centroid rejection triggered!{RESET}\n")
            else:
                print(f"[{fmt_time()}] Payload evaluated by classifier.\n")

        await asyncio.sleep(sleep_gap)

    print(f"\n{GREEN}{BOLD}[{fmt_time()}] Simulation duration completed successfully.{RESET}")
    print(f"[{fmt_time()}] Total Packets Generated : {total_pkts}")
    print(f"[{fmt_time()}] Total Bytes Emitted     : {total_bytes} B")
    print(f"[{fmt_time()}] Process standing by. Press Ctrl+C or close window.")


def main():
    parser = argparse.ArgumentParser(description="Pahredaar-IoT Attack Execution Generator")
    parser.add_argument("--session-id", default="sim_live")
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--device-name", default="Camera 01")
    parser.add_argument("--device-ip", default="192.168.1.10")
    parser.add_argument("--attack-type", default="ddos_syn_flood")
    parser.add_argument("--intensity", default="medium")
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--backend-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()

    meta = ATTACK_META.get(args.attack_type, {"title": args.attack_type.upper()})
    title = f"ATTACK - {meta['title']} - {args.device_name.upper()}"
    set_terminal_title(title)
    print_banner(args.attack_type, args.device_name, args.device_ip, args.intensity)

    try:
        asyncio.run(run_attack_loop(
            args.attack_type,
            args.device_id,
            args.device_name,
            args.device_ip,
            args.intensity,
            args.duration,
            args.backend_url,
            args.session_id
        ))
    except KeyboardInterrupt:
        print(f"\n[{fmt_time()}] Attack simulation halted by operator.")


if __name__ == "__main__":
    main()
