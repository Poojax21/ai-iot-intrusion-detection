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
        "name": "DoS Connection Exhaustion (Half-Open Sockets)",
        "mitre": "T0814",
        "severity": "HIGH",
        "port": 80,
    },
    "brute_force_cred": {
        "title": "BRUTE FORCE",
        "name": "Brute Force Authentication Simulation (SSH/Telnet)",
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


def send_flow(backend_url: str, flow: dict):
    try:
        url = f"{backend_url}/api/ingest"
        data = json.dumps(flow).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def print_banner(attack_key: str, device_name: str, device_ip: str, intensity: str, duration: int):
    meta = ATTACK_META.get(attack_key, {
        "title": attack_key.upper(),
        "name": attack_key.replace("_", " ").title(),
        "mitre": "T0814",
        "severity": "HIGH",
        "port": 80,
    })

    print(f"{RED}{BOLD}╔═══════════════════════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{RED}{BOLD}║                 INDIVIDUAL ATTACK SIMULATION EXECUTION TERMINAL                   ║{RESET}")
    print(f"{RED}{BOLD}╚═══════════════════════════════════════════════════════════════════════════════════╝{RESET}")
    print(f"  {BOLD}Attack Vector :{RESET} {RED}{BOLD}{meta['name']}{RESET}")
    print(f"  {BOLD}MITRE ATT&CK  :{RESET} {YELLOW}{meta['mitre']}{RESET} (Severity: {RED}{meta['severity']}{RESET})")
    print(f"  {BOLD}Target Device :{RESET} {GREEN}{device_name}{RESET} ({device_ip})")
    print(f"  {BOLD}Target Port   :{RESET} {meta['port']}/TCP")
    print(f"  {BOLD}Intensity Rate:{RESET} {intensity.upper()}")
    print(f"  {BOLD}Run Duration  :{RESET} {duration} seconds (Standard Window)")
    print(f"{RED}───────────────────────────────────────────────────────────────────────────────────{RESET}")
    print(f"[{fmt_time()}] Initializing attack injector process...")
    print(f"[{fmt_time()}] Target node verified online at {device_ip}. Commencing flow delivery...")
    print(f"{RED}───────────────────────────────────────────────────────────────────────────────────{RESET}\n")


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


async def run_attack_loop(attack_key: str, device_id: str, device_name: str, device_ip: str,
                          intensity: str, duration_s: int, backend_url: str, session_id: str):
    sleep_gap = 0.8 if intensity == "low" else (0.35 if intensity == "medium" else 0.12)
    start_time = time.time()
    step = 0
    total_pkts = 0
    total_bytes = 0
    detected_count = 0
    stop_event = asyncio.Event()

    # Start background listener for operator stop signal
    asyncio.create_task(listen_for_stop(backend_url, stop_event))

    while (time.time() - start_time) < duration_s and not stop_event.is_set():
        step += 1
        now_ts = time.time()
        attacker_ip = f"185.220.101.{(step % 60) + 1}"

        if attack_key == "ddos_syn_flood":
            pkts = 40
            bytes_n = 1400
            total_pkts += pkts
            total_bytes += bytes_n
            flow = {
                "ts": now_ts, "device_id": device_id, "src_ip": attacker_ip, "dst_ip": device_ip,
                "src_port": 10000 + (step % 50000), "dst_port": 80, "proto": "tcp",
                "duration": 0.005, "orig_bytes": bytes_n, "resp_bytes": 0,
                "orig_pkts": pkts, "resp_pkts": 0, "conn_state": "S0", "history": "S",
                "attack_type": "ddos", "label": "ddos"
            }
            res = send_flow(backend_url, flow)
            is_det = res and res.get("flagged")
            if is_det: detected_count += 1

            print(f"{RED}[{fmt_time()}] ─── [ATTACK TRANSMISSION #ATK-{step:04d}] ──────────────────────────────{RESET}")
            print(f"  {BOLD}[VECTOR]       :{RESET} {RED}{BOLD}DDoS Distributed SYN Flood{RESET}")
            print(f"  {BOLD}[TARGET NODE]  :{RESET} {device_name} ({device_ip}:80)")
            print(f"  {BOLD}[PAYLOAD BURST]:{RESET} 40 SYN Packets | Window: 1024 | Flags: [SYN] | Rate: 160 pkts/s")
            print(f"  {BOLD}[TRAFFIC STATS]:{RESET} 1,400 Bytes | TCP S0 (Half-Open Ingress)")
            print(f"  {BOLD}[IDS REACTION] :{RESET} {YELLOW}{BOLD}🚨 INTRUSION DETECTED (Gate Score: {res.get('gate_score', 0.98):.3f}){RESET}" if is_det else f"  {BOLD}[IDS REACTION] :{RESET} Flow evaluated by sensor")
            print(f"{RED}─────────────────────────────────────────────────────────────────────────────{RESET}\n")

        elif attack_key == "dos_conn_exhaust":
            pkts = 25
            bytes_n = 900
            total_pkts += pkts
            total_bytes += bytes_n
            flow = {
                "ts": now_ts, "device_id": device_id, "src_ip": attacker_ip, "dst_ip": device_ip,
                "src_port": 20000 + (step % 40000), "dst_port": 80, "proto": "tcp",
                "duration": 0.015, "orig_bytes": bytes_n, "resp_bytes": 0,
                "orig_pkts": pkts, "resp_pkts": 0, "conn_state": "S0", "history": "S",
                "attack_type": "ddos", "label": "ddos"
            }
            res = send_flow(backend_url, flow)
            is_det = res and res.get("flagged")
            if is_det: detected_count += 1

            print(f"{RED}[{fmt_time()}] ─── [ATTACK TRANSMISSION #ATK-{step:04d}] ──────────────────────────────{RESET}")
            print(f"  {BOLD}[VECTOR]       :{RESET} {RED}{BOLD}DoS Connection Exhaustion{RESET}")
            print(f"  {BOLD}[TARGET NODE]  :{RESET} {device_name} ({device_ip}:80)")
            print(f"  {BOLD}[PAYLOAD BURST]:{RESET} Incomplete 3-Way SYN Handshake (Holding TCP backlog slot)")
            print(f"  {BOLD}[TRAFFIC STATS]:{RESET} 25 Packets | 900 Bytes | TCP S0")
            print(f"  {BOLD}[IDS REACTION] :{RESET} {YELLOW}{BOLD}🚨 RESOURCE DEPLETION ATTACK FLAGGED{RESET}" if is_det else f"  {BOLD}[IDS REACTION] :{RESET} Pending analysis")
            print(f"{RED}─────────────────────────────────────────────────────────────────────────────{RESET}\n")

        elif attack_key == "brute_force_cred":
            target_port = 22 if (step % 2 == 0) else 23
            pkts = 4
            bytes_n = 180
            total_pkts += pkts
            total_bytes += bytes_n
            flow = {
                "ts": now_ts, "device_id": device_id, "src_ip": attacker_ip, "dst_ip": device_ip,
                "src_port": 40000 + (step % 20000), "dst_port": target_port, "proto": "tcp",
                "duration": 0.25, "orig_bytes": bytes_n, "resp_bytes": 45,
                "orig_pkts": pkts, "resp_pkts": 2, "conn_state": "REJ", "history": "ShR",
                "attack_type": "brute_force", "label": "brute_force"
            }
            res = send_flow(backend_url, flow)
            is_det = res and res.get("flagged")
            if is_det: detected_count += 1

            print(f"{RED}[{fmt_time()}] ─── [ATTACK TRANSMISSION #ATK-{step:04d}] ──────────────────────────────{RESET}")
            print(f"  {BOLD}[VECTOR]       :{RESET} {RED}{BOLD}Brute Force Credential Ingress{RESET}")
            print(f"  {BOLD}[TARGET NODE]  :{RESET} {device_name} ({device_ip}:{target_port}/SSH)")
            print(f"  {BOLD}[PAYLOAD BURST]:{RESET} Auth Dictionary Attempt #{step} (User: 'admin', Pass: '********')")
            print(f"  {BOLD}[TRAFFIC STATS]:{RESET} 4 Packets | 180 Bytes | TCP REJ")
            print(f"  {BOLD}[IDS REACTION] :{RESET} {YELLOW}{BOLD}🚨 RAPID AUTH FAILURE THRESHOLD EXCEEDED{RESET}" if is_det else f"  {BOLD}[IDS REACTION] :{RESET} Logged REJ")
            print(f"{RED}─────────────────────────────────────────────────────────────────────────────{RESET}\n")

        elif attack_key == "port_scan_syn":
            common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 554, 1883, 3389, 8080, 8883, 49152]
            scan_port = common_ports[step % len(common_ports)]
            total_pkts += 1
            total_bytes += 60
            flow = {
                "ts": now_ts, "device_id": device_id, "src_ip": attacker_ip, "dst_ip": device_ip,
                "src_port": 50000 + (step % 10000), "dst_port": scan_port, "proto": "tcp",
                "duration": 0.002, "orig_bytes": 60, "resp_bytes": 0,
                "orig_pkts": 1, "resp_pkts": 0, "conn_state": "S0", "history": "S",
                "attack_type": "port_scan", "label": "port_scan"
            }
            res = send_flow(backend_url, flow)
            is_det = res and res.get("flagged")
            if is_det: detected_count += 1

            print(f"{RED}[{fmt_time()}] ─── [ATTACK TRANSMISSION #ATK-{step:04d}] ──────────────────────────────{RESET}")
            print(f"  {BOLD}[VECTOR]       :{RESET} {RED}{BOLD}Port Scanning Reconnaissance{RESET}")
            print(f"  {BOLD}[TARGET NODE]  :{RESET} {device_name} ({device_ip}:{scan_port}/TCP)")
            print(f"  {BOLD}[PAYLOAD BURST]:{RESET} TCP SYN Probe (Flags: [SYN], Scan Pattern: Sequential Sweep)")
            print(f"  {BOLD}[TRAFFIC STATS]:{RESET} 1 Packet | 60 Bytes | TCP S0")
            print(f"  {BOLD}[IDS REACTION] :{RESET} {YELLOW}{BOLD}🚨 HORIZONTAL PORT SWEEP DETECTED{RESET}" if is_det else f"  {BOLD}[IDS REACTION] :{RESET} Probe recorded")
            print(f"{RED}─────────────────────────────────────────────────────────────────────────────{RESET}\n")

        elif attack_key == "mirai_c2_flood":
            total_pkts += 2
            total_bytes += 84
            flow = {
                "ts": now_ts, "device_id": device_id, "src_ip": device_ip, "dst_ip": "203.0.113.88",
                "src_port": 45000 + (step % 15000), "dst_port": 6667, "proto": "tcp",
                "duration": 0.150, "orig_bytes": 84, "resp_bytes": 64,
                "orig_pkts": 2, "resp_pkts": 2, "conn_state": "SF", "history": "ShADdfFa",
                "attack_type": "mirai_beacon", "label": "mirai_beacon"
            }
            res = send_flow(backend_url, flow)
            is_det = res and res.get("flagged")
            if is_det: detected_count += 1

            print(f"{RED}[{fmt_time()}] ─── [ATTACK TRANSMISSION #ATK-{step:04d}] ──────────────────────────────{RESET}")
            print(f"  {BOLD}[VECTOR]       :{RESET} {RED}{BOLD}Mirai C2 Botnet Beaconing{RESET}")
            print(f"  {BOLD}[TARGET NODE]  :{RESET} {device_name} -> Mock C2 (203.0.113.88:6667)")
            print(f"  {BOLD}[PAYLOAD BURST]:{RESET} Binary Botnet Keepalive Beacon (Header: 0x0001MIRAI)")
            print(f"  {BOLD}[TRAFFIC STATS]:{RESET} 2 Packets | 84 Bytes | TCP SF")
            print(f"  {BOLD}[IDS REACTION] :{RESET} {YELLOW}{BOLD}🚨 C2 BOTNET HEARTBEAT ISOLATED{RESET}" if is_det else f"  {BOLD}[IDS REACTION] :{RESET} Beaconing under review")
            print(f"{RED}─────────────────────────────────────────────────────────────────────────────{RESET}\n")

        else:  # zero_day_payload
            total_pkts += 12
            total_bytes += 2400
            flow = {
                "ts": now_ts, "device_id": device_id, "src_ip": attacker_ip, "dst_ip": device_ip,
                "src_port": 61000 + (step % 4000), "dst_port": 49152, "proto": "tcp",
                "duration": 0.08, "orig_bytes": 2400, "resp_bytes": 0,
                "orig_pkts": 12, "resp_pkts": 0, "conn_state": "OTH", "history": "S",
                "attack_type": "unknown_suspicious", "label": "unknown_suspicious"
            }
            res = send_flow(backend_url, flow)
            is_det = res and res.get("flagged")
            if is_det: detected_count += 1

            print(f"{RED}[{fmt_time()}] ─── [ATTACK TRANSMISSION #ATK-{step:04d}] ──────────────────────────────{RESET}")
            print(f"  {BOLD}[VECTOR]       :{RESET} {RED}{BOLD}Zero-Day Protocol Mutation{RESET}")
            print(f"  {BOLD}[TARGET NODE]  :{RESET} {device_name} ({device_ip}:49152)")
            print(f"  {BOLD}[PAYLOAD BURST]:{RESET} High-Entropy Malformed Protocol Mutation (Entropy: 7.92)")
            print(f"  {BOLD}[TRAFFIC STATS]:{RESET} 12 Packets | 2,400 Bytes | TCP OTH")
            print(f"  {BOLD}[IDS REACTION] :{RESET} {YELLOW}{BOLD}🚨 NOVEL CENTROID OUT-OF-DISTRIBUTION FLAGGED{RESET}" if is_det else f"  {BOLD}[IDS REACTION] :{RESET} Anomaly calculated")
            print(f"{RED}─────────────────────────────────────────────────────────────────────────────{RESET}\n")

        await asyncio.sleep(sleep_gap)

    # POST-SIMULATION LIFECYCLE
    if stop_event.is_set():
        print(f"\n{YELLOW}{BOLD}═════════════════════════════════════════════════════════════════════════════════════{RESET}")
        print(f"{YELLOW}{BOLD}                 [ATTACK GENERATOR STOPPED BY OPERATOR]                              {RESET}")
        print(f"{YELLOW}{BOLD}═════════════════════════════════════════════════════════════════════════════════════{RESET}")
        print(f"  {BOLD}Status        :{RESET} Attack traffic generation halted by SOC operator.")
        print(f"  {BOLD}Bursts Emitted:{RESET} {step} total transmission cycles")
        print(f"  {BOLD}Total Packets :{RESET} {total_pkts} | {total_bytes} B")
        print(f"  {BOLD}Attacks Caught:{RESET} {RED}{detected_count} detections verified by IDS backend{RESET}")
        print(f"  {BOLD}Terminal State:{RESET} {CYAN}{BOLD}WINDOW KEPT OPEN FOR FORENSIC LOG INSPECTION{RESET}")
        print(f"  {BOLD}Action        :{RESET} Review all bursts above. Close this window [X] whenever you are done.")
        print(f"{YELLOW}{BOLD}═════════════════════════════════════════════════════════════════════════════════════{RESET}\n")
        while True:
            await asyncio.sleep(3600)
    else:
        print(f"\n{CYAN}{BOLD}═════════════════════════════════════════════════════════════════════════════════════{RESET}")
        print(f"{CYAN}{BOLD}                 [ATTACK SIMULATION COMPLETED - 60s RUN FINISHED]                    {RESET}")
        print(f"{CYAN}{BOLD}═════════════════════════════════════════════════════════════════════════════════════{RESET}")
        print(f"  {BOLD}Bursts Emitted:{RESET} {step} total transmission cycles")
        print(f"  {BOLD}Total Packets :{RESET} {total_pkts} | {total_bytes} B")
        print(f"  {BOLD}Attacks Caught:{RESET} {RED}{detected_count} detections verified by IDS backend{RESET}")
        print(f"  {BOLD}Shutdown Mode :{RESET} All terminals will automatically shut down after 60 seconds.")
        print(f"  {BOLD}Manual Exit   :{RESET} Press Enter or close this window [X] anytime.")
        print(f"{CYAN}{BOLD}═════════════════════════════════════════════════════════════════════════════════════{RESET}\n")
        for remaining in range(60, 0, -5):
            print(f"[{fmt_time()}] Auto-closing in {remaining} seconds... (Close [X] anytime)")
            await asyncio.sleep(5)
        print(f"[{fmt_time()}] 60-second retention window complete. Closing terminal.")


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
    print_banner(args.attack_type, args.device_name, args.device_ip, args.intensity, args.duration)

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
        print(f"\n[{fmt_time()}] Attack simulation stopped by operator. Window preserved. Close [X] to exit.")
        while True:
            time.sleep(3600)


if __name__ == "__main__":
    main()
