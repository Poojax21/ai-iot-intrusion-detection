"""
Simulated IoT device fleet — streams live traffic to the backend over HTTP,
using the EXACT SAME JSON schema (backend/app/schemas.py: FlowRecord) that a
real Zeek/Suricata-based sensor would send (see zeek_adapter.py for that
bridge). Swapping this simulator for real hardware later means pointing a
real sensor at the same /api/ingest endpoint — nothing in the backend or
frontend needs to change.

Usage:
    python simulate_devices.py --backend http://localhost:8000 --devices 8 \
        --rate 5 --attack-prob 0.08

  --rate         average flows/second across the whole simulated fleet
  --attack-prob  probability any given flow is an attack (mixed across
                 port_scan / ddos / brute_force / mirai_beacon)
"""

import argparse
import random
import time
import sys
from pathlib import Path

import requests

sys.path.append(str(Path(__file__).resolve().parent))
try:
    from .synthetic_traffic import (
        make_device_pool, _benign_flow, _port_scan_flow, _ddos_flow,
        _brute_force_flow, _mirai_beacon_flow, EXTERNAL_IPS,
    )
except ImportError:
    from synthetic_traffic import (
        make_device_pool, _benign_flow, _port_scan_flow, _ddos_flow,
        _brute_force_flow, _mirai_beacon_flow, EXTERNAL_IPS,
    )

DEVICE_TYPE_LABELS = {
    "camera": "camera", "smart_plug": "smart_plug", "temp_sensor": "temp_sensor",
    "thermostat": "thermostat", "smart_bulb": "smart_bulb",
}


def build_flow(devices, rnd, attack_prob, victim_ip, c2_ip, brute_target):
    device = rnd.choice(devices)
    ts = time.time()
    if rnd.random() < attack_prob:
        attack_type = rnd.choices(
            ["port_scan", "ddos", "brute_force", "mirai_beacon"],
            weights=[0.3, 0.25, 0.25, 0.2],
        )[0]
        if attack_type == "port_scan":
            flow = _port_scan_flow(device, rnd, ts)
        elif attack_type == "ddos":
            flow = _ddos_flow(device, rnd, ts, victim_ip)
        elif attack_type == "brute_force":
            flow = _brute_force_flow(device, rnd, ts, brute_target)
        else:
            flow = _mirai_beacon_flow(device, rnd, ts, c2_ip)
    else:
        flow = _benign_flow(device, rnd, ts)

    flow.pop("label", None)  # a real sensor never knows the ground-truth label — neither should we send it
    flow["device_type"] = device["device_type"]
    return flow


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="http://localhost:8000")
    ap.add_argument("--devices", type=int, default=8)
    ap.add_argument("--rate", type=float, default=5.0, help="avg flows/sec across the fleet")
    ap.add_argument("--attack-prob", type=float, default=0.08)
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    rnd = random.Random(args.seed)
    devices = make_device_pool(args.devices, seed=args.seed or 42)
    victim_ip = "192.168.1.250"
    c2_ip = EXTERNAL_IPS[-1]
    brute_target = "192.168.1.251"

    print(f"Simulating {len(devices)} devices -> {args.backend}/api/ingest")
    for d in devices:
        print(f"  - {d['device_id']} ({d['device_type']}) @ {d['ip']}")
    print(f"target rate: {args.rate} flows/sec, attack_prob={args.attack_prob}\n")

    # quick health check so failures are obvious immediately, not after silent 000s
    try:
        r = requests.get(f"{args.backend}/api/health", timeout=3)
        r.raise_for_status()
        health = r.json()
        print("backend health:", health)
        if not health.get("models_loaded"):
            print("WARNING: backend reports models not loaded — run the training "
                  "notebook first, otherwise flows will be stored but never scored.\n")
    except Exception as e:
        print(f"WARNING: could not reach backend health endpoint ({e}). Continuing anyway.\n")

    interval = 1.0 / max(args.rate, 0.1)
    sent, flagged = 0, 0
    session = requests.Session()

    while True:
        flow = build_flow(devices, rnd, args.attack_prob, victim_ip, c2_ip, brute_target)
        try:
            resp = session.post(f"{args.backend}/api/ingest", json=flow, timeout=5)
            resp.raise_for_status()
            result = resp.json()
            sent += 1
            if result.get("flagged"):
                flagged += 1
                alert = result.get("alert") or {}
                print(f"[ALERT] device={flow['device_id']} type={alert.get('attack_type')} "
                      f"severity={alert.get('severity')} gate_score={result.get('gate_score'):.3f}")
        except requests.RequestException as e:
            print(f"[WARN] could not reach backend ({e}) — dropping this flow and continuing "
                  f"(a real edge sensor would buffer locally here, see plan §11)")

        if sent and sent % 50 == 0:
            print(f"... sent={sent} flagged={flagged} ({flagged/sent:.1%})")

        time.sleep(max(0.0, rnd.expovariate(1.0 / interval)))


if __name__ == "__main__":
    main()
