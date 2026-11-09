"""
Synthetic IoT flow-traffic generator.

This exists so the whole project (training + simulation) runs end-to-end
with ZERO external downloads. It generates traffic with the same *shape* of
signal the real public datasets encode (see docs/IoT-IDS-Project-Plan.md §8):
  - benign traffic that varies by device type (camera/plug/sensor/thermostat)
  - port_scan: many distinct destination ports, near-zero duration, tiny payload
  - ddos: very high packet rate, short duration, single/narrow destination
  - brute_force: many attempts to the same dst on a login port (22/23/80),
    short-ish flows, elevated failure (REJ/RSTO) rate
  - mirai_beacon: small, very regular periodic beacons to an external IP,
    low bytes, low variance in timing (looks "too regular" vs organic traffic)

>>> REPLACE WITH REAL DATA FOR PRODUCTION <<<
To train on real public datasets instead, see `load_real_dataset()` at the
bottom of this file — point it at a downloaded CICIoT2023/TON_IoT/Bot-IoT CSV
and it will map their columns onto the same FlowRecord schema used here, so
nothing else in the pipeline needs to change.
"""

import random
import time
import uuid

DEVICE_TYPES = ["camera", "smart_plug", "temp_sensor", "thermostat", "smart_bulb"]

INTERNAL_SUBNET = "192.168.1."
EXTERNAL_IPS = [f"203.0.113.{i}" for i in range(1, 40)]  # TEST-NET-3, safe placeholder range
COMMON_LOGIN_PORTS = [22, 23, 80, 443, 8080]


def make_device_pool(n_devices=8, seed=42):
    rnd = random.Random(seed)
    devices = []
    for i in range(n_devices):
        dtype = DEVICE_TYPES[i % len(DEVICE_TYPES)]
        devices.append({
            "device_id": f"{dtype}-{uuid.UUID(int=rnd.getrandbits(128)).hex[:8]}",
            "device_type": dtype,
            "ip": f"{INTERNAL_SUBNET}{10 + i}",
        })
    return devices


def _benign_flow(device, rnd, ts):
    dtype = device["device_type"]
    # each device type has its OWN normal traffic shape — this is exactly why
    # the plan insists on per-device baselining rather than a global threshold
    profile = {
        "camera":      dict(bytes_mu=180_000, bytes_sigma=40_000, dur_mu=8.0,  pkts_mu=400),
        "smart_plug":  dict(bytes_mu=800,      bytes_sigma=200,    dur_mu=0.5,  pkts_mu=6),
        "temp_sensor": dict(bytes_mu=300,       bytes_sigma=80,     dur_mu=0.2,  pkts_mu=3),
        "thermostat":  dict(bytes_mu=1200,      bytes_sigma=300,    dur_mu=1.0,  pkts_mu=10),
        "smart_bulb":  dict(bytes_mu=500,       bytes_sigma=150,    dur_mu=0.3,  pkts_mu=4),
    }[dtype]

    total_bytes = max(50, rnd.gauss(profile["bytes_mu"], profile["bytes_sigma"]))
    duration = max(0.01, rnd.gauss(profile["dur_mu"], profile["dur_mu"] * 0.3))
    total_pkts = max(1, int(rnd.gauss(profile["pkts_mu"], profile["pkts_mu"] * 0.3)))
    dst_ip = rnd.choice(EXTERNAL_IPS[:8])  # devices usually talk to a small, stable set of cloud endpoints

    return {
        "ts": ts, "device_id": device["device_id"], "src_ip": device["ip"],
        "dst_ip": dst_ip, "src_port": rnd.randint(40000, 60000),
        "dst_port": rnd.choice([443, 8883, 80]), "proto": "tcp",
        "duration": duration,
        "orig_bytes": int(total_bytes * 0.4), "resp_bytes": int(total_bytes * 0.6),
        "orig_pkts": int(total_pkts * 0.4) + 1, "resp_pkts": int(total_pkts * 0.6) + 1,
        "conn_state": "SF",
        "label": "benign",
    }


def _port_scan_flow(device, rnd, ts):
    dst_ip = rnd.choice(EXTERNAL_IPS)
    return {
        "ts": ts, "device_id": device["device_id"], "src_ip": device["ip"],
        "dst_ip": dst_ip, "src_port": rnd.randint(40000, 60000),
        "dst_port": rnd.randint(1, 65000), "proto": "tcp",
        "duration": round(rnd.uniform(0.001, 0.05), 4),
        "orig_bytes": rnd.randint(40, 80), "resp_bytes": 0,
        "orig_pkts": 1, "resp_pkts": 0,
        "conn_state": rnd.choice(["S0", "REJ"]),
        "label": "port_scan",
    }


def _ddos_flow(device, rnd, ts, victim_ip):
    return {
        "ts": ts, "device_id": device["device_id"], "src_ip": device["ip"],
        "dst_ip": victim_ip, "src_port": rnd.randint(1024, 65000),
        "dst_port": 80, "proto": rnd.choice(["tcp", "udp"]),
        "duration": round(rnd.uniform(0.001, 0.02), 4),
        "orig_bytes": rnd.randint(500, 1500), "resp_bytes": 0,
        "orig_pkts": rnd.randint(20, 60), "resp_pkts": 0,
        "conn_state": "S0",
        "label": "ddos",
    }


def _brute_force_flow(device, rnd, ts, target_ip):
    return {
        "ts": ts, "device_id": device["device_id"], "src_ip": device["ip"],
        "dst_ip": target_ip, "src_port": rnd.randint(40000, 60000),
        "dst_port": rnd.choice(COMMON_LOGIN_PORTS), "proto": "tcp",
        "duration": round(rnd.uniform(0.05, 0.4), 3),
        "orig_bytes": rnd.randint(80, 200), "resp_bytes": rnd.randint(20, 60),
        "orig_pkts": rnd.randint(2, 5), "resp_pkts": rnd.randint(1, 3),
        "conn_state": rnd.choice(["REJ", "RSTO", "S0"]),
        "label": "brute_force",
    }


def _mirai_beacon_flow(device, rnd, ts, c2_ip):
    return {
        "ts": ts, "device_id": device["device_id"], "src_ip": device["ip"],
        "dst_ip": c2_ip, "src_port": rnd.randint(40000, 60000),
        "dst_port": rnd.choice([6667, 23, 8080]), "proto": "tcp",
        "duration": round(rnd.gauss(0.15, 0.01), 3),   # unusually LOW variance -> "too regular"
        "orig_bytes": rnd.randint(60, 90), "resp_bytes": rnd.randint(60, 90),
        "orig_pkts": 2, "resp_pkts": 2,
        "conn_state": "SF",
        "label": "mirai_beacon",
    }


def generate_dataset(n_devices=8, n_flows=20000, attack_ratio=0.12, seed=42):
    """Generates a chronologically-ordered synthetic flow dataset.
    Returns a list of flow-record dicts, each with a 'label' field
    (only present in training data — never sent by a real sensor)."""
    rnd = random.Random(seed)
    devices = make_device_pool(n_devices, seed=seed)
    victim_ip = "192.168.1.250"          # simulated internal victim for DDoS
    c2_ip = EXTERNAL_IPS[-1]             # simulated external C2 for Mirai beaconing
    brute_target = "192.168.1.251"

    ts = time.time() - n_flows  # 1 flow/sec baseline pacing for realism
    flows = []
    for _ in range(n_flows):
        ts += rnd.uniform(0.5, 2.0)
        device = rnd.choice(devices)
        if rnd.random() < attack_ratio:
            attack_type = rnd.choices(
                ["port_scan", "ddos", "brute_force", "mirai_beacon"],
                weights=[0.3, 0.25, 0.25, 0.2],
            )[0]
            if attack_type == "port_scan":
                flows.append(_port_scan_flow(device, rnd, ts))
            elif attack_type == "ddos":
                flows.append(_ddos_flow(device, rnd, ts, victim_ip))
            elif attack_type == "brute_force":
                flows.append(_brute_force_flow(device, rnd, ts, brute_target))
            else:
                flows.append(_mirai_beacon_flow(device, rnd, ts, c2_ip))
        else:
            flows.append(_benign_flow(device, rnd, ts))
    return flows


def load_real_dataset(csv_path: str):
    """Stub showing where to plug in a real public dataset.
    Map the source CSV's columns onto the FlowRecord schema used throughout
    this project (ts, device_id, src_ip, dst_ip, src_port, dst_port, proto,
    duration, orig_bytes, resp_bytes, orig_pkts, resp_pkts, conn_state, label).
    See docs/IoT-IDS-Project-Plan.md §8 for dataset links and §7/§9.3 for the
    leakage-safe rules to follow when doing this mapping (never pass raw
    IP/MAC into the model as a categorical feature)."""
    import pandas as pd
    raise NotImplementedError(
        "Point this at your downloaded CICIoT2023 / TON_IoT / Bot-IoT CSV and "
        "map its columns to the schema above. Left unimplemented on purpose - "
        "column names differ per dataset/version, see the dataset's own docs."
    )
