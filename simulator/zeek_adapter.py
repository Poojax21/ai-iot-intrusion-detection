"""
Real-hardware bridge: Zeek conn.log -> backend /api/ingest

This is the piece that makes the switch from "simulated devices" to "real
IoT hardware" a non-event: point a Zeek instance at your router's SPAN/mirror
port (see plan §13 deployment diagram), then run this script pointed at
Zeek's conn.log. It tails the log, maps each line onto the exact same
FlowRecord schema the simulator sends, and POSTs it to the same endpoint.
Nothing downstream (detection, storage, frontend) needs to know the
difference.

Setup on the sensor box (Raspberry Pi / small gateway VM):
    sudo apt install zeek         # or build from source per your platform
    zeek -i <mirrored-interface>  # produces ./conn.log in the working dir

Then:
    python zeek_adapter.py --conn-log /path/to/conn.log --backend http://<collector>:8000

Device identity (plan §7): Zeek's conn.log gives you `id.orig_h` (source IP)
but not a MAC by default. If you need real per-device identity (recommended),
enable Zeek's `known-hosts`/`known-devices` scripts or join with your
router's ARP/DHCP lease table to resolve IP -> MAC -> hashed device_id.
This script includes a pluggable `resolve_device_id()` you should wire up to
that lookup for a real deployment; it falls back to a hash of the source IP
alone, which is fine for a quick test but will NOT survive DHCP lease changes.
"""

import argparse
import hashlib
import time

import requests

# Zeek conn.log default TSV columns (bro/zeek default logging format).
# If your Zeek build logs JSON instead (-> conn.log as JSON lines), skip the
# TSV parsing below entirely and json.loads() each line — the field NAMES
# are the same either way.
CONN_LOG_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
    "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig",
    "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes",
    "resp_pkts", "resp_ip_bytes", "tunnel_parents",
]


def resolve_device_id(src_ip: str, arp_table: dict | None = None) -> tuple[str, bool]:
    """Returns (device_id, mac_unstable).
    Wire this up to your router's ARP/DHCP table for a real deployment:
    mac = arp_table.get(src_ip) if arp_table else None
    if mac: return hashlib.sha256(mac.encode()).hexdigest()[:16], False
    Falls back to hashing the IP alone (works for a quick test, but a
    device's identity will "reset" if its IP changes via DHCP)."""
    if arp_table and src_ip in arp_table:
        mac = arp_table[src_ip]
        return hashlib.sha256(mac.encode()).hexdigest()[:16], False
    return hashlib.sha256(src_ip.encode()).hexdigest()[:16], True


def parse_conn_log_line(line: str) -> dict | None:
    if line.startswith("#") or not line.strip():
        return None
    parts = line.rstrip("\n").split("\t")
    if len(parts) < len(CONN_LOG_FIELDS):
        return None
    row = dict(zip(CONN_LOG_FIELDS, parts))

    def _f(v, default=0.0):
        try:
            return float(v)
        except (ValueError, TypeError):
            return default

    def _i(v, default=0):
        try:
            return int(float(v))
        except (ValueError, TypeError):
            return default

    device_id, mac_unstable = resolve_device_id(row["id.orig_h"])

    return {
        "ts": _f(row["ts"], time.time()),
        "device_id": device_id,
        "mac_unstable": mac_unstable,
        "src_ip": row["id.orig_h"],
        "dst_ip": row["id.resp_h"],
        "src_port": _i(row["id.orig_p"]),
        "dst_port": _i(row["id.resp_p"]),
        "proto": row["proto"],
        "duration": _f(row["duration"], 0.0),
        "orig_bytes": _i(row["orig_bytes"]),
        "resp_bytes": _i(row["resp_bytes"]),
        "orig_pkts": _i(row["orig_pkts"]),
        "resp_pkts": _i(row["resp_pkts"]),
        "conn_state": row["conn_state"],
    }


def tail_file(path: str):
    """Simple `tail -f` equivalent — follows a growing conn.log file."""
    with open(path, "r") as f:
        f.seek(0, 2)  # seek to end; only process NEW lines from now on
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--conn-log", required=True, help="Path to Zeek's conn.log")
    ap.add_argument("--backend", default="http://localhost:8000")
    args = ap.parse_args()

    print(f"Tailing {args.conn_log} -> {args.backend}/api/ingest")
    buffer = []  # local buffer used if the backend is briefly unreachable (plan §11)
    MAX_BUFFER = 5000

    for line in tail_file(args.conn_log):
        flow = parse_conn_log_line(line)
        if flow is None:
            continue

        buffer.append(flow)
        if len(buffer) > MAX_BUFFER:
            buffer.pop(0)  # oldest-first drop under sustained backpressure, per plan §11

        try:
            while buffer:
                resp = requests.post(f"{args.backend}/api/ingest", json=buffer[0], timeout=5)
                resp.raise_for_status()
                buffer.pop(0)
        except requests.RequestException as e:
            print(f"[WARN] backend unreachable ({e}); buffering ({len(buffer)} flows pending)")


if __name__ == "__main__":
    main()
