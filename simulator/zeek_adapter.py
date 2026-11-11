"""
Production-Hardened Zeek conn.log Ingestion Adapter.

Bridges real network traffic captured by Zeek network monitors into the Pahredaar-IoT backend.

Features:
  - Dynamic `#fields` header parsing (handles non-standard or reordered Zeek columns).
  - Native JSON-lines Zeek conn.log support.
  - Dual operation modes: Live tail (`--tail`) or Offline capture replay (`--replay`).
  - Automatic log rotation and file truncation recovery.
  - UID deduplication cache (prevents duplicate alert floods on sensor reconnection).
  - Ingestion delay and source timestamp tracking.
  - Bounded FIFO backpressure buffering with oldest-first drop policy.
  - Safe parsing of incomplete, rejected, or truncated connection records.
  - Detailed telemetry: lines read, parsed, skipped, errors, throughput.
"""

import argparse
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import time
from typing import Any, Dict, Generator, List, Optional, Set, Tuple

import requests

DEFAULT_CONN_LOG_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
    "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig",
    "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes",
    "resp_pkts", "resp_ip_bytes", "tunnel_parents",
]


def resolve_device_id(src_ip: str, arp_table: Optional[Dict[str, str]] = None) -> Tuple[str, bool]:
    """
    Resolves persistent device identifier from IP address or DHCP/ARP table.
    Returns (device_id, mac_unstable).
    """
    if arp_table and src_ip in arp_table:
        mac = arp_table[src_ip]
        return hashlib.sha256(mac.encode()).hexdigest()[:16], False
    return hashlib.sha256(src_ip.encode()).hexdigest()[:16], True


class ZeekLogProcessor:
    """
    Parses and normalizes Zeek conn.log entries with dynamic schema discovery
    and duplicate record prevention.
    """

    def __init__(
        self,
        arp_table: Optional[Dict[str, str]] = None,
        dedup_cache_size: int = 50000,
    ):
        self.arp_table = arp_table or {}
        self.active_fields: List[str] = list(DEFAULT_CONN_LOG_FIELDS)
        self.seen_uids: deque = deque(maxlen=dedup_cache_size)
        self._uid_set: Set[str] = set()

        # Telemetry counters
        self.lines_read: int = 0
        self.records_parsed: int = 0
        self.duplicates_skipped: int = 0
        self.parse_errors: int = 0
        self.dropped_records: int = 0

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parses a single Zeek conn.log line (TSV with headers, or JSON lines).
        Returns normalized FlowRecord dictionary, or None if skipped/invalid.
        """
        self.lines_read += 1
        line_clean = line.strip()
        if not line_clean:
            return None

        # 1. Dynamic Zeek Header Detection
        if line_clean.startswith("#"):
            if line_clean.startswith("#fields"):
                parts = line_clean.split("\t")
                if len(parts) > 1:
                    # Strip '#fields' prefix
                    self.active_fields = parts[1:]
                else:
                    self.active_fields = line_clean.split()[1:]
            return None

        # 2. JSON-Lines Format Parsing
        if line_clean.startswith("{") and line_clean.endswith("}"):
            try:
                row = json.loads(line_clean)
                return self._normalize_record(row)
            except Exception:
                self.parse_errors += 1
                return None

        # 3. TSV Format Parsing
        parts = line_clean.split("\t")
        if len(parts) != len(self.active_fields):
            # Fallback split by whitespace if tab length mismatches
            parts_ws = line_clean.split()
            if len(parts_ws) == len(self.active_fields):
                parts = parts_ws
            else:
                self.parse_errors += 1
                return None

        row = dict(zip(self.active_fields, parts))
        return self._normalize_record(row)

    def _normalize_record(self, row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        # Extract UID and check deduplication
        uid = str(row.get("uid", ""))
        if uid and uid != "-":
            if uid in self._uid_set:
                self.duplicates_skipped += 1
                return None
            if len(self.seen_uids) == self.seen_uids.maxlen:
                oldest = self.seen_uids.popleft()
                self._uid_set.discard(oldest)
            self.seen_uids.append(uid)
            self._uid_set.add(uid)

        def _f(v, default=0.0) -> float:
            if v is None or v == "-" or v == "(empty)":
                return default
            try:
                val = float(v)
                return 0.0 if (val != val) else val
            except (ValueError, TypeError):
                return default

        def _i(v, default=0) -> int:
            if v is None or v == "-" or v == "(empty)":
                return default
            try:
                val = float(v)
                return default if (val != val) else int(val)
            except (ValueError, TypeError):
                return default

        src_ip = str(row.get("id.orig_h") or row.get("src_ip", "0.0.0.0"))
        dst_ip = str(row.get("id.resp_h") or row.get("dst_ip", "0.0.0.0"))
        if src_ip == "-" or not src_ip:
            self.parse_errors += 1
            return None

        device_id, mac_unstable = resolve_device_id(src_ip, self.arp_table)
        source_ts = _f(row.get("ts"), time.time())
        ingest_ts = time.time()

        proto = str(row.get("proto", "tcp")).lower()
        if proto not in ("tcp", "udp", "icmp"):
            proto = "tcp"

        conn_state = str(row.get("conn_state", "SF"))
        if conn_state == "-" or not conn_state:
            conn_state = "SF"

        self.records_parsed += 1

        return {
            "ts": ingest_ts,
            "source_ts": source_ts,
            "device_id": device_id,
            "mac_unstable": mac_unstable,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": _i(row.get("id.orig_p") or row.get("src_port")),
            "dst_port": _i(row.get("id.resp_p") or row.get("dst_port")),
            "proto": proto,
            "duration": max(0.0, _f(row.get("duration"), 0.0)),
            "orig_bytes": max(0, _i(row.get("orig_bytes") or row.get("orig_ip_bytes"))),
            "resp_bytes": max(0, _i(row.get("resp_bytes") or row.get("resp_ip_bytes"))),
            "orig_pkts": max(1, _i(row.get("orig_pkts"), 1)),
            "resp_pkts": max(0, _i(row.get("resp_pkts"), 0)),
            "conn_state": conn_state,
            "zeek_uid": uid if uid != "-" else None,
        }


def follow_file(
    file_path: str,
    from_start: bool = False,
    poll_interval_sec: float = 0.5,
) -> Generator[str, None, None]:
    """
    Follows a growing file with support for offline replay, log rotation,
    and truncation recovery.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Zeek log file not found: {file_path}")

    current_inode = os.stat(path).st_ino
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        if not from_start:
            f.seek(0, 2)  # Seek to end for live tail

        while True:
            line = f.readline()
            if line:
                yield line
            else:
                # Check for log rotation or truncation
                try:
                    stat = os.stat(path)
                    if stat.st_ino != current_inode:
                        # Log was rotated! Reopen new file
                        f.close()
                        f = open(path, "r", encoding="utf-8", errors="replace")
                        current_inode = stat.st_ino
                        continue
                    elif stat.st_size < f.tell():
                        # File was truncated! Seek back to beginning
                        f.seek(0, 0)
                        continue
                except OSError:
                    pass

                time.sleep(poll_interval_sec)


def main():
    ap = argparse.ArgumentParser(description="Pahredaar-IoT Zeek Network Ingestion Bridge")
    ap.add_argument("--conn-log", required=True, help="Path to Zeek conn.log")
    ap.add_argument("--backend", default="http://127.0.0.1:8000", help="Pahredaar-IoT backend URL")
    ap.add_argument("--api-key", default=None, help="Sensor API key for backend authentication")
    ap.add_argument("--replay", action="store_true", help="Replay from start of file rather than live tail")
    ap.add_argument("--batch-size", type=int, default=10, help="Ingestion batch size")
    ap.add_argument("--max-buffer", type=int, default=5000, help="Max in-memory buffer before dropping")
    args = ap.parse_args()

    processor = ZeekLogProcessor()
    buffer: List[Dict[str, Any]] = []

    headers = {"Content-Type": "application/json"}
    if args.api_key:
        headers["X-API-Key"] = args.api_key

    mode_str = "REPLAY (from start)" if args.replay else "LIVE TAIL (from end)"
    print(f"=== Pahredaar-IoT Zeek Bridge Started [{mode_str}] ===")
    print(f"[*] Target: {args.conn_log} -> {args.backend}/api/ingest")

    try:
        for line in follow_file(args.conn_log, from_start=args.replay):
            flow = processor.parse_line(line)
            if flow is None:
                continue

            # Remove adapter-internal tracking keys before sending to strict schema
            flow_payload = {k: v for k, v in flow.items() if k not in ("source_ts", "zeek_uid")}
            buffer.append(flow_payload)

            if len(buffer) > args.max_buffer:
                buffer.pop(0)  # FIFO drop under sustained backpressure
                processor.dropped_records += 1

            if len(buffer) >= args.batch_size or args.replay:
                while buffer:
                    target = buffer[0]
                    try:
                        resp = requests.post(
                            f"{args.backend}/api/ingest",
                            json=target,
                            headers=headers,
                            timeout=5,
                        )
                        resp.raise_for_status()
                        buffer.pop(0)
                    except requests.RequestException as e:
                        print(f"[WARN] Backend unavailable ({e}). Buffered {len(buffer)} flows.")
                        time.sleep(1.0)
                        break

    except KeyboardInterrupt:
        print("\n[+] Zeek bridge terminated by operator.")
        print(f"    Lines Read: {processor.lines_read}")
        print(f"    Records Parsed: {processor.records_parsed}")
        print(f"    Duplicates Skipped: {processor.duplicates_skipped}")
        print(f"    Parse Errors: {processor.parse_errors}")
        print(f"    Dropped Records: {processor.dropped_records}")


if __name__ == "__main__":
    main()
