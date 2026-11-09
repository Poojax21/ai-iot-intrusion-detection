"""
Leakage-safe feature engineering — shared logic.

IMPORTANT: this file must stay IDENTICAL (or at least behaviourally identical)
between backend/app/features.py and training/features.py. If you change the
feature set, retrain the models, and copy this file over the training copy
(or vice versa). Training/serving skew is one of the most common ways an IDS
silently degrades after "working fine in the notebook".

Design rules (see project plan §7 / §9.3):
  - raw src_ip / dst_ip / device_id are NEVER passed to a model as categorical
    values — they are only used as grouping keys to compute behavioral
    aggregates below.
  - every feature here is something a real Zeek `conn.log`-derived flow
    record can supply, so this same code path works whether the flow came
    from the simulator or from a real Zeek/Suricata sensor.
"""

from __future__ import annotations
import math
from dataclasses import dataclass, field

EPS = 1e-6

# The exact, ordered feature vector every model is trained/served on.
FEATURE_COLUMNS = [
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
    "total_bytes",
    "total_pkts",
    "byte_rate",
    "pkt_rate",
    "avg_pkt_size",
    "is_new_edge",
    "src_fanout_recent",
    "device_zscore",
    "proto_tcp",
    "proto_udp",
    "proto_icmp",
    "conn_state_sf",
    "conn_state_s0",
    "conn_state_rej",
    "conn_state_other",
]

ATTACK_LABELS = ["benign", "port_scan", "ddos", "brute_force", "mirai_beacon"]
LABEL_TO_ID = {name: i for i, name in enumerate(ATTACK_LABELS)}
ID_TO_LABEL = {i: name for name, i in LABEL_TO_ID.items()}

# Minimal MITRE ATT&CK for ICS style mapping (illustrative, not exhaustive)
MITRE_MAP = {
    "port_scan": "T0846 (Remote System Discovery)",
    "ddos": "T0814 (Denial of Service)",
    "brute_force": "T0812 (Default Credentials) / T1110-style brute force",
    "mirai_beacon": "T0868-style C2 Communication (botnet beaconing)",
}


@dataclass
class DeviceState:
    """Rolling, per-device state kept in memory (or a fast store) by the
    backend — this IS the per-device baseline described in the plan.
    Nothing here is persisted as a raw identity feature; it only feeds the
    derived numeric features below."""
    byte_rate_history: list = field(default_factory=list)
    seen_edges: set = field(default_factory=set)          # (device_id, dst_ip)
    recent_dst_ips: list = field(default_factory=list)     # sliding window for fan-out
    max_history: int = 50
    max_recent_window: int = 30
    flow_count: int = 0   # total flows seen for this device — used for the new-device grace period

    def update_and_score(self, dst_ip: str, byte_rate: float):
        self.flow_count += 1
        # --- new-edge flag ---
        edge_key = dst_ip
        is_new_edge = edge_key not in self.seen_edges
        self.seen_edges.add(edge_key)

        # --- fan-out over a recent sliding window ---
        self.recent_dst_ips.append(dst_ip)
        if len(self.recent_dst_ips) > self.max_recent_window:
            self.recent_dst_ips.pop(0)
        fanout = len(set(self.recent_dst_ips))

        # --- device z-score vs its OWN rolling baseline (not a global one) ---
        if len(self.byte_rate_history) >= 5:
            mean = sum(self.byte_rate_history) / len(self.byte_rate_history)
            var = sum((x - mean) ** 2 for x in self.byte_rate_history) / len(self.byte_rate_history)
            std = math.sqrt(var)
            zscore = (byte_rate - mean) / (std + EPS)
        else:
            zscore = 0.0

        self.byte_rate_history.append(byte_rate)
        if len(self.byte_rate_history) > self.max_history:
            self.byte_rate_history.pop(0)

        return is_new_edge, fanout, zscore


def _proto_one_hot(proto: str):
    proto = (proto or "").lower()
    return (
        1.0 if proto == "tcp" else 0.0,
        1.0 if proto == "udp" else 0.0,
        1.0 if proto == "icmp" else 0.0,
    )


def _conn_state_one_hot(conn_state: str):
    cs = (conn_state or "").upper()
    return (
        1.0 if cs == "SF" else 0.0,
        1.0 if cs == "S0" else 0.0,
        1.0 if cs == "REJ" else 0.0,
        1.0 if cs not in ("SF", "S0", "REJ") else 0.0,
    )


def build_feature_vector(flow: dict, device_state: DeviceState) -> list[float]:
    """flow: a single flow record dict (see schemas.FlowRecord for the exact
    fields a real sensor / the simulator must supply).
    Returns a feature vector IN THE SAME ORDER as FEATURE_COLUMNS."""
    duration = max(float(flow.get("duration", 0.0)), 0.0)
    orig_bytes = float(flow.get("orig_bytes", 0))
    resp_bytes = float(flow.get("resp_bytes", 0))
    orig_pkts = float(flow.get("orig_pkts", 0))
    resp_pkts = float(flow.get("resp_pkts", 0))

    total_bytes = orig_bytes + resp_bytes
    total_pkts = orig_pkts + resp_pkts
    byte_rate = total_bytes / (duration + EPS)
    pkt_rate = total_pkts / (duration + EPS)
    avg_pkt_size = total_bytes / (total_pkts + 1.0)

    is_new_edge, fanout, zscore = device_state.update_and_score(
        dst_ip=flow.get("dst_ip", "unknown"), byte_rate=byte_rate
    )

    proto_tcp, proto_udp, proto_icmp = _proto_one_hot(flow.get("proto", ""))
    cs_sf, cs_s0, cs_rej, cs_other = _conn_state_one_hot(flow.get("conn_state", ""))

    return [
        duration, orig_bytes, resp_bytes, orig_pkts, resp_pkts,
        total_bytes, total_pkts, byte_rate, pkt_rate, avg_pkt_size,
        float(is_new_edge), float(fanout), zscore,
        proto_tcp, proto_udp, proto_icmp,
        cs_sf, cs_s0, cs_rej, cs_other,
    ]
