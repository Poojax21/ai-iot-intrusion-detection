"""
Dataset Column Mapping Registry.

Maps source dataset column headers onto the StandardRecord attributes.
"""

from typing import Dict, List, Optional

# ==============================================================================
# IoT-23 (Zeek conn.log / conn.log.labeled TSV format)
# Standard Zeek fields with IoT-23 annotation extension
# ==============================================================================
IOT23_ZEEK_COLUMNS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
    "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig",
    "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes",
    "resp_pkts", "resp_ip_bytes", "tunnel_parents", "label", "detailed-label"
]

IOT23_COLUMN_MAP: Dict[str, str] = {
    "ts": "timestamp",
    "id.orig_h": "source_ip",
    "id.orig_p": "source_port",
    "id.resp_h": "destination_ip",
    "id.resp_p": "destination_port",
    "proto": "protocol",
    "duration": "duration",
    "orig_bytes": "source_bytes",
    "resp_bytes": "destination_bytes",
    "orig_pkts": "source_packets",
    "resp_pkts": "destination_packets",
    "conn_state": "connection_state",
    "label": "original_label",
    "detailed-label": "detailed_label",
}


# ==============================================================================
# TON_IoT (Network Flow CSV Format)
# Produced via Zeek/Bro exports from the TON_IoT testbed
# ==============================================================================
TON_IOT_NETWORK_MAP: Dict[str, str] = {
    "ts": "timestamp",
    "src_ip": "source_ip",
    "src_port": "source_port",
    "dst_ip": "destination_ip",
    "dst_port": "destination_port",
    "proto": "protocol",
    "service": "service",
    "duration": "duration",
    "src_bytes": "source_bytes",
    "dst_bytes": "destination_bytes",
    "conn_state": "connection_state",
    "src_pkts": "source_packets",
    "dst_pkts": "destination_packets",
    "type": "original_label",
    "label": "binary_label",
}


# ==============================================================================
# CICIoT2023 (Tabular Statistical CSV Format)
# Features aggregated over rolling time windows
# ==============================================================================
CICIOT2023_COLUMN_MAP: Dict[str, str] = {
    "flow_duration": "duration",
    "header_length": "header_length",
    "protocol type": "protocol",
    "duration": "duration_alt",
    "rate": "pkt_rate",
    "srate": "source_rate",
    "drate": "destination_rate",
    "tot sum": "total_bytes",
    "tot size": "total_size",
    "number": "total_pkts",
    "min": "min_pkt_size",
    "max": "max_pkt_size",
    "avg": "avg_pkt_size",
    "std": "std_pkt_size",
    "label": "original_label",
}


# ==============================================================================
# Bot-IoT (UNSW Canberra Netflow / Flow CSV Format)
# ==============================================================================
BOT_IOT_COLUMN_MAP: Dict[str, str] = {
    "stime": "timestamp",
    "saddr": "source_ip",
    "sport": "source_port",
    "daddr": "destination_ip",
    "dport": "destination_port",
    "proto": "protocol",
    "state": "connection_state",
    "dur": "duration",
    "sbytes": "source_bytes",
    "dbytes": "destination_bytes",
    "spkts": "source_packets",
    "dpkts": "destination_packets",
    "category": "original_label",
    "subcategory": "detailed_label",
}


# ==============================================================================
# N-BaIoT (UCI Machine Learning Repository - 115 Flow Statistics)
# ==============================================================================
NBAIOT_COLUMN_MAP: Dict[str, str] = {
    "MI_dir_L5_weight": "source_packets",
    "MI_dir_L5_mean": "avg_pkt_size",
    "MI_dir_L5_std": "std_pkt_size",
    "H_L5_weight": "host_packets",
    "HH_L5_weight": "host_to_host_packets",
    "label": "original_label",
}
