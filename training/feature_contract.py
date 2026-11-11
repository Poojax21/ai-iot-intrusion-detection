"""
Canonical Feature Contract for Pahredaar-IoT.

Defines the single source of truth for feature definitions, ordering, data types,
units, missing-value policies, and training-serving parity across:
  - Dataset preprocessing
  - Model training pipelines
  - Production inference (FastAPI / detection.py)
  - Fleet simulator & test fixtures
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import numpy as np


class FeatureCompatibility(str, Enum):
    DIRECT = "directly_compatible"       # Field matches 1:1 in name and semantics
    DERIVABLE = "derivable"              # Computed deterministically from raw flow attributes
    PARTIAL = "partially_compatible"     # Similar concept but different unit or scale
    UNAVAILABLE = "unavailable"          # Not present in source dataset
    INCOMPATIBLE = "incompatible"        # Conflicts with feature semantics or leakage-safe rules


class MissingValuePolicy(str, Enum):
    ZERO_FILL = "zero_fill"              # Legitimate zero (e.g. 0 responder bytes)
    IMPUTE_MEDIAN = "impute_median"      # Impute with training set median
    EXPLICIT_INDICATOR = "indicator"    # Set indicator / flag
    ERROR = "error"                      # Missingness not permitted
    FORWARD_FILL = "forward_fill"        # Sequential state continuation


@dataclass(frozen=True)
class FeatureDefinition:
    """Specification of a single model feature."""
    name: str
    dtype: str
    unit: str
    source_field: str
    description: str
    transformation: str
    missing_policy: MissingValuePolicy
    live_available: bool                 # Can a real edge sensor (Zeek/Suricata) supply this?
    min_val: Optional[float] = None
    max_val: Optional[float] = None


@dataclass
class StandardRecord:
    """
    Standardized internal network flow record representation.
    Preserves all available raw attributes without fabricating values.
    """
    timestamp: float
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    duration: float
    source_bytes: int
    destination_bytes: int
    source_packets: int
    destination_packets: int
    connection_state: str
    source_device_id: Optional[str] = None
    destination_device_id: Optional[str] = None
    capture_id: Optional[str] = None
    scenario_id: Optional[str] = None
    original_label: Optional[str] = None
    normalized_label: Optional[str] = None
    dataset_name: Optional[str] = None
    extra_features: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert standard record to dictionary."""
        d = {
            "ts": self.timestamp,
            "src_ip": self.source_ip,
            "dst_ip": self.destination_ip,
            "src_port": self.source_port,
            "dst_port": self.destination_port,
            "proto": self.protocol,
            "duration": self.duration,
            "orig_bytes": self.source_bytes,
            "resp_bytes": self.destination_bytes,
            "orig_pkts": self.source_packets,
            "resp_pkts": self.destination_packets,
            "conn_state": self.connection_state,
            "device_id": self.source_device_id or f"dev-{self.source_ip}",
            "capture_id": self.capture_id,
            "scenario_id": self.scenario_id,
            "original_label": self.original_label,
            "normalized_label": self.normalized_label,
            "dataset_name": self.dataset_name,
        }
        d.update(self.extra_features)
        return d


# ==============================================================================
# CANONICAL V1 FEATURE DEFINITIONS (20 Features)
# Must remain identical to backend/app/features.py: FEATURE_COLUMNS
# ==============================================================================

V1_FEATURE_DEFINITIONS: List[FeatureDefinition] = [
    FeatureDefinition(
        name="duration",
        dtype="float64",
        unit="seconds",
        source_field="duration",
        description="Flow duration from first to last packet",
        transformation="max(val, 0.0)",
        missing_policy=MissingValuePolicy.ZERO_FILL,
        live_available=True,
        min_val=0.0,
    ),
    FeatureDefinition(
        name="orig_bytes",
        dtype="float64",
        unit="bytes",
        source_field="orig_bytes",
        description="Payload bytes sent by originator",
        transformation="float(val)",
        missing_policy=MissingValuePolicy.ZERO_FILL,
        live_available=True,
        min_val=0.0,
    ),
    FeatureDefinition(
        name="resp_bytes",
        dtype="float64",
        unit="bytes",
        source_field="resp_bytes",
        description="Payload bytes sent by responder",
        transformation="float(val)",
        missing_policy=MissingValuePolicy.ZERO_FILL,
        live_available=True,
        min_val=0.0,
    ),
    FeatureDefinition(
        name="orig_pkts",
        dtype="float64",
        unit="packets",
        source_field="orig_pkts",
        description="Packets sent by originator",
        transformation="float(val)",
        missing_policy=MissingValuePolicy.ZERO_FILL,
        live_available=True,
        min_val=0.0,
    ),
    FeatureDefinition(
        name="resp_pkts",
        dtype="float64",
        unit="packets",
        source_field="resp_pkts",
        description="Packets sent by responder",
        transformation="float(val)",
        missing_policy=MissingValuePolicy.ZERO_FILL,
        live_available=True,
        min_val=0.0,
    ),
    FeatureDefinition(
        name="total_bytes",
        dtype="float64",
        unit="bytes",
        source_field="orig_bytes + resp_bytes",
        description="Total bidirectional byte count",
        transformation="orig_bytes + resp_bytes",
        missing_policy=MissingValuePolicy.ZERO_FILL,
        live_available=True,
        min_val=0.0,
    ),
    FeatureDefinition(
        name="total_pkts",
        dtype="float64",
        unit="packets",
        source_field="orig_pkts + resp_pkts",
        description="Total bidirectional packet count",
        transformation="orig_pkts + resp_pkts",
        missing_policy=MissingValuePolicy.ZERO_FILL,
        live_available=True,
        min_val=0.0,
    ),
    FeatureDefinition(
        name="byte_rate",
        dtype="float64",
        unit="bytes/sec",
        source_field="total_bytes / (duration + 1e-6)",
        description="Byte throughput rate",
        transformation="total_bytes / (duration + 1e-6)",
        missing_policy=MissingValuePolicy.ZERO_FILL,
        live_available=True,
        min_val=0.0,
    ),
    FeatureDefinition(
        name="pkt_rate",
        dtype="float64",
        unit="pkts/sec",
        source_field="total_pkts / (duration + 1e-6)",
        description="Packet throughput rate",
        transformation="total_pkts / (duration + 1e-6)",
        missing_policy=MissingValuePolicy.ZERO_FILL,
        live_available=True,
        min_val=0.0,
    ),
    FeatureDefinition(
        name="avg_pkt_size",
        dtype="float64",
        unit="bytes/pkt",
        source_field="total_bytes / (total_pkts + 1.0)",
        description="Average packet payload size",
        transformation="total_bytes / (total_pkts + 1.0)",
        missing_policy=MissingValuePolicy.ZERO_FILL,
        live_available=True,
        min_val=0.0,
    ),
    FeatureDefinition(
        name="is_new_edge",
        dtype="float64",
        unit="indicator",
        source_field="DeviceState.seen_edges",
        description="1.0 if dst_ip never contacted before by this device, else 0.0",
        transformation="float(dst_ip not in seen_edges)",
        missing_policy=MissingValuePolicy.ZERO_FILL,
        live_available=True,
        min_val=0.0,
        max_val=1.0,
    ),
    FeatureDefinition(
        name="src_fanout_recent",
        dtype="float64",
        unit="cardinality",
        source_field="DeviceState.recent_dst_ips",
        description="Unique destination IPs targeted in last 30 flows",
        transformation="float(len(set(recent_dst_ips)))",
        missing_policy=MissingValuePolicy.ZERO_FILL,
        live_available=True,
        min_val=1.0,
    ),
    FeatureDefinition(
        name="device_zscore",
        dtype="float64",
        unit="std_deviations",
        source_field="DeviceState.byte_rate_history",
        description="Standard score of byte rate vs device's own rolling history",
        transformation="(byte_rate - mean) / (std + 1e-6)",
        missing_policy=MissingValuePolicy.ZERO_FILL,
        live_available=True,
    ),
    FeatureDefinition(
        name="proto_tcp",
        dtype="float64",
        unit="indicator",
        source_field="proto",
        description="1.0 if TCP transport layer",
        transformation="1.0 if proto == 'tcp' else 0.0",
        missing_policy=MissingValuePolicy.ZERO_FILL,
        live_available=True,
        min_val=0.0,
        max_val=1.0,
    ),
    FeatureDefinition(
        name="proto_udp",
        dtype="float64",
        unit="indicator",
        source_field="proto",
        description="1.0 if UDP transport layer",
        transformation="1.0 if proto == 'udp' else 0.0",
        missing_policy=MissingValuePolicy.ZERO_FILL,
        live_available=True,
        min_val=0.0,
        max_val=1.0,
    ),
    FeatureDefinition(
        name="proto_icmp",
        dtype="float64",
        unit="indicator",
        source_field="proto",
        description="1.0 if ICMP transport layer",
        transformation="1.0 if proto == 'icmp' else 0.0",
        missing_policy=MissingValuePolicy.ZERO_FILL,
        live_available=True,
        min_val=0.0,
        max_val=1.0,
    ),
    FeatureDefinition(
        name="conn_state_sf",
        dtype="float64",
        unit="indicator",
        source_field="conn_state",
        description="1.0 if Zeek connection state SF (Normal SYN/FIN)",
        transformation="1.0 if conn_state == 'SF' else 0.0",
        missing_policy=MissingValuePolicy.ZERO_FILL,
        live_available=True,
        min_val=0.0,
        max_val=1.0,
    ),
    FeatureDefinition(
        name="conn_state_s0",
        dtype="float64",
        unit="indicator",
        source_field="conn_state",
        description="1.0 if Zeek connection state S0 (SYN seen, no reply)",
        transformation="1.0 if conn_state == 'S0' else 0.0",
        missing_policy=MissingValuePolicy.ZERO_FILL,
        live_available=True,
        min_val=0.0,
        max_val=1.0,
    ),
    FeatureDefinition(
        name="conn_state_rej",
        dtype="float64",
        unit="indicator",
        source_field="conn_state",
        description="1.0 if Zeek connection state REJ (Connection rejected)",
        transformation="1.0 if conn_state == 'REJ' else 0.0",
        missing_policy=MissingValuePolicy.ZERO_FILL,
        live_available=True,
        min_val=0.0,
        max_val=1.0,
    ),
    FeatureDefinition(
        name="conn_state_other",
        dtype="float64",
        unit="indicator",
        source_field="conn_state",
        description="1.0 if any other connection state (RSTO, SH, etc.)",
        transformation="1.0 if conn_state not in ('SF','S0','REJ') else 0.0",
        missing_policy=MissingValuePolicy.ZERO_FILL,
        live_available=True,
        min_val=0.0,
        max_val=1.0,
    ),
]


class FeatureContract:
    """Canonical feature contract registry and verification utility."""

    def __init__(self, version: str = "v1_standard", definitions: Optional[List[FeatureDefinition]] = None):
        self.version = version
        self.definitions = definitions or V1_FEATURE_DEFINITIONS
        self.feature_names = [f.name for f in self.definitions]
        self.name_to_def = {f.name: f for f in self.definitions}

    def validate_vector(self, vector: List[float]) -> Tuple[bool, Optional[str]]:
        """Validate an extracted feature vector against the contract."""
        if len(vector) != len(self.definitions):
            return False, f"Length mismatch: got {len(vector)}, expected {len(self.definitions)}"
        for i, (val, defn) in enumerate(zip(vector, self.definitions)):
            if not isinstance(val, (int, float, np.floating, np.integer)):
                return False, f"Feature '{defn.name}' at index {i} is non-numeric: {type(val)}"
            if np.isnan(val) or np.isinf(val):
                return False, f"Feature '{defn.name}' at index {i} has invalid value: {val}"
            if defn.min_val is not None and val < defn.min_val - 1e-6:
                return False, f"Feature '{defn.name}' value {val} is below minimum {defn.min_val}"
            if defn.max_val is not None and val > defn.max_val + 1e-6:
                return False, f"Feature '{defn.name}' value {val} is above maximum {defn.max_val}"
        return True, None

    def evaluate_dataset_compatibility(self, dataset_columns: List[str]) -> Dict[str, Any]:
        """
        Evaluates a dataset's column inventory against the feature contract.
        Returns a classified compatibility breakdown.
        """
        cols_lower = {c.lower(): c for c in dataset_columns}
        report: Dict[str, Dict[str, str]] = {
            "directly_compatible": {},
            "derivable": {},
            "partially_compatible": {},
            "unavailable": {},
            "incompatible": {},
        }

        # Essential raw flow anchors required to compute canonical V1 features
        flow_anchors = {"duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "proto", "conn_state"}

        for defn in self.definitions:
            fname = defn.name
            src = defn.source_field.lower()

            if fname.lower() in cols_lower:
                report["directly_compatible"][fname] = f"Matches column '{cols_lower[fname.lower()]}'"
            elif any(anchor in cols_lower for anchor in flow_anchors) and (
                "DeviceState" in defn.source_field or "+" in defn.source_field or "/" in defn.source_field
            ):
                report["derivable"][fname] = f"Derivable via state engine from raw flow fields: {defn.source_field}"
            elif "proto" in fname and ("proto" in cols_lower or "protocol" in cols_lower):
                report["derivable"][fname] = "Derivable from protocol field via one-hot encoder"
            elif "conn_state" in fname and ("conn_state" in cols_lower or "state" in cols_lower):
                report["derivable"][fname] = "Derivable from connection state field via one-hot encoder"
            else:
                report["unavailable"][fname] = f"Missing required source inputs ({defn.source_field})"

        total = len(self.definitions)
        n_compat = len(report["directly_compatible"]) + len(report["derivable"])
        score = (n_compat / total) * 100.0

        return {
            "contract_version": self.version,
            "feature_count": total,
            "compatible_count": n_compat,
            "compatibility_percentage": round(score, 2),
            "breakdown": report,
            "is_fully_compatible": score >= 100.0,
        }


# Global standard instance
canonical_contract = FeatureContract("v1_standard", V1_FEATURE_DEFINITIONS)
