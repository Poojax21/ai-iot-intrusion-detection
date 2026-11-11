"""
Wire schema for flow ingestion.

This is deliberately shaped like a Zeek `conn.log` record so that a REAL
sensor (Zeek/Suricata on a router, or a simple script reading conn.log — see
simulator/zeek_adapter.py) can POST the exact same JSON shape as the
simulator does. Nothing about /api/ingest changes when you swap the
simulator for real hardware.
"""

from pydantic import BaseModel, Field
from typing import Any, List, Optional


class FlowRecord(BaseModel):
    ts: float = Field(..., description="Unix epoch seconds when the flow started")
    device_id: str = Field(..., description=(
        "Stable per-device identity key. For real hardware, derive this as a "
        "HASHED MAC address (never store/forward the raw MAC — see plan §7/§11). "
        "If the device is known to randomize its MAC, fall back to a "
        "traffic-fingerprint-derived id instead, and set mac_unstable=true."
    ))
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str = Field(..., description="tcp | udp | icmp")
    duration: float = Field(..., ge=0)
    orig_bytes: int = Field(..., ge=0)
    resp_bytes: int = Field(..., ge=0)
    orig_pkts: int = Field(..., ge=0)
    resp_pkts: int = Field(..., ge=0)
    conn_state: str = Field("SF", description="Zeek-style conn_state code, e.g. SF/S0/REJ/RSTO")
    mac_unstable: bool = Field(False, description="True if device_id fallback (non-MAC) identity was used")
    device_type: Optional[str] = Field(None, description="Optional hint for the dashboard, e.g. 'camera'")


class AlertOut(BaseModel):
    id: int
    ts: float
    device_id: str
    device_type: Optional[str]
    src_ip: str
    dst_ip: str
    attack_type: str
    mitre: Optional[str]
    severity: str
    gate_score: float
    anomaly_score: float
    confidence_tier: str
    top_features: list
    shap_values: Optional[List[Any]] = None
    shap_base_value: Optional[float] = None
    decision: Optional[str] = Field(None, description="Triage decision: benign | known_attack | unknown_suspicious | uncertain")
    is_unknown: Optional[bool] = Field(False, description="True if classified as unknown suspicious")
    novelty_score: Optional[float] = Field(None, description="Novelty distance factor relative to known class boundaries")
    calibrated_anomaly_score: Optional[float] = Field(None, description="Calibrated ECDF percentile of anomaly score")
    reason_codes: Optional[List[str]] = Field(default_factory=list, description="Triage reason codes")
    raw_flow: dict


class DeviceOut(BaseModel):
    device_id: str
    device_type: Optional[str]
    ip: Optional[str]
    flow_count: int
    alert_count: int
    risk_score: float
    last_seen: Optional[float]
