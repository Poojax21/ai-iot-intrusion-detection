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
    composite_device_risk: Optional[float] = Field(None, description="Composite multi-tier device risk score (0-100)")
    fused_event_threat: Optional[float] = Field(None, description="Instantaneous non-dilutive event threat score (0-100)")
    risk_tier: Optional[str] = Field(None, description="Hierarchical risk tier: LOW | ELEVATED | HIGH | CRITICAL")
    temporal_risk: Optional[float] = Field(None, description="Temporal sequence anomaly risk contribution (0-100)")
    graph_risk: Optional[float] = Field(None, description="Topological graph communication risk contribution (0-100)")
    risk_breakdown: Optional[dict] = Field(None, description="Detailed component breakdown of risk scoring")
    raw_flow: dict


class DeviceOut(BaseModel):
    device_id: str
    device_type: Optional[str]
    ip: Optional[str]
    flow_count: int
    alert_count: int
    risk_score: float
    last_seen: Optional[float]
    risk_tier: Optional[str] = Field("LOW", description="Hierarchical risk tier: LOW | ELEVATED | HIGH | CRITICAL")
    temporal_risk: Optional[float] = Field(0.0, description="Latest temporal sequence risk (0-100)")
    graph_risk: Optional[float] = Field(0.0, description="Latest graph communication risk (0-100)")


# --- Phase 6: Authentication, RBAC & Multi-Tenant Schemas ---

class UserRegister(BaseModel):
    email: str = Field(..., description="User corporate email address")
    password: str = Field(..., min_length=8, description="User password (min 8 characters with complexity)")
    full_name: str = Field(..., min_length=2, description="User full display name")
    organization_name: str = Field(..., min_length=2, description="Name of the organization/facility to join or create")
    organization_slug: Optional[str] = Field(None, description="Optional unique tenant slug")


class UserLogin(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in_sec: int


class TokenRefreshRequest(BaseModel):
    refresh_token: str


class UserOut(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    organization_id: str
    organization_name: str
    is_active: bool
    permissions: List[str] = Field(default_factory=list)


class SensorCreate(BaseModel):
    sensor_name: str = Field(..., min_length=2, description="Display name for network probe")
    sensor_identifier: str = Field(..., min_length=2, description="Unique sensor hostname or serial")
    rate_limit_per_sec: int = Field(500, ge=1, le=5000, description="Rate limit allowance in flows/sec")


class SensorCreateResponse(BaseModel):
    id: str
    sensor_name: str
    sensor_identifier: str
    api_key: str = Field(..., description="RAW API Key shown only once. Store securely.")
    organization_id: str
    rate_limit_per_sec: int


class SensorOut(BaseModel):
    id: str
    sensor_name: str
    sensor_identifier: str
    is_active: bool
    rate_limit_per_sec: int
    last_seen: Optional[str] = None
    created_at: str


class SensorRotateKeyResponse(BaseModel):
    id: str
    sensor_identifier: str
    api_key: str = Field(..., description="New RAW API Key shown only once.")
    rotated_at: str


class AuditEventOut(BaseModel):
    id: int
    action: str
    resource_type: str
    resource_id: Optional[str]
    timestamp: str
    source_ip: Optional[str]
    metadata: dict

