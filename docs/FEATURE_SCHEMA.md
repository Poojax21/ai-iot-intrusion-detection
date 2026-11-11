# Pahredaar-IoT — Feature Schema & Contract Specification
**Document Version:** 2.0  
**Authority:** `training/feature_contract.py`  

---

## 1. Canonical Feature Contract (V1 Standard — 20 Features)

The canonical feature contract defines the exact feature ordering, data types, physical units, and transformations expected by all Stage 1 and Stage 2 models.

| Index | Feature Name | Dtype | Unit | Source Attribute | Transformation / Semantics | Missing Policy | Live Edge |
|---|---|---|---|---|---|---|---|
| `0` | `duration` | float64 | seconds | `duration` | `max(val, 0.0)` | Zero-fill | Yes |
| `1` | `orig_bytes` | float64 | bytes | `orig_bytes` | `float(val)` | Zero-fill | Yes |
| `2` | `resp_bytes` | float64 | bytes | `resp_bytes` | `float(val)` | Zero-fill | Yes |
| `3` | `orig_pkts` | float64 | packets | `orig_pkts` | `float(val)` | Zero-fill | Yes |
| `4` | `resp_pkts` | float64 | packets | `resp_pkts` | `float(val)` | Zero-fill | Yes |
| `5` | `total_bytes` | float64 | bytes | `orig_bytes + resp_bytes` | Sum of originator and responder bytes | Zero-fill | Yes |
| `6` | `total_pkts` | float64 | packets | `orig_pkts + resp_pkts` | Sum of originator and responder packets | Zero-fill | Yes |
| `7` | `byte_rate` | float64 | bytes/sec | derived | `total_bytes / (duration + 1e-6)` | Zero-fill | Yes |
| `8` | `pkt_rate` | float64 | pkts/sec | derived | `total_pkts / (duration + 1e-6)` | Zero-fill | Yes |
| `9` | `avg_pkt_size` | float64 | bytes/pkt | derived | `total_bytes / (total_pkts + 1.0)` | Zero-fill | Yes |
| `10` | `is_new_edge` | float64 | indicator | `DeviceState` | `1.0` if `dst_ip` never contacted, else `0.0` | Zero-fill | Yes |
| `11` | `src_fanout_recent` | float64 | count | `DeviceState` | Unique `dst_ip` count in last 30 flows | Zero-fill | Yes |
| `12` | `device_zscore` | float64 | std dev | `DeviceState` | `(byte_rate - mean) / (std + 1e-6)` | Zero-fill | Yes |
| `13` | `proto_tcp` | float64 | indicator | `proto` | `1.0` if TCP, else `0.0` | Zero-fill | Yes |
| `14` | `proto_udp` | float64 | indicator | `proto` | `1.0` if UDP, else `0.0` | Zero-fill | Yes |
| `15` | `proto_icmp` | float64 | indicator | `proto` | `1.0` if ICMP, else `0.0` | Zero-fill | Yes |
| `16` | `conn_state_sf` | float64 | indicator | `conn_state` | `1.0` if `SF` (Normal completion) | Zero-fill | Yes |
| `17` | `conn_state_s0` | float64 | indicator | `conn_state` | `1.0` if `S0` (SYN without ACK) | Zero-fill | Yes |
| `18` | `conn_state_rej` | float64 | indicator | `conn_state` | `1.0` if `REJ` (Rejected connection) | Zero-fill | Yes |
| `19` | `conn_state_other` | float64 | indicator | `conn_state` | `1.0` if other state (`RSTO`, `SH`, etc.) | Zero-fill | Yes |

---

## 2. Common Dataset Schema (`StandardRecord`)

Every dataset loader parses raw logs into the normalized `StandardRecord` container before feature vectorization:

```python
@dataclass
class StandardRecord:
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
```

---

## 3. Dataset Compatibility Matrix

| Feature | IoT-23 | TON_IoT (Network) | CICIoT2023 |
|---|---|---|---|
| `duration` | ✅ Direct | ✅ Direct | ✅ Direct (`flow_duration`) |
| `orig_bytes` | ✅ Direct | ✅ Direct | ⚠️ Derivable (`Tot sum * 0.5`) |
| `resp_bytes` | ✅ Direct | ✅ Direct | ⚠️ Derivable (`Tot sum * 0.5`) |
| `orig_pkts` | ✅ Direct | ✅ Direct | ⚠️ Derivable (`Number * 0.5`) |
| `resp_pkts` | ✅ Direct | ✅ Direct | ⚠️ Derivable (`Number * 0.5`) |
| `total_bytes` | ✅ Derivable | ✅ Derivable | ✅ Direct (`Tot sum`) |
| `total_pkts` | ✅ Derivable | ✅ Derivable | ✅ Direct (`Number`) |
| `byte_rate` | ✅ Derivable | ✅ Derivable | ✅ Derivable (`Tot sum / Duration`) |
| `pkt_rate` | ✅ Derivable | ✅ Derivable | ✅ Direct (`Rate`) |
| `avg_pkt_size` | ✅ Derivable | ✅ Derivable | ✅ Direct (`AVG`) |
| `is_new_edge` | ✅ Derivable (State) | ✅ Derivable (State) | ⚠️ Unavailable (No IP tuples in CSV) |
| `src_fanout_recent` | ✅ Derivable (State) | ✅ Derivable (State) | ⚠️ Unavailable (No IP tuples in CSV) |
| `device_zscore` | ✅ Derivable (State) | ✅ Derivable (State) | ⚠️ Unavailable (No IP tuples in CSV) |
| `proto_*` | ✅ Direct | ✅ Direct | ✅ Direct (`Protocol Type`) |
| `conn_state_*` | ✅ Direct | ✅ Direct | ⚠️ Derivable (TCP flag numbers) |
| **V1 Compatibility** | **100% Fully Compatible** | **100% Fully Compatible** | **Specialized 46-Feature Schema** |
