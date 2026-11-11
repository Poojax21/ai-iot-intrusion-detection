"""
Missing and Malformed Value Handling Module.

Explicitly sanitizes Zeek special characters ('-', '(empty)'), CSV missing tokens,
NaNs, and infinities according to the canonical missing-value policy.
"""

from typing import Any, Dict, Optional, Type, Union
import math
import numpy as np


def clean_numeric(
    val: Any,
    default: float = 0.0,
    target_type: Type[Union[int, float]] = float,
    allow_inf: bool = False,
) -> Union[int, float]:
    """
    Sanitizes missing, non-numeric, or corrupted numbers to a safe default.
    Converts '-' (Zeek null), '(empty)', 'nan', 'inf' safely.
    """
    if val is None:
        return target_type(default)

    if isinstance(val, (int, float)):
        if math.isnan(val):
            return target_type(default)
        if math.isinf(val):
            return target_type(default) if not allow_inf else val
        return target_type(val)

    s = str(val).strip().lower()
    if not s or s in ("-", "(empty)", "none", "nan", "null", "?", ""):
        return target_type(default)

    if s in ("inf", "+inf", "-inf"):
        return target_type(default) if not allow_inf else float(s)

    try:
        num = float(s)
        if math.isnan(num) or (math.isinf(num) and not allow_inf):
            return target_type(default)
        return target_type(num)
    except (ValueError, TypeError):
        return target_type(default)


def clean_string(val: Any, default: str = "") -> str:
    """Sanitizes text strings, stripping whitespace and Zeek empty indicators."""
    if val is None:
        return default
    s = str(val).strip()
    if s in ("-", "(empty)", "none", "null", ""):
        return default
    return s


def clean_value(val: Any, default: Any = 0.0, target_type: type = float) -> Any:
    """Generic value cleaner dispatching on target type."""
    if target_type in (int, float):
        return clean_numeric(val, default=default, target_type=target_type)
    elif target_type is str:
        return clean_string(val, default=default)
    elif target_type is bool:
        if isinstance(val, bool):
            return val
        s = str(val).strip().lower()
        return s in ("true", "1", "t", "yes", "y")
    return val if val is not None else default


def sanitize_flow_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    """Applies canonical schema sanitization to a raw flow dictionary."""
    return {
        "ts": clean_numeric(d.get("ts", d.get("timestamp")), default=0.0, target_type=float),
        "src_ip": clean_string(d.get("src_ip", d.get("id.orig_h")), default="0.0.0.0"),
        "dst_ip": clean_string(d.get("dst_ip", d.get("id.resp_h")), default="0.0.0.0"),
        "src_port": clean_numeric(d.get("src_port", d.get("id.orig_p")), default=0, target_type=int),
        "dst_port": clean_numeric(d.get("dst_port", d.get("id.resp_p")), default=0, target_type=int),
        "proto": clean_string(d.get("proto", d.get("protocol")), default="tcp").lower(),
        "duration": max(0.0, clean_numeric(d.get("duration", d.get("flow_duration")), default=0.0, target_type=float)),
        "orig_bytes": max(0, clean_numeric(d.get("orig_bytes", d.get("src_bytes")), default=0, target_type=int)),
        "resp_bytes": max(0, clean_numeric(d.get("resp_bytes", d.get("dst_bytes")), default=0, target_type=int)),
        "orig_pkts": max(0, clean_numeric(d.get("orig_pkts", d.get("src_pkts")), default=0, target_type=int)),
        "resp_pkts": max(0, clean_numeric(d.get("resp_pkts", d.get("dst_pkts")), default=0, target_type=int)),
        "conn_state": clean_string(d.get("conn_state", d.get("state")), default="SF").upper(),
        "device_id": clean_string(d.get("device_id"), default=f"dev-{d.get('src_ip', 'unknown')}"),
    }
