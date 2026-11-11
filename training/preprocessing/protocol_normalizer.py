"""
Protocol Normalization Module.

Normalizes varied protocol representations (strings, uppercase, numeric IANA codes,
abbreviations) into standard lowercase canonical tokens: tcp, udp, icmp, or other.
"""

from typing import Any, Union

IANA_PROTOCOL_MAP = {
    1: "icmp",
    2: "igmp",
    6: "tcp",
    17: "udp",
    41: "ipv6",
    47: "gre",
    50: "esp",
    51: "ah",
    58: "icmpv6",
    89: "ospf",
    132: "sctp",
}


def normalize_protocol(val: Any) -> str:
    """
    Normalizes a protocol value to 'tcp', 'udp', 'icmp', or 'other'.
    Supports string names, integer IANA numbers, and float representations.
    """
    if val is None:
        return "other"

    # Numeric handling (IANA numbers or float from CSV/pandas)
    if isinstance(val, (int, float)):
        try:
            int_val = int(val)
            proto_name = IANA_PROTOCOL_MAP.get(int_val, "other")
            return proto_name if proto_name in ("tcp", "udp", "icmp") else "other"
        except (ValueError, OverflowError):
            return "other"

    s = str(val).strip().lower()

    # Empty or Zeek null marker
    if not s or s in ("-", "(empty)", "none", "nan"):
        return "other"

    # Check direct name matches
    if "tcp" in s:
        return "tcp"
    if "udp" in s:
        return "udp"
    if "icmp" in s:
        return "icmp"

    # Stringified integers
    if s.isdigit():
        int_val = int(s)
        proto_name = IANA_PROTOCOL_MAP.get(int_val, "other")
        return proto_name if proto_name in ("tcp", "udp", "icmp") else "other"

    return "other"
