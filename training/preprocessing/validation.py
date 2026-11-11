"""
Row-Level Validation and Diagnostic Filtering.

Inspects raw and parsed records against integrity constraints before training.
"""

from typing import Any, Dict, List, Optional, Tuple
from training.feature_contract import StandardRecord


def validate_flow_record(record: StandardRecord) -> Tuple[bool, Optional[str]]:
    """
    Validates a StandardRecord against physical networking sanity constraints.
    Returns (is_valid, failure_reason).
    """
    if record.timestamp is None or record.timestamp < 0:
        return False, f"Invalid timestamp: {record.timestamp}"

    if not record.source_ip or record.source_ip in ("0.0.0.0", "unknown", "-"):
        return False, f"Invalid source IP: {record.source_ip}"

    if record.duration < 0:
        return False, f"Negative duration: {record.duration}"

    if record.source_bytes < 0 or record.destination_bytes < 0:
        return False, "Negative byte counters"

    if record.source_packets < 0 or record.destination_packets < 0:
        return False, "Negative packet counters"

    if record.protocol not in ("tcp", "udp", "icmp", "other"):
        return False, f"Unnormalized protocol: {record.protocol}"

    return True, None
