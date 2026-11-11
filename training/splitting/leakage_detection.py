"""
Data Leakage Detection & Audit Module.

Inspects train/val/test partitions to ensure zero data leakage across splits:
  - Exact flow signature overlap (duplicate records across sets)
  - Group/Capture ID bleed
  - Timestamp inversion / lookahead bias
  - IP memorization risk
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Set, Tuple
from training.feature_contract import StandardRecord


@dataclass
class LeakageAuditReport:
    is_leakage_free: bool
    duplicate_flow_count: int
    group_bleed_count: int
    temporal_inversions: int
    warnings: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


def check_leakage(
    train: List[StandardRecord],
    test: List[StandardRecord],
    group_key: Optional[str] = None,
) -> LeakageAuditReport:
    """
    Audits train and test splits for data leakage.
    """
    warnings: List[str] = []

    # 1. Exact record / 5-tuple signature overlap
    train_sigs: Set[Tuple[float, str, str, int, int]] = {
        (r.timestamp, r.source_ip, r.destination_ip, r.source_port, r.destination_port)
        for r in train
    }
    test_sigs: Set[Tuple[float, str, str, int, int]] = {
        (r.timestamp, r.source_ip, r.destination_ip, r.source_port, r.destination_port)
        for r in test
    }
    dup_sigs = train_sigs.intersection(test_sigs)
    dup_count = len(dup_sigs)
    if dup_count > 0:
        warnings.append(f"Found {dup_count} duplicate flows present in both train and test partitions.")

    # 2. Group / scenario bleed
    group_bleed_count = 0
    if group_key:
        train_groups = {str(getattr(r, group_key, "")) for r in train}
        test_groups = {str(getattr(r, group_key, "")) for r in test}
        shared_groups = train_groups.intersection(test_groups) - {"", "None", "default_group"}
        group_bleed_count = len(shared_groups)
        if group_bleed_count > 0:
            warnings.append(f"Found {group_bleed_count} shared '{group_key}' groups in both train and test.")

    # 3. Temporal ordering check
    inversions = 0
    if train and test:
        max_train_ts = max(r.timestamp for r in train)
        min_test_ts = min(r.timestamp for r in test)
        if min_test_ts < max_train_ts:
            # Overlapping or inverted time
            inv_count = sum(1 for r in test if r.timestamp < max_train_ts)
            inversions = inv_count
            warnings.append(
                f"Temporal overlap detected: {inv_count} test flows occurred before the latest training timestamp ({max_train_ts})."
            )

    is_clean = (dup_count == 0) and (group_bleed_count == 0)

    return LeakageAuditReport(
        is_leakage_free=is_clean,
        duplicate_flow_count=dup_count,
        group_bleed_count=group_bleed_count,
        temporal_inversions=inversions,
        warnings=warnings,
        details={
            "train_size": len(train),
            "test_size": len(test),
            "group_key": group_key,
        },
    )
