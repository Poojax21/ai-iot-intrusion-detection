"""
Chronological Split Module.

Partitions a sequence of records strictly by timestamp.
Preserves temporal causality so models are never tested on events preceding their training window.
"""

from dataclasses import dataclass
from typing import List, Tuple
from training.feature_contract import StandardRecord


@dataclass
class ChronologicalSplitResult:
    train: List[StandardRecord]
    val: List[StandardRecord]
    test: List[StandardRecord]
    train_ratio: float
    val_ratio: float
    test_ratio: float
    train_time_range: Tuple[float, float]
    val_time_range: Tuple[float, float]
    test_time_range: Tuple[float, float]


def chronological_split(
    records: List[StandardRecord],
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
) -> ChronologicalSplitResult:
    """
    Sorts records by timestamp and partitions chronologically.
    """
    if not records:
        raise ValueError("Cannot split empty record list")

    total_ratio = train_ratio + val_ratio + test_ratio
    if abs(total_ratio - 1.0) > 1e-5:
        raise ValueError(f"Split ratios must sum to 1.0, got {total_ratio}")

    # Enforce strictly chronological order
    sorted_records = sorted(records, key=lambda r: r.timestamp)
    n = len(sorted_records)

    i_train = int(n * train_ratio)
    i_val = int(n * (train_ratio + val_ratio))

    train = sorted_records[:i_train]
    val = sorted_records[i_train:i_val]
    test = sorted_records[i_val:]

    def t_range(subset: List[StandardRecord]) -> Tuple[float, float]:
        if not subset:
            return (0.0, 0.0)
        return (subset[0].timestamp, subset[-1].timestamp)

    return ChronologicalSplitResult(
        train=train,
        val=val,
        test=test,
        train_ratio=train_ratio,
        val_ratio=val_ratio,
        test_ratio=test_ratio,
        train_time_range=t_range(train),
        val_time_range=t_range(val),
        test_time_range=t_range(test),
    )
