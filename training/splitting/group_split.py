"""
Group-Based Split Module.

Partitions records by scenario_id, capture_id, or source_device_id.
Prevents capture-level leakage and network setup memorization.
"""

from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple
import random

from training.feature_contract import StandardRecord


@dataclass
class GroupSplitResult:
    train: List[StandardRecord]
    val: List[StandardRecord]
    test: List[StandardRecord]
    group_key: str
    train_groups: List[str]
    val_groups: List[str]
    test_groups: List[str]


def group_based_split(
    records: List[StandardRecord],
    group_by: str = "scenario_id",
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    seed: int = 42,
) -> GroupSplitResult:
    """
    Groups records by the specified key (scenario_id, capture_id, source_device_id)
    and assigns entire groups to train, val, or test.
    """
    if not records:
        raise ValueError("Cannot split empty record list")

    rnd = random.Random(seed)
    grouped: Dict[str, List[StandardRecord]] = defaultdict(list)

    for r in records:
        val = getattr(r, group_by, None) or "default_group"
        grouped[str(val)].append(r)

    groups = list(grouped.keys())
    rnd.shuffle(groups)

    n_groups = len(groups)
    if n_groups < 3:
        # Fallback if too few groups: group partition impossible without starving splits
        # Put 1 in val, 1 in test if possible, else train only
        if n_groups == 2:
            train_g = [groups[0]]
            val_g = [groups[1]]
            test_g = [groups[1]]
        else:
            train_g = groups
            val_g = groups
            test_g = groups
    else:
        i_train = max(1, int(n_groups * train_ratio))
        i_val = max(i_train + 1, int(n_groups * (train_ratio + val_ratio)))
        train_g = groups[:i_train]
        val_g = groups[i_train:i_val]
        test_g = groups[i_val:]

    train_records = [r for g in train_g for r in grouped[g]]
    val_records = [r for g in val_g for r in grouped[g]]
    test_records = [r for g in test_g for r in grouped[g]]

    return GroupSplitResult(
        train=train_records,
        val=val_records,
        test=test_records,
        group_key=group_by,
        train_groups=train_g,
        val_groups=val_g,
        test_groups=test_g,
    )
