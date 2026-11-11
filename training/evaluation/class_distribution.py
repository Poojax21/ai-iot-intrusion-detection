"""
Class Distribution and Imbalance Metrics.
"""

from collections import Counter
from dataclasses import dataclass
import math
from typing import Dict, List, Optional
from training.feature_contract import StandardRecord


@dataclass
class ClassDistributionReport:
    total_samples: int
    class_counts: Dict[str, int]
    class_percentages: Dict[str, float]
    imbalance_ratio: float               # max_class_count / min_class_count
    shannon_entropy: float              # class diversity index


def compute_class_distribution(records: List[StandardRecord]) -> ClassDistributionReport:
    """Computes distribution statistics over normalized_label."""
    if not records:
        return ClassDistributionReport(
            total_samples=0,
            class_counts={},
            class_percentages={},
            imbalance_ratio=1.0,
            shannon_entropy=0.0,
        )

    labels = [r.normalized_label or "UNKNOWN" for r in records]
    counts = Counter(labels)
    total = len(labels)

    percentages = {cls: round((cnt / total) * 100.0, 2) for cls, cnt in counts.items()}

    # Imbalance ratio
    max_c = max(counts.values())
    min_c = min(counts.values())
    imb_ratio = round(max_c / max(1, min_c), 2)

    # Shannon entropy
    entropy = 0.0
    for cnt in counts.values():
        p = cnt / total
        if p > 0:
            entropy -= p * math.log2(p)

    return ClassDistributionReport(
        total_samples=total,
        class_counts=dict(counts),
        class_percentages=percentages,
        imbalance_ratio=imb_ratio,
        shannon_entropy=round(entropy, 4),
    )
