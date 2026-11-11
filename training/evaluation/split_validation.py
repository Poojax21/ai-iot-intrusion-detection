"""
Split Validation Module.

Verifies that train/val/test splits maintain valid class representation.
"""

from typing import Dict, List, Tuple
from training.feature_contract import StandardRecord


def validate_split_balance(
    train: List[StandardRecord],
    val: List[StandardRecord],
    test: List[StandardRecord],
) -> Tuple[bool, List[str]]:
    """
    Checks that splits are non-empty and verifies whether classes in val/test exist in train.
    Returns (is_valid, warnings).
    """
    warnings: List[str] = []

    if not train:
        return False, ["Train split is empty"]
    if not val:
        warnings.append("Validation split is empty")
    if not test:
        warnings.append("Test split is empty")

    train_classes = {r.normalized_label for r in train}
    val_classes = {r.normalized_label for r in val}
    test_classes = {r.normalized_label for r in test}

    unseen_in_val = val_classes - train_classes
    if unseen_in_val:
        warnings.append(f"Validation set contains classes not in training: {unseen_in_val}")

    unseen_in_test = test_classes - train_classes
    if unseen_in_test:
        warnings.append(f"Test set contains classes not in training (Open-Set evaluation): {unseen_in_test}")

    return True, warnings
