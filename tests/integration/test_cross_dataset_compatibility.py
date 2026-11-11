"""
Integration test for cross-dataset schema compatibility and feature alignment.
"""

from pathlib import Path
from training.datasets.registry import get_dataset_loader
from training.preprocessing.feature_alignment import batch_align_features
from training.feature_contract import canonical_contract

FIXTURE_IOT23 = Path("tests/fixtures/sample_iot23.log")
FIXTURE_TON_IOT = Path("tests/fixtures/sample_ton_iot.csv")


def test_cross_dataset_feature_alignment():
    # 1. Load IoT-23
    loader_iot23 = get_dataset_loader("iot23", FIXTURE_IOT23)
    records_iot23 = loader_iot23.load_all()

    # 2. Load TON_IoT
    loader_ton = get_dataset_loader("ton_iot", FIXTURE_TON_IOT)
    records_ton = loader_ton.load_all()

    assert len(records_iot23) > 0
    assert len(records_ton) > 0

    # 3. Batch align IoT-23
    matrix_iot23, _ = batch_align_features(records_iot23)
    assert matrix_iot23.shape == (len(records_iot23), 20)

    # 4. Batch align TON_IoT
    matrix_ton, _ = batch_align_features(records_ton)
    assert matrix_ton.shape == (len(records_ton), 20)

    # Both produce exactly 20 features matching the canonical contract
    assert matrix_iot23.shape[1] == len(canonical_contract.definitions)
    assert matrix_ton.shape[1] == len(canonical_contract.definitions)
