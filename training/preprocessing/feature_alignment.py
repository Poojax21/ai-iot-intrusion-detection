"""
Feature Alignment and State Execution Module.

Executes sequential feature extraction with training/inference parity against the
canonical FeatureContract.
"""

from typing import Dict, List, Optional, Tuple
import numpy as np

from backend.app.features import DeviceState, build_feature_vector, FEATURE_COLUMNS
from training.feature_contract import FeatureContract, StandardRecord, canonical_contract


def align_features_v1(
    flow_record: StandardRecord | Dict,
    device_state: DeviceState,
    validate: bool = True,
) -> List[float]:
    """
    Extracts the canonical 20-feature V1 vector from a flow record and updates DeviceState.
    Guarantees bitwise behavioural parity with backend/app/detection.py.
    """
    if isinstance(flow_record, StandardRecord):
        flow_dict = flow_record.to_dict()
    else:
        flow_dict = dict(flow_record)

    # Execute canonical feature extractor
    vec = build_feature_vector(flow_dict, device_state)

    if validate:
        valid, err = canonical_contract.validate_vector(vec)
        if not valid:
            raise ValueError(f"Feature vector failed contract validation: {err}")

    return vec


def batch_align_features(
    records: List[StandardRecord | Dict],
    device_states: Optional[Dict[str, DeviceState]] = None,
) -> Tuple[np.ndarray, Dict[str, DeviceState]]:
    """
    Sequentially processes a chronological stream of records, updating per-device state.
    Returns (feature_matrix: ndarray, updated_states: dict).
    """
    states = device_states if device_states is not None else {}
    rows = []

    for r in records:
        if isinstance(r, StandardRecord):
            dev_id = r.source_device_id or f"dev-{r.source_ip}"
        else:
            dev_id = r.get("device_id", f"dev-{r.get('src_ip', 'unknown')}")

        if dev_id not in states:
            states[dev_id] = DeviceState()

        vec = align_features_v1(r, states[dev_id], validate=True)
        rows.append(vec)

    return np.array(rows, dtype=np.float64), states
