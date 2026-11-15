"""
Unit tests for N-BaIoT CSV loader.
"""

from pathlib import Path
from training.datasets.nbaiot_loader import NBaIoTLoader
from training.preprocessing.label_normalizer import NormalizedLabel

FIXTURE_PATH = Path("tests/fixtures/sample_nbaiot.csv")


def test_nbaiot_inspect_schema():
    loader = NBaIoTLoader(FIXTURE_PATH)
    schema = loader.inspect_schema()
    assert schema["dataset_name"] == "nbaiot"
    assert schema["is_nbaiot"] is True
    assert any("mi_dir" in c.lower() for c in schema["columns"])


def test_nbaiot_load_records():
    loader = NBaIoTLoader(FIXTURE_PATH)
    records = loader.load_all()
    assert len(records) == 4

    # Record 0: benign
    r0 = records[0]
    assert r0.normalized_label == NormalizedLabel.BENIGN.value
    assert r0.protocol == "tcp"

    # Record 1: mirai_scan
    r1 = records[1]
    assert r1.normalized_label == NormalizedLabel.PORT_SCAN.value

    # Record 2: mirai_syn
    r2 = records[2]
    assert r2.normalized_label == NormalizedLabel.DDOS.value

    # Record 3: gafgyt_combo
    r3 = records[3]
    assert r3.normalized_label == NormalizedLabel.BOTNET.value
