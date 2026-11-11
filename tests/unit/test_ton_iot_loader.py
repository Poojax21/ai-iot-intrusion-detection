"""
Unit tests for TON_IoT Network Flow CSV loader.
"""

from pathlib import Path
from training.datasets.ton_iot_loader import TonIoTLoader
from training.preprocessing.label_normalizer import NormalizedLabel

FIXTURE_PATH = Path("tests/fixtures/sample_ton_iot.csv")


def test_ton_iot_inspect_schema():
    loader = TonIoTLoader(FIXTURE_PATH)
    schema = loader.inspect_schema()
    assert schema["dataset_name"] == "ton_iot"
    assert schema["is_network_dataset"] is True
    assert "src_ip" in schema["columns"]
    assert "type" in schema["columns"]


def test_ton_iot_load_records():
    loader = TonIoTLoader(FIXTURE_PATH)
    records = loader.load_all()
    assert len(records) == 5

    # Record 0: normal
    r0 = records[0]
    assert r0.normalized_label == NormalizedLabel.BENIGN.value
    assert r0.protocol == "udp"
    assert r0.destination_port == 53

    # Record 1: scanning
    r1 = records[1]
    assert r1.normalized_label == NormalizedLabel.PORT_SCAN.value
    assert r1.connection_state == "S0"

    # Record 2: ddos
    r2 = records[2]
    assert r2.normalized_label == NormalizedLabel.DDOS.value

    # Record 3: password
    r3 = records[3]
    assert r3.normalized_label == NormalizedLabel.BRUTE_FORCE.value
    assert r3.destination_port == 22

    # Record 4: xss (other attack)
    r4 = records[4]
    assert r4.normalized_label == NormalizedLabel.OTHER_ATTACK.value
