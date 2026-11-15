"""
Unit tests for Bot-IoT CSV loader.
"""

from pathlib import Path
from training.datasets.bot_iot_loader import BotIoTLoader
from training.preprocessing.label_normalizer import NormalizedLabel

FIXTURE_PATH = Path("tests/fixtures/sample_bot_iot.csv")


def test_bot_iot_inspect_schema():
    loader = BotIoTLoader(FIXTURE_PATH)
    schema = loader.inspect_schema()
    assert schema["dataset_name"] == "bot_iot"
    assert schema["is_bot_iot"] is True
    assert "saddr" in [c.lower() for c in schema["columns"]]
    assert "category" in [c.lower() for c in schema["columns"]]


def test_bot_iot_load_records():
    loader = BotIoTLoader(FIXTURE_PATH)
    records = loader.load_all()
    assert len(records) == 5

    # Record 0: Normal
    r0 = records[0]
    assert r0.normalized_label == NormalizedLabel.BENIGN.value
    assert r0.protocol == "udp"
    assert r0.destination_port == 53
    assert r0.source_packets == 1

    # Record 1: Reconnaissance / Service_Scan
    r1 = records[1]
    assert r1.normalized_label == NormalizedLabel.PORT_SCAN.value
    assert r1.connection_state == "RST"

    # Record 2: DDoS
    r2 = records[2]
    assert r2.normalized_label == NormalizedLabel.DDOS.value
    assert r2.source_packets == 500

    # Record 3: Theft / Data Exfiltration
    r3 = records[3]
    assert r3.normalized_label == NormalizedLabel.OTHER_ATTACK.value

    # Record 4: DoS
    r4 = records[4]
    assert r4.normalized_label == NormalizedLabel.OTHER_ATTACK.value
