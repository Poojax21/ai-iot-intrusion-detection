"""
Unit tests for IoT-23 Zeek conn.log loader.
"""

from pathlib import Path
from training.datasets.iot23_loader import IoT23Loader
from training.preprocessing.label_normalizer import NormalizedLabel

FIXTURE_PATH = Path("tests/fixtures/sample_iot23.log")


def test_iot23_inspect_schema():
    loader = IoT23Loader(FIXTURE_PATH)
    schema = loader.inspect_schema()
    assert schema["dataset_name"] == "iot23"
    assert schema["format"] == "zeek_tsv"
    assert "id.orig_h" in schema["columns"]
    assert "detailed-label" in schema["columns"]


def test_iot23_load_records():
    loader = IoT23Loader(FIXTURE_PATH)
    records = loader.load_all()
    assert len(records) == 6

    # Verify first benign record
    r0 = records[0]
    assert r0.source_ip == "192.168.1.195"
    assert r0.destination_ip == "203.0.113.1"
    assert r0.destination_port == 443
    assert r0.protocol == "tcp"
    assert r0.duration == 5.2
    assert r0.source_bytes == 1200
    assert r0.destination_bytes == 3400
    assert r0.connection_state == "SF"
    assert r0.normalized_label == NormalizedLabel.BENIGN.value

    # Verify port scan record
    r1 = records[1]
    assert r1.normalized_label == NormalizedLabel.PORT_SCAN.value
    assert r1.connection_state == "S0"

    # Verify DDoS record
    r3 = records[3]
    assert r3.normalized_label == NormalizedLabel.DDOS.value

    # Verify Mirai HeartBeat record
    r4 = records[4]
    assert r4.normalized_label == NormalizedLabel.MIRAI_BEACON.value


def test_iot23_chunking():
    loader = IoT23Loader(FIXTURE_PATH)
    chunks = list(loader.load_chunks(chunk_size=2))
    assert len(chunks) == 3
    assert len(chunks[0]) == 2
    assert len(chunks[1]) == 2
    assert len(chunks[2]) == 2
