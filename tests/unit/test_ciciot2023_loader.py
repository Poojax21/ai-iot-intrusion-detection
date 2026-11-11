"""
Unit tests for CICIoT2023 CSV loader.
"""

from pathlib import Path
from training.datasets.ciciot2023_loader import CICIoT2023Loader
from training.preprocessing.label_normalizer import NormalizedLabel

FIXTURE_PATH = Path("tests/fixtures/sample_ciciot2023.csv")


def test_ciciot2023_inspect_schema():
    loader = CICIoT2023Loader(FIXTURE_PATH)
    schema = loader.inspect_schema()
    assert schema["dataset_name"] == "ciciot2023"
    assert schema["format"] == "csv"
    assert "flow_duration" in schema["columns"]
    assert "Tot sum" in schema["columns"]
    assert "label" in schema["columns"]


def test_ciciot2023_load_records():
    loader = CICIoT2023Loader(FIXTURE_PATH)
    records = loader.load_all()
    assert len(records) == 5

    # Record 0: BenignTraffic
    r0 = records[0]
    assert r0.normalized_label == NormalizedLabel.BENIGN.value
    assert r0.protocol == "tcp"

    # Record 1: Recon-PortScan
    r1 = records[1]
    assert r1.normalized_label == NormalizedLabel.PORT_SCAN.value

    # Record 2: DDoS-UDP_Flood
    r2 = records[2]
    assert r2.normalized_label == NormalizedLabel.DDOS.value
    assert r2.protocol == "udp"

    # Record 3: DictionaryBruteForce
    r3 = records[3]
    assert r3.normalized_label == NormalizedLabel.BRUTE_FORCE.value

    # Record 4: Mirai-greeth_flood
    r4 = records[4]
    assert r4.normalized_label == NormalizedLabel.MIRAI_BEACON.value


def test_ciciot2023_chunking():
    loader = CICIoT2023Loader(FIXTURE_PATH)
    chunks = list(loader.load_chunks(chunk_size=2))
    assert len(chunks) == 3
    assert len(chunks[0]) == 2
    assert len(chunks[1]) == 2
    assert len(chunks[2]) == 1
