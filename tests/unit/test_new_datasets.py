"""
Unit tests for Edge-IIoTset and UNSW-NB15 dataset loaders.
"""

import pytest
from training.datasets.registry import get_dataset_loader, list_supported_datasets
from training.preprocessing.label_normalizer import label_normalizer, NormalizedLabel


def test_supported_datasets_includes_new_benchmarks():
    datasets = list_supported_datasets()
    assert "edge_iiotset" in datasets
    assert "unsw_nb15" in datasets
    assert "iot23" in datasets
    assert "ciciot2023" in datasets
    assert "ton_iot" in datasets
    assert "bot_iot" in datasets
    assert "nbaiot" in datasets


def test_edge_iiotset_label_normalization():
    # Normal benign
    res_normal = label_normalizer.normalize("Normal", dataset_name="edge_iiotset")
    assert res_normal.normalized_label == NormalizedLabel.BENIGN
    assert not res_normal.is_attack

    # DDoS UDP
    res_ddos = label_normalizer.normalize("DDoS_UDP", dataset_name="edge_iiotset")
    assert res_ddos.normalized_label == NormalizedLabel.DDOS
    assert res_ddos.is_attack

    # Port scanning
    res_scan = label_normalizer.normalize("Port_Scanning", dataset_name="edge_iiotset")
    assert res_scan.normalized_label == NormalizedLabel.PORT_SCAN
    assert res_scan.is_attack

    # Password brute force
    res_pass = label_normalizer.normalize("Password", dataset_name="edge_iiotset")
    assert res_pass.normalized_label == NormalizedLabel.BRUTE_FORCE
    assert res_pass.is_attack

    # Ransomware
    res_ransom = label_normalizer.normalize("Ransomware", dataset_name="edge_iiotset")
    assert res_ransom.normalized_label == NormalizedLabel.OTHER_ATTACK
    assert res_ransom.attack_category == "malware_ransomware"


def test_unsw_nb15_label_normalization():
    # Normal
    res_normal = label_normalizer.normalize("Normal", dataset_name="unsw_nb15")
    assert res_normal.normalized_label == NormalizedLabel.BENIGN
    assert not res_normal.is_attack

    # Reconnaissance
    res_recon = label_normalizer.normalize("Reconnaissance", dataset_name="unsw_nb15")
    assert res_recon.normalized_label == NormalizedLabel.PORT_SCAN
    assert res_recon.is_attack

    # DoS
    res_dos = label_normalizer.normalize("DoS", dataset_name="unsw_nb15")
    assert res_dos.normalized_label == NormalizedLabel.DDOS
    assert res_dos.is_attack

    # Worms
    res_worms = label_normalizer.normalize("Worms", dataset_name="unsw_nb15")
    assert res_worms.normalized_label == NormalizedLabel.BOTNET
    assert res_worms.is_attack
