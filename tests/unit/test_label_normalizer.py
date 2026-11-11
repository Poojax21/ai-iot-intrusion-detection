"""
Unit tests for centralized label normalization and taxonomy mapping.
"""

from training.preprocessing.label_normalizer import (
    LabelNormalizer,
    NormalizedLabel,
    label_normalizer,
)


def test_benign_labels_across_datasets():
    # IoT-23
    res1 = label_normalizer.normalize("Benign", dataset_name="iot23")
    assert res1.normalized_label == NormalizedLabel.BENIGN
    assert res1.is_attack is False
    assert res1.confidence == 1.0

    # CICIoT2023
    res2 = label_normalizer.normalize("BenignTraffic", dataset_name="ciciot2023")
    assert res2.normalized_label == NormalizedLabel.BENIGN
    assert res2.is_attack is False

    # TON_IoT
    res3 = label_normalizer.normalize("normal", dataset_name="ton_iot")
    assert res3.normalized_label == NormalizedLabel.BENIGN
    assert res3.is_attack is False


def test_attack_labels_iot23():
    # Port scan
    res = label_normalizer.normalize("PartOfAHorizontalPortScan", dataset_name="iot23")
    assert res.normalized_label == NormalizedLabel.PORT_SCAN
    assert res.is_attack is True

    # C&C
    res_c2 = label_normalizer.normalize("C&C", dataset_name="iot23")
    assert res_c2.normalized_label == NormalizedLabel.BOTNET

    # Mirai heartbeat
    res_mb = label_normalizer.normalize("C&C-HeartBeat", dataset_name="iot23")
    assert res_mb.normalized_label == NormalizedLabel.MIRAI_BEACON


def test_attack_labels_ciciot2023():
    res_ps = label_normalizer.normalize("Recon-PortScan", dataset_name="ciciot2023")
    assert res_ps.normalized_label == NormalizedLabel.PORT_SCAN

    res_ddos = label_normalizer.normalize("DDoS-UDP_Flood", dataset_name="ciciot2023")
    assert res_ddos.normalized_label == NormalizedLabel.DDOS

    res_bf = label_normalizer.normalize("DictionaryBruteForce", dataset_name="ciciot2023")
    assert res_bf.normalized_label == NormalizedLabel.BRUTE_FORCE

    res_mirai = label_normalizer.normalize("Mirai-greeth_flood", dataset_name="ciciot2023")
    assert res_mirai.normalized_label == NormalizedLabel.MIRAI_BEACON


def test_unmapped_and_dos_distinction():
    # DoS must NOT be forced into DDoS
    res_dos = label_normalizer.normalize("dos", dataset_name="ton_iot")
    assert res_dos.normalized_label == NormalizedLabel.OTHER_ATTACK
    assert "dos" in res_dos.attack_category

    # Unmapped random string becomes UNKNOWN
    res_unk = label_normalizer.normalize("completely_novel_exploit_2026", dataset_name="generic")
    assert res_unk.normalized_label == NormalizedLabel.UNKNOWN
    assert res_unk.is_attack is True
