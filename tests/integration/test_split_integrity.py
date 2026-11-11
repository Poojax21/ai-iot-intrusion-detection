"""
Integration test for splitting strategies and leakage detection.
"""

from training.feature_contract import StandardRecord
from training.splitting.chronological_split import chronological_split
from training.splitting.group_split import group_based_split
from training.splitting.leakage_detection import check_leakage


def test_chronological_split_integrity():
    records = [
        StandardRecord(
            timestamp=100.0 + i,
            source_ip=f"192.168.1.{i}",
            destination_ip="203.0.113.1",
            source_port=1000 + i,
            destination_port=80,
            protocol="tcp",
            duration=1.0,
            source_bytes=100,
            destination_bytes=200,
            source_packets=2,
            destination_packets=2,
            connection_state="SF",
        )
        for i in range(10)
    ]
    res = chronological_split(records, train_ratio=0.7, val_ratio=0.2, test_ratio=0.1)
    assert len(res.train) == 7
    assert len(res.val) == 2
    assert len(res.test) == 1

    # Verify time ranges do not overlap
    assert res.train_time_range[1] <= res.val_time_range[0]
    assert res.val_time_range[1] <= res.test_time_range[0]

    # Verify leakage audit passes
    audit = check_leakage(res.train, res.test)
    assert audit.is_leakage_free is True
    assert audit.duplicate_flow_count == 0


def test_group_split_prevents_leakage():
    records = []
    # 3 distinct scenarios
    for scen in ["CTU-1", "CTU-2", "CTU-3", "CTU-4"]:
        for i in range(5):
            records.append(
                StandardRecord(
                    timestamp=100.0 + i,
                    source_ip="192.168.1.10",
                    destination_ip="203.0.113.1",
                    source_port=1000 + i,
                    destination_port=80,
                    protocol="tcp",
                    duration=1.0,
                    source_bytes=100,
                    destination_bytes=200,
                    source_packets=2,
                    destination_packets=2,
                    connection_state="SF",
                    scenario_id=scen,
                )
            )

    res = group_based_split(records, group_by="scenario_id", train_ratio=0.5, val_ratio=0.25, test_ratio=0.25)
    train_scens = set(res.train_groups)
    test_scens = set(res.test_groups)

    # Scenarios must be strictly disjoint
    assert train_scens.isdisjoint(test_scens)

    # Leakage check verifies no group bleed
    audit = check_leakage(res.train, res.test, group_key="scenario_id")
    assert audit.group_bleed_count == 0
