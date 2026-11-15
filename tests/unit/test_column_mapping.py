"""
Unit tests for column mapping tables across datasets.
"""

from training.preprocessing.column_mapping import (
    IOT23_COLUMN_MAP,
    CICIOT2023_COLUMN_MAP,
    TON_IOT_NETWORK_MAP,
    BOT_IOT_COLUMN_MAP,
    NBAIOT_COLUMN_MAP,
)


def test_iot23_column_map_coverage():
    assert "ts" in IOT23_COLUMN_MAP
    assert "id.orig_h" in IOT23_COLUMN_MAP
    assert "id.resp_h" in IOT23_COLUMN_MAP
    assert "proto" in IOT23_COLUMN_MAP
    assert "duration" in IOT23_COLUMN_MAP
    assert "orig_bytes" in IOT23_COLUMN_MAP
    assert "conn_state" in IOT23_COLUMN_MAP
    assert "detailed-label" in IOT23_COLUMN_MAP


def test_ciciot2023_column_map_coverage():
    assert "flow_duration" in CICIOT2023_COLUMN_MAP
    assert "tot sum" in CICIOT2023_COLUMN_MAP
    assert "rate" in CICIOT2023_COLUMN_MAP
    assert "label" in CICIOT2023_COLUMN_MAP


def test_ton_iot_column_map_coverage():
    assert "ts" in TON_IOT_NETWORK_MAP
    assert "src_ip" in TON_IOT_NETWORK_MAP
    assert "dst_ip" in TON_IOT_NETWORK_MAP
    assert "proto" in TON_IOT_NETWORK_MAP
    assert "type" in TON_IOT_NETWORK_MAP


def test_bot_iot_column_map_coverage():
    assert "stime" in BOT_IOT_COLUMN_MAP
    assert "saddr" in BOT_IOT_COLUMN_MAP
    assert "category" in BOT_IOT_COLUMN_MAP
    assert "dur" in BOT_IOT_COLUMN_MAP


def test_nbaiot_column_map_coverage():
    assert "MI_dir_L5_weight" in NBAIOT_COLUMN_MAP
    assert "label" in NBAIOT_COLUMN_MAP
