"""
Unit tests for Zeek conn.log Ingestion Adapter (simulator/zeek_adapter.py).
"""

import json
from pathlib import Path
import pytest

from simulator.zeek_adapter import ZeekLogProcessor, resolve_device_id


def test_resolve_device_id_arp_and_fallback():
    # 1. ARP Table resolution
    arp = {"192.168.1.50": "aa:bb:cc:dd:ee:ff"}
    dev_id, unstable = resolve_device_id("192.168.1.50", arp_table=arp)
    assert len(dev_id) == 16
    assert unstable is False

    # 2. IP Fallback resolution
    dev_id2, unstable2 = resolve_device_id("192.168.1.99")
    assert len(dev_id2) == 16
    assert unstable2 is True


def test_zeek_tsv_header_and_parsing():
    processor = ZeekLogProcessor()
    fixture_path = Path(__file__).resolve().parent.parent / "fixtures" / "zeek_sample.log"
    assert fixture_path.exists()

    parsed_records = []
    with open(fixture_path, "r", encoding="utf-8") as f:
        for line in f:
            rec = processor.parse_line(line)
            if rec:
                parsed_records.append(rec)

    # Out of 5 data lines, 4 are unique and 1 is a duplicate UID
    assert len(parsed_records) == 4
    assert processor.duplicates_skipped == 1

    # Check DNS UDP record
    r_dns = parsed_records[0]
    assert r_dns["proto"] == "udp"
    assert r_dns["dst_port"] == 53
    assert r_dns["conn_state"] == "SF"

    # Check TCP SSL record
    r_tcp = parsed_records[1]
    assert r_tcp["proto"] == "tcp"
    assert r_tcp["dst_port"] == 443
    assert r_tcp["orig_bytes"] == 1200
    assert r_tcp["resp_bytes"] == 4500

    # Check REJ record
    r_rej = parsed_records[2]
    assert r_rej["conn_state"] == "REJ"

    # Check ICMP record
    r_icmp = parsed_records[3]
    assert r_icmp["proto"] == "icmp"


def test_zeek_json_lines_parsing():
    processor = ZeekLogProcessor()

    json_line = json.dumps({
        "ts": 1700000050.123,
        "uid": "Cjson01020304",
        "id.orig_h": "192.168.1.120",
        "id.orig_p": 49152,
        "id.resp_h": "192.168.1.254",
        "id.resp_p": 80,
        "proto": "tcp",
        "duration": 0.05,
        "orig_bytes": 250,
        "resp_bytes": 1050,
        "conn_state": "SF",
    })

    rec = processor.parse_line(json_line)
    assert rec is not None
    assert rec["src_ip"] == "192.168.1.120"
    assert rec["dst_port"] == 80
    assert rec["duration"] == 0.05
    assert rec["zeek_uid"] == "Cjson01020304"

    # Sending identical JSON line again should be deduplicated
    rec_dupe = processor.parse_line(json_line)
    assert rec_dupe is None
    assert processor.duplicates_skipped == 1


def test_zeek_malformed_lines_graceful_handling():
    processor = ZeekLogProcessor()

    assert processor.parse_line("") is None
    assert processor.parse_line("   \n") is None
    assert processor.parse_line("# This is a comment") is None
    assert processor.parse_line("incomplete\tline") is None
    assert processor.parse_line("{invalid: json}") is None
    assert processor.parse_errors > 0
