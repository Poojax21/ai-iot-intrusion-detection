"""
Unit tests for the device fleet simulator and synthetic traffic generation.
"""

import random
from simulator.synthetic_traffic import (
    make_device_pool,
    _benign_flow,
    _port_scan_flow,
    _ddos_flow,
    _brute_force_flow,
    _mirai_beacon_flow,
    generate_dataset,
    DEVICE_TYPES,
)
from simulator.simulate_devices import build_flow


def test_make_device_pool():
    devices = make_device_pool(n_devices=5, seed=42)
    assert len(devices) == 5
    types = {d["device_type"] for d in devices}
    assert types == set(DEVICE_TYPES)
    for d in devices:
        assert d["ip"].startswith("192.168.1.")
        assert d["device_id"].startswith(d["device_type"])


def test_benign_flow_generation():
    rnd = random.Random(42)
    device = {"device_id": "test-cam", "device_type": "camera", "ip": "192.168.1.15"}
    flow = _benign_flow(device, rnd, ts=1000.0)
    assert flow["src_ip"] == device["ip"]
    assert flow["conn_state"] == "SF"
    assert flow["label"] == "benign"
    assert flow["orig_bytes"] > 0
    assert flow["resp_bytes"] > 0


def test_attack_flow_signatures():
    rnd = random.Random(42)
    device = {"device_id": "test-bulb", "device_type": "smart_bulb", "ip": "192.168.1.20"}

    # Port scan
    ps = _port_scan_flow(device, rnd, ts=1000.0)
    assert ps["label"] == "port_scan"
    assert ps["conn_state"] in ["S0", "REJ"]
    assert ps["orig_pkts"] == 1

    # DDoS
    ddos = _ddos_flow(device, rnd, ts=1000.0, victim_ip="192.168.1.250")
    assert ddos["label"] == "ddos"
    assert ddos["dst_ip"] == "192.168.1.250"
    assert ddos["orig_pkts"] >= 20

    # Brute force
    bf = _brute_force_flow(device, rnd, ts=1000.0, target_ip="192.168.1.251")
    assert bf["label"] == "brute_force"
    assert bf["dst_ip"] == "192.168.1.251"
    assert bf["dst_port"] in [22, 23, 80, 443, 8080]

    # Mirai beacon
    mb = _mirai_beacon_flow(device, rnd, ts=1000.0, c2_ip="203.0.113.39")
    assert mb["label"] == "mirai_beacon"
    assert mb["dst_ip"] == "203.0.113.39"
    assert 60 <= mb["orig_bytes"] <= 90
    assert 60 <= mb["resp_bytes"] <= 90


def test_simulate_devices_build_flow_strips_label():
    rnd = random.Random(42)
    devices = make_device_pool(n_devices=4, seed=42)
    # Generate flow
    flow = build_flow(
        devices=devices,
        rnd=rnd,
        attack_prob=0.5,
        victim_ip="192.168.1.250",
        c2_ip="203.0.113.39",
        brute_target="192.168.1.251",
    )
    # Crucial security test: real edge sensor or simulator never passes ground-truth label to ingestion
    assert "label" not in flow
    assert "device_id" in flow
    assert "src_ip" in flow
    assert "dst_ip" in flow
    assert "device_type" in flow


def test_generate_dataset_chronological_order():
    flows = generate_dataset(n_devices=4, n_flows=100, attack_ratio=0.1, seed=42)
    assert len(flows) == 100
    timestamps = [f["ts"] for f in flows]
    assert timestamps == sorted(timestamps)
