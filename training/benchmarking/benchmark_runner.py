"""
Reproducible Performance Benchmarking Suite for Pahredaar-IoT.

Measures isolated latency percentiles (mean, p50, p90, p95, p99),
throughput (flows/sec), memory footprint, CPU utilization, and model loading times.
Saves machine-readable JSON results to benchmark_results.json.
"""

from dataclasses import dataclass, asdict
import json
import os
import platform
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import psutil

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.config import settings
from backend.app.detection import DetectionEngine, FEATURE_COLUMNS
from backend.app.features import DeviceState, build_feature_vector
from backend.app.risk.risk_engine import HierarchicalRiskEngine
from simulator.synthetic_traffic import generate_dataset


def compute_percentiles(latencies_ms: List[float]) -> Dict[str, float]:
    arr = np.array(latencies_ms)
    return {
        "mean_ms": round(float(np.mean(arr)), 4),
        "median_p50_ms": round(float(np.median(arr)), 4),
        "p90_ms": round(float(np.percentile(arr, 90)), 4),
        "p95_ms": round(float(np.percentile(arr, 95)), 4),
        "p99_ms": round(float(np.percentile(arr, 99)), 4),
        "min_ms": round(float(np.min(arr)), 4),
        "max_ms": round(float(np.max(arr)), 4),
    }


def run_benchmarks(n_trials: int = 500, n_warmup: int = 50) -> Dict[str, Any]:
    print("=== Starting Pahredaar-IoT Performance Benchmark Suite ===")
    process = psutil.Process()
    mem_before_mb = process.memory_info().rss / (1024 * 1024)

    # 1. Measure Model Deserialization & Loading Time
    t_load_start = time.perf_counter()
    engine = DetectionEngine()
    load_time_sec = time.perf_counter() - t_load_start
    print(f"[+] DetectionEngine Model Loading Time: {load_time_sec:.4f} seconds")

    mem_after_load_mb = process.memory_info().rss / (1024 * 1024)

    # Generate benchmark flow dataset
    flows = generate_dataset(n_devices=5, n_flows=n_trials + n_warmup, attack_ratio=0.20, seed=42)
    warmup_flows = flows[:n_warmup]
    eval_flows = flows[n_warmup:]

    # Prime engines with warm-up
    print(f"[*] Priming caches with {n_warmup} warm-up flows...")
    for wf in warmup_flows:
        engine.score_flow(wf)

    # Prepare reusable components for isolated microbenchmarks
    dummy_flow = eval_flows[0]
    dev_state = DeviceState()
    raw_vec = build_feature_vector(dummy_flow, dev_state)
    X = np.array([raw_vec])
    X_s = engine.scaler.transform(X) if engine.scaler else X

    results: Dict[str, Any] = {
        "system_info": {
            "platform": platform.platform(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "cpu_count_logical": psutil.cpu_count(logical=True),
            "cpu_count_physical": psutil.cpu_count(logical=False),
            "total_ram_gb": round(psutil.virtual_memory().total / (1024**3), 2),
        },
        "model_loading_time_sec": round(load_time_sec, 4),
        "memory_usage": {
            "initial_mb": round(mem_before_mb, 2),
            "post_model_load_mb": round(mem_after_load_mb, 2),
            "model_memory_delta_mb": round(mem_after_load_mb - mem_before_mb, 2),
        },
        "components": {},
    }

    # Microbenchmark 1: Feature Extraction
    print("[*] Benchmarking Feature Extraction...")
    lat_fe = []
    for f in eval_flows:
        t0 = time.perf_counter()
        _ = build_feature_vector(f, dev_state)
        lat_fe.append((time.perf_counter() - t0) * 1000.0)
    results["components"]["1_feature_extraction"] = compute_percentiles(lat_fe)

    # Microbenchmark 2: V1 Baseline Inference (Gate + IsolationForest + Multiclass)
    print("[*] Benchmarking V1 Inference Pipeline...")
    lat_v1 = []
    for _ in range(n_trials):
        t0 = time.perf_counter()
        _ = engine.gate_model.predict_proba(X_s)[0, 1]
        _ = engine.anomaly_model.score_samples(X_s)[0]
        _ = engine.multiclass_model.predict_proba(X_s)[0]
        lat_v1.append((time.perf_counter() - t0) * 1000.0)
    results["components"]["2_v1_inference"] = compute_percentiles(lat_v1)

    # Microbenchmark 3: Open-Set Inference
    print("[*] Benchmarking Open-Set Inference...")
    lat_os = []
    if engine.open_set_classifier:
        for _ in range(n_trials):
            t0 = time.perf_counter()
            _ = engine.open_set_classifier.predict_sample(raw_vec, feature_names=FEATURE_COLUMNS)
            lat_os.append((time.perf_counter() - t0) * 1000.0)
    results["components"]["3_open_set_inference"] = compute_percentiles(lat_os) if lat_os else "disabled"

    # Microbenchmark 4: Temporal LSTM Inference
    print("[*] Benchmarking Temporal LSTM...")
    lat_temp = []
    if engine.temporal_detector:
        for f in eval_flows:
            t0 = time.perf_counter()
            _ = engine.temporal_detector.score_flow(f["device_id"], X_s[0])
            lat_temp.append((time.perf_counter() - t0) * 1000.0)
    results["components"]["4_temporal_inference"] = compute_percentiles(lat_temp) if lat_temp else "disabled"

    # Microbenchmark 5: Graph Construction & Topological Scoring
    print("[*] Benchmarking Graph Construction & Inference...")
    lat_graph = []
    if engine.graph_detector:
        for f in eval_flows:
            t0 = time.perf_counter()
            _ = engine.graph_detector.score_flow(f)
            lat_graph.append((time.perf_counter() - t0) * 1000.0)
    results["components"]["5_graph_inference"] = compute_percentiles(lat_graph) if lat_graph else "disabled"

    # Microbenchmark 6: Exact TreeSHAP Attribution
    print("[*] Benchmarking TreeSHAP Explanation...")
    lat_shap = []
    if engine.shap_explainer:
        for _ in range(min(n_trials, 200)):
            t0 = time.perf_counter()
            _ = engine.shap_explainer.explain(x_raw=raw_vec, x_scaled=X_s, target_class="attack", top_k=8)
            lat_shap.append((time.perf_counter() - t0) * 1000.0)
    results["components"]["6_treeshap_explanation"] = compute_percentiles(lat_shap) if lat_shap else "disabled"

    # Microbenchmark 7: Hierarchical Risk Aggregation
    print("[*] Benchmarking Hierarchical Risk Engine v2...")
    lat_risk = []
    flow_res_mock = {"gate_score": 0.85, "calibrated_anomaly_score": 0.92, "is_flagged": True, "severity": "critical"}
    temp_res_mock = {"temporal_risk": 0.75, "temporal_flagged": True}
    graph_res_mock = {"graph_risk": 0.60, "is_lateral_movement": False}
    risk_eng = HierarchicalRiskEngine()
    for i in range(n_trials):
        t0 = time.perf_counter()
        _ = risk_eng.evaluate_risk(
            device_id="bench-dev-01",
            timestamp=1000.0 + i,
            flow_result=flow_res_mock,
            temporal_result=temp_res_mock,
            graph_result=graph_res_mock,
        )
        lat_risk.append((time.perf_counter() - t0) * 1000.0)
    results["components"]["7_risk_aggregation"] = compute_percentiles(lat_risk)

    # Microbenchmark 8: End-to-End score_flow (Full Hybrid Steady State)
    print("[*] Benchmarking Full Hybrid End-to-End Pipeline...")
    lat_e2e = []
    engine.device_states.clear()
    t_start_e2e = time.perf_counter()
    for f in eval_flows:
        t0 = time.perf_counter()
        _ = engine.score_flow(f)
        lat_e2e.append((time.perf_counter() - t0) * 1000.0)
    total_e2e_time = time.perf_counter() - t_start_e2e
    throughput_fps = len(eval_flows) / total_e2e_time

    results["end_to_end"] = {
        "sample_count": len(eval_flows),
        "throughput_flows_per_sec": round(throughput_fps, 2),
        "latencies": compute_percentiles(lat_e2e),
    }

    # Microbenchmark 9: Batch Processing Performance
    print("[*] Benchmarking Batch Vectorized Processing...")
    batch_sizes = [10, 50, 100]
    results["batch_benchmarks"] = {}
    for bs in batch_sizes:
        batch_vecs = np.repeat(X_s, bs, axis=0)
        t_b0 = time.perf_counter()
        _ = engine.gate_model.predict_proba(batch_vecs)
        b_time_ms = (time.perf_counter() - t_b0) * 1000.0
        results["batch_benchmarks"][f"batch_{bs}"] = {
            "total_ms": round(b_time_ms, 3),
            "per_sample_ms": round(b_time_ms / bs, 4),
            "effective_fps": round(bs / (b_time_ms / 1000.0), 1),
        }

    # Final Resource Usage
    cpu_percent = psutil.cpu_percent(interval=0.5)
    mem_final_mb = process.memory_info().rss / (1024 * 1024)
    results["resource_utilization"] = {
        "final_rss_mb": round(mem_final_mb, 2),
        "peak_memory_delta_mb": round(mem_final_mb - mem_before_mb, 2),
        "cpu_percent": cpu_percent,
    }

    output_path = Path(__file__).resolve().parent / "benchmark_results.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[+] Benchmark suite completed successfully! Results written to: {output_path}")
    return results


if __name__ == "__main__":
    run_benchmarks()
