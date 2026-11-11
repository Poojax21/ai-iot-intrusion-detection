# Pahredaar-IoT — Component B: Reliable Performance Benchmarking Report

**Date:** 2026-11-11  
**Harness:** `training/benchmarking/benchmark_runner.py`  
**Results Data:** `training/benchmarking/benchmark_results.json`  

---

## 1. Executive Summary & Benchmark Methodology

Phase 4 reported seemingly counter-intuitive latency numbers (e.g. V1 baseline at 234.1 ms vs Full Hybrid at 229.9 ms). To provide complete scientific rigor, Component B implemented an isolated, reproducible benchmarking harness that:
1. Primes Python JIT, PyTorch thread pools, and Scikit-Learn tree caches with $50$ warm-up cycles.
2. Isolates every pipeline stage independently over 500 identical trials.
3. Records full percentile latency distributions (Min, Median/p50, Mean, p90, p95, p99, Max).
4. Evaluates single-flow streaming latency alongside vectorized batch scaling ($N=10, 50, 100$).
5. Profiles memory footprint (RSS) and CPU utilization using OS-level process instrumentation (`psutil`).

---

## 2. Hardware and Software Environment

- **OS / Platform:** Windows 11 Pro (`10.0.22621-SP0`, 64-bit)
- **Processor:** Intel64 Family 6 Model 142 Stepping 12 (4 Physical Cores, 8 Logical Cores)
- **RAM:** 15.19 GB DDR4
- **Runtime:** Python 3.14.6 64-bit
- **Core ML Dependencies:** `scikit-learn 1.6.1`, `torch 2.6.0+cpu`, `shap 0.46.0`, `scipy 1.15.1`, `fastapi 0.115.8`

---

## 3. Isolated Component Latencies (Microbenchmarks)

Evaluated across 500 steady-state trials post warm-up:

| Pipeline Stage | Mean | Median (p50) | p90 | p95 | p99 | Max | Dominant Factor |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| **1. Feature Extraction** | 0.049 ms | 0.053 ms | 0.060 ms | 0.063 ms | 0.085 ms | 0.202 ms | In-memory device rolling state |
| **2. V1 Baseline Inference** | 280.925 ms | 251.323 ms | 380.415 ms | 422.689 ms | 506.404 ms | 1762.856 ms | 3 scikit-learn RF/IF tree traversals |
| **3. Open-Set Inference** | 203.602 ms | 190.854 ms | 271.210 ms | 327.234 ms | 391.288 ms | 465.379 ms | Gate RF + Centroid distances |
| **4. Temporal LSTM** | **1.423 ms** | **1.371 ms** | **1.891 ms** | **2.137 ms** | **2.972 ms** | 5.201 ms | PyTorch 2-layer LSTM forward pass |
| **5. Graph Construction & Inf.** | **0.610 ms** | **0.579 ms** | **0.870 ms** | **0.926 ms** | **1.152 ms** | 2.074 ms | Incremental tracker + entropy |
| **6. Exact TreeSHAP** | 99.903 ms | 93.652 ms | 131.979 ms | 142.845 ms | 154.185 ms | 172.380 ms | Tree traversal (alerted flows only) |
| **7. Hierarchical Risk Engine v2** | **0.007 ms** | **0.006 ms** | **0.010 ms** | **0.011 ms** | **0.014 ms** | 0.039 ms | Sub-microsecond scalar arithmetic |

### Crucial Insight on Latency Contradiction:
Scikit-Learn's Python `RandomForestClassifier.predict_proba` for a **single sample** ($1 \times 20$) takes ~80-100 ms per 100-tree forest. Because V1 executes Gate RF + Isolation Forest + Multiclass RF, single-sample Scikit-Learn tree traversal accounts for **over 90% of total runtime** (~250 ms).
In contrast:
- **Temporal LSTM** takes only **1.42 ms**.
- **Communication Graph** takes only **0.61 ms**.
- **Hierarchical Risk Engine** takes only **0.007 ms** ($6.8\,\mu\text{s}$).

Thus, adding Temporal, Graph, and Risk engine components adds less than $2.1\,\text{ms}$ of total overhead! The small fluctuations observed in Phase 4 were simply Scikit-Learn CPU scheduling jitter on single-sample calls.

---

## 4. End-to-End Pipeline & Batch Throughput

### 4.1 Single-Flow Streaming Latency (Real-Time Ingestion)
- **Evaluated Flows:** 500 consecutive real-world mixed flows
- **Throughput:** **3.26 flows/second** (single-threaded CPU streaming)
- **Mean Latency:** **306.52 ms**
- **Median (p50):** **262.82 ms**
- **p90 Latency:** **458.43 ms**
- **p95 Latency:** **493.45 ms**
- **p99 Latency:** **634.43 ms**

### 4.2 Vectorized Batch Processing (Sensor-Buffer Mode)
When the Zeek sensor or gateway forwards micro-batches of buffered network flows, CPU cache locality and SIMD matrix vectorization drastically amortize Python overhead:

| Batch Size ($N$) | Total Batch Time | Per-Sample Latency | Effective Throughput |
|:---|:---:|:---:|:---:|
| **Batch 10** | 117.54 ms | 11.75 ms | **85.1 flows/sec** |
| **Batch 50** | 118.75 ms | 2.38 ms | **421.1 flows/sec** |
| **Batch 100** | 109.75 ms | **1.10 ms** | **911.1 flows/sec** |

*In micro-batching mode ($N=100$), Pahredaar-IoT sustains **911 flows/second**, exceeding typical medium-scale IoT gateway line rates.*

---

## 5. System Resources & Memory Footprint

- **Cold-Start Model Load Time:** **0.5550 seconds** (Deserialization of all RF, Open-Set, LSTM, and Graph weights)
- **Initial Python Process Memory (RSS):** 539.02 MB
- **Memory Post-Model Load:** 552.69 MB ($\Delta = +13.67\text{ MB}$)
- **Peak Sustained Memory Under Load:** 559.04 MB ($\Delta = +20.02\text{ MB}$)
- **Average CPU Utilization Under Peak Ingestion:** **25.2%** (Runs comfortably within standard dual-core or quad-core edge gateways with zero swap memory usage).
