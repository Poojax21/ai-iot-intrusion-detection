# Pahredaar-IoT — Real-World Dataset Integration Guide
**Version:** 2.0 (Phase 2 Release)  
**Supported Datasets:** IoT-23, UNB CICIoT2023, UNSW Canberra TON_IoT  

---

## 1. Overview & Architecture

Phase 2 introduces a modular dataset integration tier designed to ingest public IoT intrusion benchmarks without forcing artificial features or destroying ground-truth attack semantics:

```text
Public Datasets (IoT-23 / CICIoT2023 / TON_IoT)
                    │
                    ▼
          Dataset-Specific Loader
   (IoT23Loader / CICIoT2023Loader / TonIoTLoader)
                    │
                    ▼
          Preprocessing Pipeline
   ├── Protocol Normalizer (IANA mapping)
   ├── Label Normalizer (8-class taxonomy + original preservation)
   ├── Missing Value Sanitizer (Zeek '-', NaN, Inf handling)
   └── Row Validator (physical sanity checks)
                    │
                    ▼
          Common Internal Representation
                 (StandardRecord)
                    │
                    ▼
          Canonical Feature Contract
              (FeatureContract)
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
Chronological Split      Group-Based Split
(Time causality)         (Scenario isolation)
```

---

## 2. Supported Datasets

### A. Stratosphere IPS IoT-23
- **Official Source:** [https://www.stratosphereips.org/datasets-iot23](https://www.stratosphereips.org/datasets-iot23)
- **Format:** Native Zeek `conn.log` / `conn.log.labeled` (tab-delimited TSV with `#fields` headers or JSON lines).
- **Key Features:**
  - Full bidirectional flow tuples (`id.orig_h`, `id.resp_h`, `id.orig_p`, `id.resp_p`, `proto`, `duration`, `orig_bytes`, `resp_bytes`, `conn_state`).
  - Native compatibility with the V1 feature vector: 100% derivable via `DeviceState`.
  - Capture & Scenario IDs automatically inferred from folder paths (e.g. `CTU-IoT-Malware-Capture-34-1`).

### B. UNB CICIoT2023
- **Official Source:** [https://www.unb.ca/cic/datasets/iotdataset-2023.html](https://www.unb.ca/cic/datasets/iotdataset-2023.html)
- **Format:** Large CSV tabular files (46 statistical flow features).
- **Key Features:**
  - Memory-safe chunked streaming (`pd.read_csv(chunksize=10000)`).
  - Handles inf and NaN occurrences from division by zero during packet rate calculations.
  - Normalizes 33 granular attack classes into canonical categories while preserving original attack names.

### C. UNSW Canberra TON_IoT (Network Flow)
- **Official Source:** [https://research.unsw.edu.au/projects/toniot-datasets](https://research.unsw.edu.au/projects/toniot-datasets)
- **Format:** Network flow CSV exports from testbed captures.
- **Key Features:**
  - Specifically isolates network flow records from host/OS/telemetry CSVs.
  - Normalizes `ts`, `src_ip`, `dst_ip`, `proto`, `service`, `conn_state`, `src_bytes`, `dst_bytes`.
  - Maps attack `type` (e.g. `scanning`, `ddos`, `password`, `xss`, `dos`) to standardized taxonomy.

---

## 3. Command-Line Tooling (CLI)

The dataset suite provides four primary CLI operations:

### 1. Inspect Schema
```powershell
py -3.14 -m training.datasets inspect --dataset iot23 --path data/iot23/conn.log.labeled
py -3.14 -m training.datasets inspect --dataset ciciot2023 --path data/ciciot2023/sample.csv
py -3.14 -m training.datasets inspect --dataset ton_iot --path data/ton_iot/Network_dataset.csv
```

### 2. Validate Records
```powershell
py -3.14 -m training.datasets validate --dataset ciciot2023 --path data/ciciot2023/sample.csv --limit 1000
```

### 3. Generate Audit Report
```powershell
py -3.14 -m training.datasets report --dataset ton_iot --path data/ton_iot/Network_dataset.csv --limit 5000
```
Outputs audit reports to `reports/datasets/<dataset>_report.json` and `.md`.

### 4. Prepare Leakage-Safe Splits
```powershell
py -3.14 -m training.datasets prepare --dataset iot23 --path data/iot23/conn.log.labeled --limit 5000
```

---

## 4. Integration Verification

The integration has been verified against:
- 12 comprehensive unit and integration tests under `tests/unit/` and `tests/integration/`.
- Validated against realistic fixtures containing Zeek headers, missing values, infinite float rates, and multi-scenario captures.
- Retains 100% backward compatibility with all V1 detection engine and API endpoints.
