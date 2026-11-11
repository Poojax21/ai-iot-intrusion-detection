# Pahredaar-IoT — Installation & Developer Setup Guide

**Target Environment:** Windows 10/11 64-bit (or Linux/macOS)  
**Python Version:** Python 3.11, 3.12, 3.13, or 3.14  

---

## 1. Prerequisites

1. **Python 3.11+ 64-bit** with pip installed.
2. **Git** for version control.
3. **Node.js (Optional, for frontend dev server)** or any static HTTP file server.
4. **Zeek (Optional, for live network monitoring)**.

---

## 2. Step-by-Step Installation

### Step 1: Clone the Repository
```powershell
cd C:\Users\Hi\Projects
git clone <repo-url> iot-ids-project
cd iot-ids-project
```

### Step 2: Install Python Dependencies
```powershell
# Recommended: Create a virtual environment or use existing Python 3.14
py -3.14 -m pip install --upgrade pip
py -3.14 -m pip install -r requirements.txt
```

### Step 3: Configure Environment
Copy `.env.example` to `.env` (optional, defaults work out-of-the-box):
```powershell
Copy-Item .env.example .env
```

### Step 4: Validate Model Artifacts
Verify that serialized model directories exist:
- Baseline V1: `backend/app/models/*.pkl`
- Open-Set v1: `backend/app/models/open_set_v1/`
- Temporal v1: `backend/app/models/temporal_v1/`
- Graph v1: `backend/app/models/graph_v1/`

---

## 3. Running Pahredaar-IoT

### Starting the Backend API Server
```powershell
py -3.14 -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
- API Base: `http://127.0.0.1:8000`
- Interactive Swagger Docs: `http://127.0.0.1:8000/docs`
- Health Diagnostic Check: `http://127.0.0.1:8000/api/health`

### Starting the Frontend Dashboard
```powershell
# Option A: Python simple HTTP server
py -3.14 -m http.server 4173 --directory frontend

# Option B: Node / Vite preview
npx vite preview --port 4173
```
- Open in browser: `http://127.0.0.1:4173/`

### Starting the Simulated IoT Traffic Generator
```powershell
py -3.14 simulator/simulate_devices.py
```

### Starting the Zeek Network Monitor Bridge
```powershell
# For offline PCAP / conn.log replay:
py -3.14 simulator/zeek_adapter.py --conn-log tests/fixtures/zeek_sample.log --replay

# For live tail on sensor gateway:
py -3.14 simulator/zeek_adapter.py --conn-log /usr/local/zeek/logs/current/conn.log
```

---

## 4. Running Benchmarks & Tests

### Complete Test Regression Suite (All 94 tests)
```powershell
py -3.14 -m pytest tests/
```

### Reproducible Performance Benchmark
```powershell
py -3.14 training/benchmarking/benchmark_runner.py
```
