# Pahredaar-IoT — Working V1

A running end-to-end slice of the IDS described in `docs/IoT-IDS-Project-Plan.md`:
**train models → backend scores live traffic → simulated IoT devices stream flows in →
dashboard shows alerts in real time.**

This is a real, working two-stage pipeline (unsupervised anomaly model + FPR-tuned binary
gate → multiclass attack classifier), just without the GraphSAGE/LSTM upgrade or SHAP yet —
see "What's simplified vs. the full plan" below for the honest list of what's deferred.

```
training/     -> Jupyter notebook that trains & saves the models
backend/      -> FastAPI service: ingest flows, run detection, serve alerts/devices/stats
simulator/    -> simulated IoT device fleet (+ a real-hardware bridge, see below)
frontend/     -> single HTML file, talks directly to the backend
docs/         -> the full architecture/reliability plan this project implements
```

## 1. Train the models

```bash
cd training
pip install -r requirements.txt
jupyter notebook train_model.ipynb     # Run All Cells
```

This generates synthetic-but-realistic IoT traffic (benign + port_scan/ddos/brute_force/
mirai_beacon), trains the anomaly model + binary gate + multiclass classifier, and saves
everything into `backend/app/models/`. **Pretrained models are already included in this zip**
so you can skip this step and go straight to step 2 — re-run the notebook whenever you want
to retrain (e.g. after pointing it at a real dataset, see the notebook's section 1).

## 2. Start the backend

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Check it's alive and models loaded: `curl http://localhost:8000/api/health`

If you want the whole demo running at once, use the launcher at the repo root:

```bash
bash ./start.sh
```

That starts the backend, the simulator, and a local static server for the frontend.
By default it uses the backend on `http://localhost:8000` and serves the dashboard on
`http://127.0.0.1:4173`.

## 3. Start the simulated IoT device fleet

```bash
cd simulator
pip install -r requirements.txt
python simulate_devices.py --backend http://localhost:8000 --devices 8 --rate 5 --attack-prob 0.08
```

This streams live flow records for 8 simulated devices (camera/plug/sensor/thermostat/bulb),
mixing in attacks at the given probability, and prints `[ALERT]` lines as the backend flags
things.

## 4. Open the dashboard

Just open `frontend/index.html` directly in a browser (double-click it, or `python -m http.server`
from the `frontend/` folder and visit it). It talks to `http://localhost:8000` by default —
change the URL in the top bar if your backend runs elsewhere. You'll see live alerts stream in
via WebSocket, plus a device list with rolling risk scores.

### Traffic lab test modes

The dashboard now includes a built-in Traffic Lab that sends synthetic HTTP POSTs to the same
`/api/ingest` endpoint the real simulator uses:

- Normal only: all benign traffic, no attack pressure
- Suspicious heavy: attack-dominant traffic to confirm threshold behavior
- Real-world mix: bursty mixed traffic that looks closer to a real IoT environment

Use the Start traffic test button to keep feeding the backend, or Send burst now for a quick
verification pass.

---

## Connecting REAL hardware instead of the simulator

This is the part that was built to make the switch a non-event. The backend's `/api/ingest`
endpoint accepts one flow-record JSON schema (`backend/app/schemas.py: FlowRecord`) — the
simulator and a real sensor both just POST that same shape.

1. Put a small box (Raspberry Pi, spare mini-PC, or a VM) on your router's SPAN/mirror port.
2. Install Zeek on it and point it at the mirrored interface — it produces `conn.log`.
3. Run the bridge included here:
   ```bash
   python simulator/zeek_adapter.py --conn-log /path/to/conn.log --backend http://<collector-ip>:8000
   ```
4. That's it — the backend, detection pipeline, storage, and dashboard don't change at all.
   Real flows show up in the same dashboard the simulator was populating a moment ago.

Read the docstring at the top of `zeek_adapter.py` — it explains the one thing you should
wire up properly for a real deployment: resolving each flow's source IP to a stable
**hashed MAC-based device identity** (via your router's ARP/DHCP table) instead of the
IP-hash fallback it uses out of the box, which won't survive a DHCP lease change. See plan §7.

---

## What's simplified vs. the full plan (and why)

The full architecture in `docs/IoT-IDS-Project-Plan.md` also specifies a GraphSAGE
device-topology model, an LSTM per-device sequence model, and SHAP-based explanations. This
V1 ships:

| Plan component | This project |
|---|---|
| Unsupervised anomaly layer | ✅ IsolationForest, trained benign-only |
| FPR-tuned binary gate | ✅ RandomForest, threshold selected against a 2% FPR ceiling |
| Multiclass attack classifier | ✅ RandomForest (stands in for the plan's LightGBM — same role) |
| GraphSAGE (lateral movement) | ⏳ not yet — `is_new_edge`/`src_fanout_recent` features are already computed and ready for a graph model to consume later |
| LSTM (temporal drift) | ⏳ not yet — per-device rolling state already exists in `features.DeviceState`, a sequence model can be layered on the same state |
| SHAP explainability | ⏳ stand-in: `detection.py::_top_features()` reports the top raw feature deviations per alert instead |
| New-device grace period | ✅ implemented (`detection.py::GRACE_PERIOD_FLOWS`) — cuts cold-start false positives substantially, see the numbers below |
| Fail-open on detector outage | ✅ `/api/ingest` still stores flows even if models aren't loaded; never blocks traffic |
| Chronological training split | ✅ notebook sorts by `ts` before splitting, never a random row split |

This was a deliberate scope cut to ship something that actually runs end-to-end today. The
architecture is built so the deferred pieces slot in without a rewrite — the feature vectors,
per-device state, and ensemble-head pattern are already there.

### A real number from testing this build

A 20-second simulated run (216 flows, 6 devices, 12% attack rate) flagged **32% of flows**
before the grace period was added, and **11%** after — almost entirely because a
brand-new device with no traffic history looks "anomalous" by definition until its baseline
forms. This is exactly the cold-start problem the plan's reliability section warns about
(§10/§11) — it's a good illustration of why that practice exists, not just a plan bullet
point.

## Next steps

1. Swap `training/synthetic_traffic.py`'s generator for a real dataset load (CICIoT2023 etc. —
   links in plan §8) once you want real benchmark numbers, and add the plan's cross-dataset
   generalization test (§9/§17) before trusting them.
2. Add the GraphSAGE and LSTM ensemble members (plan §9.6) as additional inputs to
   `train_ensemble.py`-style stacking — the feature groundwork is already in place.
3. Swap SQLite for TimescaleDB/Postgres if you outgrow single-file storage (plan §14).
4. Wire `zeek_adapter.py`'s `resolve_device_id()` to your router's real ARP/DHCP table.
5. Add the shadow-mode/canary go-live checklist (plan §18) before trusting this on a network
   you actually care about.
