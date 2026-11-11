"""
Lightweight SQLite storage.

For a real deployment you'd swap this for TimescaleDB/Postgres (per the
plan), but SQLite keeps this project runnable with zero extra infrastructure
while preserving the same access pattern (flows table, alerts table, device
rolling stats), so swapping the backing store later is a small change
confined to this file.

Privacy note (plan §11): we only ever store flow METADATA here, never packet
payloads, and device_id is expected to already be a hashed/opaque identifier
by the time it reaches this layer (see schemas.FlowRecord).
"""

import sqlite3
import time
import json
import threading
from pathlib import Path
from .config import settings

DB_PATH = settings.DB_PATH

_lock = threading.Lock()


def get_conn(db_path: Path | str | None = None):
    target = db_path or DB_PATH
    conn = sqlite3.connect(target, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path | str | None = None):
    with _lock, get_conn(db_path) as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL, device_id TEXT, device_type TEXT,
            src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER,
            proto TEXT, duration REAL, orig_bytes INTEGER, resp_bytes INTEGER,
            orig_pkts INTEGER, resp_pkts INTEGER, conn_state TEXT,
            gate_score REAL, is_flagged INTEGER
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL, device_id TEXT, device_type TEXT,
            src_ip TEXT, dst_ip TEXT,
            attack_type TEXT, mitre TEXT, severity TEXT,
            gate_score REAL, anomaly_score REAL, confidence_tier TEXT,
            top_features TEXT, raw_flow TEXT,
            shap_values TEXT, shap_base_value REAL
        );

        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            device_type TEXT, ip TEXT,
            flow_count INTEGER DEFAULT 0,
            alert_count INTEGER DEFAULT 0,
            risk_score REAL DEFAULT 0,
            last_seen REAL
        );
        """)
        # Migrate existing DBs created before SHAP and Open-Set columns existed.
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        if "shap_values" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN shap_values TEXT")
        if "shap_base_value" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN shap_base_value REAL")
        if "decision" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN decision TEXT")
        if "is_unknown" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN is_unknown INTEGER DEFAULT 0")
        if "novelty_score" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN novelty_score REAL")
        if "calibrated_anomaly_score" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN calibrated_anomaly_score REAL")
        if "reason_codes" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN reason_codes TEXT")
        if "composite_device_risk" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN composite_device_risk REAL")
        if "risk_tier" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN risk_tier TEXT")
        if "temporal_risk" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN temporal_risk REAL")
        if "graph_risk" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN graph_risk REAL")
        if "risk_breakdown" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN risk_breakdown TEXT")

        dev_cols = {r["name"] for r in conn.execute("PRAGMA table_info(devices)").fetchall()}
        if "risk_tier" not in dev_cols:
            conn.execute("ALTER TABLE devices ADD COLUMN risk_tier TEXT DEFAULT 'LOW'")
        if "temporal_risk" not in dev_cols:
            conn.execute("ALTER TABLE devices ADD COLUMN temporal_risk REAL DEFAULT 0.0")
        if "graph_risk" not in dev_cols:
            conn.execute("ALTER TABLE devices ADD COLUMN graph_risk REAL DEFAULT 0.0")
        conn.commit()


_suppression_lock = threading.Lock()
_recent_alerts: dict[tuple[str, str], float] = {}


def should_suppress_alert(device_id: str, attack_type: str, ts: float, window_sec: float = 5.0) -> bool:
    """
    Suppresses duplicate alerts for the same device and attack within window_sec.
    Prevents alert storms while preserving first-alert visibility.
    """
    key = (device_id, attack_type)
    with _suppression_lock:
        last_ts = _recent_alerts.get(key)
        if last_ts is not None and (ts - last_ts) < window_sec:
            return True
        _recent_alerts[key] = ts
        # Evict stale entries older than 60s
        if len(_recent_alerts) > 500:
            stale_keys = [k for k, t in _recent_alerts.items() if (ts - t) > 60.0]
            for k in stale_keys:
                del _recent_alerts[k]
        return False


def record_flow(flow: dict, gate_score: float, is_flagged: bool,
                composite_risk: float = None, risk_tier: str = None,
                temporal_risk: float = None, graph_risk: float = None):
    with _lock, get_conn() as conn:
        conn.execute(
            """INSERT INTO flows (ts, device_id, device_type, src_ip, dst_ip, src_port, dst_port,
                                   proto, duration, orig_bytes, resp_bytes, orig_pkts, resp_pkts,
                                   conn_state, gate_score, is_flagged)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (flow["ts"], flow["device_id"], flow.get("device_type"), flow["src_ip"], flow["dst_ip"],
             flow["src_port"], flow["dst_port"], flow["proto"], flow["duration"],
             flow["orig_bytes"], flow["resp_bytes"], flow["orig_pkts"], flow["resp_pkts"],
             flow.get("conn_state", "SF"), gate_score, int(is_flagged)),
        )
        _touch_device(conn, flow, bump_alert=False, composite_risk=composite_risk,
                      risk_tier=risk_tier, temporal_risk=temporal_risk, graph_risk=graph_risk)
        conn.commit()


def record_alert(flow: dict, attack_type: str, mitre: str, severity: str,
                  gate_score: float, anomaly_score: float, confidence_tier: str,
                  top_features: list, shap_values: list = None,
                  shap_base_value: float = None,
                  decision: str = None, is_unknown: bool = False,
                  novelty_score: float = None, calibrated_anomaly_score: float = None,
                  reason_codes: list = None,
                  composite_device_risk: float = None, risk_tier: str = None,
                  temporal_risk: float = None, graph_risk: float = None,
                  risk_breakdown: dict = None) -> int:
    with _lock, get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO alerts (ts, device_id, device_type, src_ip, dst_ip, attack_type, mitre,
                                    severity, gate_score, anomaly_score, confidence_tier,
                                    top_features, raw_flow, shap_values, shap_base_value,
                                    decision, is_unknown, novelty_score, calibrated_anomaly_score,
                                    reason_codes, composite_device_risk, risk_tier, temporal_risk,
                                    graph_risk, risk_breakdown)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (flow["ts"], flow["device_id"], flow.get("device_type"), flow["src_ip"], flow["dst_ip"],
             attack_type, mitre, severity, gate_score, anomaly_score, confidence_tier,
             json.dumps(top_features), json.dumps(flow),
             json.dumps(shap_values or []), shap_base_value,
             decision, int(is_unknown), novelty_score, calibrated_anomaly_score,
             json.dumps(reason_codes or []),
             composite_device_risk, risk_tier, temporal_risk, graph_risk,
             json.dumps(risk_breakdown or {})),
        )
        _touch_device(conn, flow, bump_alert=True, composite_risk=composite_device_risk,
                      risk_tier=risk_tier, temporal_risk=temporal_risk, graph_risk=graph_risk)
        conn.commit()
        return cur.lastrowid


def _touch_device(conn, flow: dict, bump_alert: bool,
                  composite_risk: float = None, risk_tier: str = None,
                  temporal_risk: float = None, graph_risk: float = None):
    row = conn.execute("SELECT * FROM devices WHERE device_id=?", (flow["device_id"],)).fetchone()
    tier = risk_tier or "LOW"
    t_risk = float(temporal_risk or 0.0)
    g_risk = float(graph_risk or 0.0)
    if row is None:
        initial_risk = float(composite_risk) if composite_risk is not None else (1.0 if bump_alert else 0.0)
        conn.execute(
            "INSERT INTO devices (device_id, device_type, ip, flow_count, alert_count, risk_score, last_seen, risk_tier, temporal_risk, graph_risk) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (flow["device_id"], flow.get("device_type"), flow["src_ip"], 1, int(bump_alert),
             initial_risk, flow["ts"], tier, t_risk, g_risk),
        )
    else:
        new_flow_count = row["flow_count"] + 1
        new_alert_count = row["alert_count"] + (1 if bump_alert else 0)
        if composite_risk is not None:
            new_risk = float(composite_risk)
        else:
            new_risk = min(100.0, row["risk_score"] * 0.98 + (10.0 if bump_alert else 0.0))
        conn.execute(
            "UPDATE devices SET flow_count=?, alert_count=?, risk_score=?, last_seen=?, ip=?, risk_tier=?, temporal_risk=?, graph_risk=? WHERE device_id=?",
            (new_flow_count, new_alert_count, new_risk, flow["ts"], flow["src_ip"], tier, t_risk, g_risk, flow["device_id"]),
        )


def list_alerts(limit=100):
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["top_features"] = json.loads(d["top_features"])
            d["raw_flow"] = json.loads(d["raw_flow"])
            try:
                d["shap_values"] = json.loads(d.get("shap_values") or "[]")
            except Exception:
                d["shap_values"] = []
            try:
                d["reason_codes"] = json.loads(d.get("reason_codes") or "[]")
            except Exception:
                d["reason_codes"] = []
            try:
                d["risk_breakdown"] = json.loads(d.get("risk_breakdown") or "{}")
            except Exception:
                d["risk_breakdown"] = {}
            d["is_unknown"] = bool(d.get("is_unknown", 0))
            # shap_base_value already a REAL column; may be None for old rows.
            out.append(d)
        return out


def list_devices():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM devices ORDER BY risk_score DESC").fetchall()
        return [dict(r) for r in rows]


def get_stats():
    with get_conn() as conn:
        total_flows = conn.execute("SELECT COUNT(*) c FROM flows").fetchone()["c"]
        total_alerts = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
        unknown_alerts = conn.execute(
            "SELECT COUNT(*) c FROM alerts WHERE is_unknown=1 OR attack_type='unknown_suspicious'"
        ).fetchone()["c"]
        by_type = conn.execute(
            "SELECT attack_type, COUNT(*) c FROM alerts GROUP BY attack_type"
        ).fetchall()
        return {
            "total_flows": total_flows,
            "total_alerts": total_alerts,
            "unknown_alerts": unknown_alerts,
            "alerts_by_type": {r["attack_type"]: r["c"] for r in by_type},
        }
