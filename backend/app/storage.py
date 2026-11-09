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
        # Migrate existing DBs created before SHAP columns existed.
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        if "shap_values" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN shap_values TEXT")
        if "shap_base_value" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN shap_base_value REAL")
        conn.commit()


def record_flow(flow: dict, gate_score: float, is_flagged: bool):
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
        _touch_device(conn, flow, bump_alert=False)
        conn.commit()


def record_alert(flow: dict, attack_type: str, mitre: str, severity: str,
                  gate_score: float, anomaly_score: float, confidence_tier: str,
                  top_features: list, shap_values: list = None,
                  shap_base_value: float = None) -> int:
    with _lock, get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO alerts (ts, device_id, device_type, src_ip, dst_ip, attack_type, mitre,
                                    severity, gate_score, anomaly_score, confidence_tier,
                                    top_features, raw_flow, shap_values, shap_base_value)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (flow["ts"], flow["device_id"], flow.get("device_type"), flow["src_ip"], flow["dst_ip"],
             attack_type, mitre, severity, gate_score, anomaly_score, confidence_tier,
             json.dumps(top_features), json.dumps(flow),
             json.dumps(shap_values or []), shap_base_value),
        )
        _touch_device(conn, flow, bump_alert=True)
        conn.commit()
        return cur.lastrowid


def _touch_device(conn, flow: dict, bump_alert: bool):
    row = conn.execute("SELECT * FROM devices WHERE device_id=?", (flow["device_id"],)).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO devices (device_id, device_type, ip, flow_count, alert_count, risk_score, last_seen) "
            "VALUES (?,?,?,?,?,?,?)",
            (flow["device_id"], flow.get("device_type"), flow["src_ip"], 1, int(bump_alert),
             1.0 if bump_alert else 0.0, flow["ts"]),
        )
    else:
        new_flow_count = row["flow_count"] + 1
        new_alert_count = row["alert_count"] + (1 if bump_alert else 0)
        # simple decayed risk score: recent alerts weigh more than historical flow volume
        new_risk = min(100.0, row["risk_score"] * 0.98 + (10.0 if bump_alert else 0.0))
        conn.execute(
            "UPDATE devices SET flow_count=?, alert_count=?, risk_score=?, last_seen=?, ip=? WHERE device_id=?",
            (new_flow_count, new_alert_count, new_risk, flow["ts"], flow["src_ip"], flow["device_id"]),
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
        by_type = conn.execute(
            "SELECT attack_type, COUNT(*) c FROM alerts GROUP BY attack_type"
        ).fetchall()
        return {
            "total_flows": total_flows,
            "total_alerts": total_alerts,
            "alerts_by_type": {r["attack_type"]: r["c"] for r in by_type},
        }
