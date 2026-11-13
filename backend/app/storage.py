"""
Lightweight SQLite storage with Incident Tracking & Safe Connection Management.

For a real deployment you'd swap this for TimescaleDB/Postgres (per the
plan), but SQLite keeps this project runnable with zero extra infrastructure
while preserving the same access pattern (flows table, alerts table, devices table,
incidents table).

Privacy note (plan §11): we only ever store flow METADATA here, never packet
payloads, and device_id is expected to already be a hashed/opaque identifier
by the time it reaches this layer (see schemas.FlowRecord).
"""

from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from .config import settings

DB_PATH = settings.DB_PATH

_lock = threading.Lock()


def get_conn(db_path: Path | str | None = None) -> sqlite3.Connection:
    target = db_path or DB_PATH
    conn = sqlite3.connect(target, check_same_thread=False, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def db_session(db_path: Path | str | None = None):
    """Guarantees connection cleanup to eliminate unclosed sqlite warnings."""
    conn = get_conn(db_path)
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


def init_db(db_path: Path | str | None = None):
    with _lock, db_session(db_path) as conn:
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
            shap_values TEXT, shap_base_value REAL,
            decision TEXT, is_unknown INTEGER DEFAULT 0,
            novelty_score REAL, calibrated_anomaly_score REAL,
            reason_codes TEXT, composite_device_risk REAL,
            risk_tier TEXT, temporal_risk REAL, graph_risk REAL,
            risk_breakdown TEXT
        );

        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            device_type TEXT, ip TEXT,
            flow_count INTEGER DEFAULT 0,
            alert_count INTEGER DEFAULT 0,
            risk_score REAL DEFAULT 0,
            last_seen REAL,
            risk_tier TEXT DEFAULT 'LOW',
            temporal_risk REAL DEFAULT 0.0,
            graph_risk REAL DEFAULT 0.0
        );

        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT UNIQUE,
            device_id TEXT,
            title TEXT,
            severity TEXT,
            status TEXT DEFAULT 'OPEN',
            attack_type TEXT,
            alert_count INTEGER DEFAULT 1,
            first_seen REAL,
            last_seen REAL,
            summary TEXT,
            mitre TEXT,
            acknowledged_at REAL,
            resolved_at REAL,
            resolution_notes TEXT
        );
        """)
        # Schema migration checks for backward compatibility
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        for col_name, col_type in [
            ("shap_values", "TEXT"), ("shap_base_value", "REAL"), ("decision", "TEXT"),
            ("is_unknown", "INTEGER DEFAULT 0"), ("novelty_score", "REAL"),
            ("calibrated_anomaly_score", "REAL"), ("reason_codes", "TEXT"),
            ("composite_device_risk", "REAL"), ("risk_tier", "TEXT"),
            ("temporal_risk", "REAL"), ("graph_risk", "REAL"), ("risk_breakdown", "TEXT")
        ]:
            if col_name not in cols:
                conn.execute(f"ALTER TABLE alerts ADD COLUMN {col_name} {col_type}")

        dev_cols = {r["name"] for r in conn.execute("PRAGMA table_info(devices)").fetchall()}
        for col_name, col_type in [
            ("risk_tier", "TEXT DEFAULT 'LOW'"),
            ("temporal_risk", "REAL DEFAULT 0.0"),
            ("graph_risk", "REAL DEFAULT 0.0"),
            ("organization_id", "TEXT DEFAULT 'default-org-id'")
        ]:
            if col_name not in dev_cols:
                conn.execute(f"ALTER TABLE devices ADD COLUMN {col_name} {col_type}")

        for tbl in ["flows", "alerts", "incidents"]:
            t_cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({tbl})").fetchall()}
            if "organization_id" not in t_cols:
                conn.execute(f"ALTER TABLE {tbl} ADD COLUMN organization_id TEXT DEFAULT 'default-org-id'")

        conn.commit()


_suppression_lock = threading.Lock()
_recent_alerts: dict[tuple[str, str], float] = {}
_suppression_stats = {"total_evaluated": 0, "suppressed_count": 0}


def should_suppress_alert(device_id: str, attack_type: str, ts: float, window_sec: float = 5.0) -> bool:
    """
    Suppresses duplicate alerts for the same device and attack within window_sec.
    Prevents alert storms while preserving first-alert visibility and tracking suppression metrics.
    """
    key = (device_id, attack_type)
    with _suppression_lock:
        _suppression_stats["total_evaluated"] += 1
        last_ts = _recent_alerts.get(key)
        if last_ts is not None and (ts - last_ts) < window_sec:
            _suppression_stats["suppressed_count"] += 1
            return True
        _recent_alerts[key] = ts
        # Evict stale entries older than 60s
        if len(_recent_alerts) > 500:
            stale_keys = [k for k, t in _recent_alerts.items() if (ts - t) > 60.0]
            for k in stale_keys:
                del _recent_alerts[k]
        return False


def get_suppression_metrics() -> Dict[str, Any]:
    with _suppression_lock:
        total = _suppression_stats["total_evaluated"]
        suppressed = _suppression_stats["suppressed_count"]
        rate = (suppressed / total) if total > 0 else 0.0
        return {
            "total_alerts_evaluated": total,
            "suppressed_duplicates": suppressed,
            "suppression_rate": round(rate, 4),
        }


def record_flow(flow: dict, gate_score: float, is_flagged: bool,
                composite_risk: float = None, risk_tier: str = None,
                temporal_risk: float = None, graph_risk: float = None,
                org_id: str = "default-org-id"):
    with _lock, db_session() as conn:
        conn.execute(
            """INSERT INTO flows (ts, device_id, device_type, src_ip, dst_ip, src_port, dst_port,
                                   proto, duration, orig_bytes, resp_bytes, orig_pkts, resp_pkts,
                                   conn_state, gate_score, is_flagged, organization_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (flow["ts"], flow["device_id"], flow.get("device_type"), flow["src_ip"], flow["dst_ip"],
             flow["src_port"], flow["dst_port"], flow["proto"], flow["duration"],
             flow["orig_bytes"], flow["resp_bytes"], flow["orig_pkts"], flow["resp_pkts"],
             flow.get("conn_state", "SF"), gate_score, int(is_flagged), org_id),
        )
        _touch_device(conn, flow, bump_alert=False, composite_risk=composite_risk,
                      risk_tier=risk_tier, temporal_risk=temporal_risk, graph_risk=graph_risk, org_id=org_id)
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
                  risk_breakdown: dict = None,
                  org_id: str = "default-org-id") -> int:
    with _lock, db_session() as conn:
        cur = conn.execute(
            """INSERT INTO alerts (ts, device_id, device_type, src_ip, dst_ip, attack_type, mitre,
                                    severity, gate_score, anomaly_score, confidence_tier,
                                    top_features, raw_flow, shap_values, shap_base_value,
                                    decision, is_unknown, novelty_score, calibrated_anomaly_score,
                                    reason_codes, composite_device_risk, risk_tier, temporal_risk,
                                    graph_risk, risk_breakdown, organization_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (flow["ts"], flow["device_id"], flow.get("device_type"), flow["src_ip"], flow["dst_ip"],
             attack_type, mitre, severity, gate_score, anomaly_score, confidence_tier,
             json.dumps(top_features), json.dumps(flow),
             json.dumps(shap_values or []), shap_base_value,
             decision, int(is_unknown), novelty_score, calibrated_anomaly_score,
             json.dumps(reason_codes or []),
             composite_device_risk, risk_tier, temporal_risk, graph_risk,
             json.dumps(risk_breakdown or {}), org_id),
        )
        alert_id = cur.lastrowid
        _touch_device(conn, flow, bump_alert=True, composite_risk=composite_device_risk,
                      risk_tier=risk_tier, temporal_risk=temporal_risk, graph_risk=graph_risk, org_id=org_id)
        
        # Correlate alert into stateful security incidents
        _correlate_incident(conn, flow, attack_type, severity, mitre, org_id=org_id)

        conn.commit()
        return alert_id


def _correlate_incident(conn, flow: dict, attack_type: str, severity: str, mitre: str, org_id: str = "default-org-id"):
    """Correlates alerts into a coherent device incident within a 60-second window."""
    now = float(flow["ts"])
    dev_id = flow["device_id"]
    active_inc = conn.execute(
        "SELECT * FROM incidents WHERE device_id=? AND organization_id=? AND status IN ('OPEN', 'ACKNOWLEDGED') "
        "AND (last_seen >= ?) ORDER BY id DESC LIMIT 1",
        (dev_id, org_id, now - 60.0),
    ).fetchone()

    sev_order = {"info": 1, "warning": 2, "critical": 3}
    if active_inc is None:
        inc_id = f"INC-{int(now)}-{dev_id[:4]}-{uuid.uuid4().hex[:6]}"
        title = f"{attack_type.upper().replace('_', ' ')} Incident on {dev_id}"
        summary = f"Detected {attack_type} activity targeting or originating from {flow.get('src_ip', 'unknown')}."
        conn.execute(
            """INSERT INTO incidents (incident_id, device_id, title, severity, status, attack_type,
                                       alert_count, first_seen, last_seen, summary, mitre, organization_id)
               VALUES (?, ?, ?, ?, 'OPEN', ?, 1, ?, ?, ?, ?, ?)""",
            (inc_id, dev_id, title, severity, attack_type, now, now, summary, mitre, org_id),
        )
    else:
        new_cnt = active_inc["alert_count"] + 1
        current_sev = active_inc["severity"]
        upgraded_sev = severity if sev_order.get(severity, 1) > sev_order.get(current_sev, 1) else current_sev
        new_summary = f"{active_inc['summary']} (Total alerts: {new_cnt})"
        conn.execute(
            """UPDATE incidents SET alert_count=?, last_seen=?, severity=?, summary=?
               WHERE id=?""",
            (new_cnt, now, upgraded_sev, new_summary, active_inc["id"]),
        )


def _touch_device(conn, flow: dict, bump_alert: bool,
                  composite_risk: float = None, risk_tier: str = None,
                  temporal_risk: float = None, graph_risk: float = None,
                  org_id: str = "default-org-id"):
    row = conn.execute("SELECT * FROM devices WHERE device_id=? AND organization_id=?", (flow["device_id"], org_id)).fetchone()
    tier = risk_tier or "LOW"
    t_risk = float(temporal_risk or 0.0)
    g_risk = float(graph_risk or 0.0)
    if row is None:
        initial_risk = float(composite_risk) if composite_risk is not None else (1.0 if bump_alert else 0.0)
        conn.execute(
            "INSERT INTO devices (device_id, device_type, ip, flow_count, alert_count, risk_score, last_seen, risk_tier, temporal_risk, graph_risk, organization_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (flow["device_id"], flow.get("device_type"), flow["src_ip"], 1, int(bump_alert),
             initial_risk, flow["ts"], tier, t_risk, g_risk, org_id),
        )
    else:
        new_flow_count = row["flow_count"] + 1
        new_alert_count = row["alert_count"] + (1 if bump_alert else 0)
        if composite_risk is not None:
            new_risk = float(composite_risk)
        else:
            new_risk = min(100.0, row["risk_score"] * 0.98 + (10.0 if bump_alert else 0.0))
        conn.execute(
            "UPDATE devices SET flow_count=?, alert_count=?, risk_score=?, last_seen=?, ip=?, risk_tier=?, temporal_risk=?, graph_risk=? WHERE device_id=? AND organization_id=?",
            (new_flow_count, new_alert_count, new_risk, flow["ts"], flow["src_ip"], tier, t_risk, g_risk, flow["device_id"], org_id),
        )


def list_alerts(limit=100, org_id: Optional[str] = None, device_id: Optional[str] = None, severity: Optional[str] = None):
    with _lock, db_session() as conn:
        query = "SELECT * FROM alerts"
        clauses = []
        params = []
        if org_id:
            clauses.append("organization_id=?")
            params.append(org_id)
        if device_id:
            clauses.append("device_id=?")
            params.append(device_id)
        if severity:
            clauses.append("LOWER(severity)=?")
            params.append(severity.lower())
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, tuple(params)).fetchall()
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
            out.append(d)
        return out


def list_devices(org_id: Optional[str] = None):
    with _lock, db_session() as conn:
        if org_id:
            rows = conn.execute("SELECT * FROM devices WHERE organization_id=? ORDER BY risk_score DESC", (org_id,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM devices ORDER BY risk_score DESC").fetchall()
        return [dict(r) for r in rows]


def get_device(device_id: str, org_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    with _lock, db_session() as conn:
        if org_id:
            row = conn.execute("SELECT * FROM devices WHERE device_id=? AND organization_id=?", (device_id, org_id)).fetchone()
        else:
            row = conn.execute("SELECT * FROM devices WHERE device_id=?", (device_id,)).fetchone()
        return dict(row) if row else None


def list_incidents(status: Optional[str] = None, limit: int = 500, org_id: Optional[str] = None, device_id: Optional[str] = None) -> List[Dict[str, Any]]:
    with _lock, db_session() as conn:
        query = "SELECT * FROM incidents"
        clauses = []
        params = []
        if org_id:
            clauses.append("organization_id=?")
            params.append(org_id)
        if device_id:
            clauses.append("device_id=?")
            params.append(device_id)
        if status:
            clauses.append("status=?")
            params.append(status)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, tuple(params)).fetchall()
        return [dict(r) for r in rows]


def acknowledge_incident(incident_id: str, ts: Optional[float] = None, org_id: Optional[str] = None) -> bool:
    now = ts or time.time()
    with _lock, db_session() as conn:
        if org_id:
            cur = conn.execute(
                "UPDATE incidents SET status='ACKNOWLEDGED', acknowledged_at=? WHERE incident_id=? AND organization_id=? AND status='OPEN'",
                (now, incident_id, org_id),
            )
        else:
            cur = conn.execute(
                "UPDATE incidents SET status='ACKNOWLEDGED', acknowledged_at=? WHERE incident_id=? AND status='OPEN'",
                (now, incident_id),
            )
        conn.commit()
        return cur.rowcount > 0


def resolve_incident(incident_id: str, notes: str = "", ts: Optional[float] = None, org_id: Optional[str] = None) -> bool:
    now = ts or time.time()
    with _lock, db_session() as conn:
        if org_id:
            cur = conn.execute(
                "UPDATE incidents SET status='RESOLVED', resolved_at=?, resolution_notes=? WHERE incident_id=? AND organization_id=? AND status IN ('OPEN', 'ACKNOWLEDGED')",
                (now, notes, incident_id, org_id),
            )
        else:
            cur = conn.execute(
                "UPDATE incidents SET status='RESOLVED', resolved_at=?, resolution_notes=? WHERE incident_id=? AND status IN ('OPEN', 'ACKNOWLEDGED')",
                (now, notes, incident_id),
            )
        conn.commit()
        return cur.rowcount > 0


def get_incident_metrics(org_id: Optional[str] = None) -> Dict[str, Any]:
    with _lock, db_session() as conn:
        where_clause = " WHERE organization_id=?" if org_id else ""
        params = (org_id,) if org_id else ()

        total_incidents = conn.execute(f"SELECT COUNT(*) c FROM incidents{where_clause}", params).fetchone()["c"]
        open_filter = f"{where_clause} AND status='OPEN'" if where_clause else " WHERE status='OPEN'"
        open_incidents = conn.execute(f"SELECT COUNT(*) c FROM incidents{open_filter}", params).fetchone()["c"]
        ack_filter = f"{where_clause} AND status='ACKNOWLEDGED'" if where_clause else " WHERE status='ACKNOWLEDGED'"
        ack_incidents = conn.execute(f"SELECT COUNT(*) c FROM incidents{ack_filter}", params).fetchone()["c"]
        res_filter = f"{where_clause} AND status='RESOLVED'" if where_clause else " WHERE status='RESOLVED'"
        resolved_incidents = conn.execute(f"SELECT COUNT(*) c FROM incidents{res_filter}", params).fetchone()["c"]

        # Mean Time to Acknowledge (seconds)
        mtta_filter = f"{where_clause} AND acknowledged_at IS NOT NULL" if where_clause else " WHERE acknowledged_at IS NOT NULL"
        mtta_row = conn.execute(
            f"SELECT AVG(acknowledged_at - first_seen) avg_mtta FROM incidents{mtta_filter}",
            params,
        ).fetchone()
        avg_mtta_sec = float(mtta_row["avg_mtta"]) if mtta_row and mtta_row["avg_mtta"] is not None else 0.0

        # Mean Time to Resolve (seconds)
        mttr_filter = f"{where_clause} AND resolved_at IS NOT NULL" if where_clause else " WHERE resolved_at IS NOT NULL"
        mttr_row = conn.execute(
            f"SELECT AVG(resolved_at - first_seen) avg_mttr FROM incidents{mttr_filter}",
            params,
        ).fetchone()
        avg_mttr_sec = float(mttr_row["avg_mttr"]) if mttr_row and mttr_row["avg_mttr"] is not None else 0.0

        suppression = get_suppression_metrics()

        return {
            "total_incidents": total_incidents,
            "open_incidents": open_incidents,
            "acknowledged_incidents": ack_incidents,
            "resolved_incidents": resolved_incidents,
            "mean_time_to_acknowledge_sec": round(avg_mtta_sec, 2),
            "mean_time_to_resolve_sec": round(avg_mttr_sec, 2),
            "suppression_metrics": suppression,
        }


def get_stats(org_id: Optional[str] = None):
    with _lock, db_session() as conn:
        where_clause = " WHERE organization_id=?" if org_id else ""
        params = (org_id,) if org_id else ()

        total_flows = conn.execute(f"SELECT COUNT(*) c FROM flows{where_clause}", params).fetchone()["c"]
        total_alerts = conn.execute(f"SELECT COUNT(*) c FROM alerts{where_clause}", params).fetchone()["c"]
        
        unk_filter = f"{where_clause} AND (is_unknown=1 OR attack_type='unknown_suspicious')" if where_clause else " WHERE is_unknown=1 OR attack_type='unknown_suspicious'"
        unknown_alerts = conn.execute(
            f"SELECT COUNT(*) c FROM alerts{unk_filter}",
            params,
        ).fetchone()["c"]
        
        group_query = f"SELECT attack_type, COUNT(*) c FROM alerts{where_clause} GROUP BY attack_type"
        by_type = conn.execute(group_query, params).fetchall()

        inc_group_query = f"SELECT status, COUNT(*) c FROM incidents{where_clause} GROUP BY status"
        inc_counts = conn.execute(inc_group_query, params).fetchall()
        return {
            "total_flows": total_flows,
            "total_alerts": total_alerts,
            "unknown_alerts": unknown_alerts,
            "alerts_by_type": {r["attack_type"]: r["c"] for r in by_type},
            "incidents_by_status": {r["status"]: r["c"] for r in inc_counts},
        }
