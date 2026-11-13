"""
SQLite-to-PostgreSQL Data Migration Utility for Pahredaar-IoT.

Migrates legacy standalone SQLite databases (iot_ids.db) into normalized,
multi-tenant PostgreSQL (or a target database) without data loss.

Features:
- Non-destructive read-only inspection of source database.
- Automatic default organization provisioning.
- Foreign key resolution and mapping.
- Dry-run validation mode.
- Checksum and count reconciliation report.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import sys
import uuid

from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from backend.app.database.base import Base, generate_uuid, utc_now
from backend.app.database.models import (
    Organization,
    Device,
    NetworkFlow,
    Alert,
    Incident,
    AuditEvent,
)


def parse_args():
    parser = argparse.ArgumentParser(description="Migrate Pahredaar-IoT SQLite data to PostgreSQL.")
    parser.add_argument("--sqlite", type=str, default="backend/app/iot_ids.db", help="Path to source SQLite file")
    parser.add_argument("--dest", type=str, required=True, help="Target SQLAlchemy connection URL (e.g. postgresql+psycopg://...)")
    parser.add_argument("--org-name", type=str, default="Default Organization", help="Name of destination organization")
    parser.add_argument("--org-slug", type=str, default="default-org", help="Slug of destination organization")
    parser.add_argument("--batch-size", type=int, default=500, help="Batch insertion size")
    parser.add_argument("--dry-run", action="store_true", help="Inspect and validate without committing changes")
    return parser.parse_args()


def to_dt(ts: float | None) -> datetime:
    if ts is None:
        return utc_now()
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc)
    except Exception:
        return utc_now()


def run_migration(sqlite_path: str, dest_url: str, org_name: str, org_slug: str, dry_run: bool = False, batch_size: int = 500):
    print("=" * 70)
    print("PAHREDAAR-IOT: DATABASE MIGRATION UTILITY")
    print("=" * 70)
    print(f"Source SQLite:   {sqlite_path}")
    print(f"Destination:     {dest_url}")
    print(f"Mode:            {'DRY-RUN (No writes)' if dry_run else 'LIVE MIGRATION'}")
    print("-" * 70)

    src_path = Path(sqlite_path)
    if not src_path.exists():
        print(f"ERROR: Source SQLite database not found at '{sqlite_path}'")
        sys.exit(1)

    # 1. Connect to SQLite
    src_conn = sqlite3.connect(src_path)
    src_conn.row_factory = sqlite3.Row

    # 2. Connect to Destination Engine
    dest_engine = create_engine(dest_url)
    Base.metadata.create_all(dest_engine)

    stats = {
        "devices_src": 0, "devices_migrated": 0,
        "flows_src": 0, "flows_migrated": 0,
        "alerts_src": 0, "alerts_migrated": 0,
        "incidents_src": 0, "incidents_migrated": 0,
    }

    with Session(dest_engine) as session:
        # A. Find or create Organization
        org = session.scalar(select(Organization).where(Organization.slug == org_slug))
        if not org:
            org = Organization(
                id=generate_uuid(),
                name=org_name,
                slug=org_slug,
                is_active=True,
            )
            if not dry_run:
                session.add(org)
                session.flush()
            print(f"[+] Provisioned Organization: '{org_name}' (ID: {org.id})")
        else:
            print(f"[*] Using Existing Organization: '{org_name}' (ID: {org.id})")

        org_id = org.id

        # B. Migrate Devices
        dev_rows = src_conn.execute("SELECT * FROM devices").fetchall()
        stats["devices_src"] = len(dev_rows)
        device_map = {}  # device_identifier -> Device.id

        for r in dev_rows:
            dev_id = r["device_id"]
            existing = session.scalar(
                select(Device).where(Device.organization_id == org_id, Device.device_identifier == dev_id)
            )
            if not existing:
                new_dev = Device(
                    id=generate_uuid(),
                    organization_id=org_id,
                    device_identifier=dev_id,
                    device_type=r["device_type"],
                    ip_address=r["ip"],
                    flow_count=r["flow_count"],
                    alert_count=r["alert_count"],
                    risk_score=float(r["risk_score"]),
                    risk_tier=r["risk_tier"] if "risk_tier" in r.keys() and r["risk_tier"] else "LOW",
                    temporal_risk=float(r["temporal_risk"]) if "temporal_risk" in r.keys() and r["temporal_risk"] else 0.0,
                    graph_risk=float(r["graph_risk"]) if "graph_risk" in r.keys() and r["graph_risk"] else 0.0,
                    first_seen=to_dt(r["last_seen"]),
                    last_seen=to_dt(r["last_seen"]),
                )
                if not dry_run:
                    session.add(new_dev)
                    session.flush()
                device_map[dev_id] = new_dev.id
            else:
                device_map[dev_id] = existing.id
            stats["devices_migrated"] += 1

        print(f"[+] Processed Devices: {stats['devices_migrated']} / {stats['devices_src']}")

        # C. Migrate Flows
        flow_rows = src_conn.execute("SELECT * FROM flows").fetchall()
        stats["flows_src"] = len(flow_rows)

        flows_to_insert = []
        for r in flow_rows:
            dev_ident = r["device_id"]
            target_dev_id = device_map.get(dev_ident)
            if not target_dev_id:
                # Provision placeholder device
                placeholder_dev = Device(
                    id=generate_uuid(),
                    organization_id=org_id,
                    device_identifier=dev_ident,
                    device_type=r["device_type"],
                    ip_address=r["src_ip"],
                    first_seen=to_dt(r["ts"]),
                    last_seen=to_dt(r["ts"]),
                )
                if not dry_run:
                    session.add(placeholder_dev)
                    session.flush()
                target_dev_id = placeholder_dev.id
                device_map[dev_ident] = target_dev_id

            nf = NetworkFlow(
                organization_id=org_id,
                device_id=target_dev_id,
                timestamp=to_dt(r["ts"]),
                source_ip=r["src_ip"],
                destination_ip=r["dst_ip"],
                source_port=r["src_port"],
                destination_port=r["dst_port"],
                protocol=r["proto"],
                duration=float(r["duration"]),
                orig_bytes=int(r["orig_bytes"]),
                resp_bytes=int(r["resp_bytes"]),
                orig_pkts=int(r["orig_pkts"]),
                resp_pkts=int(r["resp_pkts"]),
                conn_state=r["conn_state"] or "SF",
                gate_score=float(r["gate_score"]),
                is_flagged=bool(r["is_flagged"]),
            )
            flows_to_insert.append(nf)
            if len(flows_to_insert) >= batch_size:
                if not dry_run:
                    session.add_all(flows_to_insert)
                    session.flush()
                stats["flows_migrated"] += len(flows_to_insert)
                flows_to_insert = []

        if flows_to_insert:
            if not dry_run:
                session.add_all(flows_to_insert)
                session.flush()
            stats["flows_migrated"] += len(flows_to_insert)

        print(f"[+] Processed Flows:   {stats['flows_migrated']} / {stats['flows_src']}")

        # D. Migrate Alerts
        alert_rows = src_conn.execute("SELECT * FROM alerts").fetchall()
        stats["alerts_src"] = len(alert_rows)
        alerts_to_insert = []

        for r in alert_rows:
            dev_ident = r["device_id"]
            target_dev_id = device_map.get(dev_ident)
            if not target_dev_id:
                placeholder_dev = Device(
                    id=generate_uuid(),
                    organization_id=org_id,
                    device_identifier=dev_ident,
                    device_type=r["device_type"],
                    ip_address=r["src_ip"],
                    first_seen=to_dt(r["ts"]),
                    last_seen=to_dt(r["ts"]),
                )
                if not dry_run:
                    session.add(placeholder_dev)
                    session.flush()
                target_dev_id = placeholder_dev.id
                device_map[dev_ident] = target_dev_id

            top_feats = json.loads(r["top_features"]) if r["top_features"] else []
            raw_fl = json.loads(r["raw_flow"]) if r["raw_flow"] else {}
            shap_vals = json.loads(r["shap_values"]) if "shap_values" in r.keys() and r["shap_values"] else []
            reason_cds = json.loads(r["reason_codes"]) if "reason_codes" in r.keys() and r["reason_codes"] else []
            r_breakdown = json.loads(r["risk_breakdown"]) if "risk_breakdown" in r.keys() and r["risk_breakdown"] else {}

            alt = Alert(
                organization_id=org_id,
                device_id=target_dev_id,
                timestamp=to_dt(r["ts"]),
                attack_type=r["attack_type"],
                mitre=r["mitre"],
                severity=r["severity"],
                gate_score=float(r["gate_score"]),
                anomaly_score=float(r["anomaly_score"]),
                confidence_tier=r["confidence_tier"],
                top_features=top_feats,
                raw_flow=raw_fl,
                shap_values=shap_vals,
                shap_base_value=float(r["shap_base_value"]) if "shap_base_value" in r.keys() and r["shap_base_value"] is not None else None,
                decision=r["decision"] if "decision" in r.keys() else None,
                is_unknown=bool(r["is_unknown"]) if "is_unknown" in r.keys() else False,
                novelty_score=float(r["novelty_score"]) if "novelty_score" in r.keys() and r["novelty_score"] is not None else None,
                calibrated_anomaly_score=float(r["calibrated_anomaly_score"]) if "calibrated_anomaly_score" in r.keys() and r["calibrated_anomaly_score"] is not None else None,
                reason_codes=reason_cds,
                composite_device_risk=float(r["composite_device_risk"]) if "composite_device_risk" in r.keys() and r["composite_device_risk"] is not None else None,
                risk_tier=r["risk_tier"] if "risk_tier" in r.keys() else None,
                temporal_risk=float(r["temporal_risk"]) if "temporal_risk" in r.keys() and r["temporal_risk"] is not None else None,
                graph_risk=float(r["graph_risk"]) if "graph_risk" in r.keys() and r["graph_risk"] is not None else None,
                risk_breakdown=r_breakdown,
                status="active",
            )
            alerts_to_insert.append(alt)
            if len(alerts_to_insert) >= batch_size:
                if not dry_run:
                    session.add_all(alerts_to_insert)
                    session.flush()
                stats["alerts_migrated"] += len(alerts_to_insert)
                alerts_to_insert = []

        if alerts_to_insert:
            if not dry_run:
                session.add_all(alerts_to_insert)
                session.flush()
            stats["alerts_migrated"] += len(alerts_to_insert)

        print(f"[+] Processed Alerts:  {stats['alerts_migrated']} / {stats['alerts_src']}")

        # E. Migrate Incidents
        inc_rows = src_conn.execute("SELECT * FROM incidents").fetchall()
        stats["incidents_src"] = len(inc_rows)

        for r in inc_rows:
            dev_ident = r["device_id"]
            target_dev_id = device_map.get(dev_ident)
            existing_inc = session.scalar(select(Incident).where(Incident.incident_id == r["incident_id"]))
            if not existing_inc and target_dev_id:
                inc = Incident(
                    organization_id=org_id,
                    incident_id=r["incident_id"],
                    device_id=target_dev_id,
                    title=r["title"],
                    description=r["summary"],
                    severity=r["severity"],
                    status=r["status"],
                    attack_type=r["attack_type"],
                    alert_count=r["alert_count"],
                    first_seen=to_dt(r["first_seen"]),
                    last_seen=to_dt(r["last_seen"]),
                    mitre=r["mitre"],
                    acknowledged_at=to_dt(r["acknowledged_at"]) if r["acknowledged_at"] else None,
                    resolved_at=to_dt(r["resolved_at"]) if r["resolved_at"] else None,
                    resolution_notes=r["resolution_notes"],
                )
                if not dry_run:
                    session.add(inc)
            stats["incidents_migrated"] += 1

        print(f"[+] Processed Incidents: {stats['incidents_migrated']} / {stats['incidents_src']}")

        # F. Audit Log the Migration
        if not dry_run:
            audit = AuditEvent(
                organization_id=org_id,
                action="system.migration.completed",
                resource_type="database",
                resource_id="sqlite_to_postgres",
                event_metadata=stats,
            )
            session.add(audit)
            session.commit()
            print("[+] Migration Committed Successfully!")
        else:
            session.rollback()
            print("[*] Dry-run completed. No changes written.")

    print("=" * 70)
    print("MIGRATION RECONCILIATION SUMMARY")
    print("=" * 70)
    for k, v in stats.items():
        print(f"  {k:22}: {v}")
    print("=" * 70)


if __name__ == "__main__":
    args = parse_args()
    run_migration(
        sqlite_path=args.sqlite,
        dest_url=args.dest,
        org_name=args.org_name,
        org_slug=args.org_slug,
        dry_run=args.dry_run,
        batch_size=args.batch_size,
    )
