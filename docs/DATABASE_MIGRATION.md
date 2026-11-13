# Database Migration & Alembic Guide

**Project:** Pahredaar-IoT Enterprise Intrusion Detection Platform  
**Tooling:** Alembic & Dedicated SQLite-to-PostgreSQL Transfer Utility  

---

## 1. Alembic Migrations

Schema versioning is managed via Alembic located at `backend/alembic/`.

### 1.1 Configuration
- **Configuration file:** `alembic.ini`
- **Environment runner:** `backend/alembic/env.py`
- **Migration scripts:** `backend/alembic/versions/`

The environment runner dynamically resolves `DATABASE_URL` from the environment or `backend/app/config.py`, converting async connection strings into synchronous drivers required by Alembic DDL executors.

### 1.2 Commands

#### Generating a New Schema Migration
```bash
# Set target database URL and generate migration script
cmd /c "set DATABASE_URL=sqlite:///backend/app/iot_ids.db && py -3.14 -m alembic revision --autogenerate -m \"add_feature\""
```

#### Applying Migrations (Upgrade to Head)
```bash
py -3.14 -m alembic upgrade head
```

#### Reverting Migrations (Downgrade One Step)
```bash
py -3.14 -m alembic downgrade -1
```

---

## 2. SQLite-to-PostgreSQL Data Migration Utility

For upgrading an existing SQLite installation (`iot_ids.db`) to enterprise PostgreSQL without data loss, use `backend/scripts/migrate_sqlite_to_postgres.py`.

### 2.1 Capabilities
- **Non-destructive:** Operates read-only on the source SQLite database.
- **Tenant Initializer:** Automatically provisions a Default Organization (`default-org`) and maps legacy devices, flows, alerts, and incidents to it.
- **Foreign Key Preservation:** Preserves original device IDs, flow attributes, and incident identifiers (`INC-...`).
- **Dry-run Mode (`--dry-run`):** Inspects and validates records without modifying PostgreSQL.
- **Integrity Check:** Compares source and destination row counts and calculates record checksums.

### 2.2 Execution
```bash
# 1. Test migration with dry-run
py -3.14 backend/scripts/migrate_sqlite_to_postgres.py --sqlite backend/app/iot_ids.db --postgres postgresql+psycopg://user:pass@localhost:5432/pahredaar --dry-run

# 2. Execute migration
py -3.14 backend/scripts/migrate_sqlite_to_postgres.py --sqlite backend/app/iot_ids.db --postgres postgresql+psycopg://user:pass@localhost:5432/pahredaar
```
