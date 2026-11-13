# Pahredaar-IoT — Enterprise Deployment & Operations Architecture

**Version:** Phase 6 Enterprise  
**Architecture:** Enterprise Multi-Tenant IoT Security Platform  

---

## 1. Deployment Topologies

Pahredaar-IoT supports two production deployment topologies:

### Topology 1: Standalone Gateway / Development Edge
Ideal for local prototyping, branch offices, smart homes, or isolated OT/ICS environments:
```
[IoT Devices: Cameras / Plugs / Sensors]
                 │
                 ▼
       [Local Router / Switch] (SPAN / Mirror Port)
                 │
                 ▼
       [Zeek Network Sensor]
                 │ (Pipe / JSON stream / X-Sensor-Key)
                 ▼
    [Pahredaar-IoT Edge Box]
    ├── Ingestion API (FastAPI)
    ├── Multi-Modal AI Engine (TreeSHAP + LSTM + Graph + Open-Set)
    ├── Local Database (SQLite + aiosqlite / WAL Mode)
    └── Dashboard UI (Port 4173)
```

### Topology 2: Distributed Multi-Tenant Enterprise Cluster
Ideal for enterprise campus networks, managed security service providers (MSSPs), and cloud SOCs:
```
[Subnet A Sensor] ──┐ (X-Sensor-Key: pds_...)
[Subnet B Sensor] ──┼──> [Pahredaar-IoT Ingestion & API Cluster]
[Subnet C Sensor] ──┘         │
                              ├── JWT / Role-Based Authorization
                              ├── Multi-Tenant Scoping (organization_id)
                              ├── Hybrid ML Evaluation
                              ├── Async Database Pool (PostgreSQL 16 + asyncpg)
                              └── Partitioned WebSocket Alert Broadcast to SOC Analysts
```

---

## 2. Docker Compose Enterprise Stack

A reference production `docker-compose.yml` configuration:

```yaml
version: '3.8'

services:
  db:
    image: postgres:16-alpine
    container_name: pahredaar-postgres
    restart: always
    environment:
      POSTGRES_USER: pahredaar_admin
      POSTGRES_PASSWORD: ${DB_PASSWORD:-secure_master_password}
      POSTGRES_DB: pahredaar_iot
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U pahredaar_admin -d pahredaar_iot"]
      interval: 5s
      timeout: 5s
      retries: 5

  backend:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: pahredaar-backend
    restart: always
    depends_on:
      db:
        condition: service_healthy
    environment:
      DATABASE_URL: postgresql+asyncpg://pahredaar_admin:${DB_PASSWORD:-secure_master_password}@db:5432/pahredaar_iot
      JWT_SECRET_KEY: ${JWT_SECRET_KEY}
      JWT_ALGORITHM: HS256
      ACCESS_TOKEN_EXPIRE_MINUTES: 15
      REFRESH_TOKEN_EXPIRE_DAYS: 7
      ENABLE_INGEST_AUTH: "true"
      SENSOR_RATE_LIMIT_PER_SEC: 100
    ports:
      - "8000:8000"

  frontend:
    image: node:20-alpine
    container_name: pahredaar-frontend
    working_dir: /app
    volumes:
      - ./frontend:/app
    command: sh -c "npm install && npm run build && npx serve -s dist -l 4173"
    ports:
      - "4173:4173"

volumes:
  pgdata:
```

---

## 3. Database Migration Procedures

### Running Schema Migrations (Alembic)
To upgrade schema to latest revision:
```bash
# Set target database URL
export DATABASE_URL="postgresql+asyncpg://pahredaar_admin:password@localhost:5432/pahredaar_iot"

# Apply migrations
alembic upgrade head
```

### Migrating Existing SQLite Database to PostgreSQL
To execute non-destructive data transfer with reconciliation:
```bash
# Dry run first to verify schema and row counts
python backend/scripts/migrate_sqlite_to_postgres.py --sqlite-path iot_ids.db --postgres-url postgresql+asyncpg://pahredaar_admin:password@localhost:5432/pahredaar_iot --dry-run

# Execute live migration with batch streaming
python backend/scripts/migrate_sqlite_to_postgres.py --sqlite-path iot_ids.db --postgres-url postgresql+asyncpg://pahredaar_admin:password@localhost:5432/pahredaar_iot --batch-size 1000
```

---

## 4. Production Security Hardening

1. **Secret Management:** Store `JWT_SECRET_KEY` and database credentials in HashiCorp Vault, AWS Secrets Manager, or Kubernetes Secrets.
2. **Explicit CORS:** Set `CORS_ORIGINS` to trusted domains (e.g., `["https://soc.enterprise.local"]`).
3. **Sensor Key Rotation:** Rotate edge sensor API keys quarterly via `POST /api/sensors/{id}/rotate-key`.
4. **Audit Log Retention:** Persist `/api/audit-logs` records to external SIEM (Splunk, Elastic, Datadog) for regulatory compliance (SOC2, ISO 27001).
