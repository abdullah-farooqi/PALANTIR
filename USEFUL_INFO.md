# PALANTIR — Core System Architecture & API Reference Guide (USEFUL_INFO.md)

This document consolidates and updates all verified architectural specifications, backend data contracts, collector capabilities, and operational rules from `SESSION_HANDOFF.md` and `BACKEND_UI_SCOPE_AND_LIMITATIONS.md`. All legacy references to Netdata have been eliminated in favor of the native PALANTIR Host Collector (`:20000`).

---

## 1. System Architecture Overview

PALANTIR operates on a distributed architecture separating the central management engine from remote host endpoints:

- **Central Master Server (`docker-compose.yml`)**:
  - **FastAPI Backend (`:8000`)**: Core REST API providing telemetry querying, alert management, dynamic threshold updates, and node registry.
  - **PostgreSQL 16 (`:5432`)**: Relational database with range-partitioned tables (`metric_snapshots` partitioned by day) and full-text search indexes (`log_events`).
  - **Redis 7 (`:6379`)**: Broker with append-only persistence (AOF) powering Celery async task distribution and health caching.
  - **Celery Workers & Beat**: 
    - `collect_all_nodes`: Polls telemetry from active endpoints every 60 seconds.
    - `evaluate_all_nodes`: Scans metrics against dynamic thresholds every 5 minutes.
    - `prune_old_snapshots`: Prunes metrics older than `METRICS_RETENTION_HOURS` (default 24h) and logs older than `LOG_RETENTION_DAYS` (default 7d).
    - `run_investigation`: Asynchronously collects deep evidence upon critical alert or anomaly triggers.
  - **Caddy Reverse Proxy (`:80 / :443`)**: Handles TLS, strips browser authorization headers, and injects role-based Bearer tokens.
  - **Authentik SSO**: Central identity management and role provider.

- **Remote Target Host (`agent/collector.py`, `:20000`)**:
  - Standalone lightweight Linux host collector deployed via `Automatic-Host-Setup.sh`.
  - Exposes zero-dependency JSON telemetry endpoints directly over HTTP port `20000`.

---

## 2. Host Collector Limits, Capabilities & Log Ingestion

### Collector Coverage & Limits
- **8 Core Categories**: `system`, `storage`, `network`, `services`, `processes`, `connections`, `containers`, `vms`.
- **Process Filtering**: Automatically filters idle background daemons with zero resource usage; ranks and persists top CPU and memory consumers.
- **Docker & Container Cap**: Capped at **500 container inventory entries** and concurrently samples live stats for at most **100 running containers**.
- **Virtualization & Sockets**: Enumerates libvirt/Proxmox VMs and TCP/UDP sockets by PID. CRI containerd and legacy LXC report as `unavailable` if not detected.
- **Namespaces**: Reading network namespace tables requires host namespace permissions; reports `permission_denied` gracefully when restricted.

### Log Ingestion Rules
- **Journald Initial Lookback**: On first contact with a node, systemd journal lookback is strictly bounded to **70 seconds**.
- **Application Files**: Custom watched log files begin tailing from the current end of the file upon initial discovery.
- **Safety**: Prevents unbounded historical log imports from overwhelming network bandwidth or exhausting PostgreSQL storage.

---

## 3. Node State & Reachability Rules

The backend differentiates administrative enablement from physical network reachability:

| Field | Meaning | Calculation / Threshold |
| :--- | :--- | :--- |
| `active` | Administrative polling flag | `true` = Celery workers will scrape; `false` = polling disabled. |
| `reachability` | Real-time network freshness | Computed from `datetime.now(utc) - last_seen_at`: |
| 🟢 `reachable` | Node is healthy and responding | Age $\le$ `NODE_REACHABLE_SECONDS` (default: **180s**) |
| 🟡 `stale` | Node delayed or missing polls | Age between **181s** and **900s** (`NODE_STALE_SECONDS`) |
| 🔴 `unreachable` | Node offline or connection dropped| Age > `NODE_STALE_SECONDS` (**900s**) |

*Note: A node marked `reachable` does not guarantee every single sub-category is populated; category freshness is tracked independently via `/api/v1/nodes/{id}/collection-status`.*

---

## 4. REST API Endpoint Reference

All endpoints (except `/healthz`) require role-scoped Bearer authentication (`read` or `admin`).

### A. Fleet & Node Management
- `GET /healthz`: Process-only health check.
- `GET /api/v1/fleet/summary`: Aggregate counts for enabled/reachability status, active alert tallies, 24-hour anomalies, and Celery worker beat heartbeats.
- `GET /api/v1/nodes`: Lists all monitored nodes (array).
- `GET /api/v1/nodes/search`: Cursor-paginated node search supporting filters for hostname (`q`), `os_type`, `reachability`, and `capability_key`.
- `GET /api/v1/nodes/{node_id}`: Returns complete metadata and URL for a single node.
- `POST /api/v1/nodes`: Registers or updates a node (`hostname`, `collector_url`, `os_type`). Requires `admin` or `enroll` token.
- `DELETE /api/v1/nodes/{node_id}`: Soft-deactivates a node (`active=false`). Requires `admin` token.

### B. Metrics & Telemetry
- `GET /api/v1/nodes/{node_id}/metrics`: Returns the latest telemetry snapshot for all 8 categories.
- `GET /api/v1/nodes/{node_id}/metrics/{category}/series`: Time-series query supporting:
  - Range bounding: `since` and `until` (rejects ranges older than `METRICS_RETENTION_HOURS`).
  - Pagination: Cursor-based with `limit` (default 250, max 1000).
  - Server-side aggregation: `bucket_seconds` aggregates numeric fields into avg/min/max.
- `GET /api/v1/nodes/{node_id}/collection-status`: Detailed diagnostic status for each category (`available`, `not_configured`, `unsupported`, `stale`, `collection_error`).
- `GET /api/v1/metrics/schema`: Versioned catalog of common snapshot envelopes and typed numeric fields.

### C. Alerts, Dynamic Thresholds & Anomalies
- `GET /api/v1/nodes/{node_id}/alerts/active`: Active non-clear alerts keyed by `(node, alert_name, chart)`.
- `GET /api/v1/events`: Consolidated fleet-wide feed of alert and anomaly events with keyset cursor pagination.
- `GET /api/v1/settings/thresholds`: Returns editable warning and critical alert thresholds (CPU %, RAM %, Disk %).
- `PUT /api/v1/settings/thresholds/{id}`: Live-updates alert thresholds in the database; instantly consumed by Celery workers.
- `GET /api/v1/nodes/{node_id}/anomalies`: Historical anomalous events detected by the anomaly engine.

### D. Structured Logs
- `GET /api/v1/logs`: Cross-node full-text log search backed by PostgreSQL full-text search. Supports filtering by `node_id`, `service`, `pid`, `severity`, and time range.

### E. Investigations
- `GET /api/v1/investigations/search`: Paginated list of automated and manual diagnostic investigations.
- `GET /api/v1/investigations/{id}`: Detailed evidence result for an investigation (`status`, `evidence_summary`, `top_processes`, `related_logs`, `metrics_snapshot`).
- `POST /api/v1/investigations`: Manually queues a diagnostic investigation for a node.

### F. Operations & Platform Health
- `GET /api/v1/health/operations`: Deep operational diagnostics reporting PostgreSQL connectivity, Redis latency, Celery worker heartbeat timestamps, task queue depth, and failure rates.

---

## 5. Automated Investigation Pipeline

When an alert status transitions to `WARNING` or `CRITICAL`, or when anomaly criteria are satisfied:
1. The event dispatcher enqueues a Celery job (`run_investigation`) into Redis.
2. The worker extracts high-density telemetry from the target node within a $\pm 5$-minute time window around the trigger.
3. The job compiles:
   - System resource snapshots and hardware utilization spikes.
   - Top CPU and memory consuming processes active during the event.
   - Correlated error and warning logs from `journald` and application logs.
4. Stores the structured payload in `agent_investigations` with an explicit `root_cause_inferred: false` flag.
5. This deterministic evidence bundle can be viewed directly in the UI or supplied to downstream LLM reasoning agents without schema alterations.

---

## 6. Security & Role Permissions Model

| Role Token | Header Injected | Permissions |
| :--- | :--- | :--- |
| **`read`** | `Authorization: Bearer <PALANTIR_API_READ_TOKEN>` | Read-only access to nodes, telemetry series, active alerts, logs, and investigation reports. |
| **`admin`** | `Authorization: Bearer <PALANTIR_API_ADMIN_TOKEN>` | Full management access: node registration, node deactivation, threshold editing, and manual investigation dispatch. |
| **`enroll`**| `Authorization: Bearer <PALANTIR_API_ENROLL_TOKEN>`| Restricted machine token: can ONLY perform initial node registration on `POST /api/v1/nodes`. Cannot read metrics or deactivate nodes. |

*Note: Tokens must be at least 32 characters, distinct, and kept strictly server-side (never exposed in client-side JavaScript bundle).*
