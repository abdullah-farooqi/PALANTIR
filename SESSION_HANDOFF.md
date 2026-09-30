# PALANTIR — Session Handoff & Knowledge Base

**Date:** 2026-09-30  
**Project Path:** `/home/abdullah-ahmad/Desktop/PALANTIR`  
**Status:** **Full Stack Live & Verified** (FastAPI, PostgreSQL 16, Redis 7, Celery Worker, Celery Beat running and healthy)

---

## 1. Executive Summary

In this session, we architected and implemented the core backend infrastructure and Netdata sensor integration for **PALANTIR** as an independent, standalone project at `/home/abdullah-ahmad/Desktop/PALANTIR`.

The architecture strictly follows a decoupled layered model:
- `api/` (FastAPI) imports only from `services/`
- `services/` imports only from `integrations/netdata/`
- `integrations/netdata/` is the **only** layer with knowledge of Netdata Agent API semantics and port 19999
- `workers/` (Celery) acts as a thin execution layer invoking `services/`
- `PostgreSQL` stores partitioned time-series metrics, anomaly events, and alert logs

All 5 core container services are live, healthy, and communicating over the Docker network. The REST API healthcheck returns `{"status":"ok","app":"PALANTIR"}`.

---

## 2. What Was Accomplished & Verified Live

### A. Netdata Integration Layer (`backend/integrations/netdata/`)
* **[`exceptions.py`](file:///home/abdullah-ahmad/Desktop/PALANTIR/backend/integrations/netdata/exceptions.py)**: Custom exceptions (`NetdataUnavailable`, `NetdataParseError`).
* **[`schemas.py`](file:///home/abdullah-ahmad/Desktop/PALANTIR/backend/integrations/netdata/schemas.py)**: Strict Pydantic response models (`NetdataDataResponse`, `NetdataWeightsResponse`, `NetdataInfoResponse`).
* **[`contexts.py`](file:///home/abdullah-ahmad/Desktop/PALANTIR/backend/integrations/netdata/contexts.py)**: Verified context string constants preventing silent 0-row queries (`net.net`, `system.cpu`, `mem.swap`, `app.cpu_utilization`, `cgroup.cpu`, etc.).
* **[`parsers.py`](file:///home/abdullah-ahmad/Desktop/PALANTIR/backend/integrations/netdata/parsers.py)**: 
  * `extract_value()`: Safely extracts scalar numbers from Netdata `json2` dimension triples (`[value, arp, pa]`).
  * `parse_rows()`: Normalizes multidimensional instance rows into flat dictionary records keyed by timestamp.
  * `parse_anomaly_rates()`: Extracts anomaly rate mapping while gracefully returning empty during the initial 900s ML warmup.
* **[`client.py`](file:///home/abdullah-ahmad/Desktop/PALANTIR/backend/integrations/netdata/client.py)**: Asynchronous `httpx` client implementing verified query parameters (`contexts=`, `after=-60`, `group_by=instance`, `format=json2`, `method=anomaly-rate`, and bare `?all` for alarms).

### B. Database Schema & Models (`sql/` & `backend/models/`)
* **[`sql/init.sql`](file:///home/abdullah-ahmad/Desktop/PALANTIR/sql/init.sql)**:
  * `monitored_nodes`: Node registry and discovered context/alert counts.
  * `metric_snapshots`: Rolling 24-hour metric buffer, range-partitioned by `collected_at`, with GIN index on `data` (JSONB).
  * `anomaly_events`: Anomaly threshold triggers.
  * `alert_events`: Webhook notifications.
  * `agent_investigations`: Dedicated table for LangGraph autonomous agent execution records.
* **[`backend/models/`](file:///home/abdullah-ahmad/Desktop/PALANTIR/backend/models)**: Complete SQLAlchemy 2.0 ORM models for all tables and relationships.

### C. Services Layer (`backend/services/`)
* **[`metrics.py`](file:///home/abdullah-ahmad/Desktop/PALANTIR/backend/services/metrics.py)**: Multi-category collectors (`collect_network`, `collect_system`, `collect_processes`, `collect_containers`) and resilient persistence in `collect_and_persist()`.
* **[`anomaly.py`](file:///home/abdullah-ahmad/Desktop/PALANTIR/backend/services/anomaly.py)**: Multi-context threshold evaluation (`>= 0.7`), requiring at least 2 simultaneous anomalies, with a 10-minute cooldown window to avoid repeated alerts.
* **[`alerts.py`](file:///home/abdullah-ahmad/Desktop/PALANTIR/backend/services/alerts.py)**: Webhook classifier logging alert states and triggering investigations on WARNING/CRITICAL.
* **[`nodes.py`](file:///home/abdullah-ahmad/Desktop/PALANTIR/backend/services/nodes.py)**: Node registration probing `/api/v1/info`, `/api/v1/contexts`, and `/api/v1/alarms?all`.

### D. Celery Asynchronous Workers (`backend/workers/`)
* **[`celery_app.py`](file:///home/abdullah-ahmad/Desktop/PALANTIR/backend/workers/celery_app.py)**: Beat schedule configured for:
  * 60s metric collection (`workers.metrics_tasks.collect_all_nodes`)
  * 5m anomaly scoring (`workers.anomaly_tasks.evaluate_all_nodes`)
  * Daily 3:00 AM snapshot pruning (`workers.maintenance_tasks.prune_old_snapshots`)

### E. FastAPI Application (`backend/api/v1/` & `backend/main.py`)
* **[`internal.py`](file:///home/abdullah-ahmad/Desktop/PALANTIR/backend/api/v1/internal.py)**: `POST /internal/alert` authenticated via `X-PALANTIR-Secret`.
* **[`nodes.py`](file:///home/abdullah-ahmad/Desktop/PALANTIR/backend/api/v1/nodes.py)**: CRUD endpoints for monitored hosts.
* **[`metrics.py`](file:///home/abdullah-ahmad/Desktop/PALANTIR/backend/api/v1/metrics.py)**: Latest snapshots across all or specific categories.
* **[`alerts.py`](file:///home/abdullah-ahmad/Desktop/PALANTIR/backend/api/v1/alerts.py)**: Active alarms and historical event logs.
* **[`investigations.py`](file:///home/abdullah-ahmad/Desktop/PALANTIR/backend/api/v1/investigations.py)**: Investigation history and manual triggering.

### F. Netdata Node Configuration Assets (`services/netdata/`)
* **[`health_alarm_notify.conf`](file:///home/abdullah-ahmad/Desktop/PALANTIR/services/netdata/health_alarm_notify.conf)**: Shell integration pushing alerts via curl to `/internal/alert`.
* **[`health.d/palantir.conf`](file:///home/abdullah-ahmad/Desktop/PALANTIR/services/netdata/health.d/palantir.conf)**: Custom alerts with verified explicit `calc:` lines (preventing false critical alerts from dimension sum defaults).

### G. Deployment, Live Containers & Test Verification
* **CI/CD Pipeline**: [`.github/workflows/ci.yml`](file:///home/abdullah-ahmad/Desktop/PALANTIR/.github/workflows/ci.yml) (Automated multi-version Python testing matrix 3.11/3.12, Docker Compose stack build, and live container smoke test).
* **Unit Tests**: [`backend/tests/test_netdata.py`](file:///home/abdullah-ahmad/Desktop/PALANTIR/backend/tests/test_netdata.py) executed via pytest: **10/10 passed in 0.14s**.
* **Container Stack**: `docker compose up -d` running live:
  * `palantir-postgres`: `postgres:16-alpine` (Healthy)
  * `palantir-redis`: `redis:7-alpine` (Healthy)
  * `palantir-backend`: `palantir-backend:latest` (Started / Up, responding on port 8000)
  * `palantir-celery-worker`: `palantir-celery-worker:latest` (Started / Up)
  * `palantir-celery-beat`: `palantir-celery-beat:latest` (Started / Up)
* **Live Healthcheck Verified**:
  `curl -s http://localhost:8000/healthz` -> `{"status":"ok","app":"PALANTIR"}`
* **End-to-End Test Suite Verified Live**:
  1. *Schema Integrity*: Verified all 6 tables in PostgreSQL (`agent_investigations`, `alert_events`, `anomaly_events`, `metric_snapshots`, `metric_snapshots_default`, `monitored_nodes`) with range partitioning on `collected_at`.
  2. *Security Gate*: Validated `POST /internal/alert` rejects wrong secrets with HTTP 403 Forbidden.
  3. *Unregistered Node Guard*: Safely ignores webhooks for hosts not yet in `monitored_nodes`.
  4. *Push Webhook Ingestion*: Ingested critical alarm payload for `prod-app-01`, created `alert_events` record ID 1 with `triggered_agent: true`.
  5. *Alert Querying*: Verified `GET /api/v1/nodes/1/alerts/active` correctly retrieves WARNING/CRITICAL events.
  6. *Investigation Engine*: Verified `POST /api/v1/investigations` creates running investigation records retrievable via `GET /api/v1/investigations`.
  7. *Celery Scheduling & Error Resilience*: Verified Celery Beat dispatches `collect-metrics-60s` and `collect-anomaly-5min`, and Celery Worker gracefully logs offline Netdata nodes without task failure.

---

## 3. Difficulties Encountered & Solutions

| Challenge / Difficulty | Impact | How We Resolved It |
|---|---|---|
| **Workspace Pollution vs. Standalone Location** | The initial environment was inside `/home/abdullah-ahmad/Desktop/netdata (2)`, which is the upstream Netdata C/Go repo. Putting PALANTIR inside would mix git histories and pollute git status. | Consulted the user with numbered options and pros/cons. Decided on a clean standalone path: `/home/abdullah-ahmad/Desktop/PALANTIR`. |
| **User Command Execution Constraint** | The user specifically requested: *"if you want to run a command give me the command and i would run them"*. | The assistant ceased direct shell execution, created all necessary code and configuration files via file tools, and provided exact, copy-pasteable terminal commands for the user. |
| **Silent API Failures in Netdata** | Netdata returns HTTP 200 with empty or incorrect data for subtle mistakes: using `?chart=` instead of `?contexts=`, omitting `?after=-60`, omitting `group_by=instance`, passing `?all=1` instead of bare `?all`, or requesting wrong context names like `net.eth0` instead of `net.net`. | Enforced verified constants in [`contexts.py`](file:///home/abdullah-ahmad/Desktop/PALANTIR/backend/integrations/netdata/contexts.py) and hardcoded correct query parameter combinations in [`client.py`](file:///home/abdullah-ahmad/Desktop/PALANTIR/backend/integrations/netdata/client.py). |
| **Dimension Values as Triples** | Netdata `json2` returns dimension values as arrays `[val, arp, pa]` rather than scalar numbers. Blindly casting or treating them as floats raises runtime TypeError. | Implemented `extract_value()` in [`parsers.py`](file:///home/abdullah-ahmad/Desktop/PALANTIR/backend/integrations/netdata/parsers.py) to reliably pull index 0. |
| **ML Engine 900-Second Warmup** | Freshly started Netdata instances return 0 or empty anomaly rates for the first 15 minutes. Treating this as a failure breaks collection. | Implemented `parse_anomaly_rates()` to treat missing/empty data as expected warmup and safely skip anomaly evaluations without logging errors. |
| **Health Alert Dimension Summing** | Netdata alerts without an explicit `calc:` line default `$this` to the sum of all raw dimension units (e.g. bytes), resulting in permanent CRITICAL false alarms. | Authored [`palantir.conf`](file:///home/abdullah-ahmad/Desktop/PALANTIR/services/netdata/health.d/palantir.conf) with verified explicit `calc:` expressions for CPU, RAM, drops, and errors. |
| **SQLAlchemy Asyncio Missing `greenlet` in Container** | Container crashed with `ModuleNotFoundError: No module named 'greenlet'` when importing `sqlalchemy.ext.asyncio`. | Added `sqlalchemy[asyncio]` and `greenlet>=3.0.3` to `backend/requirements.txt` and added `backend/.dockerignore` to exclude the 145MB local venv from image builds. |
| **SQLAlchemy 2.0 Sync Driver `psycopg` vs `psycopg2`** | `create_engine("postgresql://...")` in SQLAlchemy 2.0 defaults to psycopg v3, failing with `ModuleNotFoundError: No module named 'psycopg'`. | Added `psycopg[binary]>=3.1.18` to `requirements.txt` and set `SYNC_DATABASE_URL` explicitly to `postgresql+psycopg://...`. |
| **Pre-existing Docker Volume Schema Drift** | Old PostgreSQL volume from prior experiments had outdated column names (`added_at` vs `registered_at`, `triggered_at` vs `received_at`), causing table creation to skip. | Reset volume via `docker compose down -v` so `sql/init.sql` cleanly created all tables and range partitions on startup. |
| **Docker BuildKit PyPI / Network Timeouts** | Docker BuildKit experienced DNS / TLS handshake timeouts during `pip install` and image manifest pulls. | Configured `network: host` in `docker-compose.yml` build blocks and added `--retries 5 --timeout 60` to `pip install` in `backend/Dockerfile`. |

---

## 4. Instructions for Incoming Agents / Future Sessions

When resuming work on this repository:

1. **Working Directory:** All code resides at `/home/abdullah-ahmad/Desktop/PALANTIR`.
2. **Local Test Execution:**
   ```bash
   cd /home/abdullah-ahmad/Desktop/PALANTIR/backend
   source venv/bin/activate  # (create via `python3 -m venv venv` if not present)
   pip install -r requirements.txt
   pytest -v
   ```
3. **Stack Management:**
   ```bash
   cd /home/abdullah-ahmad/Desktop/PALANTIR
   docker compose ps
   docker compose logs -f backend celery_worker
   ```
4. **Planned Next Steps:**
   - **Step 1: Connect Live Netdata Node**: Register a running Netdata sensor via `POST /api/v1/nodes` and verify Celery 60-second snapshot collection in PostgreSQL.
   - **Step 2: LangGraph Autonomous Investigation Agent**: Implement `workers/agent_tasks.py` and hook into `AnomalyService` and `AlertService` to execute investigative reasoning graphs.
   - **Step 3: React Frontend Dashboard**: Scaffold `frontend/` (Vite + React + Tailwind) to consume `/api/v1/nodes`, `/api/v1/metrics`, and `/api/v1/alerts`.
