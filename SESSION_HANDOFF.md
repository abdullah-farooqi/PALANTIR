# PALANTIR — Session Handoff

**Date:** 2026-10-02
**Project Path:** `/home/abdullah-ahmad/Desktop/PALANTIR`
**Reference:** `/home/abdullah-ahmad/Desktop/netdata/PALANTIR`
**Status:** **Implementation and documentation changes are uncommitted; verify `git status` before handoff.**

---

## 1. Current Architecture and Accomplishments

PALANTIR is a central FastAPI/Celery/PostgreSQL service that pulls telemetry
from one or more Netdata HTTP endpoints. Remote endpoints only need Netdata;
they do not run the PALANTIR database, Redis, or workers.

The current collection path is:
1. `NetdataClient` probes `/api/v1/info` for host labels/RAM and `/api/v3/info`
   for agent identity, hardware, capabilities, and context counts.
2. `/api/v3/data` is queried with explicit contexts, an explicit recent
   `after` window, `format=json2`, and `group_by=instance` where separation
   matters.
3. JSON2 rows are parsed as timestamp plus dimension values. Each dimension
   value is `[value, anomaly-rate, flags]`; the first item is the metric value.
4. The ingestion normalizer strips `@<machine-guid>` suffixes, removes idle
   zero/null process dimensions, and emits ranked `top_processes` arrays.
5. `metric_snapshots` stores cleaned JSONB plus nullable typed columns for CPU,
   RAM, load, swap, and top processes. It is range-partitioned by time.
6. Celery schedules collection, anomaly evaluation, and retention work. Alert
   definitions, current alerts, and alert transitions use separate endpoints.

Implemented in the current worktree:
- Netdata key normalization and active process extraction.
- JSON2 parsing with GUID removal and missing-value tolerance.
- Typed metric fields, migration-safe SQL, and query indexes.
- Host RAM discovery from v1 info/host labels with a v3 hardware fallback.
- v3 info, anomaly, current-alert, alert-transition, and alert-config calls.
- A semantic live verifier at `backend/scripts/verify_live.py`.
- Compose health gating so backend and Celery wait for a healthy Netdata API.

---

## 2. Node Inventory Guidance

Do not carry historical IPs, node IDs, context counts, or alert counts forward
as constants. Query the current registry and probe each endpoint because these
values are host-specific and can change between sessions.

---

## 3. Node Enrollment Scripts Guide

### A. Central Platform: `scripts/register-node.sh`
Run this script on the central server to register either the local host or any remote machine without manually writing JSON payloads:

```bash
# 1. Register the local central server:
./scripts/register-node.sh --local

# 2. Register a remote endpoint (automatically probes sensor & fetches real hostname):
./scripts/register-node.sh 192.168.18.50

# 3. Register a remote endpoint on a custom port or specify a custom hostname:
./scripts/register-node.sh --target 192.168.18.50 --port 19999 --hostname prod-worker-01

# 4. Point to a remote PALANTIR server:
./scripts/register-node.sh 192.168.18.50 --server http://192.168.18.43:8000
```

### B. Remote Agent: `scripts/install-agent.sh`
Run this one-liner on **any** remote Linux machine or VM (requires only Docker):

```bash
# Direct execution from GitHub or local copy:
./scripts/install-agent.sh http://<SYSADMIN_SERVER_IP>:8000

# Or via curl:
curl -fsSL https://raw.githubusercontent.com/abdullah-farooqi/PALANTIR/telemetry_pipeline/scripts/install-agent.sh | bash -s -- http://<SYSADMIN_SERVER_IP>:8000
```
*The installer automatically launches `abdullahahmadfarooqi/palantir-netdata:latest`, queries the kernel routing table to determine its IP facing `<SYSADMIN_SERVER_IP>`, verifies sensor readiness, and registers the node.*

---

## 4. Ingestion and Database Status

The three previously identified storage problems are now addressed in the
current implementation:

### 1. GUID Key Pollution (`@<machine-guid>`)
- **Observation:** Netdata v2/v3 appends the unique host machine GUID to all metric context labels (e.g. `system.cpu@a3d4921e-c907-4718-b308-9bbd71278e6d`, `mem.swap@a3d4921e...`, `app.firefox_mem_usage@a3d4921e...`).
- **Impact:** SQL queries cannot query standard keys like `data->>'system.cpu'`. Developers or analytical models must know the machine GUID or write fragile regex searches over JSONB keys.
- **Status:** `integrations/netdata/parsers.py` and the normalizer strip
  `@<guid>` suffixes at ingestion, standardizing keys such as `system.cpu`,
  `system.ram`, `system.load`, and `mem.swap`.

### 2. Excessive Noise & Sparse Zero-Padding
- **Observation:** In the `processes` category, Netdata dumps dimension entries for every known system daemon (over 150 entries per second), even when idle, resulting in dozens of `0.0` values (`app.agetty_fds_open: 0.0`, `app.tuned_cpu_utilization: 0.0`).
- **Impact:** PostgreSQL storage accumulates tens of thousands of rows of mostly zero-filled JSON blobs, causing rapid database bloat without providing operational signal.
- **Status:** `services/metrics.py` filters zero/null dimensions for inactive
  processes and sorts the remaining data into Top-N CPU and memory consumers.

### 3. Lack of Structured, Queryable Typed Fields
- **Status:** `metric_snapshots` now promotes `cpu_pct`, `ram_used_mb`,
  `ram_total_mb`, `load_avg`, and `swap_used_mb` to typed columns and stores
  `top_processes` as a structured JSON array. It retains cleaned `data` JSONB
  for compatibility. The SQL migration is safe to rerun against an existing
  database volume.
  - Example `top_processes` value:
    ```json
    "top_processes": [
      {"name": "firefox", "cpu_pct": 0.50, "mem_mb": 3656.9},
      {"name": "alacritty", "cpu_pct": 0.08, "mem_mb": 669.3}
    ]
    ```

---

## 5. API-v3 Rules That Must Not Regress

Netdata API-v3 is permissive and can return plausible but incorrect data for
bad requests. Treat these as integration invariants:

| Area | Correct request/interpretation | Silent failure |
|---|---|---|
| Data selection | `contexts=system.cpu,...` | `chart=` may be ignored and query all contexts |
| Fresh-agent window | `after=-60` or another explicit recent window | The default window can predate startup and return no rows |
| Per-instance data | `group_by=instance` for NICs, mounts, processes, containers | Missing grouping aggregates instances |
| Payload format | `format=json2` | Values are triples, not scalars |
| Response location | Read `.result.labels` and `.result.data` | Top-level `.data` gives false emptiness |
| Anomaly scores | `/api/v3/weights?...&method=anomaly-rate` | Other method names can select another calculation |
| Alert definitions | `/api/v1/alarms?all` | `/api/v1/alerts` is not the endpoint; bare `all` matters |
| Current alerts | POST `/api/v3/alerts` with an `options` array | A healthy host can return only `api`, `nodes`, and `timings` |
| Alert configuration | GET `/api/v3/alert_config?config=<hash>` | The configuration hash is required |
| Alert history | POST `/api/v3/alert_transitions` with `after` | Do not infer history from current firing alerts |

An empty current-alert result does not prove that health monitoring is down.
Confirm the envelope, v3 health capability, and (when needed) v1 alarm
definitions before reporting a health failure.

## 6. Next Steps

The normalizer and typed persistence path are implemented. Remaining work is
operational hardening and the planned investigation workflow:

### Phase 1: Autonomous Investigation Agent (LangGraph)
1. Wire `backend/workers/agent_tasks.py`:
   - Trigger LangGraph diagnostic workflows whenever an anomaly is flagged or an alert is received with `triggered_agent == True`.
   - Pass normalized metrics from the new structured schema into the prompt/context for root-cause analysis.
   - Write investigation results into the `agent_investigations` table.

### Phase 2: Database Retention & Performance
1. Implement metric aggregation (rollups) or snapshot pruning to keep database storage lightweight and performant.

---

## 7. Verification Commands Quick Reference

```bash
# Check running containers:
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Check enrolled nodes in database:
docker exec palantir-postgres psql -U palantir -d palantir -c \
  "SELECT id, hostname, netdata_url, active, context_count, alert_count FROM monitored_nodes ORDER BY id;"

# Check live snapshot counts per node:
docker exec palantir-postgres psql -U palantir -d palantir -c \
  "SELECT node_id, category, count(*), max(collected_at) FROM metric_snapshots GROUP BY node_id, category ORDER BY node_id;"

# Apply an idempotent schema migration to an existing database:
docker exec -i palantir-postgres psql -v ON_ERROR_STOP=1 \
  -U palantir -d palantir < sql/init.sql

# Verify a live Netdata endpoint:
NETDATA_URL=http://localhost:19999 \
  ./backend/venv/bin/python backend/scripts/verify_live.py

# Run the central platform registration utility:
./scripts/register-node.sh --help
./scripts/register-node.sh --local

# Stream live Celery worker ingestion logs:
docker logs --tail 30 -f palantir-celery-worker

# Run full backend test suite:
cd backend && ./venv/bin/pytest -q
docker exec palantir-backend pytest -q
```

The current suite contains 58 tests covering normalizer behavior, API
contracts, JSON2 parsing, typed persistence, security validation, workers, and
webhook handling. Record the exact pass count from the command output rather
than copying a historical count into future handoffs.

## 8. Live Host Facts Verified During This Session

The available local agent responded at `http://localhost:19999` with Netdata
`v2.11.1`, machine GUID `87f56850-57c0-43b7-a6e2-13c37aaaa009`, and 261
available v3 contexts. Host RAM was exposed in bytes through v3 hardware and
v1 `ram_total`/`_system_ram_total`. Current alerts returned the expected
`api`/`nodes`/`timings` envelope with no firing instances, and anomaly weights
echoed `method: anomaly-rate`.

These are observations of the current local host, not constants for remote
nodes. Always rerun the verifier for another endpoint.
