# PALANTIR — Session Handoff

**Date:** 2026-10-07
**Project Path:** `/home/abdullah-ahmad/Desktop/PALANTIR`
**Reference:** `/home/abdullah-ahmad/Desktop/netdata/PALANTIR`
**Status:** **A broad backend, deployment, and CI audit is in progress. The worktree contains uncommitted fixes; its CI run is pending.**

### Expanded Linux Agent Implementation and Validation Status

The monitored-host deployment now has a Compose design with Netdata on `19999`
and a PALANTIR collector on `20000`. The collector exposes category JSON and
structured systemd/application log events; the central worker polls both
endpoints. Existing nodes may continue registering only `netdata_url`.

Collector coverage currently includes system resources, disk/filesystem and
`/proc/mdstat` RAID state, interface/protocol counters, systemd services,
process memory/CPU time/OOM counters, TCP/UDP sockets by PID, Docker and LXD
containers, libvirt and Proxmox VMs, and Kubernetes pods when API credentials
are configured. Missing integrations are reported through the capabilities
endpoint and skipped. Docker inventory is capped at 500 entries and live stats
are gathered concurrently for at most 100 running containers. Firewall
enumeration may report permission denied when host namespace access is blocked.
Direct containerd CRI and legacy LXC adapters are not implemented yet; the
capabilities response identifies those rather than claiming they are collected.

Logs are read from journald plus configured files, parsed into JSON event
fields, and stored separately in `log_events`. On first poll, journald starts
with a 70-second lookback; file tails begin at the current end when first seen.
This avoids an unbounded historical import. Metric retention is configurable
with `METRICS_RETENTION_HOURS` (default 24); log retention uses
`LOG_RETENTION_DAYS` (default 7).

The collector Compose service mounts host `/`, `/proc`, `/sys`, `/run`, and
`/var/log` read-only. This exposes host file contents to the collector, and the
Docker socket permits Docker API actions despite the read-only mount. Keep the
published agent ports private and restrict them to the central server.

CI run `37347718534` passed the Python 3.11/3.12 suites, Docker stack smoke
checks, and backend tests at commit `8b221d0`; it published the backend,
Netdata, and host collector images. The current audit changes were made after
that run and still need their own CI result. Real DNS, Authentik login, LAN
firewall, and remote-host enrollment need deployment-specific validation.
`scripts/setup-central.sh` replays the idempotent `sql/init.sql` migration
before starting the API and workers, including when an existing database volume
is reused.

The LAN gateway is defined by the root `Caddyfile` and `docker-compose.yml`:
Caddy exposes `palantir.home.arpa` and `auth.palantir.home.arpa`, Authentik is
backed by a separate PostgreSQL volume, and Caddy injects read/admin/enrollment
tokens based on Authentik group headers after clearing browser-supplied identity
headers. A restricted enrollment token is accepted only on machine `POST
/api/v1/nodes` requests. Direct backend, PostgreSQL, Redis, and central Netdata
ports are bound to host loopback. Configure local DNS,
`PALANTIR_LAN_BIND_IP`, all required secrets, Authentik's initial administrator,
and the proxy application/groups before LAN access. Caddy's private root CA must
be trusted by client devices. A prior CI smoke started the Compose services but
did not validate real LAN DNS, Authentik login, or client certificate trust.
Those deployment-specific steps remain to be checked on the target network.

API tokens and the webhook secret must each be independently generated, at
least 32 characters, and distinct; no default webhook secret is accepted.
Manual Compose deployments can omit the enrollment token and register later
from the central host with `scripts/register-node.sh` and an admin token. The
guided `scripts/setup-agent.sh` flow expects the token so it can confirm
enrollment before reporting success.

---

## 1. Current Architecture and Accomplishments

PALANTIR is a central FastAPI/Celery/PostgreSQL service that pulls telemetry
from Netdata and optional PALANTIR host-collector HTTP endpoints. Remote
endpoints do not run the PALANTIR database, Redis, or central workers.

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

### Priority 1 backend UI gaps addressed

The Priority 1 scope and API contract are recorded in
[`BACKEND_UI_SCOPE_AND_LIMITATIONS.md`](BACKEND_UI_SCOPE_AND_LIMITATIONS.md).
The implementation adds:

- Node successful-contact and collection timestamps, plus derived
  `reachable`/`stale`/`unreachable` state. Defaults are 180 seconds for
  reachable and 900 seconds for stale; override with `NODE_REACHABLE_SECONDS`
  and `NODE_STALE_SECONDS`.
- `GET /api/v1/fleet/summary` for enabled and reachability counts, latest metric
  time, latest-transition active alert count, 24-hour anomaly summary, and
  database/API plus Celery collection/evaluation heartbeats. A task heartbeat
  measures pipeline activity and node-level failures, not per-category scrape success.
- `GET /api/v1/events` for filterable alert/anomaly rows with stable keyset
  pagination. Clients should reuse the same filters when following a cursor.
- `GET /api/v1/nodes/{node_id}/metrics/{category}/series` for retention-bounded
  ranges, source selection, cursor pages, raw timestamped snapshot envelopes,
  or source-grouped numeric buckets.
- `GET /api/v1/metrics/schema` and
  `GET /api/v1/nodes/{node_id}/collection-status` for schema version 1, stable
  typed field metadata, source-specific status, freshness, and safe error codes.

Snapshot retention defaults to 24 hours. Category staleness defaults to 180
seconds (`METRIC_STALE_SECONDS`). The series endpoint rejects ranges older than
retention or wider than the configured retention window. The schema documents
the common envelope and typed fields; arbitrary source JSON remains
collector-defined. The migration adds `last_collection_at`, status/heartbeat
tables and supporting indexes. Apply `sql/init.sql` before deploying updated
API/worker containers.

The earlier successful CI run exercised the Priority 1 code present at
`8b221d0`. The current audit fixes have not yet been tested; the pending CI run
will check the updated worktree.

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
PALANTIR_API_ADMIN_TOKEN='<CENTRAL_ADMIN_TOKEN>' \
  ./scripts/register-node.sh --local

# 2. Register a remote endpoint (automatically probes sensor & fetches real hostname):
PALANTIR_API_ADMIN_TOKEN='<CENTRAL_ADMIN_TOKEN>' \
  ./scripts/register-node.sh 192.168.18.50 --server http://127.0.0.1:8000

# 3. Register a remote endpoint on a custom port or specify a custom hostname:
PALANTIR_API_ADMIN_TOKEN='<CENTRAL_ADMIN_TOKEN>' \
  ./scripts/register-node.sh --target 192.168.18.50 --port 19999 \
    --hostname prod-worker-01 --server http://127.0.0.1:8000

```

### B. Remote Agent: `scripts/setup-agent.sh`
Copy the agent-only secrets file and public Caddy root CA certificate to the
remote host, then run this on a Linux host that has Docker and Compose:

```bash
sudo ./scripts/setup-agent.sh \
  --secrets-file /path/to/.env.agent-secrets \
  --ca-cert /path/to/caddy-root.crt
```
The setup script writes a mode-600 `.env.agent`, pulls the images, starts both
services, waits for health, and submits create-only enrollment. Do not pass
secret values as command-line arguments. The compatibility
`scripts/install-agent.sh` wrapper rejects secret flags and delegates to the
same secure setup flow. The central server requires separate read/admin API
tokens; Caddy injects them after Authentik login. Keep all API tokens out of
browser code. The proxy setup expects the UI to be same-origin; CORS
credentials remain disabled.

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

## 6. Remaining Work

Priority 2 and 3 changes now add fleet log search, durable Redis/Celery
investigation jobs, validated event ownership, a strict bounded result schema version 1,
investigation search, searchable node inventory, and operational health. Alert
and qualifying anomaly events enqueue a telemetry evidence summary; event links
are saved only after successful queue dispatch. This workflow does not call an
LLM or infer root cause. A future LangGraph diagnosis can replace the workflow
behind the same job/result contract if configured and reviewed.

The Redis service now uses append-only persistence. `scripts/setup-central.sh`
applies the expanded, idempotent `sql/init.sql` before starting API, worker, and
beat containers. The preceding successful CI run exercised these endpoints and
migrations at `8b221d0`. Changes from the current audit still need the pending
CI run; do not claim they are verified until it completes.

Metric and log pruning now use environment-configured retention; rollups remain
a future optimization once collection volume is measured.

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

The preceding Netdata-only baseline contained 58 tests. The expanded agent,
logs, and category API changes were added afterward; do not treat that earlier
pass count as validation of the current worktree. Record fresh results when
the user requests verification.

## 8. Live Host Facts Verified During This Session

The available local agent responded at `http://localhost:19999` with Netdata
`v2.11.1`, machine GUID `87f56850-57c0-43b7-a6e2-13c37aaaa009`, and 261
available v3 contexts. Host RAM was exposed in bytes through v3 hardware and
v1 `ram_total`/`_system_ram_total`. Current alerts returned the expected
`api`/`nodes`/`timings` envelope with no firing instances, and anomaly weights
echoed `method: anomaly-rate`.

These are observations of the current local host, not constants for remote
nodes. Always rerun the verifier for another endpoint.
