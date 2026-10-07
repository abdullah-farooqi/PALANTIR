# PALANTIR Backend: Current UI Scope and Limitations

**Purpose:** describe what a first PALANTIR React UI can reliably display from the backend as it exists today, identify behavior that could be misrepresented by UI labels, and list backend improvements that would support the current product scope.

**Scope reviewed:** fleet and node overview, node detail and telemetry, alerts, anomalies, structured logs, investigations, and the API access needed by those screens. This is a source-code review of the checked-out backend, agent, proxy, and deployment configuration. It is not a live-stack verification.

**Validation note (2026-10-07):** CI run `37347718534` passed the Python
3.11/3.12 unit suites and Docker stack smoke/backend tests at commit `8b221d0`.
The follow-up backend, deployment, and CI audit changes are newer than that run
and need a fresh CI result before they can be called verified.

## 1. Current system behavior

PALANTIR currently has a FastAPI API under `/api/v1`, a PostgreSQL store, Redis/Celery workers, a Netdata agent, and an optional PALANTIR host collector. Celery schedules metric collection every 60 seconds, anomaly evaluation every five minutes, and daily retention cleanup. The React UI will be a new client of these APIs; there is no frontend API/BFF layer in the current backend.

The main data flows are:

1. Active nodes are polled by the metrics worker. Netdata metrics are stored as `MetricSnapshot` rows. When a host collector URL is configured, its categories and log events are collected as well.
2. A Netdata webhook posts alert events to `/internal/alert`; the backend validates the shared webhook secret and persists the event.
3. The anomaly worker queries a small fixed set of Netdata anomaly rates, applies configured thresholds, and records qualifying events.
4. The public API returns node records, snapshots, alert/anomaly event rows, logs, and investigation records.

Relevant implementation references include [`backend/main.py`](backend/main.py), [`backend/workers/celery_app.py`](backend/workers/celery_app.py), [`backend/workers/metrics_tasks.py`](backend/workers/metrics_tasks.py), [`backend/workers/anomaly_tasks.py`](backend/workers/anomaly_tasks.py), and [`backend/services/metrics.py`](backend/services/metrics.py).

## 2. What the UI can display now

| UI area | Existing data and endpoints | What can be shown now | Current qualification |
|---|---|---|---|
| Service status | `GET /healthz` | Whether the API health endpoint responds | This is an API process health check; it does not report database, worker, Redis, or node health. |
| Node inventory | `GET /api/v1/nodes?active_only=true` | Hostname, ID, OS type, enabled flag, Netdata/collector URLs, capabilities, discovered context/alert counts, last successful contact and collection timestamps, and derived reachability | `active` means enabled for polling. Reachability is based on successful contact age and configurable thresholds; it is not a promise that every category is fresh. |
| Node record | `GET /api/v1/nodes/{node_id}` | Same record for one node | Inactive nodes can still be fetched by ID. No endpoint reports a live online/offline state. |
| Collector capabilities | `GET /api/v1/nodes/{node_id}/capabilities` | Collector URL and capability/status JSON | Values may be unavailable, not configured, or stale; they are not a complete per-metric freshness report. |
| Latest telemetry | `GET /api/v1/nodes/{node_id}/metrics` | Latest stored record for each of eight named categories, common typed system fields, and a `sources` grouping | The response has a fixed category list. A null latest value does not distinguish unsupported, not collected, failed, or empty. |
| Category history | `GET /api/v1/nodes/{node_id}/metrics/{category}/series` | Retention-bounded raw timestamped envelopes or server-side numeric time buckets; supports time range, source, cursor, and page size | Raw pages default to 250 and cap at 1,000. Aggregation covers typed numeric fields and groups by source. The legacy category route remains available with its 100-row cap. |
| Alert event history | `GET /api/v1/nodes/{node_id}/alerts?limit=N` | Recent alert transitions/events with received time, name, chart, status, value, and units | This is per-node event history, not an alert lifecycle object with acknowledgement, owner, or resolution metadata. |
| Active alerts | `GET /api/v1/nodes/{node_id}/alerts/active` | The latest WARNING or CRITICAL transition for each alert identity | Current state is derived from the newest event keyed by node, alert name, and chart. The webhook does not provide a separate stable alert ID, so this identity can collide if a node reuses the same name/chart pair. |
| Anomaly events | `GET /api/v1/nodes/{node_id}/anomalies?limit=N` | Recorded event time, anomalous contexts, scores, and maximum score | Only threshold-qualified events are persisted; the API does not expose all evaluated scores or a continuous anomaly history. |
| Fleet summary and events | `GET /api/v1/fleet/summary`, `GET /api/v1/events` | Node reachability counts, current active-alert count, recent anomalies, API/database/task health, and a filterable fleet event feed | Event pagination is keyset-based and stable for an unchanged filter set. Worker heartbeats show scheduled pipeline execution, not successful polling of each node. |
| Metric schema | `GET /api/v1/metrics/schema` | Versioned categories, common snapshot envelope, typed fields, units, labels, and source support | Collector-specific JSON keys outside the typed fields remain source-defined; clients should tolerate absent keys. |
| Category collection state | `GET /api/v1/nodes/{node_id}/collection-status` | Per-category and per-source status, last attempt/success, safe error codes/messages, and staleness | `stale` is computed from the most recent success and configured age threshold. Unsupported Netdata categories remain explicitly marked. |
| Fleet logs | `GET /api/v1/logs` | Cross-node full-text message search, node/service/PID/source/severity/time filters, event fields, and stable cursor pagination | Uses PostgreSQL simple-language full-text matching; results are bounded to 500 per page and log retention. |
| Investigations | `GET /api/v1/investigations/search`, `GET /api/v1/investigations/{id}` | Filtered keyset pages and queued/running/complete/failed status, job ID, progress, queue delay, result schema, and safe failure details | The current workflow is a bounded telemetry evidence summary; it does not infer a root cause or invoke an LLM. |
| Create investigation | `POST /api/v1/investigations` | Admins can queue manual jobs or jobs tied to an alert/anomaly event | Jobs use the Redis-backed Celery queue. Dispatch failure is persisted and returned as HTTP 503 with its investigation ID. WARNING/CRITICAL alerts and qualifying anomaly events enqueue automatically. |
| Node inventory search | `GET /api/v1/nodes/search` | Searchable cursor pages with enabled, OS, reachability, top-level capability, and per-source category-status filters | The original list route remains available; search pages cap at 500 and use hostname keyset ordering. |
| Operational health | `GET /api/v1/health/operations` | Database/Redis checks, Celery worker ping, beat-dispatch heartbeat, queue depth, task duration/failure rates, and investigation queue delay | Queue delay is measured for investigation jobs; `GET /healthz` remains a process-only check. |
| Node enrollment | `POST /api/v1/nodes` | UI can submit hostname, Netdata URL, optional collector URL, and OS type | Registration probes the endpoints synchronously and can return 400, 422, 502, or 500. There is no edit endpoint. |
| Node deactivation | `DELETE /api/v1/nodes/{id}` | UI can deactivate a node | This is a soft deactivation. The node and its historical data remain; the API returns no content. |

The category names accepted by the metrics API are `network`, `system`, `storage`, `services`, `processes`, `connections`, `containers`, and `vms`. Data availability is node-specific and depends on whether the optional collector is configured and whether its host integrations work.

## 3. Backend limitations and UI impact

### 3.1 Fleet and node state

1. **Reachability is derived from successful contact age.** Node responses expose `last_seen_at`, `last_collection_at`, and `reachability`; `active` still only means enabled for polling. Thresholds default to reachable within 180 seconds and stale within 900 seconds. Category freshness is reported separately.
2. **Legacy inventory listing remains unpaged.** The original `/nodes` list preserves its array contract. Use `/nodes/search` for hostname query, OS/enabled/reachability and capability filters, per-source category-status filters, stable cursor paging, and `has_more`.
3. **Registration metadata can age.** `context_count` and `alert_count` are discovered during registration/re-registration, not continuously refreshed by ordinary polling. They should not be displayed as live counts without that caveat.
4. **Fleet summary is intentionally aggregate.** `/api/v1/fleet/summary` reports enabled/reachability counts, the latest metric time, active alerts using latest-transition semantics, anomaly events from the prior 24 hours, and API/database/worker-task health. Use `/api/v1/events` for the event rows. Worker status records task execution and node-level failures; it does not certify that every node or category collection succeeded.
5. **No node edit or reactivation endpoint.** A node can be registered and deactivated. Re-registering the same hostname updates/reactivates the existing row, but there is no dedicated edit/reactivate operation for a management UI.

### 3.2 Metrics and telemetry

1. **Raw JSON is the main contract for many metrics.** `MetricSnapshot.data` is flexible JSONB and differs by collector/category. Only a small set of system fields is promoted into typed columns. Host-agent snapshots are stored without filling those typed columns. The UI needs category-specific parsers and must tolerate absent keys and schema variation.
2. **Latest endpoint collapses source and time information.** `/metrics` returns one newest `data` value per hard-coded category and a `sources` grouping assembled from up to 200 records. It is not a normalized time-series contract with a timestamped series per source. The UI should use category history for a chart and use each snapshot's own `collected_at`.
3. **Use the new range endpoint for history.** Metric retention defaults to 24 hours. The `/series` endpoint accepts timezone-aware `since`/`until`, source, a stable cursor and limit up to 1,000, and rejects windows that exceed configured retention. `bucket_seconds` enables server-side aggregation for numeric typed fields (average/minimum/maximum), grouped by source. The response includes the requested window and retention cutoff. The legacy route still caps at 100 snapshots.
4. **Category outcomes are source-specific.** `/collection-status` reports `available`, `not_configured`, `unsupported`, `collection_error`, `unknown`, or derived `stale`, with last attempt/success and safe error details. A successful empty collection is `available`; it does not mean the category contains non-empty rows.
5. **Freshness remains best-effort.** Workers are scheduled every 60 seconds, but node/category requests can fail or lag. Reachability and per-category staleness expose age thresholds, and worker heartbeats expose task completion/partial failure. Neither guarantees that every node was collected in the latest cycle.
6. **The catalog describes stable fields, not every raw collector key.** `/api/v1/metrics/schema` versions the common envelope and typed fields with units and labels. Category JSON outside typed fields remains collector-defined; the UI must tolerate absent or additional keys.

### 3.3 Alerts and anomalies

1. **Alert identity relies on webhook labels.** The active endpoint now derives state from the newest transition for each node + alert name + chart key, so a later CLEAR removes an alert from the active list. Netdata's webhook payload does not expose a stable alert ID here; two distinct alerts that reuse the same name/chart pair could be combined. Add a source alert ID if Netdata provides one before relying on lifecycle identity across such configurations.
2. **Fleet events have shared filters and stable paging.** `GET /api/v1/events` supports event type, node, alert severity, anomaly minimum score, time range, and keyset cursor pagination. Alert-name filtering, acknowledgement, assignment, and explicit resolution endpoints are not provided.
3. **Agent dispatch is not implemented.** Alert and anomaly ingestion no longer marks events as agent-triggered, and the public event responses omit the legacy `triggered_agent` flag. Existing database values may contain the old placeholder `true`; they are not evidence that an agent ran.
4. **Anomaly coverage is narrow and thresholded.** The evaluator checks a fixed set of five contexts, runs every five minutes, and only persists an event when at least two context rates meet the configured threshold. Lower scores and other contexts are not exposed by the API. There is no per-node anomaly configuration or API for the current rates.
5. **Cooldown and event semantics are not visible.** The anomaly path uses the cooldown setting to suppress qualifying events, but the API does not expose suppression reason, thresholds used, next eligible time, or evaluation status. A missing anomaly row is not proof that the node was evaluated and healthy.
6. **Alert event time fidelity is limited.** The webhook payload accepts a timestamp, while the alert model/API display `received_at`. The stored schema does not expose a distinct source event time in the alert response. The UI can reliably show receipt time, not necessarily the time Netdata says the transition occurred.

### 3.4 Logs

1. **The fleet log API uses full-text message matching.** `GET /api/v1/logs` searches across nodes and filters by node, service, PID, source, severity, and time. It returns stable keyset pages with `has_more`; it does not return a total count.
2. **Legacy node logs retain offset paging.** `/nodes/{node_id}/logs` remains available for compatibility and has no text, service, PID, or cursor filters. Use the fleet route for new UI work.
3. **Retention is short by default.** Log retention defaults to seven days. The UI cannot retrieve older data after the pruning task removes it.
4. **Log-source health is not tracked separately.** Category status is durable for the eight metric categories, but log ingestion has no source-specific last-success/error record. An empty log search can mean no events or no functioning log source.

### 3.5 Investigations

1. **Investigation work is queued durably.** Manual POST requests and WARNING/CRITICAL alert or qualifying anomaly events enqueue Celery jobs through Redis. The database stores job ID, queued/start/complete timestamps, progress, queue delay, terminal state, and safe failure reason. Queue dispatch failure is persisted and the event remains unlinked.
2. **Trigger references are checked before dispatch.** Alert/anomaly requests require an existing event owned by the requested node; manual requests cannot supply a trigger ID. Event rows are linked only after the broker accepts the job.
3. **The current workflow summarizes evidence.** Its version 1 result is bounded and typed, with latest metric groups, active alert summaries, recent anomalies, trigger details, and an explicit `root_cause_inferred: false`. It does not invoke an LLM or claim root-cause diagnosis.
4. **Investigation search supports stable paging.** `/investigations/search` filters by node, status, trigger type, and time range and uses a keyset cursor. The original limited list route remains for compatibility.
5. **Cancellation and retry controls are not exposed.** Failed jobs have a terminal state and safe error code/message; operators can issue a new investigation request when needed.

### 3.6 API security and operational integration

1. **API tokens must be provisioned and kept server-side.** `/api/v1` requires a Bearer token: read tokens allow read routes, admin tokens allow management operations, and an optional enrollment token can create nodes or repeat an identical enrollment but cannot modify or reactivate one. The LAN deployment includes Caddy with Authentik forward authentication; Caddy strips browser-supplied authorization/identity headers and injects the role token. A machine enrollment token is accepted only for `POST /api/v1/nodes`. Registration probes the supplied Netdata and collector URLs, including private LAN addresses needed for monitoring; an enrollment-token holder can therefore cause central-side requests to reachable URLs. Give this token only to trusted host administrators. Backend port 8000, PostgreSQL, Redis, and central Netdata are bound to host loopback. Do not embed shared tokens in browser JavaScript. `/healthz` remains a process health endpoint, and `/internal/alert` uses its webhook secret.
2. **CORS is explicit and disabled by default.** Set `CORS_ALLOWED_ORIGINS` to explicit origins only when needed. Credentials are not enabled; the Authentik proxy setup expects a same-origin UI, so its CORS setting can remain empty.
3. **Operational health is separate from process health.** `/healthz` remains a simple process check. `/api/v1/health/operations` reports database and Redis checks, Celery worker ping, scheduled beat-dispatch heartbeat, queue depth, task duration/failure rates, and investigation queue delay. Node/category timestamps remain the source for scrape freshness.
4. **Polling remains the delivery contract.** Summary, cursor, and time-window endpoints support polling. No evidence currently shows that polling is inadequate, so SSE/WebSocket is deferred until UI load or update-latency measurements justify it.
5. **Node endpoint URLs are included in the node response.** Netdata and collector URLs are visible to read-role clients behind the trusted proxy. Keep the UI same-origin and do not use these values for browser-side connections; consider redacting them if read-role users should not learn internal addresses.

## 4. Safe UI behavior with the current backend

Until the backend gaps are addressed, the UI should:

- Label `active` as **Enabled** or **Polling enabled**, not Online. Use `reachability` for reachable/stale/unreachable node state.
- Display `last_collection_at` and each category's `last_success_at`; use the returned status/error code to explain stale, unsupported, not-configured, and collection-error states.
- Distinguish a successful empty collection from no successful collection; `available` can have no data rows for the selected window.
- Show `sources` and collector capability statuses where present; do not assume every node has every category.
- Use the series endpoint for charts, preserve the exact filters when following its cursor, and display its window/retention metadata and aggregation method.
- Use `/api/v1/events` for fleet event history and the per-node active route for latest non-clear state per node/alert-name/chart key.
- Show anomaly rows as recorded threshold events. Do not show absent rows as “No anomalies detected” unless an evaluation-success signal is added.
- Use `GET /api/v1/logs` for fleet log search and preserve filters while following its cursor; the legacy per-node log route remains offset-paged.
- Show investigation job status, progress, queue delay, safe failure details, and the bounded evidence result. Treat the result as collected evidence, not an inferred root cause.
- Use `/api/v1/nodes/search` and `/api/v1/health/operations` for large inventory and operational health screens.
- Authenticate API calls through the Authentik-protected same-origin proxy. Give browser users read access by default and route management actions through admin authorization; never ship API tokens in the React bundle.
- Keep node enrollment tokens separate from admin tokens. The optional enrollment token can create nodes and safely repeat an identical enrollment, but cannot read data, modify existing nodes, or deactivate nodes.

## 5. Backend strengthening plan for this UI scope

### Priority 0 — prevent misleading or unsafe UI states

1. **Implemented:** require distinct role-scoped Bearer tokens of at least 32 characters for `/api/v1`; admin protects node deactivation and investigation requests, while node registration can use admin or an optional create-only enrollment token. The LAN stack now includes Caddy + Authentik, injects server-held tokens by Authentik group, and binds direct backend access to loopback. The webhook secret has no insecure built-in default and must also be configured with at least 32 characters.
2. **Implemented:** restrict CORS with explicit `CORS_ALLOWED_ORIGINS`; credentials are disabled.
3. **Implemented:** do not mark events as agent-triggered before dispatch; clear legacy placeholder flags during the SQL migration and omit the legacy field from public responses. A real dispatch outcome still requires a worker implementation.
4. **Implemented:** derive active state from the latest transition by node + alert name + chart, which acts as the alert key. Use a source alert ID instead if the webhook begins providing one.
5. **Implemented:** the API validates trigger ownership and persists a queued job before dispatch; failed broker submissions become explicit failed rows. This replaces the earlier 503-without-record behavior.

### Priority 1 — make overview and detail screens reliable

1. **Implemented:** node responses expose `last_seen_at`, `last_collection_at`, and derived reachability. Successful Netdata or host-collector contact updates last-seen; every completed collection attempt updates last-collection. Reachable/stale thresholds default to 180/900 seconds.
2. **Implemented:** `GET /api/v1/fleet/summary` returns enabled/reachability counts, latest metric time, latest-transition active alert count, 24-hour anomaly count/latest five, and API/database plus collection/evaluation task health.
3. **Implemented:** `GET /api/v1/events` returns a fleet-wide alert/anomaly feed with node, severity, score, time-window filters, and stable keyset cursors.
4. **Implemented:** `GET /api/v1/nodes/{node_id}/metrics/{category}/series` adds retention-bounded time windows, source filter, keyset cursor, raw pages, numeric server-side buckets, and retention/window metadata.
5. **Implemented:** `GET /api/v1/metrics/schema` publishes schema version 1, the common snapshot envelope, typed field names/types/units/labels, category source support, and a note about collector-defined raw keys.
6. **Implemented:** `GET /api/v1/nodes/{node_id}/collection-status` returns all categories and source statuses, last attempt/success, safe error codes/messages, and computed staleness.

### Priority 2 — make logs and investigations operationally usable

1. **Implemented:** `GET /api/v1/logs` provides fleet-wide full-text message search, node/service/PID/source/severity/time filters, retention metadata, and stable cursor pages with `has_more`.
2. **Implemented:** manual, alert, and anomaly investigation jobs use the Redis-backed Celery queue and persist job ID, queued/started/completed times, progress, queue delay, terminal status, and safe failure details. Redis uses append-only persistence.
3. **Implemented:** trigger IDs are required and validated against node ownership; event rows link only after successful broker dispatch. WARNING/CRITICAL alerts and qualifying anomalies enqueue automatically.
4. **Implemented:** result schema version 1 is strictly typed, validated before persistence, bounded, and excludes arbitrary source JSON. The workflow collects evidence but does not claim AI root-cause analysis.
5. **Implemented:** `/api/v1/investigations/search` filters by node/status/trigger/time and supports stable keyset cursors. Retry and cancel controls remain optional operational enhancements.

### Priority 3 — scale and resilience

1. **Implemented:** `GET /api/v1/nodes/search` supports hostname search, enabled/OS/reachability, top-level capability, per-source category-status filters, stable cursors, and `has_more`.
2. **Implemented:** `GET /api/v1/health/operations` reports database/Redis checks, Celery worker ping, beat-dispatch heartbeat, queue depth, collection/evaluation duration and failure rates, plus investigation queue-delay statistics.
3. **Evaluated:** push streaming is conditional. Cursor-based event/log/investigation APIs and telemetry windows support polling; revisit SSE/WebSocket if measured load or latency makes polling inadequate.
4. **Implemented:** API contract tests cover versioned schemas, route registration, trigger-reference validation, and stable cursor behavior. Existing alert lifecycle coverage checks clear-to-active state.

## 6. Suggested API contract checklist

Before calling the first UI milestone complete, the backend should ideally provide:

- [x] Authenticated, role-checked API access and explicit CORS origins.
- [x] Node reachability/freshness distinct from administrative `active`.
- [x] Fleet summary endpoint with server-computed active alert semantics and worker task status.
- [x] Alert current state derived from clear/transition events, plus history endpoint (identity currently uses node/name/chart).
- [x] Per-category collection status and last successful collection time.
- [x] Metric range filters and pagination/downsampling consistent with retention.
- [x] Consistent timestamped metric envelope and documented units/field schema.
- [x] Fleet-wide alert/anomaly feed with filterable stable pagination.
- [x] Global log search with stable paging and supported filters.
- [x] Durable investigation queue dispatch with persisted job lifecycle and bounded result schema.
- [x] Investigation trigger references validated and linked to events only after dispatch.
- [x] Searchable, filterable node inventory with keyset paging.
- [x] Operational database/Redis/Celery/beat/queue and task health metrics.
- [x] API contract/version test coverage is present. The earlier passing CI run
  tested the code at `8b221d0`; the current audit changes need a fresh CI run.
- [x] API/database and scheduled collection/evaluation worker health exposed in fleet summary separately from `/healthz`; Redis, Celery worker/beat dispatch, queue depth, task metrics, and investigation queue delay are reported by `/api/v1/health/operations`.

## 7. Source files reviewed

- API and proxy: `backend/main.py`, `backend/core/api_auth.py`, `backend/core/cursors.py`, `backend/api/v1/nodes.py`, `metrics.py`, `catalog.py`, `fleet.py`, `events.py`, `alerts.py`, `logs.py`, `fleet_logs.py`, `health.py`, `investigations.py`, `internal.py`, `Caddyfile`.
- Services: `backend/services/nodes.py`, `metrics.py`, `collection_status.py`, `heartbeats.py`, `alerts.py`, `anomaly.py`.
- Models: `backend/models/node.py`, `metric.py`, `category_status.py`, `service_heartbeat.py`, `alert.py`, `anomaly.py`, `log_event.py`, `investigation.py`.
- Workers and config: `backend/workers/celery_app.py`, `metrics_tasks.py`, `anomaly_tasks.py`, `maintenance_tasks.py`, `health_tasks.py`, `investigation_tasks.py`, `backend/core/config.py`, `backend/core/investigation_contracts.py`, `backend/core/security.py`.
- Agent: `agent/collector.py`.
- Product/deployment documentation and API contract coverage: `README.md`, `SESSION_HANDOFF.md`, `docker-compose.yml`, `backend/tests/test_priority_api_contracts.py`.
