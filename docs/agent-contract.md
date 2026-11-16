# PALANTIR host agent contract

The host agent serves the versioned contract below while retaining `/api/v1/*` for
existing PALANTIR masters. Read-only routes use the configured
`PALANTIR_AGENT_TOKEN` policy. PCAP and action routes keep their stricter controls.

## Snapshot routes

`GET /v1/snapshot` returns the eight categories together. Individual categories are
available at `GET /v1/snapshot/{category}`. The canonical VM category is
`virtual_machines`; legacy storage and backend SQL continue to call it `vms`.

Every category result has `schema_version`, `category`, `collector_version`,
`collected_at`, `status`, and `data`. Timestamps are UTC ISO-8601 strings ending in
`Z`. `status.state` is `available`, `partial`, `stale`, `unsupported`,
`not_configured`, `permission_denied`, or `unavailable`. The status object includes
`reason`, `source`, `last_success`, and `last_attempt`. Missing source values remain
null. A failed refresh returns the most recent successful data with `stale` status.

Category results are refreshed independently. `CATEGORY_REFRESH_SECONDS` defaults
to 60 seconds and `CATEGORY_TIMEOUT_SECONDS` defaults to 4 seconds (bounded to 0.5
through 10 seconds). An aggregate snapshot shares one timeout budget across its
eight category collectors. Data older than three refresh intervals is marked stale.
`/v1/health` reports process uptime, RSS, CPU, and per-category freshness.

Canonical telemetry adds named nested fields while retaining collector-specific
detail fields. Examples include `system_info` and `cpu` under `system`,
`interface_rows` under `network`, `rows` and `truncated` under `processes`, and
`virtual_machines` under that category. The backend retains these values in the
existing JSONB snapshot and adapts fields needed by current screens; no metric
columns are added.

## Capabilities and logs

`GET /v1/capabilities` returns a versioned list with a name, status, reason, and
source for each detected feature and runtime. `GET /v1/logs` accepts `since_cursor`,
`limit`, `service`, `severity`, `contains`, `pid`, `source`, `since`, and `until`.
Its `data` includes normalized `events`, `next_cursor`, `has_more`, `dropped`, and
`redaction_applied`. Log messages and fields remain redacted by default; the
canonical response explicitly reports whether redaction was applied. Setting
`UNREDACTED_LOGS=1` opts the canonical route into raw values. Legacy routes remain
redacted. Paths are never accepted from the request; file collection uses the
configured `APP_LOG_GLOBS` allowlist.

## Actions and packet capture

Canonical action routes are `POST /v1/containers/{id}/action`,
`POST /v1/vms/{id}/action`, and `POST /v1/processes/{pid}/terminate`. Action JSON
uses an allowlisted `action`; VM actions may include boolean `force`, and process
termination may include `signal`, `expected_process_name`, and
`expected_start_time`. `ACTIONS_ENABLED=0` disables these endpoints. Actions require
the configured token unless the existing explicit anonymous-control setting is
enabled.

`GET /v1/pcap/status` reports capture configuration and retention. Manual and alert
snapshots use `POST /v1/pcap/snapshot?trigger_type=manual|alert`; alert captures run
the configured larger-snaplen window. Every finalized file advertises its interface,
snaplen, packet count when parseable, compression, byte counts, and asynchronous
SHA-256 status. `PCAP_MAX_TOTAL_SIZE_MB` caps retained capture bytes in addition to
the existing file-count limit. PCAP access still requires `PALANTIR_AGENT_TOKEN`.

## Configuration

New settings are optional for existing deployments:

| Setting | Default | Purpose |
| --- | ---: | --- |
| `CATEGORY_REFRESH_SECONDS` | `60` | Per-category cache interval |
| `CATEGORY_TIMEOUT_SECONDS` | `4` | Canonical category wait limit |
| `PROCESS_LIMIT` | `100` | Maximum canonical process rows |
| `SOCKET_LIMIT` | `5000` | Maximum retained socket rows |
| `ACTIONS_ENABLED` | `1` | Canonical action-route gate |
| `UNREDACTED_LOGS` | `0` | Permit raw values on canonical log reads |
| `PCAP_ALERT_SNAPLEN` | `4096` | Snap length during alert capture window |
| `PCAP_ALERT_WINDOW_SECONDS` | `10` | Alert capture duration, from 1 to 30 seconds |
| `PCAP_MAX_TOTAL_SIZE_MB` | `PCAP_MAX_SIZE_MB × PCAP_MAX_FILES` | Total retained PCAP byte limit |

See [the snapshot envelope schema](../schemas/agent/snapshot-envelope.schema.json) and
the related endpoint schemas under `schemas/agent/`.
