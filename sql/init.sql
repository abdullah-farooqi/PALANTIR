-- ─────────────────────────────────────────────────────────────────────
-- PALANTIR PostgreSQL Database Schema
-- ─────────────────────────────────────────────────────────────────────

-- Node registry
CREATE TABLE IF NOT EXISTS monitored_nodes (
    id              SERIAL PRIMARY KEY,
    hostname        TEXT        NOT NULL UNIQUE,
    netdata_url     TEXT        NOT NULL,       -- http://<ip>:19999
    collector_url   TEXT,                       -- optional PALANTIR host collector endpoint
    capabilities    JSONB,
    os_type         TEXT        NOT NULL DEFAULT 'linux',
    active          BOOLEAN     NOT NULL DEFAULT TRUE,
    context_count   INT,                        -- set on registration
    alert_count     INT,                        -- set on registration
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Rolling metric buffer — 24h window
-- Partitioned by time for efficient range queries
CREATE TABLE IF NOT EXISTS metric_snapshots (
    id           BIGSERIAL,
    node_id      INT         NOT NULL REFERENCES monitored_nodes(id) ON DELETE CASCADE,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    category     TEXT        NOT NULL
                 CHECK (category IN ('network','system','processes','containers')),
    data         JSONB       NOT NULL,
    cpu_pct      FLOAT,
    ram_used_mb  FLOAT,
    ram_total_mb FLOAT,
    load_avg     FLOAT,
    swap_used_mb FLOAT,
    top_processes JSONB,
    PRIMARY KEY (id, collected_at)
) PARTITION BY RANGE (collected_at);

CREATE TABLE IF NOT EXISTS metric_snapshots_default
    PARTITION OF metric_snapshots DEFAULT;

-- Keep rerunning this file safe when upgrading an existing database volume.
ALTER TABLE metric_snapshots ADD COLUMN IF NOT EXISTS cpu_pct FLOAT;
ALTER TABLE metric_snapshots ADD COLUMN IF NOT EXISTS ram_used_mb FLOAT;
ALTER TABLE metric_snapshots ADD COLUMN IF NOT EXISTS ram_total_mb FLOAT;
ALTER TABLE metric_snapshots ADD COLUMN IF NOT EXISTS load_avg FLOAT;
ALTER TABLE metric_snapshots ADD COLUMN IF NOT EXISTS swap_used_mb FLOAT;
ALTER TABLE metric_snapshots ADD COLUMN IF NOT EXISTS top_processes JSONB;
ALTER TABLE monitored_nodes ADD COLUMN IF NOT EXISTS collector_url TEXT;
ALTER TABLE monitored_nodes ADD COLUMN IF NOT EXISTS capabilities JSONB;
ALTER TABLE monitored_nodes ADD COLUMN IF NOT EXISTS last_collection_at TIMESTAMPTZ;

-- Per-source collection attempts let the API distinguish missing, stale, and failed data.
CREATE TABLE IF NOT EXISTS node_category_collection_status (
    node_id          INT NOT NULL REFERENCES monitored_nodes(id) ON DELETE CASCADE,
    category         VARCHAR(32) NOT NULL
                     CHECK (category IN ('system','storage','network','services','processes','connections','containers','vms')),
    source           VARCHAR(32) NOT NULL
                     CHECK (source IN ('netdata','palantir-agent')),
    status           VARCHAR(32) NOT NULL
                     CHECK (status IN ('unknown','available','not_configured','unsupported','collection_error')),
    last_attempt_at  TIMESTAMPTZ,
    last_success_at  TIMESTAMPTZ,
    error_code       VARCHAR(64),
    error_message    VARCHAR(300),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (node_id, category, source)
);

-- Task completion is the pipeline heartbeat; it does not claim that every node scrape succeeded.
CREATE TABLE IF NOT EXISTS service_heartbeats (
    name              VARCHAR(64) PRIMARY KEY,
    last_started_at   TIMESTAMPTZ,
    last_completed_at TIMESTAMPTZ,
    status            VARCHAR(16) NOT NULL DEFAULT 'unknown'
                      CHECK (status IN ('unknown','running','completed','failed')),
    error_code        VARCHAR(64),
    last_success_at   TIMESTAMPTZ,
    last_duration_ms  INT,
    run_count         INT NOT NULL DEFAULT 0,
    failure_count     INT NOT NULL DEFAULT 0,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE service_heartbeats ADD COLUMN IF NOT EXISTS last_success_at TIMESTAMPTZ;
ALTER TABLE service_heartbeats ADD COLUMN IF NOT EXISTS last_duration_ms INT;
ALTER TABLE service_heartbeats ADD COLUMN IF NOT EXISTS run_count INT NOT NULL DEFAULT 0;
ALTER TABLE service_heartbeats ADD COLUMN IF NOT EXISTS failure_count INT NOT NULL DEFAULT 0;

-- Backfill successful history for databases upgraded after telemetry collection began.
INSERT INTO node_category_collection_status (
    node_id, category, source, status, last_attempt_at, last_success_at
)
SELECT DISTINCT ON (
    node_id,
    category,
    CASE WHEN data->>'source' = 'palantir-agent' THEN 'palantir-agent' ELSE 'netdata' END
)
    node_id,
    category,
    CASE WHEN data->>'source' = 'palantir-agent' THEN 'palantir-agent' ELSE 'netdata' END,
    'available',
    collected_at,
    collected_at
FROM metric_snapshots
ORDER BY
    node_id,
    category,
    CASE WHEN data->>'source' = 'palantir-agent' THEN 'palantir-agent' ELSE 'netdata' END,
    collected_at DESC,
    id DESC
ON CONFLICT (node_id, category, source) DO NOTHING;

UPDATE monitored_nodes AS n
SET last_collection_at = history.latest,
    last_seen_at = GREATEST(n.last_seen_at, history.latest)
FROM (
    SELECT node_id, MAX(collected_at) AS latest
    FROM metric_snapshots
    GROUP BY node_id
) AS history
WHERE n.id = history.node_id
  AND n.last_collection_at IS NULL;

-- Keep category expansion safe for existing database volumes.
ALTER TABLE metric_snapshots DROP CONSTRAINT IF EXISTS metric_snapshots_category_check;
ALTER TABLE metric_snapshots ADD CONSTRAINT metric_snapshots_category_check
    CHECK (category IN ('network','system','storage','services','processes','connections','containers','vms'));

-- Structured host and application logs are events, not periodic metric snapshots.
CREATE TABLE IF NOT EXISTS log_events (
    id          BIGSERIAL PRIMARY KEY,
    node_id     INT NOT NULL REFERENCES monitored_nodes(id) ON DELETE CASCADE,
    event_id    VARCHAR(64) NOT NULL,
    event_at    TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source      VARCHAR(255) NOT NULL,
    severity    VARCHAR(32) NOT NULL DEFAULT 'unknown',
    service     VARCHAR(255),
    pid         INT,
    message     TEXT NOT NULL,
    fields      JSONB NOT NULL DEFAULT '{}'::jsonb,
    parser      VARCHAR(64),
    CONSTRAINT uq_log_events_node_event UNIQUE (node_id, event_id)
);

-- Anomaly events — when correlation threshold is crossed
CREATE TABLE IF NOT EXISTS anomaly_events (
    id                  BIGSERIAL   PRIMARY KEY,
    node_id             INT         NOT NULL REFERENCES monitored_nodes(id) ON DELETE CASCADE,
    detected_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    contexts            TEXT[]      NOT NULL,  -- which contexts anomalous
    scores              JSONB       NOT NULL,  -- {context: float} map
    max_score           FLOAT       NOT NULL,
    triggered_agent     BOOLEAN     NOT NULL DEFAULT FALSE,
    investigation_id    INT         -- set after agent completes
);

-- Alert events — from Netdata push webhook
CREATE TABLE IF NOT EXISTS alert_events (
    id                  BIGSERIAL   PRIMARY KEY,
    node_id             INT         NOT NULL REFERENCES monitored_nodes(id) ON DELETE CASCADE,
    received_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    alert_name          TEXT        NOT NULL,
    chart               TEXT        NOT NULL,
    status              TEXT        NOT NULL
                        CHECK (status IN ('WARNING','CRITICAL','CLEAR')),
    value               FLOAT,
    units               TEXT,
    triggered_agent     BOOLEAN     NOT NULL DEFAULT FALSE,
    investigation_id    INT
);

-- Previous backend code set these flags before any agent task was dispatched.
-- Apply the correction once so later real dispatch outcomes are not overwritten.
CREATE TABLE IF NOT EXISTS palantir_schema_migrations (
    version     TEXT PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM palantir_schema_migrations
        WHERE version = '2026-10-04-clear-placeholder-agent-flags'
    ) THEN
        UPDATE anomaly_events SET triggered_agent = FALSE WHERE triggered_agent = TRUE;
        UPDATE alert_events SET triggered_agent = FALSE WHERE triggered_agent = TRUE;
        INSERT INTO palantir_schema_migrations (version)
        VALUES ('2026-10-04-clear-placeholder-agent-flags');
    END IF;
END;
$$;

-- Durable investigation queue and bounded evidence results.
CREATE TABLE IF NOT EXISTS agent_investigations (
    id              SERIAL      PRIMARY KEY,
    node_id         INT         NOT NULL REFERENCES monitored_nodes(id) ON DELETE CASCADE,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    trigger_type    TEXT        NOT NULL
                    CHECK (trigger_type IN ('anomaly','alert','manual')),
    trigger_id      INT,        -- anomaly_events.id or alert_events.id
    status          TEXT        NOT NULL DEFAULT 'running'
                    CHECK (status IN ('running','complete','failed')),
    summary         TEXT,       -- bounded human-readable evidence summary
    raw_output      JSONB       -- versioned bounded workflow result
);

ALTER TABLE agent_investigations ADD COLUMN IF NOT EXISTS job_id VARCHAR(64);
ALTER TABLE agent_investigations ADD COLUMN IF NOT EXISTS queued_at TIMESTAMPTZ;
ALTER TABLE agent_investigations ADD COLUMN IF NOT EXISTS progress INT NOT NULL DEFAULT 0;
ALTER TABLE agent_investigations ADD COLUMN IF NOT EXISTS queue_delay_ms INT;
ALTER TABLE agent_investigations ADD COLUMN IF NOT EXISTS error_code VARCHAR(64);
ALTER TABLE agent_investigations ADD COLUMN IF NOT EXISTS error_message TEXT;
ALTER TABLE agent_investigations ALTER COLUMN started_at DROP NOT NULL;
ALTER TABLE agent_investigations ALTER COLUMN started_at DROP DEFAULT;
ALTER TABLE agent_investigations ALTER COLUMN status SET DEFAULT 'queued';
ALTER TABLE agent_investigations DROP CONSTRAINT IF EXISTS agent_investigations_status_check;
ALTER TABLE agent_investigations ADD CONSTRAINT agent_investigations_status_check
    CHECK (status IN ('queued','running','complete','failed','cancelled'));
ALTER TABLE agent_investigations DROP CONSTRAINT IF EXISTS ck_investigation_progress;
ALTER TABLE agent_investigations ADD CONSTRAINT ck_investigation_progress
    CHECK (progress >= 0 AND progress <= 100);
UPDATE agent_investigations
SET status = 'failed',
    completed_at = COALESCE(completed_at, NOW()),
    progress = 0,
    error_code = 'legacy_not_dispatched',
    error_message = 'This legacy running record has no queued job and was never dispatched.',
    summary = COALESCE(summary, 'Legacy investigation was not dispatched.')
WHERE status = 'running' AND job_id IS NULL;
-- Queued rows are not started until a worker claims them.
UPDATE agent_investigations
SET started_at = NULL
WHERE status = 'queued' AND completed_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_investigations_job_id
    ON agent_investigations (job_id)
    WHERE job_id IS NOT NULL;

-- Indexes
CREATE INDEX IF NOT EXISTS idx_snapshots_node_time
    ON metric_snapshots (node_id, collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_snapshots_category
    ON metric_snapshots (category, collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_snapshots_data_gin
    ON metric_snapshots USING GIN (data);

CREATE INDEX IF NOT EXISTS idx_snapshots_node_cat_time
    ON metric_snapshots (node_id, category, collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_snapshots_cpu_pct
    ON metric_snapshots (cpu_pct);

CREATE INDEX IF NOT EXISTS idx_snapshots_ram_used_mb
    ON metric_snapshots (ram_used_mb)
    WHERE ram_used_mb IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_snapshots_load_avg
    ON metric_snapshots (load_avg)
    WHERE load_avg IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_snapshots_swap_used_mb
    ON metric_snapshots (swap_used_mb)
    WHERE swap_used_mb IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_snapshots_top_processes_gin
    ON metric_snapshots USING GIN (top_processes)
    WHERE top_processes IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_snapshots_source_category_time
    ON metric_snapshots ((COALESCE(data->>'source', 'netdata')), category, collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_collection_status_node_category
    ON node_category_collection_status (node_id, category, source);

CREATE INDEX IF NOT EXISTS idx_service_heartbeats_completed
    ON service_heartbeats (last_completed_at DESC);

CREATE INDEX IF NOT EXISTS idx_log_events_node_time
    ON log_events (node_id, event_at DESC);

CREATE INDEX IF NOT EXISTS idx_log_events_node_severity_time
    ON log_events (node_id, severity, event_at DESC);

CREATE INDEX IF NOT EXISTS idx_log_events_fields_gin
    ON log_events USING GIN (fields);

CREATE INDEX IF NOT EXISTS idx_log_events_message_fts
    ON log_events USING GIN (to_tsvector('simple', COALESCE(message, '')));

CREATE INDEX IF NOT EXISTS idx_log_events_time_id
    ON log_events (event_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_log_events_service_time
    ON log_events (service, event_at DESC, id DESC)
    WHERE service IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_log_events_source_time
    ON log_events (source, event_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_nodes_active_seen_hostname
    ON monitored_nodes (active, last_seen_at DESC, hostname);

CREATE INDEX IF NOT EXISTS idx_nodes_capabilities_gin
    ON monitored_nodes USING GIN (capabilities);

CREATE INDEX IF NOT EXISTS idx_anomaly_node_time
    ON anomaly_events (node_id, detected_at DESC);

CREATE INDEX IF NOT EXISTS idx_anomaly_time_id
    ON anomaly_events (detected_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_anomaly_max_score_time
    ON anomaly_events (max_score, detected_at DESC);

CREATE INDEX IF NOT EXISTS idx_anomaly_uninvestigated
    ON anomaly_events (node_id, detected_at DESC)
    WHERE triggered_agent = FALSE;

CREATE INDEX IF NOT EXISTS idx_alerts_node_time
    ON alert_events (node_id, received_at DESC);

CREATE INDEX IF NOT EXISTS idx_alerts_time_id
    ON alert_events (received_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_alerts_node_identity_time
    ON alert_events (node_id, alert_name, chart, received_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_alerts_status
    ON alert_events (status, received_at DESC)
    WHERE status IN ('WARNING','CRITICAL');

CREATE INDEX IF NOT EXISTS idx_investigations_node
    ON agent_investigations (node_id, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_investigations_timeline
    ON agent_investigations ((COALESCE(started_at, queued_at)) DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_investigations_node_timeline
    ON agent_investigations (node_id, (COALESCE(started_at, queued_at)) DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_investigations_queued
    ON agent_investigations (queued_at DESC, id DESC)
    WHERE status = 'queued';

CREATE INDEX IF NOT EXISTS idx_investigations_status
    ON agent_investigations (status)
    WHERE status = 'running';

-- ─────────────────────────────────────────────────────────────────────
-- Default Seed: Local Netdata Sensor Node (Auto-Registered)
-- ─────────────────────────────────────────────────────────────────────
INSERT INTO monitored_nodes (hostname, netdata_url, os_type, active)
VALUES ('local-node', 'http://netdata:19999', 'linux', TRUE)
ON CONFLICT (hostname) DO NOTHING;
