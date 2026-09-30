-- ─────────────────────────────────────────────────────────────────────
-- PALANTIR PostgreSQL Database Schema
-- ─────────────────────────────────────────────────────────────────────

-- Node registry
CREATE TABLE IF NOT EXISTS monitored_nodes (
    id              SERIAL PRIMARY KEY,
    hostname        TEXT        NOT NULL UNIQUE,
    netdata_url     TEXT        NOT NULL,       -- http://<ip>:19999
    os_type         TEXT        NOT NULL DEFAULT 'linux'
                                CHECK (os_type IN ('linux', 'windows')),
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
    PRIMARY KEY (id, collected_at)
) PARTITION BY RANGE (collected_at);

CREATE TABLE IF NOT EXISTS metric_snapshots_default
    PARTITION OF metric_snapshots DEFAULT;

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

-- Agent investigation results (LangGraph hook)
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
    summary         TEXT,       -- RAG-generated forensic summary
    raw_output      JSONB       -- full LangGraph output
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_snapshots_node_time
    ON metric_snapshots (node_id, collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_snapshots_category
    ON metric_snapshots (category, collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_snapshots_data_gin
    ON metric_snapshots USING GIN (data);

CREATE INDEX IF NOT EXISTS idx_anomaly_node_time
    ON anomaly_events (node_id, detected_at DESC);

CREATE INDEX IF NOT EXISTS idx_anomaly_uninvestigated
    ON anomaly_events (node_id, detected_at DESC)
    WHERE triggered_agent = FALSE;

CREATE INDEX IF NOT EXISTS idx_alerts_node_time
    ON alert_events (node_id, received_at DESC);

CREATE INDEX IF NOT EXISTS idx_alerts_status
    ON alert_events (status, received_at DESC)
    WHERE status IN ('WARNING','CRITICAL');

CREATE INDEX IF NOT EXISTS idx_investigations_node
    ON agent_investigations (node_id, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_investigations_status
    ON agent_investigations (status)
    WHERE status = 'running';

-- ─────────────────────────────────────────────────────────────────────
-- Default Seed: Local Netdata Sensor Node (Auto-Registered)
-- ─────────────────────────────────────────────────────────────────────
INSERT INTO monitored_nodes (hostname, netdata_url, os_type, active)
VALUES ('local-node', 'http://netdata:19999', 'linux', TRUE)
ON CONFLICT (hostname) DO NOTHING;

