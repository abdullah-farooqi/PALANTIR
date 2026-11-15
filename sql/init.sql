-- ─────────────────────────────────────────────────────────────────────
-- PALANTIR PostgreSQL Database Schema
-- ─────────────────────────────────────────────────────────────────────

-- Node registry
CREATE TABLE IF NOT EXISTS monitored_nodes (
    id              SERIAL PRIMARY KEY,
    machine_id      TEXT,
    hostname        TEXT        NOT NULL,
    collector_url   TEXT        NOT NULL,
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
ALTER TABLE monitored_nodes ADD COLUMN IF NOT EXISTS machine_id TEXT;
ALTER TABLE monitored_nodes ADD COLUMN IF NOT EXISTS collector_url TEXT;
ALTER TABLE monitored_nodes ADD COLUMN IF NOT EXISTS capabilities JSONB;
ALTER TABLE monitored_nodes ADD COLUMN IF NOT EXISTS last_collection_at TIMESTAMPTZ;
DO $$ BEGIN IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='monitored_nodes' AND column_name='netdata_url') THEN ALTER TABLE monitored_nodes ALTER COLUMN netdata_url DROP NOT NULL; END IF; END $$;
CREATE UNIQUE INDEX IF NOT EXISTS idx_monitored_nodes_machine_id ON monitored_nodes(machine_id) WHERE machine_id IS NOT NULL;
ALTER TABLE monitored_nodes DROP CONSTRAINT IF EXISTS monitored_nodes_hostname_key;

-- Per-source collection attempts let the API distinguish missing, stale, and failed data.
CREATE TABLE IF NOT EXISTS node_category_collection_status (
    node_id          INT NOT NULL REFERENCES monitored_nodes(id) ON DELETE CASCADE,
    category         VARCHAR(32) NOT NULL
                     CHECK (category IN ('system','storage','network','services','processes','connections','containers','vms')),
    source           VARCHAR(32) NOT NULL
                     CHECK (source IN ('palantir-agent')),
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
    category
)
    node_id,
    category,
    'palantir-agent',
    'available',
    collected_at,
    collected_at
FROM metric_snapshots
ORDER BY
    node_id,
    category,
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

-- Alert events
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
ALTER TABLE alert_events ADD COLUMN IF NOT EXISTS event_at TIMESTAMPTZ;

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

-- Individual network-capture artifacts are stored on the shared evidence volume.
CREATE TABLE IF NOT EXISTS investigation_evidence (
    id                      SERIAL PRIMARY KEY,
    investigation_id        INT NOT NULL REFERENCES agent_investigations(id) ON DELETE CASCADE,
    alert_event_id           BIGINT REFERENCES alert_events(id) ON DELETE SET NULL,
    node_id                  INT NOT NULL REFERENCES monitored_nodes(id) ON DELETE CASCADE,
    evidence_type            VARCHAR(50) NOT NULL DEFAULT 'pcap_collection',
    capture_snapshot_id      VARCHAR(32),
    collector_file_id        VARCHAR(255),
    file_name                VARCHAR(512),
    storage_key              VARCHAR(1024),
    size_bytes               BIGINT,
    original_size_bytes      BIGINT,
    capture_started_at       TIMESTAMPTZ,
    capture_finished_at      TIMESTAMPTZ,
    duration_seconds         INT,
    captured_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    uploaded_at              TIMESTAMPTZ,
    upload_started_at        TIMESTAMPTZ,
    sha256                   VARCHAR(64),
    compression              VARCHAR(16),
    status                   VARCHAR(16) NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'uploading', 'complete', 'failed', 'unavailable')),
    error_message            TEXT,
    CONSTRAINT uq_inv_evidence_collector_file UNIQUE (investigation_id, collector_file_id),
    CONSTRAINT ck_investigation_evidence_size_nonnegative CHECK (size_bytes IS NULL OR size_bytes >= 0)
);
ALTER TABLE investigation_evidence ADD COLUMN IF NOT EXISTS duration_seconds INT;
CREATE INDEX IF NOT EXISTS idx_investigation_evidence_inv
    ON investigation_evidence (investigation_id);
CREATE INDEX IF NOT EXISTS idx_investigation_evidence_node
    ON investigation_evidence (node_id);
CREATE INDEX IF NOT EXISTS idx_investigation_evidence_status
    ON investigation_evidence (status) WHERE status IN ('queued', 'uploading');

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
    ON metric_snapshots ((COALESCE(data->>'source', 'palantir-agent')), category, collected_at DESC);

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
-- Monitored Nodes: dynamically enrolled via Automatic-Host-Setup.sh or UI
-- ─────────────────────────────────────────────────────────────────────

-- Dynamic threshold settings for collector native alert evaluation
CREATE TABLE IF NOT EXISTS system_alert_thresholds (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    chart VARCHAR(64) NOT NULL,
    metric_key VARCHAR(64) NOT NULL,
    units VARCHAR(32) NOT NULL,
    warning_val FLOAT NOT NULL,
    critical_val FLOAT NOT NULL,
    description TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO system_alert_thresholds (id, name, chart, metric_key, units, warning_val, critical_val, description)
VALUES 
  ('cpu', 'high_cpu_utilization', 'system.cpu', 'cpu_pct', '%', 5.0, 80.0, 'Host CPU utilization threshold'),
  ('ram', 'ram_in_use', 'system.ram', 'ram_pct', '%', 50.0, 85.0, 'Host memory utilization threshold'),
  ('disk', 'root_disk_space', 'system.disk', 'root_used_pct', '%', 80.0, 90.0, 'Root disk partition used percentage')
ON CONFLICT (id) DO NOTHING;

-- ─────────────────────────────────────────────────────────────────────
-- PCAP Forensic Analysis Pipeline
-- ─────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS pcap_analysis_runs (
    id                  SERIAL PRIMARY KEY,
    run_id              VARCHAR(64) NOT NULL UNIQUE,
    evidence_id         INT NOT NULL REFERENCES investigation_evidence(id) ON DELETE CASCADE,
    investigation_id    INT NOT NULL REFERENCES agent_investigations(id) ON DELETE CASCADE,
    node_id             INT NOT NULL REFERENCES monitored_nodes(id) ON DELETE CASCADE,
    status              VARCHAR(16) NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'running', 'complete', 'failed', 'rolled_back')),
    current_step        VARCHAR(64),
    started_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMPTZ,
    error_message       TEXT,
    error_step          VARCHAR(64),
    rollback_started_at TIMESTAMPTZ,
    rollback_completed_at TIMESTAMPTZ,
    CONSTRAINT ck_pcap_analysis_runs_evidence_inv
        CHECK (evidence_id IS NOT NULL AND investigation_id IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_pcap_runs_evidence ON pcap_analysis_runs(evidence_id);
CREATE INDEX IF NOT EXISTS idx_pcap_runs_investigation ON pcap_analysis_runs(investigation_id);
CREATE INDEX IF NOT EXISTS idx_pcap_runs_node ON pcap_analysis_runs(node_id);
CREATE INDEX IF NOT EXISTS idx_pcap_runs_status ON pcap_analysis_runs(status) WHERE status IN ('running', 'pending');

CREATE TABLE IF NOT EXISTS pcap_flows (
    id                  BIGSERIAL PRIMARY KEY,
    run_id              VARCHAR(64) NOT NULL REFERENCES pcap_analysis_runs(run_id) ON DELETE CASCADE,
    evidence_id         INT NOT NULL REFERENCES investigation_evidence(id) ON DELETE CASCADE,
    src_ip              INET NOT NULL,
    dst_ip              INET NOT NULL,
    src_port            INT CHECK (src_port >= 0 AND src_port <= 65535),
    dst_port            INT CHECK (dst_port >= 0 AND dst_port <= 65535),
    protocol            VARCHAR(8) NOT NULL CHECK (protocol IN ('tcp', 'udp', 'icmp', 'icmpv6')),
    flow_key            VARCHAR(128) NOT NULL,
    packet_count        INT NOT NULL DEFAULT 0 CHECK (packet_count >= 0),
    byte_count          BIGINT NOT NULL DEFAULT 0 CHECK (byte_count >= 0),
    first_seen          TIMESTAMPTZ NOT NULL,
    last_seen           TIMESTAMPTZ NOT NULL,
    duration_seconds    FLOAT,
    bidirectional       BOOLEAN NOT NULL DEFAULT FALSE,
    reverse_packet_count INT DEFAULT 0 CHECK (reverse_packet_count >= 0),
    reverse_byte_count   BIGINT DEFAULT 0 CHECK (reverse_byte_count >= 0),
    flags               JSONB,
    dscp                INT,
    fragment_count      INT DEFAULT 0,
    captured_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_pcap_flows_run_key UNIQUE (run_id, flow_key),
    CONSTRAINT ck_pcap_flows_duration CHECK (duration_seconds IS NULL OR duration_seconds >= 0)
);

CREATE INDEX IF NOT EXISTS idx_pcap_flows_run ON pcap_flows(run_id);
CREATE INDEX IF NOT EXISTS idx_pcap_flows_evidence ON pcap_flows(evidence_id);
CREATE INDEX IF NOT EXISTS idx_pcap_flows_src_ip ON pcap_flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_pcap_flows_dst_ip ON pcap_flows(dst_ip);
CREATE INDEX IF NOT EXISTS idx_pcap_flows_dst_port ON pcap_flows(dst_port);
CREATE INDEX IF NOT EXISTS idx_pcap_flows_protocol ON pcap_flows(protocol);
CREATE INDEX IF NOT EXISTS idx_pcap_flows_time ON pcap_flows(first_seen, last_seen);
CREATE INDEX IF NOT EXISTS idx_pcap_flows_flow_key ON pcap_flows(flow_key);

CREATE TABLE IF NOT EXISTS tcp_sessions (
    id                  BIGSERIAL PRIMARY KEY,
    run_id              VARCHAR(64) NOT NULL REFERENCES pcap_analysis_runs(run_id) ON DELETE CASCADE,
    evidence_id         INT NOT NULL REFERENCES investigation_evidence(id) ON DELETE CASCADE,
    src_ip              INET NOT NULL,
    dst_ip              INET NOT NULL,
    src_port            INT NOT NULL CHECK (src_port >= 0 AND src_port <= 65535),
    dst_port            INT NOT NULL CHECK (dst_port >= 0 AND dst_port <= 65535),
    state               VARCHAR(16) NOT NULL DEFAULT 'open'
                        CHECK (state IN ('open', 'established', 'closed', 'reset', 'half_open', 'incomplete')),
    server_isn          BIGINT,
    client_isn          BIGINT,
    server_win_size     INT,
    client_win_size     INT,
    total_bytes         BIGINT NOT NULL DEFAULT 0,
    reassembled_bytes   BIGINT NOT NULL DEFAULT 0,
    missing_bytes       BIGINT NOT NULL DEFAULT 0,
    retransmit_bytes    BIGINT NOT NULL DEFAULT 0,
    ooo_bytes           BIGINT NOT NULL DEFAULT 0,
    overlap_bytes       BIGINT NOT NULL DEFAULT 0,
    reassembly_quality  FLOAT,
    syn_time            TIMESTAMPTZ,
    established_time    TIMESTAMPTZ,
    close_time          TIMESTAMPTZ,
    last_activity       TIMESTAMPTZ,
    snaplen             INT NOT NULL,
    payload_truncated   BOOLEAN NOT NULL DEFAULT FALSE,
    confidence          VARCHAR(8) NOT NULL DEFAULT 'high'
                        CHECK (confidence IN ('high', 'medium', 'low')),
    first_seen          TIMESTAMPTZ NOT NULL,
    last_seen           TIMESTAMPTZ NOT NULL,
    duration_seconds    FLOAT,
    captured_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_tcp_sessions_run_flow UNIQUE (run_id, src_ip, dst_ip, src_port, dst_port, first_seen)
);

CREATE INDEX IF NOT EXISTS idx_tcp_sessions_run ON tcp_sessions(run_id);
CREATE INDEX IF NOT EXISTS idx_tcp_sessions_evidence ON tcp_sessions(evidence_id);
CREATE INDEX IF NOT EXISTS idx_tcp_sessions_state ON tcp_sessions(state);
CREATE INDEX IF NOT EXISTS idx_tcp_sessions_quality ON tcp_sessions(reassembly_quality);
CREATE INDEX IF NOT EXISTS idx_tcp_sessions_truncated ON tcp_sessions(payload_truncated) WHERE payload_truncated = TRUE;
CREATE INDEX IF NOT EXISTS idx_tcp_sessions_confidence ON tcp_sessions(confidence);

CREATE TABLE IF NOT EXISTS pcap_artifacts (
    id                  BIGSERIAL PRIMARY KEY,
    run_id              VARCHAR(64) NOT NULL REFERENCES pcap_analysis_runs(run_id) ON DELETE CASCADE,
    evidence_id         INT NOT NULL REFERENCES investigation_evidence(id) ON DELETE CASCADE,
    artifact_type       VARCHAR(32) NOT NULL
                        CHECK (artifact_type IN ('http_request', 'http_response', 'dns_query', 'dns_response', 'tls_client_hello', 'tls_server_hello', 'tls_certificate', 'tls_ja3')),
    session_id          BIGINT REFERENCES tcp_sessions(id) ON DELETE SET NULL,
    flow_id             BIGINT REFERENCES pcap_flows(id) ON DELETE SET NULL,
    content_type        VARCHAR(255),
    content_length      BIGINT CHECK (content_length IS NULL OR content_length >= 0),
    sha256              VARCHAR(64),
    storage_key         VARCHAR(1024),
    storage_prefix      VARCHAR(255),
    metadata            JSONB NOT NULL DEFAULT '{}',
    size_bytes          BIGINT NOT NULL DEFAULT 0 CHECK (size_bytes >= 0),
    max_size_exceeded   BOOLEAN NOT NULL DEFAULT FALSE,
    captured_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_pcap_artifacts_storage
        CHECK (
            storage_key IS NULL OR sha256 IS NOT NULL
        )
);

CREATE INDEX IF NOT EXISTS idx_pcap_artifacts_run ON pcap_artifacts(run_id);
CREATE INDEX IF NOT EXISTS idx_pcap_artifacts_evidence ON pcap_artifacts(evidence_id);
CREATE INDEX IF NOT EXISTS idx_pcap_artifacts_type ON pcap_artifacts(artifact_type);
CREATE INDEX IF NOT EXISTS idx_pcap_artifacts_sha256 ON pcap_artifacts(sha256) WHERE sha256 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_pcap_artifacts_storage_prefix ON pcap_artifacts(storage_prefix) WHERE storage_prefix IS NOT NULL;


-- PCAP IOC Allowlist
CREATE TABLE IF NOT EXISTS pcap_ioc_allowlist (
    id                  SERIAL PRIMARY KEY,
    ioc_type            VARCHAR(32) NOT NULL,
    pattern             VARCHAR(512) NOT NULL,
    description         TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_pcap_ioc_allowlist_uniq ON pcap_ioc_allowlist(ioc_type, pattern);

-- PCAP Extracted IOCs
CREATE TABLE IF NOT EXISTS pcap_iocs (
    id                  SERIAL PRIMARY KEY,
    run_id              VARCHAR(64) NOT NULL REFERENCES pcap_analysis_runs(run_id) ON DELETE CASCADE,
    evidence_id         INTEGER NOT NULL REFERENCES investigation_evidence(id) ON DELETE CASCADE,
    ioc_type            VARCHAR(32) NOT NULL,
    ioc_value           VARCHAR(512) NOT NULL,
    context             JSONB NOT NULL DEFAULT '{}',
    is_allowlisted      BOOLEAN NOT NULL DEFAULT FALSE,
    threat_intel_match  JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pcap_iocs_run ON pcap_iocs(run_id);
CREATE INDEX IF NOT EXISTS idx_pcap_iocs_evidence ON pcap_iocs(evidence_id);
CREATE INDEX IF NOT EXISTS idx_pcap_iocs_type_val ON pcap_iocs(ioc_type, ioc_value);
CREATE INDEX IF NOT EXISTS idx_pcap_iocs_allowlisted ON pcap_iocs(is_allowlisted);

-- Seed default allowlist patterns
INSERT INTO pcap_ioc_allowlist (ioc_type, pattern, description) VALUES
    ('ipv4', '10.0.0.0/8', 'RFC 1918 Private Network'),
    ('ipv4', '172.16.0.0/12', 'RFC 1918 Private Network'),
    ('ipv4', '192.168.0.0/16', 'RFC 1918 Private Network'),
    ('ipv4', '127.0.0.0/8', 'Loopback'),
    ('ipv4', '100.64.0.0/10', 'Carrier-Grade NAT (RFC 6598)'),
    ('ipv4', '169.254.0.0/16', 'Link-Local (RFC 3927)'),
    ('ipv4', '224.0.0.0/4', 'Multicast (RFC 5771)'),
    ('ipv4', '240.0.0.0/4', 'Reserved (RFC 1112)'),
    ('ipv6', '::1/128', 'IPv6 Loopback'),
    ('ipv6', 'fc00::/7', 'IPv6 Unique Local Addresses (ULA)'),
    ('ipv6', 'fe80::/10', 'IPv6 Link-Local'),
    ('domain', '*.local', 'mDNS / Local network'),
    ('domain', '*.internal', 'Internal network domain'),
    ('domain', '*.localhost', 'Localhost domain'),
    ('domain', '*.home.arpa', 'Home network special-use domain')
ON CONFLICT (ioc_type, pattern) DO NOTHING;


-- PCAP CVE Matches
CREATE TABLE IF NOT EXISTS pcap_cve_matches (
    id                  SERIAL PRIMARY KEY,
    run_id              VARCHAR(64) NOT NULL REFERENCES pcap_analysis_runs(run_id) ON DELETE CASCADE,
    evidence_id         INTEGER NOT NULL REFERENCES investigation_evidence(id) ON DELETE CASCADE,
    flow_id             BIGINT REFERENCES pcap_flows(id) ON DELETE SET NULL,
    artifact_id         BIGINT REFERENCES pcap_artifacts(id) ON DELETE SET NULL,
    cve_id              VARCHAR(32) NOT NULL,
    cvss_score          NUMERIC(3, 1),
    severity            VARCHAR(16) NOT NULL,
    match_type          VARCHAR(32) NOT NULL,
    confidence          VARCHAR(16) NOT NULL DEFAULT 'medium',
    description         TEXT,
    matched_data        JSONB NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_pcap_cve_score CHECK (cvss_score IS NULL OR (cvss_score >= 0.0 AND cvss_score <= 10.0)),
    CONSTRAINT ck_pcap_cve_severity CHECK (severity IN ('none', 'low', 'medium', 'high', 'critical'))
);

CREATE INDEX IF NOT EXISTS idx_pcap_cve_run ON pcap_cve_matches(run_id);
CREATE INDEX IF NOT EXISTS idx_pcap_cve_evidence ON pcap_cve_matches(evidence_id);
CREATE INDEX IF NOT EXISTS idx_pcap_cve_id ON pcap_cve_matches(cve_id);
CREATE INDEX IF NOT EXISTS idx_pcap_cve_severity ON pcap_cve_matches(severity);

-- PCAP Severity Scores
CREATE TABLE IF NOT EXISTS pcap_severity_scores (
    id                  SERIAL PRIMARY KEY,
    run_id              VARCHAR(64) NOT NULL UNIQUE REFERENCES pcap_analysis_runs(run_id) ON DELETE CASCADE,
    evidence_id         INTEGER NOT NULL REFERENCES investigation_evidence(id) ON DELETE CASCADE,
    investigation_id    INTEGER NOT NULL REFERENCES agent_investigations(id) ON DELETE CASCADE,
    overall_score       NUMERIC(3, 1) NOT NULL,
    overall_severity    VARCHAR(16) NOT NULL,
    cvss_base_max       NUMERIC(3, 1) DEFAULT 0.0,
    ioc_risk_score      NUMERIC(3, 1) DEFAULT 0.0,
    anomaly_score       NUMERIC(3, 1) DEFAULT 0.0,
    factors             JSONB NOT NULL DEFAULT '{}',
    calculated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_pcap_severity_overall CHECK (overall_score >= 0.0 AND overall_score <= 10.0),
    CONSTRAINT ck_pcap_severity_level CHECK (overall_severity IN ('low', 'medium', 'high', 'critical'))
);

CREATE INDEX IF NOT EXISTS idx_pcap_severity_run ON pcap_severity_scores(run_id);
CREATE INDEX IF NOT EXISTS idx_pcap_severity_evidence ON pcap_severity_scores(evidence_id);
CREATE INDEX IF NOT EXISTS idx_pcap_severity_inv ON pcap_severity_scores(investigation_id);
CREATE INDEX IF NOT EXISTS idx_pcap_severity_level ON pcap_severity_scores(overall_severity);




