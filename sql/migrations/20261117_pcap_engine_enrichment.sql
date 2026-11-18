-- Migration: 20261117_pcap_engine_enrichment.sql
-- Enriches PCAP forensic analysis engine with Stitch specifications:
-- 1. Pipeline step durations & sub-progress telemetry
-- 2. Forensic rollback telemetry (rollback ID, exit code, scratch file cleanup)
-- 3. Snaplen truncation detection & engine versions
-- 4. Extracted artifact MD5 checksums, source URIs, and sandbox TTL expiration
-- 5. Multi-vector Bayesian composite weights and ordered top risk factors

ALTER TABLE pcap_analysis_runs
  ADD COLUMN IF NOT EXISTS step_durations JSONB NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS step_progress JSONB DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS rollback_id VARCHAR(64) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS exit_code VARCHAR(32) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS purged_scratch_files INT DEFAULT 0,
  ADD COLUMN IF NOT EXISTS snaplen INT DEFAULT 65535,
  ADD COLUMN IF NOT EXISTS is_truncated BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS engine_versions JSONB NOT NULL DEFAULT '{"suricata": "7.0.2", "zeek": "6.0.4", "ruleset": "v4.12", "engine_version": "v2.4"}'::jsonb;

ALTER TABLE pcap_artifacts
  ADD COLUMN IF NOT EXISTS md5 VARCHAR(32) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS source_uri VARCHAR(1024) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS source_protocol VARCHAR(32) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP WITH TIME ZONE DEFAULT NULL;

ALTER TABLE pcap_severity_scores
  ADD COLUMN IF NOT EXISTS top_risk_factors JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS composite_weights JSONB NOT NULL DEFAULT '{}'::jsonb;
