-- Extend existing PCAP evidence rows without rewriting historical evidence.
-- Safe to run more than once; every new column remains nullable for legacy rows.
ALTER TABLE investigation_evidence
    ADD COLUMN IF NOT EXISTS capture_snapshot_created_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS capture_trigger_type VARCHAR(16),
    ADD COLUMN IF NOT EXISTS collector_size_bytes BIGINT,
    ADD COLUMN IF NOT EXISTS capture_interface VARCHAR(256),
    ADD COLUMN IF NOT EXISTS snaplen INT,
    ADD COLUMN IF NOT EXISTS packet_count BIGINT,
    ADD COLUMN IF NOT EXISTS collector_sha256 VARCHAR(64),
    ADD COLUMN IF NOT EXISTS hash_status VARCHAR(16);
