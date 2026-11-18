-- Migration: 20261118_pcap_threat_intel_cache.sql
-- 24h cache for AbuseIPDB / OTX lookups during PCAP IOC enrichment.

CREATE TABLE IF NOT EXISTS pcap_threat_intel_cache (
    id SERIAL PRIMARY KEY,
    ioc_type VARCHAR(32) NOT NULL,
    ioc_value VARCHAR(512) NOT NULL,
    provider VARCHAR(32) NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_pcap_threat_intel_cache UNIQUE (ioc_type, ioc_value, provider)
);

CREATE INDEX IF NOT EXISTS idx_pcap_threat_intel_fetched ON pcap_threat_intel_cache (fetched_at);
