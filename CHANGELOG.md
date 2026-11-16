# Changelog

## Unreleased

- Added the versioned host-agent `/v1` telemetry, health, capability, log, PCAP, and action contract while retaining legacy routes.
- Added independent category caching, stale status, bounded refresh waits, configurable row limits, and expanded normalized host telemetry.
- Added explicit log-redaction metadata, protected process termination checks, alert-triggered larger-snaplen capture, PCAP digests, packet metadata, and total-byte retention limits.
- Updated backend ingestion to prefer canonical agent responses with legacy fallback and to pass alert capture triggers.
