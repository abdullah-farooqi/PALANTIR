# Local agent performance check

Measurements were taken on 2026-11-16 in an ephemeral Docker container using the
workspace agent source mounted read-only. They describe this development container,
not a representative production host.

| Check | Result |
| --- | ---: |
| Full `/v1/snapshot` response time | 0.102 s |
| Idle sample duration | 600 s |
| Idle CPU use | 0.73 CPU seconds; 0.1217% of one core |
| RSS mean | 63,979,520 bytes (61.0 MiB) |
| RSS peak | 64,397,312 bytes (61.4 MiB) |
| `/v1/logs?limit=200`, 100 requests: median | 4.562 ms |
| `/v1/logs?limit=200`, 100 requests: p95 / max | 5.634 ms / 23.891 ms |
| Mean log response size / returned events | 340 bytes / 0 |

The snapshot saw `services=unsupported`, `containers=not_configured`,
`virtual_machines=not_configured`, `connections=partial`, and `system=partial`.
This container did not provide the host journald mount, so the log-tail timing
covers an empty result and does not estimate parsing a busy host's journal. Runtime
and host namespace access were also limited; these results are useful as local
overhead checks only.

The local verification run also validated the HTTP responses against the checked-in
schemas for health, capabilities, the aggregate snapshot, all eight category
snapshots, logs, PCAP status/snapshot, and action success/error responses. The full
agent suite passed 39 tests, the full backend suite passed 51 tests, and the
frontend's existing Node test passed.
