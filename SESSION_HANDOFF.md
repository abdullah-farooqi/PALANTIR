# PALANTIR — Session Handoff & Knowledge Base

**Date:** 2026-10-01  
**Project Path:** `/home/abdullah-ahmad/Desktop/PALANTIR`  
**Current Branch:** `telemetry_pipeline` (Tracked with `origin/telemetry_pipeline`, PR #1 open to `initial_project`)  
**Status:** **Distributed Multi-Node Telemetry Verified + Remote Physical Sensor (Fedora) + Central Auto-Registration Script + CI/CD 100% Passing**  

---

## 1. Executive Summary & Latest Accomplishments

In the most recent sessions, the **distributed telemetry pipeline** was expanded from simulated/VM endpoints to real-world physical and multi-node architectures:
1. **Physical Remote Endpoint Deployment (`fedora`, Node ID 6)**:
   - Deployed the lightweight Netdata telemetry sensor (`abdullahahmadfarooqi/palantir-netdata:latest`) onto an external physical Fedora laptop (`172.15.80.252:19999`).
   - Auto-discovered **265 telemetry contexts** and **209 alert rules**.
   - Successfully ingested hundreds of snapshots into PostgreSQL across `system`, `network`, `processes`, and `cgroup` categories.
   - Verified anomaly scoring (`workers.anomaly_tasks.evaluate_all_nodes`) and alert webhook dispatching (`POST /internal/alert`) for the remote node.
2. **Automated Registration & Discovery Utility (`scripts/register-node.sh`)**:
   - Created a dedicated CLI tool for the Central Platform that eliminates manual `curl` errors and placeholder mistakes (e.g., `<REMOTE_ENDPOINT_IP>`).
   - Automatically probes target Netdata sensors, extracts the real hostname (`host_labels._hostname` or `mirrored_hosts[0]`), OS type, and architecture, and registers the node in PALANTIR.
   - Supports `--local` mode to auto-detect the host's routable network interface and register the central server itself with zero configuration.
3. **Smart IP Routing on Agent (`scripts/install-agent.sh`)**:
   - Upgraded agent network discovery to query kernel routing (`ip -4 route get <SERVER_HOST>`), ensuring the sensor automatically detects and advertises the exact IP facing the central platform regardless of complex network topologies or VPNs.
4. **CI/CD Pipeline Fixed**:
   - Fixed invalid GitHub Actions secrets syntax in `.github/workflows/docker-publish.yml`.
   - Bootstrapped PostgreSQL & Redis services in `.github/workflows/ci.yml` so automated unit tests (32/32) pass cleanly on GitHub Actions runners.
   - GitHub Pull Request #1 opened: [https://github.com/abdullah-farooqi/PALANTIR/pull/1](https://github.com/abdullah-farooqi/PALANTIR/pull/1).

---

## 2. Monitored Node Inventory

| Node ID | Hostname | Netdata Sensor URL | OS | Status | Notes |
| :---: | :---: | :---: | :---: | :---: | :--- |
| **2** | `local-node` | `http://192.168.18.43:19999` (or `http://netdata:19999`) | Linux | **ACTIVE** | Central PALANTIR host platform (12 cores, 16 GB RAM). |
| **5** | `kali-vm` | `http://192.168.18.43:19998` | Linux | **PAUSED** | VirtualBox VM running with NAT port forwarding (`19998 -> 19999`). Inactive when VM is shut down. |
| **6** | `fedora` | `http://172.15.80.252:19999` | Linux | **ACTIVE** | Remote physical ThinkPad/Fedora workstation (8 cores, 16 GB RAM). Ingested 420+ snapshots. |

---

## 3. Node Enrollment Scripts Guide

### A. Central Platform: `scripts/register-node.sh`
Run this script on the central server to register either the local host or any remote machine without manually writing JSON payloads:

```bash
# 1. Register the local central server:
./scripts/register-node.sh --local

# 2. Register a remote endpoint (automatically probes sensor & fetches real hostname):
./scripts/register-node.sh 192.168.18.50

# 3. Register a remote endpoint on a custom port or specify a custom hostname:
./scripts/register-node.sh --target 192.168.18.50 --port 19999 --hostname prod-worker-01

# 4. Point to a remote PALANTIR server:
./scripts/register-node.sh 192.168.18.50 --server http://192.168.18.43:8000
```

### B. Remote Agent: `scripts/install-agent.sh`
Run this one-liner on **any** remote Linux machine or VM (requires only Docker):

```bash
# Direct execution from GitHub or local copy:
./scripts/install-agent.sh http://<SYSADMIN_SERVER_IP>:8000

# Or via curl:
curl -fsSL https://raw.githubusercontent.com/abdullah-farooqi/PALANTIR/telemetry_pipeline/scripts/install-agent.sh | bash -s -- http://<SYSADMIN_SERVER_IP>:8000
```
*The installer automatically launches `abdullahahmadfarooqi/palantir-netdata:latest`, queries the kernel routing table to determine its IP facing `<SYSADMIN_SERVER_IP>`, verifies sensor readiness, and registers the node.*

---

## 4. Problem Diagnosis: Database Protection, Noise Filtering & Structured Ingestion

During multi-node verification, three key structural issues were identified in the ingestion pipeline that must be resolved in the upcoming session:

### 1. GUID Key Pollution (`@<machine-guid>`)
- **Observation:** Netdata v2/v3 appends the unique host machine GUID to all metric context labels (e.g. `system.cpu@a3d4921e-c907-4718-b308-9bbd71278e6d`, `mem.swap@a3d4921e...`, `app.firefox_mem_usage@a3d4921e...`).
- **Impact:** SQL queries cannot query standard keys like `data->>'system.cpu'`. Developers or analytical models must know the machine GUID or write fragile regex searches over JSONB keys.
- **Solution:** Implement a normalization pass in `integrations/netdata/parsers.py` that strips `@<guid>` suffixes upon ingestion, standardizing all keys to `system.cpu`, `system.ram`, `system.load`, `mem.swap`, etc.

### 2. Excessive Noise & Sparse Zero-Padding
- **Observation:** In the `processes` category, Netdata dumps dimension entries for every known system daemon (over 150 entries per second), even when idle, resulting in dozens of `0.0` values (`app.agetty_fds_open: 0.0`, `app.tuned_cpu_utilization: 0.0`).
- **Impact:** PostgreSQL storage accumulates tens of thousands of rows of mostly zero-filled JSON blobs, causing rapid database bloat without providing operational signal.
- **Solution:** Implement filtering in `services/metrics.py`:
  - Filter out zero/null dimensions for inactive processes.
  - Sort and extract **Top-N CPU Consumers** and **Top-N Memory Consumers** (e.g., top 10 processes) rather than storing 150 idle background tasks.

### 3. Lack of Structured, Queryable Typed Fields
- **Observation:** `metric_snapshots` currently stores telemetry exclusively as unstructured `data (jsonb)`.
- **Impact:** Querying time-series trends (e.g., "Give me CPU utilization > 80% over the last hour") requires expensive JSONB parsing operations across all rows.
- **Solution:** Introduce a structured normalization layer ("Structured Metrics Logger"):
  - Promote key high-cardinality metrics to indexed, typed columns (e.g., `cpu_utilization FLOAT`, `ram_used_mb FLOAT`, `ram_total_mb FLOAT`, `load_1m FLOAT`, `swap_used_mb FLOAT`, `net_rx_kbps FLOAT`, `net_tx_kbps FLOAT`).
  - Store detailed process breakdowns as a clean, structured JSON array:
    ```json
    "top_processes": [
      {"name": "firefox", "cpu_pct": 0.50, "mem_mb": 3656.9},
      {"name": "alacritty", "cpu_pct": 0.08, "mem_mb": 669.3}
    ]
    ```

---

## 5. Next Session Action Plan

In the upcoming session, work will focus on refactoring the ingestion pipeline for database protection, structured querying, and automated agent root-cause analysis:

### Phase 1: Ingestion Normalizer & Structured Metrics Logger
1. **Create `backend/integrations/netdata/normalizer.py`**:
   - `strip_machine_guid(key: str) -> str`: Normalizes `metric@guid` $\rightarrow$ `metric`.
   - `filter_active_metrics(data: dict) -> dict`: Discards inactive 0.0 entries.
   - `extract_top_processes(process_data: dict, top_n: int = 10) -> List[dict]`: Groups CPU and memory usage by process name and outputs the top consumers.
2. **Schema Upgrade for `metric_snapshots`**:
   - Add first-class typed columns to `metric_snapshots`:
     - `cpu_pct` (Double Precision / Float)
     - `ram_used_mb` (Double Precision / Float)
     - `ram_total_mb` (Double Precision / Float)
     - `load_avg` (Double Precision / Float)
     - `swap_used_mb` (Double Precision / Float)
   - Add B-Tree indexes on `(node_id, category, collected_at)` and `(cpu_pct)`.
3. **Update `MetricsService.collect_and_persist`**:
   - Apply the normalizer before persisting to PostgreSQL.
   - Store clean, queryable payloads in both the typed columns and cleaned JSONB.

### Phase 2: Autonomous Investigation Agent (LangGraph)
1. Wire `backend/workers/agent_tasks.py`:
   - Trigger LangGraph diagnostic workflows whenever an anomaly is flagged or an alert is received with `triggered_agent == True`.
   - Pass normalized metrics from the new structured schema into the prompt/context for root-cause analysis.
   - Write investigation results into the `agent_investigations` table.

### Phase 3: Database Retention & Performance
1. Implement metric aggregation (rollups) or snapshot pruning to keep database storage lightweight and performant.

---

## 6. Verification Commands Quick Reference

```bash
# Check running containers:
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Check enrolled nodes in database:
docker exec palantir-postgres psql -U palantir -d palantir -c \
  "SELECT id, hostname, netdata_url, active, context_count, alert_count FROM monitored_nodes ORDER BY id;"

# Check live snapshot counts per node:
docker exec palantir-postgres psql -U palantir -d palantir -c \
  "SELECT node_id, category, count(*), max(collected_at) FROM metric_snapshots GROUP BY node_id, category ORDER BY node_id;"

# Run the central platform registration utility:
./scripts/register-node.sh --help
./scripts/register-node.sh --local

# Stream live Celery worker ingestion logs:
docker logs --tail 30 -f palantir-celery-worker

# Run full backend test suite:
docker exec palantir-backend pytest -v
```
