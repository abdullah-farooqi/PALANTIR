# PALANTIR — Autonomous Linux Monitoring & Security Investigation Platform

PALANTIR is an autonomous, enterprise-grade Linux observability and security investigation platform. It provides high-frequency telemetry collection, structured security log ingestion, dynamic threshold evaluation, and automated incident investigations across distributed Linux infrastructure.

---

## Architecture Overview

```mermaid
flowchart TD
    subgraph TargetHosts ["Monitored Linux Infrastructure"]
        Host1["Target Host Collector (:20000)"]
        Host2["Target Host Collector (:20000)"]
        HostN["Local / Edge Collector (:20000)"]
    end

    subgraph MasterServer ["PALANTIR Master Server"]
        Browser["Operator Browser"]
        Caddy["Caddy HTTPS + Authentik SSO (:443)"]
        UI["React 18 Dashboard (:3000)"]
        API["FastAPI Backend (:8000)"]
        Beat["Celery Beat (Scheduler)"]
        Worker["Celery Worker (Scraper & Investigation Engine)"]
        DB[(PostgreSQL 16 Partitioned Tables :5432)]
        Broker[(Redis 7 Broker & Cache :6379)]
        
        Browser -->|"HTTPS (SSO Auth)"| Caddy
        Caddy -->|"Proxy /"| UI
        Caddy -->|"Proxy /api/v1 (Injected Bearer Auth)"| API
        API --> DB
        API --> Broker
        Beat -->|"Schedule 60s Scrapes & Retention"| Broker
        Broker --> Worker
        Worker --> DB
    end

    Worker -->|"Pull Telemetry & Logs (Bearer Auth :20000)"| Host1
    Worker -->|"Pull Telemetry & Logs (Bearer Auth :20000)"| Host2
    Worker -->|"Pull Telemetry & Logs (Bearer Auth :20000)"| HostN
    TargetHosts -.->|"Proc / Sysfs / Docker / Systemd"| TargetHosts
```

### Core Architecture Components

1. **Master Control Plane**:
   - **FastAPI Backend (`:8000`)**: Asynchronous REST API serving telemetry querying, host registration, threshold management, and investigation triggering.
   - **React 18 Dashboard (`:3000`)**: Modern terminal-styled dashboard for real-time fleet health, interactive telemetry charts, audit event logs, dynamic threshold customization, and security incident investigations.
   - **PostgreSQL 16 (`:5432`)**: Relational database utilizing monthly range-partitioned tables (`metric_snapshots`, `audit_events`, `system_logs`) for high-throughput, low-latency queries.
   - **Redis 7 (`:6379`) & Celery**: Distributed task broker and workers executing 60-second host metrics collection, anomaly detection, automated retention pruning, and incident investigations.
   - **Caddy & Authentik SSO**: Enterprise reverse proxy with automated TLS termination and forward role-based authentication (`read`, `admin`, `enroll`).

2. **Native Host Collector (`:20000`)**:
   - Lightweight, standalone containerized Python daemon located in `agent/` (Docker image: `abdullahahmadfarooqi/palantir-host-collector:latest`).
   - Collects kernel, systemd, process, network, storage, container, and security metrics directly from `/proc`, `/sys`, and `/var/run/docker.sock` without third-party agent dependencies.
   - Protected via Bearer token authentication (`AGENT_AUTH_TOKEN`).

---

## Key Features

- **8 Core Telemetry Categories**:
  - `system`: CPU core utilization, load averages, memory, swap, uptime.
  - `storage`: Mount points, disk usage, partition capacity, read/write I/O operations.
  - `network`: Interface bandwidth, packet rates, errors, drop rates.
  - `services`: Systemd units, active/failed service statuses.
  - `processes`: Top resource-consuming processes, thread counts, process states.
  - `connections`: Active listening ports, established TCP/UDP network connections.
  - `containers`: Docker container states, CPU/memory resource usage.
  - `vms`: Virtual machine hypervisor telemetry (LXD, KVM/QEMU, Proxmox).
- **Dynamic Threshold Engine**: Real-time evaluation of metric conditions (Warning/Critical) with full UI customization.
- **Automated Security Investigations**: Background correlation of system alerts with audit logs, process anomalies, and network connections.
- **Time-Partitioned Storage**: Monthly metric partition maintenance and metric pruning handled automatically by Celery background workers.

---

## 1. Quickstart: Central Master Server (Ubuntu)

Run the automated master installer on your primary Ubuntu server:

```bash
git clone -b telemetry_pipeline https://github.com/abdullah-farooqi/PALANTIR.git
cd PALANTIR

# Run the master setup script
sudo bash scripts/Automatic-Master-Server-Setup.sh
```

### What the Master Setup Script Does:
1. **System & Dependency Verification**: Checks Docker engine and Node.js / npm (v18+) requirements.
2. **Automated Secret Generation**: Generates 32-character cryptographic hex secrets in `.env` with strict permissions (`chmod 600`).
3. **Port Conflict Resolution**: Automatically detects and frees ports `3000`, `8000`, `5432`, and `6379` if occupied.
4. **Backend Stack Initialization**: Launches `palantir-backend`, `palantir-celery-worker`, `palantir-celery-beat`, `palantir-postgres`, and `palantir-redis` via Docker Compose.
5. **Schema & Partition Migration**: Applies PostgreSQL initializations, B-tree indexes, GIN indexes, and range-partitioned tables (`sql/init.sql`).
6. **Frontend Dashboard Launch**: Installs UI dependencies in `frontend/` and starts the React dashboard on `http://localhost:3000`.

---

## 2. Quickstart: Monitored Target Hosts (Remote / Edge / VMs)

Remote hosts do not run PostgreSQL, Redis, Celery, or the central backend. To monitor any remote Linux server or VM, run the automated host setup script:

```bash
git clone -b telemetry_pipeline https://github.com/abdullah-farooqi/PALANTIR.git
cd PALANTIR

# Run the host collector setup script
sudo bash scripts/Automatic-Host-Setup.sh
```

### What the Host Setup Script Does:
1. Verifies Docker engine installation on the target host.
2. Stops any conflicting collector processes and frees port `20000`.
3. Opens inbound port `20000/tcp` on the local firewall (UFW) if enabled.
4. Pulls the latest container image: `abdullahahmadfarooqi/palantir-host-collector:latest`.
5. Deploys the collector daemon (`palantir-collector`) listening on port `20000` with read-only host mounts (`/proc`, `/sys`, `/etc`, `/var/run/docker.sock`).
6. Detects the host's LAN IP address and prints the enrollment parameters for your Master UI.

To inspect the running collector on a target host:
```bash
docker ps --filter "name=palantir-collector"
docker logs -f --tail 50 palantir-collector
```

---

## 3. VirtualBox / NAT VM Networking Guide

If deploying the host collector inside a virtual machine (e.g., VirtualBox with default NAT IP `10.0.2.15`), the central server cannot route inbound traffic directly into `10.0.2.15:20000`. Choose one of two options:

### Option 1: Bridged Networking (Recommended)
1. In VirtualBox: **VM Settings → Network → Adapter 1 → Attached to: Bridged Adapter**.
2. Inside the VM, renew DHCP lease: `sudo dhclient -v`.
3. The VM receives a direct LAN IP (e.g., `192.168.1.X`), directly reachable by the central server on port `20000`.

### Option 2: Live Port Forwarding (While Keeping NAT)
From the VM host machine, forward a host port (e.g. `20001`) to the guest's port `20000` without restarting the VM:

```bash
VBoxManage controlvm "<VM_NAME>" natpf1 "palantir-collector,tcp,,20001,,20000"
```
Then register the node in the PALANTIR Master UI specifying the host IP and forwarded port `http://<HOST_IP>:20001`.

---

## 4. Reverse Proxy & Authentik SSO Setup (Optional LAN Gateway)

For enterprise deployments requiring HTTPS and single sign-on, Caddy and Authentik manage authentication and forward-proxying to the backend.

### DNS Configuration
The included Caddy reverse proxy uses `palantir.home.arpa` and `auth.palantir.home.arpa`. Add both domain names to your LAN DNS server (or local `/etc/hosts`), pointing to your central server's static LAN IP:
```
<CENTRAL_SERVER_LAN_IP> palantir.home.arpa auth.palantir.home.arpa
```

### Initial TLS Certificate Setup
Caddy generates an internal Certificate Authority (CA) for private HTTPS. Make an initial TLS handshake from the server:
```bash
openssl s_client -connect <PALANTIR_LAN_IP>:443 -servername palantir.home.arpa </dev/null
```
Export Caddy's root certificate and install it on client machines:
```bash
# Export from Caddy container
docker cp palantir-caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt

# Install on Ubuntu / Debian client machines:
sudo install -m 0644 caddy-root.crt /usr/local/share/ca-certificates/palantir-caddy.crt
sudo update-ca-certificates
```

### Authentik Group Roles
Open `https://auth.palantir.home.arpa/if/flow/initial-setup/` and complete initial setup. Create the following groups:
- `palantir-read`: UI/API read-only access.
- `palantir-admin`: Read, threshold editing, node deactivation, and investigation management.
- `palantir-enroll`: Machine-to-machine node registration (`POST /api/v1/nodes`).

Caddy inspects incoming sessions, strips browser-supplied authorization headers, and injects the corresponding server-side Bearer token (`PALANTIR_API_READ_TOKEN`, `PALANTIR_API_ADMIN_TOKEN`, `PALANTIR_API_ENROLL_TOKEN`) directly into the backend request.

---

## 5. Backend REST Telemetry APIs & Data Retention

All `/api/v1/*` routes require a Bearer token (`Authorization: Bearer <TOKEN>`).

### Telemetry & Fleet APIs
- `GET /api/v1/fleet/summary`: Fleet-wide summary showing total/enabled/disabled nodes, reachability counts, latest metric timestamp, active alerts, 24h anomaly statistics, and backend/worker health status.
- `GET /api/v1/events`: Fleet-wide alert and anomaly feed supporting `event_type` (`alert` | `anomaly` | `all`), `node_id`, severity, and opaque keyset cursor pagination (`next_cursor`).
- `GET /api/v1/nodes/{node_id}`: Detailed node state including `last_seen_at`, `last_collection_at`, and reachability status (derived via `NODE_REACHABLE_SECONDS=180` and `NODE_STALE_SECONDS=900`).
- `GET /api/v1/nodes/{node_id}/collection-status`: Status report across all 8 categories (`system`, `storage`, `network`, `services`, `processes`, `connections`, `containers`, `vms`) detailing last attempt/success and error details.
- `GET /api/v1/nodes/{node_id}/metrics/{category}/series`: Time-series query route supporting `since`, `until`, `limit` (1–1000), `bucket_seconds` (10–86400 for server-side min/max/avg rollups), and cursor pagination.
- `GET /api/v1/metrics/schema`: Versioned snapshot schema detailing supported categories, metric names, data types, units, and label definitions.

### Investigation & Log APIs
- `GET /api/v1/logs`: Full-text search across ingested fleet logs supporting `q`, `node_id`, `service`, `pid`, `severity`, and cursor pagination.
- `POST /api/v1/investigations`: Enqueues an automated security investigation. Automatically dispatched on `WARNING` or `CRITICAL` alerts or qualifying anomaly events.
- `GET /api/v1/investigations/search`: Query and filter investigations by node, status (`queued`, `running`, `completed`, `failed`), and trigger type.
- `GET /api/v1/health/operations`: Operational health check returning database ping, Redis connectivity, Celery worker status, beat scheduler heartbeat, and task failure rates.

### Data Retention
- Metric snapshots are retained for 24 hours by default (`METRICS_RETENTION_HOURS=24`).
- Structured security logs are retained for 7 days by default (`LOG_RETENTION_DAYS=7`).
- Scheduled Celery maintenance tasks automatically prune partitions and expired data based on these settings.

---

## 6. Verification & Testing

### Verify Live Ingestion on Central Master
```bash
# 1. Watch incoming metric snapshot ingestion rate (updates every 60s)
watch -n 5 "docker exec palantir-postgres psql -U palantir -d palantir -c \
  'SELECT category, count(*), max(collected_at) AS latest_stream FROM metric_snapshots GROUP BY category;'"

# 2. Query live node metrics via REST API
curl -s http://localhost:8000/api/v1/nodes/1/metrics | python3 -m json.tool

# 3. Stream background Celery worker collection logs
docker logs -f --tail 25 palantir-celery-worker
```

### Running Backend Integration & Unit Tests
```bash
# Run prioritized API contract test suite
docker exec palantir-backend pytest -v tests/test_priority_api_contracts.py

# Run security & authentication test suite
docker exec palantir-backend pytest -v tests/test_security.py
```

---

## 7. Configuration Reference

All environment variables are declared in `.env` (template provided in `.env.example`).

| Variable | Description | Default / Example |
| :--- | :--- | :--- |
| `POSTGRES_USER` | PostgreSQL database user | `palantir` |
| `POSTGRES_PASSWORD` | PostgreSQL database password | Secure random hex |
| `POSTGRES_DB` | Primary database name | `palantir` |
| `DATABASE_URL` | Async SQLAlchemy database URL | `postgresql+asyncpg://palantir:...@localhost:5432/palantir` |
| `SYNC_DATABASE_URL` | Sync psycopg database URL for Celery | `postgresql+psycopg://palantir:...@localhost:5432/palantir` |
| `REDIS_URL` | Redis broker and caching URL | `redis://localhost:6379/0` |
| `PALANTIR_API_READ_TOKEN` | Bearer token for read-only API access | Secure 32-char hex |
| `PALANTIR_API_ADMIN_TOKEN` | Bearer token for administrator API access | Secure 32-char hex |
| `PALANTIR_API_ENROLL_TOKEN`| Bearer token for automated node enrollment | Secure 32-char hex |
| `AGENT_AUTH_TOKEN` | Shared secret for Host Collector (`:20000`) | Secure 32-char hex |
| `PALANTIR_WEBHOOK_SECRET` | Secret for alert webhook integration | Secure 32-char hex |
| `PALANTIR_LAN_BIND_IP` | Reverse proxy LAN bind address | `127.0.0.1` |
| `METRICS_RETENTION_HOURS` | Retention window for raw metric snapshots | `24` |
| `LOG_RETENTION_DAYS` | Retention window for security log events | `7` |
| `NODE_REACHABLE_SECONDS` | Timeout before node is marked unreachable | `180` |
| `NODE_STALE_SECONDS` | Timeout before node is marked stale | `900` |

---

## 8. Security & Network Ports

| Port | Service | Access / Boundary |
| :--- | :--- | :--- |
| `3000` | React UI Dashboard | Operator LAN / Localhost |
| `8000` | FastAPI Backend & REST API | Master Server Localhost (`/docs` for OpenAPI Swagger) |
| `20000` | PALANTIR Host Collector | Target Host (Protected by Bearer Token) |
| `5432` | PostgreSQL 16 Database | Master Server Localhost / Docker internal network |
| `6379` | Redis 7 Task Broker & Cache | Master Server Localhost / Docker internal network |

---

## 9. Project Directory Structure

```
PALANTIR/
├── agent/                  # Standalone Linux Host Collector daemon (:20000)
│   ├── collector.py        # Host telemetry & log scraper
│   ├── Dockerfile          # Agent container definition
│   ├── requirements.txt    # Agent Python dependencies
│   └── tests/              # Collector unit tests
├── backend/                # FastAPI Master Backend & Celery Workers
│   ├── api/v1/             # REST API routers (nodes, metrics, alerts, thresholds)
│   ├── core/               # App configuration, database, Redis & authentication
│   ├── models/             # SQLAlchemy ORM models (Nodes, Snapshots, Alerts)
│   ├── services/           # Metric scrapers, threshold engine, investigations
│   ├── workers/            # Celery background tasks (scrapes, pruning, health)
│   ├── Dockerfile          # Production backend multi-stage Docker build
│   └── pyproject.toml      # Backend dependencies & tools configuration
├── frontend/               # React 18 / Vite Dashboard (:3000)
│   ├── src/                # UI components, API client, hooks & state
│   ├── package.json        # Frontend npm dependencies
│   └── vite.config.js      # Vite build and proxy configuration
├── scripts/                # Deployment and operations automation
│   ├── Automatic-Master-Server-Setup.sh        # One-click Master server deployment
│   ├── Automatic-Host-Setup.sh                 # One-click Target Host deployment
│   └── Automatic-Build-And-Push-Docker-Image.sh # Automated Docker build & push
├── sql/
│   └── init.sql            # PostgreSQL schema, indexes & time partitions
├── Caddyfile               # Production HTTPS reverse proxy configuration
├── docker-compose.yml      # Master stack compose definition (Postgres, Redis, Backend, Workers)
├── .env.example            # Environment variables configuration template
└── USEFUL_INFO.md          # Comprehensive reference guide & operational handbook
```

---

## 10. Building and Publishing Docker Images

To build and push updated production images:

```bash
# Run the automated build & push script
bash scripts/Automatic-Build-And-Push-Docker-Image.sh
```

---

## 11. License

Licensed under the MIT License. See [LICENSE](file:///home/ma542005/PALANTIR/LICENSE) for details.
