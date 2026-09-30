# PALANTIR — Netdata Autonomous Monitoring & Investigation Platform

PALANTIR integrates with Netdata Agent sensors across monitored nodes to collect high-resolution per-second performance metrics, evaluate machine learning anomaly scores, and ingest real-time alert webhooks.

## Architecture

- **Backend**: FastAPI (`/api/v1/*` for UI, `/internal/alert` for push webhooks).
- **Background Workers**: Celery with Redis broker (60s metric collection, 5m anomaly evaluation, 24h retention pruning).
- **Database**: PostgreSQL 16 with range-partitioned metric storage.
- **Sensor**: Lightweight Netdata Agent instances on monitored nodes.

## Running Tests Locally

1. Create and activate a Python virtual environment:
   ```bash
   cd /home/abdullah-ahmad/Desktop/PALANTIR/backend
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. Run test suite:
   ```bash
   pytest
   ```

## Starting with Docker Compose

1. Copy `.env.example` to `.env`:
   ```bash
   cd /home/abdullah-ahmad/Desktop/PALANTIR
   cp .env.example .env
   ```

2. Start the services:
   ```bash
   docker compose up --build -d
   ```

3. View logs:
   ```bash
   docker compose logs -f backend celery_worker
   ```
