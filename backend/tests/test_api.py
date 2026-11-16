import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import respx
import httpx
from httpx import AsyncClient, ASGITransport
from main import app
from core.config import settings
from core.api_auth import get_api_role
from models.node import MonitoredNode
from models.metric import MetricSnapshot
from models.alert import AlertEvent
from models.investigation_evidence import InvestigationEvidence
from models.investigation import AgentInvestigation
from models.pcap_analysis import (
    PcapAnalysisRuns,
    PcapArtifacts,
    PcapCveMatches,
    PcapFlows,
    PcapIocs,
    PcapSeverityScores,
    TcpSessions,
)
from core.database import AsyncSessionLocal
from services import investigations as investigation_service
from services import alerts as alert_service
from sqlalchemy import select


@pytest.fixture
async def client(monkeypatch):
    # Business endpoint tests use an explicit test-only admin identity. API
    # authentication itself is covered independently in test_security.py.
    app.dependency_overrides[get_api_role] = lambda: "admin"
    monkeypatch.setattr(settings, "PALANTIR_WEBHOOK_SECRET", "test-webhook-secret-" + "x" * 40)
    monkeypatch.setattr(investigation_service, "_enqueue", lambda *_args, **_kwargs: None)

    async def no_pcap_request(*_args, **_kwargs):
        return 0

    monkeypatch.setattr(investigation_service, "request_pcap_evidence_for_alert", no_pcap_request)
    monkeypatch.setattr(alert_service, "request_pcap_evidence_for_alert", no_pcap_request)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as ac:
            yield ac
    finally:
        app.dependency_overrides.pop(get_api_role, None)


@pytest.fixture
async def existing_node():
    """Ensure an isolated test fixture node exists during test execution."""
    async with AsyncSessionLocal() as session:
        stmt = select(MonitoredNode).where(MonitoredNode.hostname == "test-fixture-node")
        node = (await session.execute(stmt)).scalar_one_or_none()
        if not node:
            node = MonitoredNode(
                hostname="test-fixture-node",
                collector_url="http://127.0.0.1:20000",
                os_type="linux",
                active=True,
                context_count=200,
                alert_count=50,
            )
            session.add(node)
            await session.commit()
            await session.refresh(node)
        elif not node.active:
            node.active = True
            await session.commit()
            await session.refresh(node)

    yield node

    # Clean up test fixture node after test
    try:
        async with AsyncSessionLocal() as cleanup_session:
            stmt = select(MonitoredNode).where(MonitoredNode.id == node.id)
            n = (await cleanup_session.execute(stmt)).scalar_one_or_none()
            if n:
                await cleanup_session.delete(n)
                await cleanup_session.commit()
    except Exception:
        pass


# =====================================================================
# Health Check Endpoint
# =====================================================================

@pytest.mark.asyncio
async def test_healthz(client: AsyncClient):
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["app"] == settings.PROJECT_NAME


# =====================================================================
# Monitored Nodes Endpoints
# =====================================================================

@pytest.mark.asyncio
async def test_list_and_get_nodes(client: AsyncClient, existing_node: MonitoredNode):
    # List active nodes
    resp = await client.get("/api/v1/nodes")
    assert resp.status_code == 200
    nodes = resp.json()
    assert isinstance(nodes, list)
    assert any(n["hostname"] == existing_node.hostname for n in nodes)

    # Get specific existing node
    resp = await client.get(f"/api/v1/nodes/{existing_node.id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == existing_node.id
    assert resp.json()["hostname"] == existing_node.hostname

    # Get non-existent node
    resp = await client.get("/api/v1/nodes/999999")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Node not found"

    # Invalid path parameter validation
    resp = await client.get("/api/v1/nodes/0")
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_fleet_telemetry_returns_latest_full_snapshot_and_omits_sample_rows(
    client: AsyncClient,
    existing_node: MonitoredNode,
):
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as session:
        session.add_all([
            MetricSnapshot(
                node_id=existing_node.id,
                collected_at=now,
                category="system",
                data={"cpu_pct": 44.5},
                cpu_pct=44.5,
                ram_used_mb=400.0,
                ram_total_mb=1000.0,
                top_processes=[{"name": "collector", "cpu_pct": 3.2}],
            ),
            MetricSnapshot(
                node_id=existing_node.id,
                collected_at=now + timedelta(seconds=1),
                category="system",
                data={"sample": "cpu", "cpu_pct": 99.0},
                cpu_pct=99.0,
            ),
        ])
        await session.commit()

    response = await client.get("/api/v1/fleet/telemetry?limit=5")
    assert response.status_code == 200
    payload = response.json()
    entry = next(row for row in payload["items"] if row["node_id"] == existing_node.id)
    assert entry["cpu_pct"] == 44.5
    assert entry["ram_pct"] == 40.0
    assert entry["top_processes"] == [{"name": "collector", "cpu_pct": 3.2}]
    assert entry["collected_at"] == now.isoformat()
    assert "storage_key" not in entry


@pytest.mark.asyncio
@respx.mock
async def test_register_and_deactivate_node(client: AsyncClient):
    new_node_url = "http://192.168.10.200:20000"

    # Mock PALANTIR Collector endpoints
    respx.get(f"{new_node_url}/healthz").respond(
        status_code=200,
        json={"status": "ok"},
    )
    respx.get(f"{new_node_url}/api/v1/info").respond(
        status_code=200,
        json={
            "version": "1.0.0",
            "hostname": "test-sensor-node",
            "os": "Linux-6.8.0-x86_64-with-glibc2.39",
            "os_release": {"ID": "ubuntu", "PRETTY_NAME": "Ubuntu 24.04 LTS"},
        },
    )
    respx.get(f"{new_node_url}/api/v1/capabilities").respond(
        status_code=200,
        json={"capabilities": {"system": {"status": "available"}}},
    )

    # 1. Register new node
    payload = {
        "hostname": "test-sensor-node",
        "collector_url": new_node_url,
        "os_type": "linux",
    }
    resp = await client.post("/api/v1/nodes", json=payload)
    assert resp.status_code == 201
    node_data = resp.json()
    node_id = node_data["id"]
    assert node_data["hostname"] == "test-sensor-node"
    assert node_data["collector_url"] == new_node_url
    assert node_data["os_type"] == "linux"
    assert node_data["active"] is True

    # 2. Re-registering existing node updates metadata
    resp = await client.post("/api/v1/nodes", json=payload)
    assert resp.status_code == 201
    assert resp.json()["id"] == node_id

    # 3. Deactivate node
    del_resp = await client.delete(f"/api/v1/nodes/{node_id}")
    assert del_resp.status_code == 204

    # Verify node is deactivated
    get_resp = await client.get(f"/api/v1/nodes/{node_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["active"] is False

    # Deactivating non-existent node -> 404
    bad_del = await client.delete("/api/v1/nodes/999999")
    assert bad_del.status_code == 404


@pytest.mark.asyncio
@respx.mock
async def test_register_node_collector_offline(client: AsyncClient):
    respx.get("http://192.168.10.201:20000/api/v1/info").mock(
        side_effect=httpx.ConnectError("Connection refused")
    )
    payload = {
        "hostname": "offline-node",
        "collector_url": "http://192.168.10.201:20000",
        "os_type": "linux",
    }
    resp = await client.post("/api/v1/nodes", json=payload)
    assert resp.status_code == 502
    assert "unreachable" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_register_node_validation_and_ssrf(client: AsyncClient):
    # Invalid hostname format
    resp = await client.post(
        "/api/v1/nodes",
        json={"hostname": "bad host name!", "collector_url": "http://192.168.1.1:20000"},
    )
    assert resp.status_code == 422

    # Forbidden loopback port SSRF
    resp = await client.post(
        "/api/v1/nodes",
        json={"hostname": "ssrf-node", "collector_url": "http://127.0.0.1:5432"},
    )
    assert resp.status_code == 422

    # Cloud metadata IMDS SSRF
    resp = await client.post(
        "/api/v1/nodes",
        json={"hostname": "ssrf-imds", "collector_url": "http://169.254.169.254/latest"},
    )
    assert resp.status_code == 422

    # Extra fields forbidden (or ignored if extra=ignore)
    resp = await client.post(
        "/api/v1/nodes",
        json={
            "hostname": "bad-url-node",
            "collector_url": "ftp://192.168.1.50:20000",
        },
    )
    assert resp.status_code == 422


# =====================================================================
# Metrics Endpoints
# =====================================================================

@pytest.mark.asyncio
async def test_metrics_endpoints(client: AsyncClient, existing_node: MonitoredNode):
    # Get latest metrics for all categories
    resp = await client.get(f"/api/v1/nodes/{existing_node.id}/metrics")
    assert resp.status_code == 200
    data = resp.json()
    assert "network" in data
    assert "system" in data
    assert "processes" in data
    assert "containers" in data

    # Query specific category
    resp = await client.get(f"/api/v1/nodes/{existing_node.id}/metrics/system?limit=5")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

    # Invalid category
    resp = await client.get(f"/api/v1/nodes/{existing_node.id}/metrics/unknown_category")
    assert resp.status_code == 400
    assert "Invalid category" in resp.json()["detail"]

    # Non-existent node
    resp = await client.get("/api/v1/nodes/999999/metrics")
    assert resp.status_code == 404

    # Bounds validation on limit
    resp = await client.get(f"/api/v1/nodes/{existing_node.id}/metrics/system?limit=0")
    assert resp.status_code == 422

    resp = await client.get(f"/api/v1/nodes/{existing_node.id}/metrics/system?limit=101")
    assert resp.status_code == 422


# =====================================================================
# Alerts & Anomalies Endpoints
# =====================================================================

@pytest.mark.asyncio
async def test_alerts_and_anomalies_endpoints(client: AsyncClient, existing_node: MonitoredNode):
    # Alerts history
    resp = await client.get(f"/api/v1/nodes/{existing_node.id}/alerts")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

    # Active alerts
    resp = await client.get(f"/api/v1/nodes/{existing_node.id}/alerts/active")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

    # Anomalies history
    resp = await client.get(f"/api/v1/nodes/{existing_node.id}/anomalies")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

    # Non-existent node
    resp = await client.get("/api/v1/nodes/999999/alerts")
    assert resp.status_code == 404

    resp = await client.get("/api/v1/nodes/999999/anomalies")
    assert resp.status_code == 404


# =====================================================================
# Internal Webhook (/internal/alert) Security & Classification
# =====================================================================

@pytest.mark.asyncio
async def test_internal_webhook_auth_and_processing(client: AsyncClient, existing_node: MonitoredNode):
    payload = {
        "node": existing_node.hostname,
        "alert": "test_security_spike",
        "chart": "system.cpu",
        "status": "CRITICAL",
        "value": 98.7,
        "units": "%",
    }

    # 1. Missing secret header -> 403 Forbidden
    resp = await client.post("/internal/alert", json=payload)
    assert resp.status_code == 403

    # 2. Invalid secret header -> 403 Forbidden
    resp = await client.post(
        "/internal/alert",
        headers={"X-PALANTIR-Secret": "invalid-secret"},
        json=payload,
    )
    assert resp.status_code == 403

    # 3. Valid secret but unregistered node -> 200 Ignored
    unregistered_payload = dict(payload, node="unknown-ghost-node")
    resp = await client.post(
        "/internal/alert",
        headers={"X-PALANTIR-Secret": settings.PALANTIR_WEBHOOK_SECRET},
        json=unregistered_payload,
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"

    # 4. Valid secret and registered node -> 200 Received and an investigation link.
    resp = await client.post(
        "/internal/alert",
        headers={"X-PALANTIR-Secret": settings.PALANTIR_WEBHOOK_SECRET},
        json=payload,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "received"
    event_id = data["event_id"]

    # Verify event in DB
    async with AsyncSessionLocal() as session:
        stmt = select(AlertEvent).where(AlertEvent.id == event_id)
        ev = (await session.execute(stmt)).scalar_one_or_none()
        assert ev is not None
        assert ev.alert_name == "test_security_spike"
        assert ev.status == "CRITICAL"
        assert ev.triggered_agent is False
        assert ev.investigation_id is not None

    # 5. Case-insensitivity normalization test (lowercase "warning" -> "WARNING")
    warn_payload = {
        "node": existing_node.hostname,
        "alert": "ram_pressure",
        "chart": "system.ram",
        "status": "warning",
        "value": 85.0,
        "units": "%",
    }
    resp = await client.post(
        "/internal/alert",
        headers={"X-PALANTIR-Secret": settings.PALANTIR_WEBHOOK_SECRET},
        json=warn_payload,
    )
    assert resp.status_code == 200
    warn_event_id = resp.json()["event_id"]

    async with AsyncSessionLocal() as session:
        stmt = select(AlertEvent).where(AlertEvent.id == warn_event_id)
        ev = (await session.execute(stmt)).scalar_one_or_none()
        assert ev.status == "WARNING"
        assert ev.triggered_agent is False
        assert ev.investigation_id is not None

    # 6. CLEAR status -> triggered_agent should be False
    clear_payload = {
        "node": existing_node.hostname,
        "alert": "ram_pressure",
        "chart": "system.ram",
        "status": "CLEAR",
        "value": 40.0,
        "units": "%",
    }
    resp = await client.post(
        "/internal/alert",
        headers={"X-PALANTIR-Secret": settings.PALANTIR_WEBHOOK_SECRET},
        json=clear_payload,
    )
    assert resp.status_code == 200
    clear_event_id = resp.json()["event_id"]

    async with AsyncSessionLocal() as session:
        stmt = select(AlertEvent).where(AlertEvent.id == clear_event_id)
        ev = (await session.execute(stmt)).scalar_one_or_none()
        assert ev.status == "CLEAR"
        assert ev.triggered_agent is False


# =====================================================================
# Investigations Endpoints
# =====================================================================

@pytest.mark.asyncio
async def test_investigations_lifecycle(client: AsyncClient, existing_node: MonitoredNode):
    # 1. Non-existent node -> 404
    resp = await client.post(
        "/api/v1/investigations",
        json={"node_id": 999999, "trigger_type": "manual"},
    )
    assert resp.status_code == 404

    # 2. Invalid trigger_type pattern -> 422
    resp = await client.post(
        "/api/v1/investigations",
        json={"node_id": existing_node.id, "trigger_type": "invalid_type"},
    )
    assert resp.status_code == 422

    # 3. Create valid investigation
    resp = await client.post(
        "/api/v1/investigations",
        json={"node_id": existing_node.id, "trigger_type": "manual"},
    )
    assert resp.status_code == 202
    data = resp.json()
    assert "id" in data
    inv_id = data["id"]
    assert data["status"] == "queued"
    assert data["job_id"]

    # 4. List investigations
    resp = await client.get("/api/v1/investigations")
    assert resp.status_code == 200
    inv_list = resp.json()
    assert any(i["id"] == inv_id for i in inv_list)

    # 5. Get investigation details
    resp = await client.get(f"/api/v1/investigations/{inv_id}")
    assert resp.status_code == 200
    inv_detail = resp.json()
    assert inv_detail["id"] == inv_id
    assert inv_detail["node_id"] == existing_node.id
    assert inv_detail["trigger_type"] == "manual"
    assert inv_detail["status"] == "queued"

    # 6. Non-existent investigation ID -> 404
    resp = await client.get("/api/v1/investigations/999999")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_investigation_pcap_evidence_list_and_download(
    client: AsyncClient,
    existing_node: MonitoredNode,
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(settings, "PCAP_STORAGE_DIR", tmp_path)
    created = await client.post(
        "/api/v1/investigations",
        json={"node_id": existing_node.id, "trigger_type": "manual"},
    )
    assert created.status_code == 202
    investigation_id = created.json()["id"]
    stored = tmp_path / "node" / "capture.pcap.zst"
    stored.parent.mkdir(parents=True)
    stored.write_bytes(b"pcap evidence fixture")

    async with AsyncSessionLocal() as session:
        complete = InvestigationEvidence(
            investigation_id=investigation_id,
            node_id=existing_node.id,
            evidence_type="pcap_collection",
            collector_file_id="capture_20261112T120000Z_0123456789ab.pcap",
            file_name="capture.pcap.zst",
            storage_key="node/capture.pcap.zst",
            size_bytes=stored.stat().st_size,
            duration_seconds=300,
            status="complete",
        )
        pending = InvestigationEvidence(
            investigation_id=investigation_id,
            node_id=existing_node.id,
            evidence_type="pcap_collection",
            status="queued",
        )
        session.add_all([complete, pending])
        await session.commit()
        await session.refresh(complete)
        await session.refresh(pending)
        complete_id, pending_id = complete.id, pending.id

    listed = await client.get(f"/api/v1/investigations/{investigation_id}/evidence")
    assert listed.status_code == 200
    entries = listed.json()["items"]
    assert {entry["file_id"] for entry in entries} == {complete_id, pending_id}
    assert next(entry for entry in entries if entry["file_id"] == complete_id)["duration_seconds"] == 300

    downloaded = await client.get(
        f"/api/v1/investigations/{investigation_id}/evidence/{complete_id}/download"
    )
    assert downloaded.status_code == 200
    assert downloaded.content == b"pcap evidence fixture"

    not_ready = await client.get(
        f"/api/v1/investigations/{investigation_id}/evidence/{pending_id}/download"
    )
    assert not_ready.status_code == 409
    deleted = await client.delete(f"/api/v1/investigations/{investigation_id}")
    assert deleted.status_code == 204
    assert not stored.exists()


@pytest.mark.asyncio
async def test_warning_alert_snapshot_is_recorded_and_transfer_is_queued(
    existing_node: MonitoredNode,
    monkeypatch,
):
    monkeypatch.setattr(settings, "PCAP_ALERT_COOLDOWN_SECONDS", 0)
    timestamp = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as session:
        event = AlertEvent(
            node_id=existing_node.id,
            alert_name="pcap-integration-test",
            chart="pcap.integration",
            status="WARNING",
        )
        session.add(event)
        await session.flush()
        investigation = AgentInvestigation(
            node_id=existing_node.id,
            job_id=str(uuid4()),
            queued_at=timestamp,
            trigger_type="alert",
            trigger_id=event.id,
            status="queued",
            progress=0,
        )
        session.add(investigation)
        await session.flush()
        event_id, investigation_id = event.id, investigation.id
        await session.commit()

        async def fake_snapshot(_self, trigger_type="manual"):
            assert trigger_type == "alert"
            return {
                "snapshot_id": "a" * 32,
                "files": [{
                    "file_id": "capture_20261112T120000Z_0123456789ab.pcap",
                    "filename": "capture_20261112T120000Z_0123456789ab.pcap.zst",
                    "size_bytes": 1024,
                    "original_size_bytes": 4096,
                    "capture_started_at": timestamp.isoformat(),
                    "capture_finished_at": timestamp.isoformat(),
                    "duration_seconds": 300,
                    "compression": "zst",
                }],
            }

        async def queued_transfer(_evidence_id):
            return True

        monkeypatch.setattr(investigation_service.AgentCollectorClient, "create_pcap_snapshot", fake_snapshot)
        monkeypatch.setattr(investigation_service, "_enqueue_pcap_transfer", queued_transfer)
        queued = await investigation_service.request_pcap_evidence_for_alert(
            session,
            event_id=event_id,
            node_id=existing_node.id,
            investigation_id=investigation_id,
        )
        assert queued == 1
        evidence = (await session.execute(
            select(InvestigationEvidence).where(
                InvestigationEvidence.investigation_id == investigation_id
            )
        )).scalar_one()
        assert evidence.status == "queued"
        assert evidence.alert_event_id == event_id
        assert evidence.capture_snapshot_id == "a" * 32


@pytest.mark.asyncio
async def test_investigation_pcap_analysis_api(
    client: AsyncClient,
    existing_node: MonitoredNode,
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(settings, "PCAP_STORAGE_DIR", tmp_path)
    created = await client.post(
        "/api/v1/investigations",
        json={"node_id": existing_node.id, "trigger_type": "manual"},
    )
    assert created.status_code == 202
    investigation_id = created.json()["id"]

    run_id = uuid4().hex
    async with AsyncSessionLocal() as session:
        ev = InvestigationEvidence(
            investigation_id=investigation_id,
            node_id=existing_node.id,
            evidence_type="pcap_collection",
            file_name="analysis.pcap",
            storage_key="analysis.pcap",
            status="complete",
        )
        session.add(ev)
        await session.flush()
        ev_id = ev.id

        run = PcapAnalysisRuns(
            run_id=run_id,
            evidence_id=ev_id,
            investigation_id=investigation_id,
            node_id=existing_node.id,
            status="complete",
            current_step="score_severity",
        )
        session.add(run)
        await session.flush()

        score = PcapSeverityScores(
            run_id=run_id,
            evidence_id=ev_id,
            investigation_id=investigation_id,
            overall_score=8.5,
            overall_severity="high",
            cvss_base_max=10.0,
            ioc_risk_score=6.0,
            anomaly_score=4.0,
            factors={"cvss_base_max": 10.0},
        )
        session.add(score)

        flow = PcapFlows(
            run_id=run_id,
            evidence_id=ev_id,
            src_ip="192.168.1.100",
            dst_ip="93.184.216.34",
            src_port=54321,
            dst_port=443,
            protocol="tcp",
            flow_key="tcp:192.168.1.100:54321-93.184.216.34:443",
            packet_count=20,
            byte_count=2500,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        session.add(flow)
        session.add_all([
            PcapFlows(
                run_id=run_id,
                evidence_id=ev_id,
                src_ip="192.168.1.101",
                dst_ip="198.51.100.10",
                src_port=54001,
                dst_port=53,
                protocol="udp",
                flow_key=f"udp:192.168.1.101:54001-198.51.100.10:53-{run_id}",
                packet_count=4,
                byte_count=320,
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
            ),
            PcapFlows(
                run_id=run_id,
                evidence_id=ev_id,
                src_ip="192.168.1.102",
                dst_ip="203.0.113.8",
                src_port=54002,
                dst_port=443,
                protocol="tcp",
                flow_key=f"tcp:192.168.1.102:54002-203.0.113.8:443-{run_id}",
                packet_count=8,
                byte_count=640,
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
            ),
        ])
        await session.flush()

        tcp_session = TcpSessions(
            run_id=run_id,
            evidence_id=ev_id,
            src_ip="192.168.1.100",
            dst_ip="93.184.216.34",
            src_port=54321,
            dst_port=443,
            state="established",
            total_bytes=2500,
            reassembled_bytes=2200,
            reassembly_quality=0.88,
            confidence="high",
            snaplen=65535,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        session.add(tcp_session)
        await session.flush()

        cve = PcapCveMatches(
            run_id=run_id,
            evidence_id=ev_id,
            cve_id="CVE-2021-44228",
            cvss_score=10.0,
            severity="critical",
            match_type="payload_signature",
            confidence="high",
            description="Log4Shell attempt",
            flow_id=flow.id,
        )
        session.add(cve)

        ioc = PcapIocs(
            run_id=run_id,
            evidence_id=ev_id,
            ioc_type="ipv4",
            ioc_value="93.184.216.34",
            is_allowlisted=False,
        )
        session.add(ioc)

        from core.storage import get_storage_backend
        storage = get_storage_backend()
        storage_key, _sha = storage.save_artifact(f"analysis-{run_id}", b"<h1>Artifact Body</h1>", "html")

        art = PcapArtifacts(
            run_id=run_id,
            evidence_id=ev_id,
            artifact_type="http_response",
            content_type="text/html",
            size_bytes=22,
            sha256=_sha,
            storage_key=storage_key,
            flow_id=flow.id,
            session_id=tcp_session.id,
            metadata_json={"status_code": 200},
        )
        session.add(art)
        await session.commit()
        art_id = art.id

    # 1. Trigger endpoint
    monkeypatch.setattr("api.v1.investigations.start_pcap_analysis", lambda _ev_id: "new-test-run-id")
    trigger_resp = await client.post(f"/api/v1/investigations/{investigation_id}/analysis/trigger")
    assert trigger_resp.status_code == 202
    assert trigger_resp.json()["run_id"] == "new-test-run-id"

    # 2. List runs endpoint
    list_resp = await client.get(f"/api/v1/investigations/{investigation_id}/analysis")
    assert list_resp.status_code == 200
    list_json = list_resp.json()
    assert list_json["total_runs"] >= 1
    run_item = next(r for r in list_json["items"] if r["run_id"] == run_id)
    assert run_item["status"] == "complete"
    assert run_item["severity_score"]["overall_score"] == 8.5
    assert run_item["flow_count"] == 3
    assert run_item["session_count"] == 1
    assert run_item["cve_match_count"] == 1

    # 3. Detail run endpoint
    detail_resp = await client.get(f"/api/v1/investigations/{investigation_id}/analysis/{run_id}")
    assert detail_resp.status_code == 200
    detail_json = detail_resp.json()
    assert detail_json["severity"]["overall_severity"] == "high"
    assert len(detail_json["flows"]) == 3
    assert len(detail_json["sessions"]) == 1
    assert len(detail_json["cve_matches"]) == 1
    assert detail_json["cve_matches"][0]["cve_id"] == "CVE-2021-44228"
    assert len(detail_json["iocs"]) == 1

    compact_resp = await client.get(
        f"/api/v1/investigations/{investigation_id}/analysis/{run_id}?include_records=false"
    )
    assert compact_resp.status_code == 200
    assert compact_resp.json()["flows"] == []
    assert compact_resp.json()["counts"]["flows"] == 3

    first_page = await client.get(
        f"/api/v1/investigations/{investigation_id}/analysis/{run_id}/collections/flows?limit=2"
    )
    assert first_page.status_code == 200
    first_json = first_page.json()
    assert first_json["total_count"] == 3
    assert len(first_json["items"]) == 2
    assert first_json["has_more"] is True
    assert "storage_key" not in first_json["items"][0]

    second_page = await client.get(
        f"/api/v1/investigations/{investigation_id}/analysis/{run_id}/collections/flows",
        params={"limit": 2, "cursor": first_json["next_cursor"]},
    )
    assert second_page.status_code == 200
    assert len(second_page.json()["items"]) == 1
    assert second_page.json()["has_more"] is False
    assert not {row["id"] for row in first_json["items"]} & {row["id"] for row in second_page.json()["items"]}

    udp = await client.get(
        f"/api/v1/investigations/{investigation_id}/analysis/{run_id}/collections/flows?protocol=udp"
    )
    assert udp.status_code == 200
    assert udp.json()["total_count"] == 1
    assert udp.json()["items"][0]["protocol"] == "udp"

    sessions = await client.get(
        f"/api/v1/investigations/{investigation_id}/analysis/{run_id}/collections/sessions",
        params={"state": "established", "confidence": "high"},
    )
    assert sessions.status_code == 200
    assert sessions.json()["total_count"] == 1
    assert sessions.json()["items"][0]["reassembled_bytes"] == 2200

    artifacts = await client.get(
        f"/api/v1/investigations/{investigation_id}/analysis/{run_id}/collections/artifacts",
        params={"artifact_type": "http_response", "q": "text/html"},
    )
    assert artifacts.status_code == 200
    assert artifacts.json()["total_count"] == 1
    assert artifacts.json()["items"][0]["has_file"] is True
    assert "storage_key" not in artifacts.json()["items"][0]

    cves = await client.get(
        f"/api/v1/investigations/{investigation_id}/analysis/{run_id}/collections/cve_matches",
        params={"severity": "critical", "confidence": "high", "q": "Log4Shell"},
    )
    assert cves.status_code == 200
    assert cves.json()["total_count"] == 1
    assert cves.json()["items"][0]["flow_id"] == flow.id

    unallowlisted = await client.get(
        f"/api/v1/investigations/{investigation_id}/analysis/{run_id}/collections/iocs",
        params={"is_allowlisted": "false"},
    )
    assert unallowlisted.status_code == 200
    assert unallowlisted.json()["total_count"] == 1
    assert unallowlisted.json()["items"][0]["is_allowlisted"] is False

    invalid_cursor = await client.get(
        f"/api/v1/investigations/{investigation_id}/analysis/{run_id}/collections/flows?cursor=invalid"
    )
    assert invalid_cursor.status_code == 400

    unsupported_filter = await client.get(
        f"/api/v1/investigations/{investigation_id}/analysis/{run_id}/collections/flows?state=closed"
    )
    assert unsupported_filter.status_code == 400

    no_matches = await client.get(
        f"/api/v1/investigations/{investigation_id}/analysis/{run_id}/collections/flows",
        params={"protocol": "icmpv6", "q": "no-matching-indicator"},
    )
    assert no_matches.status_code == 200
    assert no_matches.json()["total_count"] == 0
    assert no_matches.json()["items"] == []

    wrong_investigation = await client.get(
        f"/api/v1/investigations/{investigation_id + 1}/analysis/{run_id}/collections/flows"
    )
    assert wrong_investigation.status_code == 404

    # 4. Artifact download endpoint
    dl_resp = await client.get(f"/api/v1/investigations/{investigation_id}/analysis/{run_id}/artifacts/{art_id}/download")
    assert dl_resp.status_code == 200
    assert dl_resp.content == b"<h1>Artifact Body</h1>"
    assert dl_resp.headers["content-type"].startswith("text/html")

