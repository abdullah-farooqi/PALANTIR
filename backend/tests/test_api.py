import pytest
import respx
import httpx
from httpx import AsyncClient, ASGITransport
from main import app
from core.config import settings
from models.node import MonitoredNode
from models.alert import AlertEvent
from core.database import AsyncSessionLocal
from sqlalchemy import select


@pytest.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac


@pytest.fixture
async def existing_node():
    """Ensure at least one node ('local-node') exists in DB."""
    async with AsyncSessionLocal() as session:
        stmt = select(MonitoredNode).where(MonitoredNode.hostname == "local-node")
        node = (await session.execute(stmt)).scalar_one_or_none()
        if not node:
            node = MonitoredNode(
                hostname="local-node",
                netdata_url="http://netdata:19999",
                os_type="linux",
                active=True,
                context_count=200,
                alert_count=50,
            )
            session.add(node)
            await session.commit()
            await session.refresh(node)
        return node


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
    assert any(n["hostname"] == "local-node" for n in nodes)

    # Get specific existing node
    resp = await client.get(f"/api/v1/nodes/{existing_node.id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == existing_node.id
    assert resp.json()["hostname"] == "local-node"

    # Get non-existent node
    resp = await client.get("/api/v1/nodes/999999")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Node not found"

    # Invalid path parameter validation
    resp = await client.get("/api/v1/nodes/0")
    assert resp.status_code == 422


@pytest.mark.asyncio
@respx.mock
async def test_register_and_deactivate_node(client: AsyncClient):
    new_node_url = "http://192.168.10.200:19999"

    # Mock Netdata Agent endpoints
    respx.get(f"{new_node_url}/api/v1/info").respond(
        status_code=200,
        json={"version": "v2.11.1", "uid": "mock-node-uid"},
    )
    respx.get(f"{new_node_url}/api/v1/contexts").respond(
        status_code=200,
        json={"contexts": {"system.cpu": {}, "net.net": {}, "disk.io": {}}},
    )
    respx.get(f"{new_node_url}/api/v1/alarms").respond(
        status_code=200,
        json={"alarms": {"high_cpu": {}, "packet_drops": {}}},
    )

    # 1. Register new node
    payload = {
        "hostname": "test-sensor-node",
        "netdata_url": new_node_url,
        "os_type": "linux",
    }
    resp = await client.post("/api/v1/nodes", json=payload)
    assert resp.status_code == 201
    node_data = resp.json()
    node_id = node_data["id"]
    assert node_data["hostname"] == "test-sensor-node"
    assert node_data["context_count"] == 3
    assert node_data["alert_count"] == 2
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
async def test_register_node_netdata_offline(client: AsyncClient):
    respx.get("http://192.168.10.201:19999/api/v1/info").mock(
        side_effect=httpx.ConnectError("Connection refused")
    )
    payload = {
        "hostname": "offline-node",
        "netdata_url": "http://192.168.10.201:19999",
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
        json={"hostname": "bad host name!", "netdata_url": "http://192.168.1.1:19999"},
    )
    assert resp.status_code == 422

    # Forbidden loopback port SSRF
    resp = await client.post(
        "/api/v1/nodes",
        json={"hostname": "ssrf-node", "netdata_url": "http://127.0.0.1:5432"},
    )
    assert resp.status_code == 422

    # Cloud metadata IMDS SSRF
    resp = await client.post(
        "/api/v1/nodes",
        json={"hostname": "ssrf-imds", "netdata_url": "http://169.254.169.254/latest"},
    )
    assert resp.status_code == 422

    # Extra fields forbidden
    resp = await client.post(
        "/api/v1/nodes",
        json={
            "hostname": "valid-node",
            "netdata_url": "http://192.168.1.50:19999",
            "unknown_field": "injected",
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
        "node": "local-node",
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

    # 4. Valid secret and registered node -> 200 Received + triggered_agent=True
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
        assert ev.triggered_agent is True

    # 5. Case-insensitivity normalization test (lowercase "warning" -> "WARNING")
    warn_payload = {
        "node": "local-node",
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
        assert ev.triggered_agent is True

    # 6. CLEAR status -> triggered_agent should be False
    clear_payload = {
        "node": "local-node",
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
    assert resp.status_code == 201
    data = resp.json()
    assert "id" in data
    inv_id = data["id"]
    assert data["status"] == "running"

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
    assert inv_detail["status"] == "running"

    # 6. Non-existent investigation ID -> 404
    resp = await client.get("/api/v1/investigations/999999")
    assert resp.status_code == 404
