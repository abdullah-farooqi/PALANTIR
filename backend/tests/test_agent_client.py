import asyncio

import pytest

from integrations.agent.client import AgentCollectorClient


def test_client_maps_canonical_vm_category_and_stale_data():
    client = AgentCollectorClient("http://agent")
    requested = []

    async def fake_get(path, params=None, timeout=None):
        requested.append(path)
        return {
            "schema_version": "1.0",
            "category": "virtual_machines",
            "collector_version": "0.1.0",
            "collected_at": "2026-11-16T12:00:00Z",
            "status": {"state": "stale", "reason": "runtime unavailable"},
            "data": {"virtual_machines": [{"name": "vm-a"}]},
        }

    client._get = fake_get
    result = asyncio.run(client.get_metrics("vms"))

    assert requested == ["/v1/snapshot/virtual_machines"]
    assert result["status"] == "partial"
    assert result["data"]["vms"] == [{"name": "vm-a"}]
    assert result["status_detail"]["reason"] == "runtime unavailable"


def test_client_adapts_canonical_network_interfaces_for_existing_consumers():
    client = AgentCollectorClient("http://agent")

    async def fake_get(path, params=None, timeout=None):
        return {
            "status": {"state": "available"},
            "data": {"interfaces": [{"name": "lo", "is_loopback": True, "bytes_recv": 10}]},
        }

    client._get = fake_get
    result = asyncio.run(client.get_metrics("network"))

    assert result["data"]["interfaces"] == {"lo": {"is_loopback": True, "bytes_recv": 10}}
    assert result["data"]["interface_rows"][0]["name"] == "lo"


def test_client_falls_back_to_legacy_metrics_route():
    client = AgentCollectorClient("http://agent")
    requested = []

    async def fake_get(path, params=None, timeout=None):
        requested.append(path)
        if path.startswith("/v1/"):
            raise RuntimeError("404 not found")
        return {"category": "system", "status": "available", "data": {"cpu_pct": 2}}

    client._get = fake_get
    result = asyncio.run(client.get_metrics("system"))

    assert requested == ["/v1/snapshot/system", "/api/v1/metrics/system"]
    assert result["data"]["cpu_pct"] == 2


def test_client_does_not_mask_canonical_authorization_errors_with_legacy_retry():
    client = AgentCollectorClient("http://agent")
    requested = []

    async def fake_get(path, params=None, timeout=None):
        requested.append(path)
        raise RuntimeError("Host collector request failed (HTTP 403): forbidden")

    client._get = fake_get
    with pytest.raises(RuntimeError, match="HTTP 403"):
        asyncio.run(client.get_metrics("system"))

    assert requested == ["/v1/snapshot/system"]


def test_client_sends_alert_trigger_on_canonical_pcap_snapshot():
    client = AgentCollectorClient("http://agent")
    requested = []

    async def fake_post(path, params=None, timeout=None, json_body=None):
        requested.append((path, params))
        return {"snapshot_id": "a" * 32}

    client._post = fake_post
    result = asyncio.run(client.create_pcap_snapshot(trigger_type="alert"))

    assert requested == [("/v1/pcap/snapshot", {"trigger_type": "alert"})]
    assert result["snapshot_id"] == "a" * 32


def test_client_prefers_canonical_pcap_files_route():
    client = AgentCollectorClient("http://agent")
    requested = []

    async def fake_get(path, params=None, timeout=None):
        requested.append((path, params))
        return {"schema_version": "1.0", "files": []}

    client._get = fake_get
    result = asyncio.run(client.get_pcap_files(snapshot_id="b" * 32))

    assert requested == [("/v1/pcap/files", {"snapshot_id": "b" * 32})]
    assert result["schema_version"] == "1.0"


def test_client_falls_back_to_legacy_pcap_files_route():
    client = AgentCollectorClient("http://agent")
    requested = []

    async def fake_get(path, params=None, timeout=None):
        requested.append(path)
        if path.startswith("/v1/"):
            raise RuntimeError("404 not found")
        return {"schema_version": 1, "files": []}

    client._get = fake_get
    result = asyncio.run(client.get_pcap_files())

    assert requested == ["/v1/pcap/files", "/api/v1/capture/files"]
    assert result["schema_version"] == 1
