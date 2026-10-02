import pytest
import respx
import httpx
from integrations.netdata.parsers import (
    extract_value,
    parse_rows,
    parse_anomaly_rates,
)
from integrations.netdata.schemas import (
    NetdataDataResponse,
    NetdataWeightsResponse,
    NetdataInfoResponse,
)
from integrations.netdata.client import NetdataClient
from integrations.netdata.exceptions import NetdataUnavailable, NetdataParseError
from integrations.netdata.contexts import (
    NetworkContexts,
    SystemContexts,
    ProcessContexts,
)


# =====================================================================
# Unit Tests: Value Extraction & Parsers
# =====================================================================

def test_extract_value_triples():
    """Verify [value, arp, pa] triple handling according to spec."""
    assert extract_value([1234.5, 0, 0]) == 1234.5
    assert extract_value([0.0, 1, 0]) == 0.0
    assert extract_value([None, 0, 0]) is None
    assert extract_value([]) is None


def test_extract_value_scalars():
    """Verify scalar fallback for backward compatibility."""
    assert extract_value(42.5) == 42.5
    assert extract_value(100) == 100.0
    assert extract_value("12.34") == 12.34
    assert extract_value(None) is None
    assert extract_value("invalid") is None


def test_extract_value_nan_inf_resilience():
    """Verify NaN and Inf values are safely converted to None."""
    assert extract_value([float("nan"), 0, 0]) is None
    assert extract_value([float("inf"), 0, 0]) is None
    assert extract_value([float("-inf"), 0, 0]) is None
    assert extract_value(float("nan")) is None
    assert extract_value(float("inf")) is None
    assert extract_value("nan") is None
    assert extract_value("Infinity") is None


def test_parse_rows():
    """Verify conversion of json2 response into flat row dicts."""
    raw_payload = {
        "result": {
            "labels": ["time", "eth0_received", "eth0_sent", "lo_received"],
            "data": [
                [1727000000, [1234.5, 0, 0], [567.8, 0, 0], [0.1, 0, 0]],
                [1727000001, [1289.3, 0, 0], [543.2, 0, 0], [0.2, 0, 0]],
            ],
        }
    }
    response = NetdataDataResponse(**raw_payload)
    parsed = parse_rows(response)

    assert len(parsed) == 2
    assert parsed[0]["timestamp"] == 1727000000
    assert parsed[0]["eth0_received"] == 1234.5
    assert parsed[0]["eth0_sent"] == 567.8
    assert parsed[0]["lo_received"] == 0.1

    assert parsed[1]["timestamp"] == 1727000001
    assert parsed[1]["eth0_received"] == 1289.3


def test_parse_rows_strips_machine_guid():
    """Verify parse_rows automatically strips Netdata machine GUID suffixes."""
    raw_payload = {
        "result": {
            "labels": [
                "time",
                "system.cpu@87f56850-57c0-43b7-a6e2-13c37aaaa009",
                "system.ram@87f56850-57c0-43b7-a6e2-13c37aaaa009",
            ],
            "data": [
                [1727000000, [15.2, 0, 0], [4096.0, 0, 0]],
            ],
        }
    }
    response = NetdataDataResponse(**raw_payload)
    parsed = parse_rows(response)
    assert len(parsed) == 1
    assert parsed[0]["timestamp"] == 1727000000
    assert "system.cpu" in parsed[0]
    assert parsed[0]["system.cpu"] == 15.2
    assert "system.ram" in parsed[0]
    assert parsed[0]["system.ram"] == 4096.0
    assert "system.cpu@87f56850-57c0-43b7-a6e2-13c37aaaa009" not in parsed[0]


def test_parse_rows_jagged_or_missing_dimensions():
    """Verify parse_rows handles jagged rows without crashing."""
    raw_payload = {
        "result": {
            "labels": ["time", "eth0_received", "eth0_sent"],
            "data": [
                [1727000000, [100.0, 0, 0]],  # missing eth0_sent column
                [1727000001],                  # missing all data columns
            ],
        }
    }
    response = NetdataDataResponse(**raw_payload)
    parsed = parse_rows(response)
    assert len(parsed) == 2
    assert parsed[0]["eth0_received"] == 100.0
    assert parsed[0]["eth0_sent"] is None
    assert parsed[1]["eth0_received"] is None
    assert parsed[1]["eth0_sent"] is None


def test_parse_anomaly_rates():
    """Verify anomaly rate parser handles both active and warmup states."""
    active_payload = {
        "result": {
            "net.net": {"anomaly_rate": 0.82},
            "system.cpu": {"anomaly_rate": 0.15},
            "system.ram": {"anomaly_rate": 0.09},
        }
    }
    response = NetdataWeightsResponse(**active_payload)
    rates = parse_anomaly_rates(response)
    assert rates["net.net"] == 0.82
    assert rates["system.cpu"] == 0.15
    assert rates["system.ram"] == 0.09

    # Warmup scenario (empty dict or empty list result)
    warmup_response = NetdataWeightsResponse(result={})
    assert parse_anomaly_rates(warmup_response) == {}

    warmup_list_response = NetdataWeightsResponse(result=[])
    assert parse_anomaly_rates(warmup_list_response) == {}


def test_parse_anomaly_rates_clamping_and_corruption():
    """Verify anomaly rates clamp to [0, 1] and reject NaN, Inf, and malformed items."""
    corrupt_payload = {
        "result": {
            "ctx.over": {"anomaly_rate": 1.5},       # Should clamp to 1.0
            "ctx.under": {"anomaly_rate": -0.2},     # Should clamp to 0.0
            "ctx.nan": {"anomaly_rate": float("nan")},  # Should omit
            "ctx.inf": {"anomaly_rate": float("inf")},  # Should omit
            "ctx.bad": {"anomaly_rate": "invalid"},  # Should omit
            "ctx.empty": {},                         # Should omit
        }
    }
    response = NetdataWeightsResponse(**corrupt_payload)
    rates = parse_anomaly_rates(response)
    assert rates["ctx.over"] == 1.0
    assert rates["ctx.under"] == 0.0
    assert "ctx.nan" not in rates
    assert "ctx.inf" not in rates
    assert "ctx.bad" not in rates
    assert "ctx.empty" not in rates


# =====================================================================
# Unit Tests: NetdataClient with Mocked HTTP
# =====================================================================

@pytest.mark.asyncio
@respx.mock
async def test_client_info():
    client = NetdataClient(base_url="http://testnode:19999")
    respx.get("http://testnode:19999/api/v1/info").respond(
        status_code=200,
        json={
            "version": "v2.11.0-466-gf5bc7f2350",
            "uid": "abc123node",
            "mirrored_hosts": [],
        },
    )

    info = await client.info()
    assert isinstance(info, NetdataInfoResponse)
    assert info.version == "v2.11.0-466-gf5bc7f2350"
    assert info.uid == "abc123node"
    assert info.mirrored_hosts == []


@pytest.mark.asyncio
@respx.mock
async def test_client_v3_info_and_host_metadata():
    client = NetdataClient(base_url="http://testnode:19999")
    respx.get("http://testnode:19999/api/v1/info").respond(
        status_code=200,
        json={
            "version": "v2.11.1",
            "uid": "abc123node",
            "ram_total": "16410095616",
            "host_labels": {"_hostname": "test-host", "_os": "linux"},
        },
    )
    respx.get("http://testnode:19999/api/v3/info").respond(
        status_code=200,
        json={
            "api": 2,
            "agents": [{"mg": "machine-guid", "nd": "node-id", "nm": "test-host"}],
            "nodes": [],
            "timings": {},
        },
    )

    info = await client.get_v3_info()
    metadata = await client.get_host_metadata()
    assert info.agents[0]["mg"] == "machine-guid"
    assert metadata["hostname"] == "test-host"
    assert metadata["machine_guid"] == "machine-guid"
    assert metadata["ram_total"] == "16410095616"


@pytest.mark.asyncio
@respx.mock
async def test_client_current_alerts_uses_v3_post_envelope():
    client = NetdataClient(base_url="http://testnode:19999")
    route = respx.post("http://testnode:19999/api/v3/alerts").respond(
        status_code=200,
        json={"api": 2, "nodes": [], "timings": {}},
    )

    response = await client.get_active_alerts()
    assert route.called
    assert response["api"] == 2
    assert b'"options"' in route.calls[0].request.content


@pytest.mark.asyncio
@respx.mock
async def test_client_alert_transitions_and_config():
    client = NetdataClient(base_url="http://testnode:19999")
    transitions = respx.post(
        "http://testnode:19999/api/v3/alert_transitions"
    ).respond(status_code=200, json={"api": 2, "transitions": []})
    config = respx.get("http://testnode:19999/api/v3/alert_config").respond(
        status_code=200,
        json={"config": {"name": "high_cpu"}},
    )

    transition_response = await client.get_alert_transitions(after=-3600)
    config_response = await client.get_alert_config("config-uuid")
    assert transitions.called
    assert b'"after":-3600' in transitions.calls[0].request.content
    assert config.called
    assert dict(config.calls[0].request.url.params)["config"] == "config-uuid"
    assert config_response["config"]["name"] == "high_cpu"
    assert transition_response["transitions"] == []


def test_parse_anomaly_rates_v3_positional_rows():
    response = NetdataWeightsResponse(
        result=[[0, 0, 0, 0, 0, 0, [0, 0, 10, 0, 10, 2]]],
        dictionaries={"contexts": ["system.cpu"]},
    )
    assert parse_anomaly_rates(response) == {"system.cpu": 0.2}


def test_parse_anomaly_rates_v3_dictionary_contexts_and_timeframe():
    response = NetdataWeightsResponse(
        result=[
            {"ci": 0, "value": [0, 0, 0, 0, 20, 3]},
            {"ci": -1, "value": [0, 0, 0, 0, 20, 20]},
        ],
        dictionaries={"contexts": {"0": "system.cpu"}},
    )
    assert parse_anomaly_rates(response) == {"system.cpu": 0.15}


def test_parse_anomaly_rates_rejects_non_integral_dictionary_indexes():
    response = NetdataWeightsResponse(
        result=[[0, 0, 0.5, 0, 0, 0, [0, 0, 0, 0, 10, 1]]],
        dictionaries={"contexts": ["system.cpu"]},
    )
    assert parse_anomaly_rates(response) == {}


@pytest.mark.asyncio
@respx.mock
async def test_client_get_contexts():
    client = NetdataClient(base_url="http://testnode:19999")
    respx.get("http://testnode:19999/api/v1/contexts").respond(
        status_code=200,
        json={
            "contexts": {
                "net.net": {"title": "Network", "units": "kilobits/s"},
                "system.cpu": {"title": "CPU", "units": "%"},
            }
        },
    )

    contexts = await client.get_contexts()
    assert len(contexts) == 2
    assert "net.net" in contexts
    assert "system.cpu" in contexts


@pytest.mark.asyncio
@respx.mock
async def test_client_get_metrics():
    client = NetdataClient(base_url="http://testnode:19999")
    route = respx.get("http://testnode:19999/api/v3/data").respond(
        status_code=200,
        json={
            "result": {
                "labels": ["time", "inbound", "outbound"],
                "data": [[1727000000, [100.0, 0, 0], [50.0, 0, 0]]],
            }
        },
    )

    resp = await client.get_metrics(
        contexts=[NetworkContexts.BANDWIDTH, NetworkContexts.PACKETS],
        after=-60,
        group_by="instance",
    )
    assert route.called
    query_params = dict(route.calls[0].request.url.params)
    assert query_params["contexts"] == "net.net,net.packets"
    assert query_params["after"] == "-60"
    assert query_params["group_by"] == "instance"
    assert query_params["format"] == "json2"
    assert len(resp.result.data) == 1


@pytest.mark.asyncio
@respx.mock
async def test_client_get_metrics_omits_optional_group_by():
    client = NetdataClient(base_url="http://testnode:19999")
    route = respx.get("http://testnode:19999/api/v3/data").respond(
        status_code=200,
        json={"result": {"labels": ["time"], "data": []}},
    )

    await client.get_metrics(contexts=[SystemContexts.CPU], group_by=None)
    assert route.called
    query_params = dict(route.calls[0].request.url.params)
    assert "group_by" not in query_params


@pytest.mark.asyncio
@respx.mock
async def test_client_rejects_empty_context_queries():
    client = NetdataClient(base_url="http://testnode:19999")
    with pytest.raises(ValueError):
        await client.get_metrics(contexts=[])
    with pytest.raises(ValueError):
        await client.get_anomaly_scores(contexts=[])
    with pytest.raises(ValueError):
        await client.get_metrics(contexts=None)


@pytest.mark.asyncio
@respx.mock
async def test_client_get_anomaly_scores():
    client = NetdataClient(base_url="http://testnode:19999")
    route = respx.get("http://testnode:19999/api/v3/weights").respond(
        status_code=200,
        json={
            "result": {
                "system.cpu": {"anomaly_rate": 0.45}
            }
        },
    )

    resp = await client.get_anomaly_scores(
        contexts=[SystemContexts.CPU],
        after=-300,
    )
    assert route.called
    query_params = dict(route.calls[0].request.url.params)
    assert query_params["method"] == "anomaly-rate"
    assert query_params["contexts"] == "system.cpu"
    assert resp.result["system.cpu"]["anomaly_rate"] == 0.45


@pytest.mark.asyncio
@respx.mock
async def test_client_get_alerts():
    client = NetdataClient(base_url="http://testnode:19999")
    route = respx.get("http://testnode:19999/api/v1/alarms").respond(
        status_code=200,
        json={
            "alarms": {
                "system.cpu.high_cpu": {
                    "status": "CLEAR",
                    "value": 15.2,
                }
            }
        },
    )

    resp = await client.get_alerts(all_definitions=True)
    assert route.called
    assert "alarms" in resp
    assert route.calls[0].request.url.query == b"all"


@pytest.mark.asyncio
@respx.mock
async def test_client_unavailable_error():
    client = NetdataClient(base_url="http://offline-node:19999")
    respx.get("http://offline-node:19999/api/v1/info").mock(
        side_effect=httpx.ConnectError("Connection refused")
    )

    with pytest.raises(NetdataUnavailable):
        await client.info()


@pytest.mark.asyncio
@respx.mock
async def test_client_http_status_error_is_unavailable():
    client = NetdataClient(base_url="http://testnode:19999")
    respx.get("http://testnode:19999/api/v1/info").respond(status_code=503, text="offline")

    with pytest.raises(NetdataUnavailable, match="HTTP 503"):
        await client.info()


@pytest.mark.asyncio
@respx.mock
async def test_client_invalid_json_is_parse_error():
    client = NetdataClient(base_url="http://testnode:19999")
    respx.get("http://testnode:19999/api/v1/info").respond(status_code=200, text="not-json")

    with pytest.raises(NetdataParseError):
        await client.info()


@pytest.mark.asyncio
@respx.mock
async def test_client_rejects_non_object_generic_responses():
    client = NetdataClient(base_url="http://testnode:19999")
    respx.get("http://testnode:19999/api/v1/contexts").respond(
        status_code=200,
        json=[],
    )

    with pytest.raises(NetdataParseError):
        await client.get_contexts()
