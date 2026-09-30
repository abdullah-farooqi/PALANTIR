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


@pytest.mark.asyncio
@respx.mock
async def test_client_unavailable_error():
    client = NetdataClient(base_url="http://offline-node:19999")
    respx.get("http://offline-node:19999/api/v1/info").mock(
        side_effect=httpx.ConnectError("Connection refused")
    )

    with pytest.raises(NetdataUnavailable):
        await client.info()
