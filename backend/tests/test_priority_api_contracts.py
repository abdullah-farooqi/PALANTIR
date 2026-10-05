from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from api.v1 import investigations as investigations_api
from api.v1.investigations import InvestigationCreateRequest
from core.cursors import decode_cursor, encode_cursor
from core.investigation_contracts import InvestigationEvidenceResult
from main import app


def test_priority_two_and_three_routes_are_registered():
    registered = {
        (route.path, method)
        for route in app.routes
        if hasattr(route, "methods")
        for method in route.methods
    }

    assert ("/api/v1/logs", "GET") in registered
    assert ("/api/v1/investigations/search", "GET") in registered
    assert ("/api/v1/investigations", "POST") in registered
    assert ("/api/v1/nodes/search", "GET") in registered
    assert ("/api/v1/health/operations", "GET") in registered
    create_route = next(
        route
        for route in app.routes
        if getattr(route, "path", None) == "/api/v1/investigations"
        and "POST" in getattr(route, "methods", set())
    )
    assert create_route.status_code == 202


def test_investigation_request_requires_consistent_trigger_reference():
    assert InvestigationCreateRequest(node_id=1, trigger_type="manual").trigger_id is None
    assert InvestigationCreateRequest(
        node_id=1, trigger_type="alert", trigger_id=12
    ).trigger_id == 12

    with pytest.raises(ValidationError):
        InvestigationCreateRequest(node_id=1, trigger_type="alert")
    with pytest.raises(ValidationError):
        InvestigationCreateRequest(
            node_id=1, trigger_type="manual", trigger_id=12
        )


@pytest.mark.asyncio
async def test_investigation_rejects_trigger_event_not_owned_by_node(monkeypatch):
    class Result:
        def __init__(self, value):
            self.value = value

        def scalar_one_or_none(self):
            return self.value

    node = SimpleNamespace(id=7)
    session = SimpleNamespace(
        execute=AsyncMock(side_effect=[Result(node), Result(None)])
    )
    enqueue = AsyncMock()
    monkeypatch.setattr(investigations_api, "enqueue_investigation_async", enqueue)

    with pytest.raises(HTTPException) as error:
        await investigations_api.trigger_investigation(
            InvestigationCreateRequest(
                node_id=7, trigger_type="alert", trigger_id=91
            ),
            session,
            None,
        )

    assert error.value.status_code == 404
    enqueue.assert_not_awaited()


def test_keyset_cursor_round_trip_is_stable_and_rejects_wrong_shape():
    position = {"timestamp": "2026-10-05T12:00:00+00:00", "id": 41}
    cursor = encode_cursor(position)

    assert cursor == encode_cursor(position)
    assert decode_cursor(cursor, {"timestamp", "id"}) == position
    with pytest.raises(ValueError, match="Cursor is invalid"):
        decode_cursor(cursor, {"hostname", "id"})


def test_investigation_result_schema_is_versioned_and_bounded():
    schema = InvestigationEvidenceResult.model_json_schema()

    assert schema["properties"]["schema_version"]["const"] == 1
    assert schema["properties"]["kind"]["const"] == "telemetry_evidence_summary"
    assert schema["additionalProperties"] is False
    assert schema["$defs"]["InvestigationEvidence"]["properties"]["latest_metrics"]["maxItems"] == 16
    assert schema["$defs"]["InvestigationAssessment"]["properties"]["root_cause_inferred"]["const"] is False
