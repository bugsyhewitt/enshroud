"""Tests for introspection check."""
from __future__ import annotations

import json
import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import introspection
from enshroud.client import GraphQLClient
from tests.fixtures.mock_graphql_server import create_app


# ── Existing tests ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_introspection_enabled(mock_url):
    client = GraphQLClient(mock_url)
    findings = await introspection.check(client)
    assert len(findings) == 1
    assert findings[0]["category"] == "introspection_enabled"
    assert findings[0]["severity"] == "MEDIUM"
    assert "evidence" in findings[0]


@pytest.mark.asyncio
async def test_introspection_disabled(mock_server):
    """Server with introspection disabled should produce no findings."""
    host = "127.0.0.1"
    s = socket.socket()
    s.bind((host, 0))
    port = s.getsockname()[1]
    s.close()

    app = create_app(introspection_enabled=False)
    config = uvicorn.Config(app, host=host, port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            c = socket.create_connection((host, port), timeout=0.5)
            c.close()
            break
        except OSError:
            time.sleep(0.05)

    url = f"http://{host}:{port}/graphql"
    client = GraphQLClient(url)
    findings = await introspection.check(client)
    assert findings == []

    server.should_exit = True


# ── Pure unit tests: probe query shape ──────────────────────────────────────

def test_introspection_query_contains_schema_root():
    """The standard probe must address __schema to detect open introspection."""
    assert "__schema" in introspection.INTROSPECTION_QUERY


def test_introspection_query_requests_query_type():
    """queryType must be requested so we can enumerate read operations."""
    assert "queryType" in introspection.INTROSPECTION_QUERY


def test_introspection_query_requests_mutation_type():
    """mutationType must be requested to surface mutation-only endpoints."""
    assert "mutationType" in introspection.INTROSPECTION_QUERY


def test_introspection_query_requests_types_with_fields():
    """The types list with field names surfaces the full type graph."""
    assert "types" in introspection.INTROSPECTION_QUERY
    assert "fields" in introspection.INTROSPECTION_QUERY


def test_introspection_check_registered_in_all_checks():
    from enshroud.cli import ALL_CHECKS, VALID_CHECKS, parse_checks

    assert "introspection" in ALL_CHECKS
    assert "introspection" in VALID_CHECKS
    assert "introspection" in parse_checks("all")
    assert parse_checks("introspection") == ["introspection"]


# ── Mock-client unit tests: edge-case responses (no server required) ─────────

class _MockClient:
    """Minimal stand-in for GraphQLClient that returns a fixed response."""

    def __init__(self, return_value=None, raise_exc: Exception | None = None):
        self._return_value = return_value
        self._raise_exc = raise_exc

    async def query(self, _query):
        if self._raise_exc is not None:
            raise self._raise_exc
        return self._return_value


@pytest.mark.asyncio
async def test_null_schema_key_in_data_fires_finding():
    """data.__schema = null still fires: the key's presence triggers the check."""
    client = _MockClient(return_value={"data": {"__schema": None}})
    findings = await introspection.check(client)
    # The check tests `"__schema" in data`, not whether the value is non-null.
    assert len(findings) == 1
    assert findings[0]["category"] == "introspection_enabled"


@pytest.mark.asyncio
async def test_missing_schema_key_no_finding():
    """data present but no __schema key → not introspection-enabled."""
    client = _MockClient(return_value={"data": {"__typename": "Query"}})
    findings = await introspection.check(client)
    assert findings == []


@pytest.mark.asyncio
async def test_errors_only_response_no_finding():
    """A pure-errors response (introspection blocked) → no finding."""
    client = _MockClient(
        return_value={"errors": [{"message": "Introspection is disabled"}]}
    )
    findings = await introspection.check(client)
    assert findings == []


@pytest.mark.asyncio
async def test_connection_error_no_finding():
    """A network-level exception must return an empty list, not raise."""
    client = _MockClient(raise_exc=Exception("Connection refused"))
    findings = await introspection.check(client)
    assert findings == []


@pytest.mark.asyncio
async def test_empty_data_dict_no_finding():
    """An empty data object carries no introspection → no finding."""
    client = _MockClient(return_value={"data": {}})
    findings = await introspection.check(client)
    assert findings == []


@pytest.mark.asyncio
async def test_schema_in_data_fires_exactly_one_finding():
    """A real __schema payload fires exactly one finding."""
    schema_resp = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": None,
                "types": [{"name": "Query", "kind": "OBJECT", "fields": []}],
            }
        }
    }
    client = _MockClient(return_value=schema_resp)
    findings = await introspection.check(client)
    assert len(findings) == 1
    assert findings[0]["category"] == "introspection_enabled"


@pytest.mark.asyncio
async def test_schema_plus_errors_still_fires():
    """A response with both __schema data and errors must still fire."""
    resp = {
        "data": {"__schema": {"queryType": {"name": "Query"}}},
        "errors": [{"message": "Partial execution error"}],
    }
    client = _MockClient(return_value=resp)
    findings = await introspection.check(client)
    assert len(findings) == 1


# ── Finding structure tests (require a live fixture) ─────────────────────────

@pytest.mark.asyncio
async def test_finding_severity_medium(mock_url):
    client = GraphQLClient(mock_url)
    findings = await introspection.check(client)
    assert findings and findings[0]["severity"] == "MEDIUM"


@pytest.mark.asyncio
async def test_finding_title_contains_introspection(mock_url):
    client = GraphQLClient(mock_url)
    findings = await introspection.check(client)
    assert findings and "Introspection" in findings[0]["title"]


@pytest.mark.asyncio
async def test_finding_has_description(mock_url):
    client = GraphQLClient(mock_url)
    findings = await introspection.check(client)
    assert findings and findings[0].get("description")


@pytest.mark.asyncio
async def test_finding_has_remediation(mock_url):
    client = GraphQLClient(mock_url)
    findings = await introspection.check(client)
    assert findings and findings[0].get("remediation")


@pytest.mark.asyncio
async def test_finding_has_reproduction(mock_url):
    client = GraphQLClient(mock_url)
    findings = await introspection.check(client)
    assert findings and findings[0].get("reproduction")


@pytest.mark.asyncio
async def test_finding_has_impact(mock_url):
    client = GraphQLClient(mock_url)
    findings = await introspection.check(client)
    assert findings and findings[0].get("impact")


@pytest.mark.asyncio
async def test_finding_evidence_capped_at_500(mock_url):
    """The evidence field must never exceed 500 characters."""
    client = GraphQLClient(mock_url)
    findings = await introspection.check(client)
    assert findings and len(findings[0]["evidence"]) <= 500


@pytest.mark.asyncio
async def test_finding_exactly_one_per_enabled_server(mock_url):
    """check() returns exactly one finding per call on an enabled server."""
    client = GraphQLClient(mock_url)
    findings = await introspection.check(client)
    assert len(findings) == 1
