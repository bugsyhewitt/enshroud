"""Tests for the federation check — Apollo Federation _service.sdl exposure."""
from __future__ import annotations

import json
import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import federation
from enshroud.client import GraphQLClient
from tests.fixtures.mock_graphql_server import create_app


def _start_server(app) -> tuple[str, int, uvicorn.Server]:
    host = "127.0.0.1"
    s = socket.socket()
    s.bind((host, 0))
    port = s.getsockname()[1]
    s.close()

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
    return host, port, server


# A minimal but realistic federation subgraph SDL.
_SAMPLE_SDL = (
    "schema { query: Query }\n"
    "type Query { me: User adminPanel: Admin }\n"
    'type User @key(fields: "id") { id: ID! email: String! }\n'
    "type Admin { secret: String! }\n"
)


# ── Unit tests for the SDL heuristic ────────────────────────────────────────


def test_looks_like_sdl_accepts_real_sdl():
    assert federation._looks_like_sdl(_SAMPLE_SDL) is True


def test_looks_like_sdl_rejects_empty_and_scalars():
    assert federation._looks_like_sdl("") is False
    assert federation._looks_like_sdl(None) is False
    assert federation._looks_like_sdl("ok") is False
    assert federation._looks_like_sdl(12345) is False


def test_field_is_unknown_detects_rejection():
    resp = {
        "errors": [{"message": 'Cannot query field "_service" on type "Query".'}]
    }
    assert federation._field_is_unknown(resp, "_service") is True


def test_field_is_unknown_false_when_no_matching_error():
    resp = {"data": {"_entities": []}}
    assert federation._field_is_unknown(resp, "_entities") is False


# ── Integration tests against a live server ─────────────────────────────────


@pytest.mark.asyncio
async def test_federation_sdl_exposed_fires_high():
    app = create_app(
        introspection_enabled=False,  # introspection "disabled" — bypass still works
        federation_sdl=_SAMPLE_SDL,
        federation_entities=True,
    )
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await federation.check(client)
        categories = {f["category"] for f in findings}
        assert "federation_sdl_exposed" in categories
        sdl_finding = next(
            f for f in findings if f["category"] == "federation_sdl_exposed"
        )
        assert sdl_finding["severity"] == "HIGH"
        evidence = json.loads(sdl_finding["evidence"])
        assert evidence["sdl_length"] == len(_SAMPLE_SDL)
        assert "type Query" in evidence["sdl_prefix"]
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_federation_entities_reachable_fires_medium():
    app = create_app(
        federation_sdl=None,  # SDL field locked down...
        federation_entities=True,  # ...but the entity resolver is reachable
    )
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await federation.check(client)
        categories = {f["category"] for f in findings}
        assert "federation_sdl_exposed" not in categories
        assert "federation_entities_exposed" in categories
        ent_finding = next(
            f for f in findings if f["category"] == "federation_entities_exposed"
        )
        assert ent_finding["severity"] == "MEDIUM"
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_federation_both_findings_fire():
    app = create_app(federation_sdl=_SAMPLE_SDL, federation_entities=True)
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await federation.check(client)
        categories = {f["category"] for f in findings}
        assert categories == {
            "federation_sdl_exposed",
            "federation_entities_exposed",
        }
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_federation_non_federation_endpoint_silent():
    # Default mock app is not a federation subgraph: both probe fields are
    # reported as unknown, so the check must stay silent.
    app = create_app(federation_sdl=None, federation_entities=False)
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await federation.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_federation_empty_sdl_no_finding():
    # A server that returns an empty SDL string must not trip the heuristic.
    app = create_app(federation_sdl="", federation_entities=False)
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await federation.check(client)
        assert findings == []
    finally:
        server.should_exit = True


def test_federation_in_all_checks():
    from enshroud.cli import ALL_CHECKS, VALID_CHECKS, parse_checks

    assert "federation" in ALL_CHECKS
    assert "federation" in VALID_CHECKS
    assert "federation" in parse_checks("all")
    assert parse_checks("federation") == ["federation"]


# ── Additional unit tests: _looks_like_sdl keyword coverage ──────────────────

def test_looks_like_sdl_with_interface_keyword():
    assert federation._looks_like_sdl("interface Node { id: ID! }") is True


def test_looks_like_sdl_with_enum_keyword():
    assert federation._looks_like_sdl("enum Status { ACTIVE INACTIVE }") is True


def test_looks_like_sdl_with_input_keyword():
    assert federation._looks_like_sdl("input CreateUserInput { name: String! }") is True


def test_looks_like_sdl_with_scalar_keyword():
    assert federation._looks_like_sdl("scalar DateTime") is True


def test_looks_like_sdl_rejects_short_string():
    """A string shorter than 8 chars is not a valid SDL document."""
    assert federation._looks_like_sdl("type") is False
    assert federation._looks_like_sdl("x") is False


# ── Additional unit tests: _field_is_unknown error wording variants ───────────

def test_field_is_unknown_with_unknown_field_wording():
    resp = {"errors": [{"message": 'Unknown field "_entities" on type "Query".'}]}
    assert federation._field_is_unknown(resp, "_entities") is True


def test_field_is_unknown_with_does_not_exist_wording():
    resp = {"errors": [{"message": 'Field "_service" does not exist on type "Query".'}]}
    assert federation._field_is_unknown(resp, "_service") is True


def test_field_is_unknown_requires_field_name_in_message():
    """An unrelated error must not be treated as 'field unknown'."""
    resp = {"errors": [{"message": "Cannot query field \"_other\" on type \"Query\"."}]}
    assert federation._field_is_unknown(resp, "_service") is False


def test_field_is_unknown_false_on_data_response():
    """A clean data response (field recognised) is not an unknown-field error."""
    assert federation._field_is_unknown({"data": {"_service": {"sdl": "..."}}}, "_service") is False


# ── Mock-client unit tests: check() edge cases ───────────────────────────────

class _MockFedClient:
    """Stand-in for GraphQLClient returning preset responses per query."""

    def __init__(self, sdl_resp=None, entities_resp=None, raise_exc: Exception | None = None):
        self._sdl_resp = sdl_resp
        self._entities_resp = entities_resp
        self._raise_exc = raise_exc

    async def query(self, q: str):
        if self._raise_exc is not None:
            raise self._raise_exc
        if "_service" in q:
            return self._sdl_resp
        return self._entities_resp


@pytest.mark.asyncio
async def test_connection_error_no_findings():
    """A network exception from both probes must return an empty list."""
    client = _MockFedClient(raise_exc=Exception("timeout"))
    findings = await federation.check(client)
    assert findings == []


@pytest.mark.asyncio
async def test_sdl_finding_severity_is_high():
    sdl_resp = {"data": {"_service": {"sdl": _SAMPLE_SDL}}}
    entities_resp = {"errors": [{"message": 'Cannot query field "_entities" on type "Query".'}]}
    client = _MockFedClient(sdl_resp=sdl_resp, entities_resp=entities_resp)
    findings = await federation.check(client)
    sdl_f = next((f for f in findings if f["category"] == "federation_sdl_exposed"), None)
    assert sdl_f is not None
    assert sdl_f["severity"] == "HIGH"


@pytest.mark.asyncio
async def test_entities_finding_severity_is_medium():
    sdl_resp = {"errors": [{"message": 'Cannot query field "_service" on type "Query".'}]}
    entities_resp = {"data": {"_entities": []}}
    client = _MockFedClient(sdl_resp=sdl_resp, entities_resp=entities_resp)
    findings = await federation.check(client)
    ent_f = next((f for f in findings if f["category"] == "federation_entities_exposed"), None)
    assert ent_f is not None
    assert ent_f["severity"] == "MEDIUM"


# ── Finding structure tests (require a live server) ───────────────────────────

@pytest.mark.asyncio
async def test_sdl_finding_has_all_required_keys():
    app = create_app(federation_sdl=_SAMPLE_SDL, federation_entities=False)
    host, port, server = _start_server(app)
    try:
        client = GraphQLClient(f"http://{host}:{port}/graphql")
        findings = await federation.check(client)
        sdl_f = next((f for f in findings if f["category"] == "federation_sdl_exposed"), None)
        assert sdl_f is not None
        for key in ("category", "severity", "title", "evidence", "description", "impact", "remediation", "reproduction"):
            assert key in sdl_f, f"missing key: {key}"
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_sdl_finding_evidence_is_valid_json():
    app = create_app(federation_sdl=_SAMPLE_SDL, federation_entities=False)
    host, port, server = _start_server(app)
    try:
        client = GraphQLClient(f"http://{host}:{port}/graphql")
        findings = await federation.check(client)
        sdl_f = next((f for f in findings if f["category"] == "federation_sdl_exposed"), None)
        assert sdl_f is not None
        evidence = json.loads(sdl_f["evidence"])
        assert "sdl_length" in evidence
        assert "sdl_prefix" in evidence
        assert evidence["sdl_length"] == len(_SAMPLE_SDL)
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_entities_finding_has_all_required_keys():
    app = create_app(federation_sdl=None, federation_entities=True)
    host, port, server = _start_server(app)
    try:
        client = GraphQLClient(f"http://{host}:{port}/graphql")
        findings = await federation.check(client)
        ent_f = next((f for f in findings if f["category"] == "federation_entities_exposed"), None)
        assert ent_f is not None
        for key in ("category", "severity", "title", "evidence", "description", "impact", "remediation", "reproduction"):
            assert key in ent_f, f"missing key: {key}"
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_entities_finding_evidence_contains_probe():
    app = create_app(federation_sdl=None, federation_entities=True)
    host, port, server = _start_server(app)
    try:
        client = GraphQLClient(f"http://{host}:{port}/graphql")
        findings = await federation.check(client)
        ent_f = next((f for f in findings if f["category"] == "federation_entities_exposed"), None)
        assert ent_f is not None
        evidence = json.loads(ent_f["evidence"])
        assert "probe" in evidence
        assert "_entities" in evidence["probe"]
    finally:
        server.should_exit = True
