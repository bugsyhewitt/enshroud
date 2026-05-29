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
