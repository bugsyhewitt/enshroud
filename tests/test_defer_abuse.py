"""Tests for the incremental-delivery (@defer / @stream) abuse check."""
from __future__ import annotations

import json
import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import defer_abuse
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


# ── Unit tests for the probe queries / rejection detector ───────────────────


def test_defer_probe_uses_inline_fragment():
    assert "@defer" in defer_abuse._DEFER_QUERY
    assert "..." in defer_abuse._DEFER_QUERY
    assert "__typename" in defer_abuse._DEFER_QUERY


def test_stream_probe_targets_typename():
    assert "@stream" in defer_abuse._STREAM_QUERY
    assert "__typename" in defer_abuse._STREAM_QUERY


def test_is_rejected_detects_unknown_directive():
    resp = {"errors": [{"message": 'Unknown directive "@defer".'}]}
    assert defer_abuse._is_rejected(resp) is True


def test_is_rejected_detects_stream_location_error():
    resp = {
        "errors": [
            {"message": 'Directive "@stream" may not be used on a non-list field.'}
        ]
    }
    assert defer_abuse._is_rejected(resp) is True


def test_is_rejected_false_on_clean_data():
    resp = {"data": {"__typename": "Query"}}
    assert defer_abuse._is_rejected(resp) is False


def test_is_rejected_false_on_unrelated_error():
    resp = {"errors": [{"message": "Cannot query field 'foo' on type 'Query'."}]}
    assert defer_abuse._is_rejected(resp) is False


# ── Integration tests against a live server ─────────────────────────────────


@pytest.mark.asyncio
async def test_incremental_delivery_enabled_fires_medium():
    """A server with @defer/@stream enabled accepts both probes → one finding."""
    app = create_app(incremental_delivery=True)
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await defer_abuse.check(client)
        assert len(findings) == 1
        finding = findings[0]
        assert finding["category"] == "incremental_delivery_dos"
        assert finding["severity"] == "MEDIUM"
        # Both vectors accepted by the exposed mock.
        assert "defer" in finding["accepted_vectors"]
        assert "stream" in finding["accepted_vectors"]
        evidence = json.loads(finding["evidence"])
        assert evidence["accepted_vectors"] == finding["accepted_vectors"]
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_incremental_delivery_disabled_no_finding():
    """A spec-compliant server rejects both probes → no finding (no FP)."""
    app = create_app(incremental_delivery=False)
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await defer_abuse.check(client)
        assert findings == []
    finally:
        server.should_exit = True


def test_defer_abuse_in_all_checks():
    from enshroud.cli import ALL_CHECKS, VALID_CHECKS, parse_checks

    assert "defer-abuse" in ALL_CHECKS
    assert "defer-abuse" in VALID_CHECKS
    assert "defer-abuse" in parse_checks("all")
    assert parse_checks("defer-abuse") == ["defer-abuse"]
