"""Tests for the field-duplication DoS check (POST_V01 #8)."""
from __future__ import annotations

import json
import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import field_dup
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


# ── Unit tests for the query builders / limit detector ──────────────────────


def test_build_duplicate_field_query_repeats_typename():
    q = field_dup._build_duplicate_field_query(5)
    assert q.count("__typename") == 5
    assert q.startswith("{") and q.endswith("}")


def test_build_repeated_fragment_query_repeats_spread():
    q = field_dup._build_repeated_fragment_query(4)
    assert q.count("...F") == 4
    assert "fragment F on Query" in q
    assert "__typename" in q


def test_is_limited_detects_complexity_error():
    resp = {"errors": [{"message": "Query complexity 500 exceeds maximum 50"}]}
    assert field_dup._is_limited(resp) is True


def test_is_limited_detects_fragment_error():
    resp = {"errors": [{"message": "Too many fragment spreads in operation"}]}
    assert field_dup._is_limited(resp) is True


def test_is_limited_false_on_clean_data():
    resp = {"data": {"__typename": "Query"}}
    assert field_dup._is_limited(resp) is False


def test_is_limited_false_on_unrelated_error():
    resp = {"errors": [{"message": "Cannot query field 'foo' on type 'Query'."}]}
    assert field_dup._is_limited(resp) is False


# ── Integration tests against a live server ─────────────────────────────────


@pytest.mark.asyncio
async def test_field_dup_no_limit_fires_medium():
    """A server with no repetition cap accepts both vectors → one finding."""
    app = create_app(field_dup_limit=None)
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await field_dup.check(client)
        assert len(findings) == 1
        finding = findings[0]
        assert finding["category"] == "field_duplication_dos"
        assert finding["severity"] == "MEDIUM"
        assert finding["duplication_count"] == field_dup.DUP_COUNT
        # Both vectors should be accepted by the unprotected mock.
        assert "repeated_fields" in finding["accepted_vectors"]
        assert "repeated_fragment_spread" in finding["accepted_vectors"]
        evidence = json.loads(finding["evidence"])
        assert evidence["duplication_count"] == field_dup.DUP_COUNT
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_field_dup_with_limit_no_finding():
    """A server that caps repetition rejects both probes → no finding."""
    app = create_app(field_dup_limit=10)
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await field_dup.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_field_dup_partial_limit_still_fires():
    """A cap above the probe count means the probe is accepted → finding fires."""
    app = create_app(field_dup_limit=field_dup.DUP_COUNT + 100)
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await field_dup.check(client)
        assert len(findings) == 1
        assert findings[0]["category"] == "field_duplication_dos"
    finally:
        server.should_exit = True


def test_field_dup_in_all_checks():
    from enshroud.cli import ALL_CHECKS, VALID_CHECKS, parse_checks

    assert "field-dup" in ALL_CHECKS
    assert "field-dup" in VALID_CHECKS
    assert "field-dup" in parse_checks("all")
    assert parse_checks("field-dup") == ["field-dup"]
