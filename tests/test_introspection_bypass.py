"""Tests for the introspection-bypass check (naive-filter introspection leak)."""
from __future__ import annotations

import json
import socket
import threading
import time

import httpx
import pytest
import uvicorn

from enshroud.checks import introspection_bypass
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


# ── Unit tests for the helpers ──────────────────────────────────────────────


def test_has_introspection_data_true_on_schema():
    assert (
        introspection_bypass._has_introspection_data(
            {"data": {"__schema": {"queryType": {"name": "Query"}}}}
        )
        is True
    )


def test_has_introspection_data_true_on_type():
    assert (
        introspection_bypass._has_introspection_data(
            {"data": {"__type": {"name": "Query", "fields": []}}}
        )
        is True
    )


def test_has_introspection_data_false_on_errors_only():
    assert (
        introspection_bypass._has_introspection_data(
            {"errors": [{"message": "Introspection is disabled"}]}
        )
        is False
    )


def test_has_introspection_data_false_on_null_schema():
    assert (
        introspection_bypass._has_introspection_data({"data": {"__schema": None}})
        is False
    )


def test_has_introspection_data_false_on_empty_schema():
    # An empty dict carries no schema → not a leak.
    assert (
        introspection_bypass._has_introspection_data({"data": {"__schema": {}}})
        is False
    )


def test_has_introspection_data_false_on_non_dict():
    assert introspection_bypass._has_introspection_data([1, 2, 3]) is False
    assert introspection_bypass._has_introspection_data(None) is False


def test_finding_shape_is_medium():
    finding = introspection_bypass._finding(
        technique="the `__type` root field (POST)",
        probe=introspection_bypass.TYPE_PROBE_QUERY,
        evidence="{}",
    )
    assert finding["category"] == "introspection_filter_bypass"
    assert finding["severity"] == "MEDIUM"
    assert "__type" in finding["title"]
    assert "remediation" in finding


# ── Integration tests against a live server ─────────────────────────────────


@pytest.mark.asyncio
async def test_schema_keyword_filter_fires_type_finding():
    """`__schema` blocked but `__type` leaks → one POST `__type` finding."""
    app = create_app(introspection_filter="schema_keyword")
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await introspection_bypass.check(client)
        assert len(findings) == 1
        f = findings[0]
        assert f["category"] == "introspection_filter_bypass"
        assert f["severity"] == "MEDIUM"
        assert "__type" in f["technique"]
        evidence = json.loads(f["evidence"])
        assert "__type" in evidence["probe"]
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_post_only_filter_fires_get_finding():
    """Introspection blocked on POST but open on GET → one GET finding."""
    app = create_app(introspection_filter="post_only")
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await introspection_bypass.check(client)
        assert len(findings) == 1
        f = findings[0]
        assert "GET" in f["technique"]
        evidence = json.loads(f["evidence"])
        assert "__schema" in evidence["probe"]
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_top_level_only_filter_fires_fragment_finding():
    """`__schema` blocked at top level but leaks via a named fragment spread."""
    app = create_app(introspection_filter="top_level_only")
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await introspection_bypass.check(client)
        assert len(findings) == 1
        f = findings[0]
        assert f["category"] == "introspection_filter_bypass"
        assert f["severity"] == "MEDIUM"
        assert "fragment" in f["technique"]
        evidence = json.loads(f["evidence"])
        assert "fragment" in evidence["probe"]
        assert "__schema" in evidence["probe"]
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_fragment_probe_constant_shape():
    """The fragment probe is a named query + named fragment carrying __schema."""
    probe = introspection_bypass.FRAGMENT_SCHEMA_QUERY
    assert "fragment" in probe
    assert "__schema" in probe
    # Must spread the fragment at top level rather than select __schema directly,
    # otherwise a top-level-name guard would catch it.
    assert "..." in probe


@pytest.mark.asyncio
async def test_introspection_enabled_no_finding():
    """Standard introspection works → check defers to `introspection`, silent."""
    app = create_app(introspection_enabled=True, introspection_filter=None)
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await introspection_bypass.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_introspection_properly_disabled_no_finding():
    """Introspection off on every transport/root field → no bypass finding."""
    app = create_app(introspection_enabled=False, introspection_filter=None)
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await introspection_bypass.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_standard_probe_denied_helper_true_when_disabled():
    app = create_app(introspection_enabled=False)
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        assert await introspection_bypass._standard_probe_denied(client) is True
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_standard_probe_denied_helper_false_when_enabled():
    app = create_app(introspection_enabled=True)
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        assert await introspection_bypass._standard_probe_denied(client) is False
    finally:
        server.should_exit = True


def test_introspection_bypass_in_all_checks():
    from enshroud.cli import ALL_CHECKS, VALID_CHECKS, parse_checks

    assert "introspection-bypass" in ALL_CHECKS
    assert "introspection-bypass" in VALID_CHECKS
    assert "introspection-bypass" in parse_checks("all")
    assert parse_checks("introspection-bypass") == ["introspection-bypass"]
