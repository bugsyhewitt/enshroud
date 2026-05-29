"""Tests for the in-browser GraphQL IDE exposure check (graphql-ide)."""
from __future__ import annotations

import json
import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import graphql_ide
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


# ── Unit tests for the HTML / marker detection helpers ──────────────────────


def test_looks_like_html_by_content_type():
    assert graphql_ide._looks_like_html("text/html; charset=utf-8", "anything")


def test_looks_like_html_by_body_shape():
    assert graphql_ide._looks_like_html("", "<!DOCTYPE html><html></html>")
    assert graphql_ide._looks_like_html("", "  <html><body></body></html>")


def test_looks_like_html_false_on_json():
    assert not graphql_ide._looks_like_html(
        "application/json", '{"data": {"__typename": "Query"}}'
    )


def test_identify_ide_graphiql():
    assert graphql_ide._identify_ide('<div id="graphiql"></div>') == "GraphiQL"


def test_identify_ide_playground():
    body = '<script src="graphql-playground-react/build/x.js"></script>'
    assert graphql_ide._identify_ide(body) == "GraphQL Playground"


def test_identify_ide_apollo_sandbox():
    body = '<div id="embeddable-sandbox"></div>'
    assert graphql_ide._identify_ide(body) == "Apollo Sandbox"


def test_identify_ide_none_on_plain_html():
    assert graphql_ide._identify_ide("<html><body>Welcome</body></html>") is None


# ── Integration tests against a live server ─────────────────────────────────


@pytest.mark.asyncio
async def test_graphiql_exposed_fires_medium():
    """A server serving GraphiQL over an HTML GET → one MEDIUM finding."""
    app = create_app(graphql_ide="graphiql")
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await graphql_ide.check(client)
        assert len(findings) == 1
        finding = findings[0]
        assert finding["category"] == "graphql_ide_exposed"
        assert finding["severity"] == "MEDIUM"
        assert finding["ide"] == "GraphiQL"
        evidence = json.loads(finding["evidence"])
        assert evidence["method"] == "GET"
        assert evidence["ide"] == "GraphiQL"
        assert "text/html" in evidence["content_type"]
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_playground_exposed_fires_medium():
    """GraphQL Playground exposure is detected and named correctly."""
    app = create_app(graphql_ide="playground")
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await graphql_ide.check(client)
        assert len(findings) == 1
        assert findings[0]["ide"] == "GraphQL Playground"
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_apollo_sandbox_exposed_fires_medium():
    """Apollo Sandbox exposure is detected and named correctly."""
    app = create_app(graphql_ide="sandbox")
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await graphql_ide.check(client)
        assert len(findings) == 1
        assert findings[0]["ide"] == "Apollo Sandbox"
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_no_ide_no_finding():
    """A server that only serves the JSON API → no finding (no false positive)."""
    app = create_app(graphql_ide=None)
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await graphql_ide.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_check_handles_transport_error():
    """An unreachable endpoint yields no finding rather than raising."""
    client = GraphQLClient("http://127.0.0.1:1/graphql", timeout=1)
    findings = await graphql_ide.check(client)
    assert findings == []


def test_graphql_ide_in_all_checks():
    from enshroud.cli import ALL_CHECKS, VALID_CHECKS, parse_checks

    assert "graphql-ide" in ALL_CHECKS
    assert "graphql-ide" in VALID_CHECKS
    assert "graphql-ide" in parse_checks("all")
    assert parse_checks("graphql-ide") == ["graphql-ide"]
