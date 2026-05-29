"""Tests for the Apollo Tracing / FTV1 exposure check (trace-exposure)."""
from __future__ import annotations

import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import trace_exposure
from enshroud.client import GraphQLClient
from tests.fixtures.mock_graphql_server import create_app


# ── helpers ──────────────────────────────────────────────────────────────────

def _start_server(app, host: str = "127.0.0.1") -> tuple[str, uvicorn.Server, threading.Thread]:
    """Start a FastAPI app on a random free port; return (url, server, thread)."""
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

    return f"http://{host}:{port}/graphql", server, thread


# ── tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_finding_when_tracing_disabled():
    """A production server with no tracing extensions produces no finding."""
    app = create_app(tracing=None)
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await trace_exposure.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_finding_when_apollo_tracing_present():
    """An Apollo Tracing block on the success path is flagged."""
    app = create_app(tracing="apollo")
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await trace_exposure.check(client)
        categories = [f["category"] for f in findings]
        assert "trace_exposure" in categories
        finding = next(f for f in findings if f["category"] == "trace_exposure")
        assert finding["severity"] == "LOW"
        assert any("apollo-tracing" in fmt for fmt in finding["tracing_formats"])
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_apollo_tracing_leaks_resolver_field_names():
    """The Apollo Tracing resolver list leak surfaces in the finding."""
    app = create_app(tracing="apollo")
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await trace_exposure.check(client)
        finding = next(f for f in findings if f["category"] == "trace_exposure")
        # The mock's resolver entry is Query.__typename: String!
        assert any("Query.__typename" in name for name in finding["leaked_fields"])
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_finding_when_ftv1_present():
    """A federation FTV1 trace string on the success path is flagged."""
    app = create_app(tracing="ftv1")
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await trace_exposure.check(client)
        finding = next(f for f in findings if f["category"] == "trace_exposure")
        assert any("FTV1" in fmt for fmt in finding["tracing_formats"])
        # FTV1 is opaque — no resolver field names are recoverable client-side.
        assert finding["leaked_fields"] == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_finding_reports_both_formats():
    """When both formats are emitted, both are named in the finding."""
    app = create_app(tracing="both")
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await trace_exposure.check(client)
        finding = next(f for f in findings if f["category"] == "trace_exposure")
        formats = " ".join(finding["tracing_formats"])
        assert "apollo-tracing" in formats
        assert "FTV1" in formats
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_finding_has_remediation_and_impact():
    """The finding includes actionable remediation and impact text."""
    app = create_app(tracing="apollo")
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await trace_exposure.check(client)
        finding = next(f for f in findings if f["category"] == "trace_exposure")
        assert finding["remediation"]
        assert "tracing" in finding["remediation"].lower()
        assert finding["impact"]
        assert "timing" in finding["impact"].lower()
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_check_registered_in_cli_all():
    """trace-exposure is wired into the default `all` check set."""
    from enshroud.cli import ALL_CHECKS, VALID_CHECKS, parse_checks

    assert "trace-exposure" in ALL_CHECKS
    assert "trace-exposure" in VALID_CHECKS
    assert "trace-exposure" in parse_checks("all")
