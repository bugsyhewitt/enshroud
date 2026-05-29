"""Tests for the depth-limit bypass check (fragment-expanded nesting)."""
import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import depth_bypass
from enshroud.client import GraphQLClient
from tests.fixtures.mock_graphql_server import create_app


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _start(app):
    """Start an app on an ephemeral port; return (url, server)."""
    host = "127.0.0.1"
    port = _free_port()
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
    return f"http://{host}:{port}/graphql", server


@pytest.mark.asyncio
async def test_depth_bypass_vulnerable():
    """Limit enforced on flat query but bypassable via a fragment → finding."""
    app = create_app(
        depth_limit=5,
        depth_limit_expands_fragments=False,  # buggy: counts operation body only
    )
    url, server = _start(app)
    try:
        client = GraphQLClient(url)
        findings = await depth_bypass.check(client)
        assert len(findings) == 1
        f = findings[0]
        assert f["category"] == "depth_limit_bypass"
        assert f["severity"] == "MEDIUM"
        assert f["probe_depth"] == depth_bypass.PROBE_DEPTH
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_depth_bypass_hardened_no_finding():
    """Limiter that expands fragments rejects both probes → no finding."""
    app = create_app(
        depth_limit=5,
        depth_limit_expands_fragments=True,  # spec-correct
    )
    url, server = _start(app)
    try:
        client = GraphQLClient(url)
        findings = await depth_bypass.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_depth_bypass_no_limit_no_finding(mock_url):
    """No depth limit at all is depth-dos territory, not a bypass → no finding."""
    client = GraphQLClient(mock_url)
    findings = await depth_bypass.check(client)
    assert findings == []


def test_flat_query_is_deeper_than_operation_body_of_fragment_query():
    """The flat probe nests in the operation body; the fragment probe hides it."""
    flat = depth_bypass._build_flat_query(depth=3)
    frag = depth_bypass._build_fragment_query(depth=3)
    # Flat probe: nesting lives in the operation body.
    assert flat.count("{") == 4  # outer brace + 3 nesting levels
    # Fragment probe: operation body is a single spread; nesting is in fragment D.
    assert "...D" in frag
    assert "fragment D on Query" in frag


def test_depth_error_detection():
    assert depth_bypass._is_depth_rejected(
        {"errors": [{"message": "Query depth 20 exceeds max depth 5"}]}
    )
    assert not depth_bypass._is_depth_rejected({"data": {"__typename": "Query"}})
    assert not depth_bypass._is_depth_rejected(
        {"errors": [{"message": "some unrelated error"}]}
    )


def test_accepted_detection():
    assert depth_bypass._is_accepted({"data": {"__typename": "Query"}})
    assert not depth_bypass._is_accepted({"errors": [{"message": "nope"}]})
    assert not depth_bypass._is_accepted({"data": None})
