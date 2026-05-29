"""Tests for the directive-enforcement (@skip / @include) bypass check."""
import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import directive_enforcement
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
async def test_directive_enforcement_bypass_vulnerable():
    """Server ignores @skip / @include → finding lists both vectors."""
    app = create_app(directive_enforcement_bypass=True)
    url, server = _start(app)
    try:
        client = GraphQLClient(url)
        findings = await directive_enforcement.check(client)
        assert len(findings) == 1
        f = findings[0]
        assert f["category"] == "directive_enforcement_bypass"
        assert f["severity"] == "MEDIUM"
        assert "skip_if_true" in f["accepted_vectors"]
        assert "include_if_false" in f["accepted_vectors"]
        # Both built-in directives surfaced in the human-readable list.
        assert any("@skip" in d for d in f["directives_failed"])
        assert any("@include" in d for d in f["directives_failed"])
        # Evidence is bounded and includes the failed vectors.
        assert "accepted_vectors" in f["evidence"]
        assert len(f["evidence"]) <= 800
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_directive_enforcement_hardened_no_finding():
    """Spec-correct server honours both directives → no finding."""
    app = create_app(directive_enforcement_bypass=False)
    url, server = _start(app)
    try:
        client = GraphQLClient(url)
        findings = await directive_enforcement.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_directive_enforcement_default_mock_no_finding(mock_url):
    """The session-wide mock server (defaults) must not trip the check.

    Regression for the alias-matcher overlap: the generic
    `(\\w+)\\s*:\\s*__typename` echoer would return both keep+drop aliases on
    every server if our dedicated probe handler did not run first.
    """
    client = GraphQLClient(mock_url)
    findings = await directive_enforcement.check(client)
    assert findings == []


def test_drop_key_returned_signal():
    """The differential signal: keep present, drop present → bypass."""
    # Bypass: both keys present.
    assert directive_enforcement._drop_key_returned(
        {"data": {"enshroudKeep": "Query", "enshroudDrop": "Query"}}
    )
    # Spec-correct: only the unconditional anchor.
    assert not directive_enforcement._drop_key_returned(
        {"data": {"enshroudKeep": "Query"}}
    )
    # Errored: never a signal.
    assert not directive_enforcement._drop_key_returned(
        {"errors": [{"message": "bad query"}]}
    )
    # No data at all: never a signal.
    assert not directive_enforcement._drop_key_returned({"data": None})
    # Drop present but keep absent: not a clean signal — the executor never ran
    # the anchor, so we cannot infer enforcement was bypassed.
    assert not directive_enforcement._drop_key_returned(
        {"data": {"enshroudDrop": "Query"}}
    )
    # Drop is null: spec-correct omission represented as null is not a "returned"
    # value.
    assert not directive_enforcement._drop_key_returned(
        {"data": {"enshroudKeep": "Query", "enshroudDrop": None}}
    )


def test_probe_shape_is_typename_only():
    """Both probes are pure-__typename, single-line, read-only by construction."""
    for vector, label, query in directive_enforcement._PROBES:
        # Probe must select only the meta-field — no schema knowledge required.
        assert "__typename" in query
        # The two aliases the differential depends on are present.
        assert directive_enforcement.KEEP_KEY in query
        assert directive_enforcement.DROP_KEY in query
        # The directive under test is present in its expected legal form.
        assert label in query
        # Read-only: the probe never sends a mutation.
        assert "mutation" not in query.lower()


@pytest.mark.asyncio
async def test_only_skip_vector_fires_when_include_honoured(monkeypatch):
    """Partial enforcement: a server that honours @include but ignores @skip.

    Demonstrates the per-probe granularity — only the failing directive shows
    up in `accepted_vectors`, not both.
    """
    # We simulate by stubbing the client to return a tailored response per probe.
    class _StubClient:
        async def query(self, q):
            if "@skip" in q:
                return {"data": {"enshroudKeep": "Query", "enshroudDrop": "Query"}}
            if "@include" in q:
                return {"data": {"enshroudKeep": "Query"}}
            return {"data": {}}

    findings = await directive_enforcement.check(_StubClient())  # type: ignore[arg-type]
    assert len(findings) == 1
    f = findings[0]
    assert f["accepted_vectors"] == ["skip_if_true"]
    assert f["directives_failed"] == ["@skip(if: true)"]


@pytest.mark.asyncio
async def test_transport_error_is_silent():
    """A probe that raises during transport is silently skipped (no finding)."""
    class _BoomClient:
        async def query(self, q):
            raise RuntimeError("network down")

    findings = await directive_enforcement.check(_BoomClient())  # type: ignore[arg-type]
    assert findings == []
