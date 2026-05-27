"""Tests for the APQ (Automatic Persisted Query) abuse check."""
from __future__ import annotations

import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import apq
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
async def test_apq_not_enabled():
    """Server with APQ disabled should produce no findings."""
    app = create_app(apq_enabled=False)
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await apq.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_apq_enabled_detection():
    """Server with APQ enabled should produce at least the apq_enabled finding."""
    app = create_app(apq_enabled=True)
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await apq.check(client)
        categories = [f["category"] for f in findings]
        assert "apq_enabled" in categories
        enabled_finding = next(f for f in findings if f["category"] == "apq_enabled")
        assert enabled_finding["severity"] == "LOW"
        assert "PersistedQueryNotFound" in enabled_finding["evidence"]
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_apq_unrestricted_registration():
    """Server with APQ enabled and no auth required should flag unrestricted registration."""
    app = create_app(apq_enabled=True, apq_require_auth=False)
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await apq.check(client)
        categories = [f["category"] for f in findings]
        assert "apq_unrestricted_registration" in categories
        reg_finding = next(f for f in findings if f["category"] == "apq_unrestricted_registration")
        assert reg_finding["severity"] == "MEDIUM"
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_apq_registration_blocked_when_auth_required():
    """Server that requires auth for APQ registration should NOT flag unrestricted registration."""
    app = create_app(apq_enabled=True, apq_require_auth=True)
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await apq.check(client)
        categories = [f["category"] for f in findings]
        # APQ is enabled (hash-only probe succeeds with PersistedQueryNotFound)
        assert "apq_enabled" in categories
        # But registration is blocked → no unrestricted_registration finding
        assert "apq_unrestricted_registration" not in categories
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_apq_no_rate_limit():
    """Server with no rate limiting should produce the apq_no_rate_limit finding."""
    app = create_app(apq_enabled=True, apq_require_auth=False, apq_rate_limit=None)
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await apq.check(client)
        categories = [f["category"] for f in findings]
        assert "apq_no_rate_limit" in categories
        rl_finding = next(f for f in findings if f["category"] == "apq_no_rate_limit")
        assert rl_finding["severity"] == "MEDIUM"
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_apq_rate_limit_suppresses_finding():
    """Server with a strict rate limit should NOT produce the apq_no_rate_limit finding."""
    # Allow only 1 registration — all rapid-fire probes beyond that will fail.
    app = create_app(apq_enabled=True, apq_require_auth=False, apq_rate_limit=1)
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await apq.check(client)
        categories = [f["category"] for f in findings]
        # APQ is still enabled and first registration succeeds → those findings appear
        assert "apq_enabled" in categories
        # But subsequent rate-limit probes are blocked → no rate-limit finding
        assert "apq_no_rate_limit" not in categories
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_apq_evidence_in_enabled_finding():
    """The apq_enabled finding evidence must contain the raw server error text."""
    app = create_app(apq_enabled=True)
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await apq.check(client)
        enabled = next((f for f in findings if f["category"] == "apq_enabled"), None)
        assert enabled is not None
        assert "evidence" in enabled
        assert len(enabled["evidence"]) > 0
    finally:
        server.should_exit = True
