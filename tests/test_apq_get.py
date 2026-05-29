"""Tests for the apq-get check (APQ persisted-query execution over GET)."""
from __future__ import annotations

import hashlib
import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import apq_get
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


_PROBE_HASH = hashlib.sha256(b"{ __typename }").hexdigest()


# ── tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_finding_when_apq_disabled():
    """APQ disabled → no probing, no finding (even if GET would serve)."""
    app = create_app(apq_enabled=False, apq_serve_over_get=True)
    url, server, _ = _start_server(app)
    try:
        findings = await apq_get.check(GraphQLClient(url))
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_no_finding_when_get_not_served():
    """APQ enabled but GET execution disabled → secure default, no finding."""
    app = create_app(apq_enabled=True, apq_serve_over_get=False)
    url, server, _ = _start_server(app)
    try:
        findings = await apq_get.check(GraphQLClient(url))
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_finding_when_get_execution_enabled():
    """APQ enabled AND served over GET → MEDIUM apq_execution_over_get finding."""
    app = create_app(apq_enabled=True, apq_serve_over_get=True)
    url, server, _ = _start_server(app)
    try:
        findings = await apq_get.check(GraphQLClient(url))
        categories = [f["category"] for f in findings]
        assert "apq_execution_over_get" in categories
        finding = next(
            f for f in findings if f["category"] == "apq_execution_over_get"
        )
        assert finding["severity"] == "MEDIUM"
        # The reproduction must reference the GET transport and the probe hash.
        assert "GET" in finding["reproduction"]
        assert finding["probe_hash"] == _PROBE_HASH
        # Evidence captures the GET URL that was executed.
        assert "extensions" in finding["evidence"]
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_no_finding_when_registration_blocked_and_get_off():
    """Auth-gated registration with GET execution off → still no finding."""
    app = create_app(
        apq_enabled=True, apq_require_auth=True, apq_serve_over_get=False
    )
    url, server, _ = _start_server(app)
    try:
        findings = await apq_get.check(GraphQLClient(url))
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_evidence_is_truncated_string():
    """Evidence is a bounded string suitable for the report pipeline."""
    app = create_app(apq_enabled=True, apq_serve_over_get=True)
    url, server, _ = _start_server(app)
    try:
        findings = await apq_get.check(GraphQLClient(url))
        finding = next(
            f for f in findings if f["category"] == "apq_execution_over_get"
        )
        assert isinstance(finding["evidence"], str)
        assert 0 < len(finding["evidence"]) <= 500
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_no_finding_when_cache_unpopulated():
    """GET-serve on, but registration auth-gated so the hash is never cached.

    The GET lookup must return PersistedQueryNotFound (empty cache) and the
    check must NOT fire — proving the finding depends on actual GET execution,
    not merely on the serve-over-get config.
    """
    app = create_app(
        apq_enabled=True, apq_require_auth=True, apq_serve_over_get=True
    )
    url, server, _ = _start_server(app)
    try:
        findings = await apq_get.check(GraphQLClient(url))
        assert findings == []
    finally:
        server.should_exit = True


def test_apq_get_in_all_checks_and_registered():
    """apq-get is in --checks all, valid, and has a check_map entry."""
    from enshroud.cli import ALL_CHECKS, VALID_CHECKS, parse_checks

    assert "apq-get" in ALL_CHECKS
    assert "apq-get" in VALID_CHECKS
    assert "apq-get" in parse_checks("all")
