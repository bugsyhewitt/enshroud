"""Tests for the APQ hash-mismatch / cache-poisoning check (apq-collision)."""
from __future__ import annotations

import hashlib
import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import apq_collision
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
async def test_no_finding_when_apq_disabled():
    """A server without APQ enabled produces no apq-collision finding."""
    app = create_app(apq_enabled=False)
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await apq_collision.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_no_finding_when_hash_verified():
    """A spec-compliant server (verifies hash) is not flagged."""
    app = create_app(apq_enabled=True, apq_verify_hash=True)
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await apq_collision.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_finding_when_hash_not_verified():
    """A server that stores a mismatched hash/query is flagged as poisonable."""
    app = create_app(apq_enabled=True, apq_verify_hash=False)
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await apq_collision.check(client)
        categories = [f["category"] for f in findings]
        assert "apq_hash_mismatch" in categories
        finding = next(f for f in findings if f["category"] == "apq_hash_mismatch")
        # Mock serves the poisoned entry on lookup → confirmed → HIGH.
        assert finding["severity"] == "HIGH"
        assert finding["poison_confirmed"] is True
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_finding_records_real_and_submitted_hashes():
    """The finding evidence distinguishes the real digest from the submitted one."""
    app = create_app(apq_enabled=True, apq_verify_hash=False)
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await apq_collision.check(client)
        finding = next(f for f in findings if f["category"] == "apq_hash_mismatch")
        real = hashlib.sha256(b"{ __typename }").hexdigest()
        assert finding["real_hash"] == real
        assert finding["submitted_hash"] == "b" * 64
        # The two hashes must differ — that asymmetry is the whole point.
        assert finding["real_hash"] != finding["submitted_hash"]
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_finding_has_remediation_and_impact():
    """The finding includes actionable remediation and impact text."""
    app = create_app(apq_enabled=True, apq_verify_hash=False)
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await apq_collision.check(client)
        finding = next(f for f in findings if f["category"] == "apq_hash_mismatch")
        assert finding["remediation"]
        assert "PersistedQueryHashMismatch" in finding["remediation"]
        assert finding["impact"]
        assert "poison" in finding["impact"].lower()
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_no_finding_when_registration_requires_auth():
    """If registration is auth-gated, the unauthenticated probe cannot poison."""
    app = create_app(
        apq_enabled=True, apq_verify_hash=False, apq_require_auth=True
    )
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await apq_collision.check(client)
        # The 401 registration is neither a hash-mismatch rejection nor an
        # accepted registration → no finding (no false positive).
        assert findings == []
    finally:
        server.should_exit = True
