"""Tests for the pq-enum check (ID-keyed persisted-query enumeration)."""
from __future__ import annotations

import json
import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import pq_enum
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
async def test_finding_when_id_store_enabled():
    """ID-keyed store enabled → MEDIUM persisted_query_id_enumeration finding."""
    app = create_app(pq_id_store=True)
    url, server, _ = _start_server(app)
    try:
        findings = await pq_enum.check(GraphQLClient(url))
        categories = [f["category"] for f in findings]
        assert "persisted_query_id_enumeration" in categories
        finding = next(
            f for f in findings
            if f["category"] == "persisted_query_id_enumeration"
        )
        assert finding["severity"] == "MEDIUM"
        # The reproduction must reference a guessable ID and the no-query-body
        # nature of the probe.
        assert "id" in finding["reproduction"].lower()
        assert finding["probe_id"] in ("1", "2", "100")
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_no_finding_when_id_store_disabled():
    """ID store off (default) → no finding (secure posture)."""
    app = create_app(pq_id_store=False)
    url, server, _ = _start_server(app)
    try:
        findings = await pq_enum.check(GraphQLClient(url))
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_no_finding_against_hash_keyed_apq_only():
    """A pure APQ (hash-keyed) server has no ID store → no pq-enum finding.

    This is the differential guarantee: APQ keys on an unguessable SHA-256 hash,
    not a guessable ID. An APQ-enabled server that does not honour ID-only
    lookups must return PersistedQueryNotFound / a non-`data` response to every
    ID probe and yield nothing here, so pq-enum never double-counts the APQ
    checks.
    """
    app = create_app(apq_enabled=True, apq_serve_over_get=True, pq_id_store=False)
    url, server, _ = _start_server(app)
    try:
        findings = await pq_enum.check(GraphQLClient(url))
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_only_one_finding_even_with_many_hits():
    """The check stops at the first confirmed signal (no endpoint hammering)."""
    app = create_app(pq_id_store=True)
    url, server, _ = _start_server(app)
    try:
        findings = await pq_enum.check(GraphQLClient(url))
        assert len(findings) == 1
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_evidence_is_truncated_string():
    """Evidence is a bounded string suitable for the report pipeline."""
    app = create_app(pq_id_store=True)
    url, server, _ = _start_server(app)
    try:
        findings = await pq_enum.check(GraphQLClient(url))
        finding = findings[0]
        assert isinstance(finding["evidence"], str)
        assert 0 < len(finding["evidence"]) <= 500
        # Evidence captures the ID-only request body that was executed.
        assert "request_body" in finding["evidence"]
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_probe_never_sends_a_query_body():
    """Every probe shape the check emits must omit a `query` field.

    Guards the read-only contract: pq-enum must only ask the server to run an
    *already-registered* operation by ID, never supply (and thereby execute) an
    operation of its own choosing.
    """
    for doc_id in ("1", "2", "100"):
        for payload in pq_enum._id_payloads(doc_id):
            assert "query" not in payload
            # The body is JSON-serialisable (it is sent verbatim over the wire).
            json.dumps(payload)


def test_pq_enum_in_all_checks_and_registered():
    """pq-enum is in --checks all, valid, and has a check_map entry."""
    from enshroud.cli import ALL_CHECKS, VALID_CHECKS, parse_checks

    assert "pq-enum" in ALL_CHECKS
    assert "pq-enum" in VALID_CHECKS
    assert "pq-enum" in parse_checks("all")
