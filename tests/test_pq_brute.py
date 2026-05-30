"""Tests for the pq-brute check (ID-keyed persisted-query brute force)."""
from __future__ import annotations

import json
import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import pq_brute
from enshroud.client import GraphQLClient
from tests.fixtures.mock_graphql_server import create_app


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


@pytest.mark.asyncio
async def test_finding_when_id_store_enumerates():
    """Range-walking an ID-keyed store yields a HIGH brute-force finding listing every hit ID."""
    app = create_app(pq_id_store=True)
    url, server, _ = _start_server(app)
    try:
        findings = await pq_brute.check(
            GraphQLClient(url),
            fuzz_rate=0,
            id_start=1,
            id_end=10,
        )
        cats = [f["category"] for f in findings]
        assert "persisted_query_id_brute_force" in cats
        finding = next(
            f for f in findings if f["category"] == "persisted_query_id_brute_force"
        )
        assert finding["severity"] == "HIGH"
        # The mock server's pq_id_store hits every ID, so the brute walk
        # should report every ID it asked about.
        assert finding["enumerated_count"] == 10
        assert finding["enumerated_ids"] == [str(i) for i in range(1, 11)]
        assert finding["probes_sent"] == 10
        assert finding["id_range"] == [1, 10]
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_no_finding_when_id_store_disabled():
    """A server without an ID-keyed store produces no brute finding."""
    app = create_app(pq_id_store=False)
    url, server, _ = _start_server(app)
    try:
        findings = await pq_brute.check(
            GraphQLClient(url),
            fuzz_rate=0,
            id_start=1,
            id_end=5,
        )
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_no_finding_against_hash_keyed_apq_only():
    """Pure APQ (hash-keyed) — every ID probe gets PersistedQueryNotFound, no finding."""
    app = create_app(apq_enabled=True, apq_serve_over_get=True, pq_id_store=False)
    url, server, _ = _start_server(app)
    try:
        findings = await pq_brute.check(
            GraphQLClient(url),
            fuzz_rate=0,
            id_start=1,
            id_end=5,
        )
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_brute_probe_carries_no_query_body():
    """Every probe shape must omit the `query` field (read-only contract)."""
    payload = pq_brute._id_payload("42")
    assert "query" not in payload
    # The persisted-query extension carries the ID but NO sha256Hash, so the
    # probe can never accidentally collide with an APQ registration.
    pq = payload["extensions"]["persistedQuery"]
    assert "sha256Hash" not in pq
    assert pq["id"] == "42"
    assert pq["version"] == 1
    json.dumps(payload)


@pytest.mark.asyncio
async def test_brute_respects_max_probes_cap():
    """A wider range than BRUTE_MAX_PROBES is clipped — no unbounded sweeps."""
    app = create_app(pq_id_store=True)
    url, server, _ = _start_server(app)
    try:
        findings = await pq_brute.check(
            GraphQLClient(url),
            fuzz_rate=0,
            id_start=1,
            id_end=1 + pq_brute.BRUTE_MAX_PROBES + 1000,  # absurdly wide
        )
        finding = findings[0]
        assert finding["probes_sent"] == pq_brute.BRUTE_MAX_PROBES
        # The reported range reflects what was actually walked, not the request.
        assert finding["id_range"] == [1, pq_brute.BRUTE_MAX_PROBES]
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_brute_caps_reported_ids_in_finding_body():
    """Enumerated IDs in the finding are capped so the payload stays bounded."""
    app = create_app(pq_id_store=True)
    url, server, _ = _start_server(app)
    try:
        # Walk more than _MAX_REPORTED_IDS hits to exercise the cap.
        findings = await pq_brute.check(
            GraphQLClient(url),
            fuzz_rate=0,
            id_start=1,
            id_end=pq_brute._MAX_REPORTED_IDS + 50,
        )
        finding = findings[0]
        # All probes still execute and the count reflects only what was kept.
        assert finding["probes_sent"] == pq_brute._MAX_REPORTED_IDS + 50
        assert len(finding["enumerated_ids"]) == pq_brute._MAX_REPORTED_IDS
        assert finding["enumerated_count"] == pq_brute._MAX_REPORTED_IDS
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_evidence_is_truncated_string():
    """Evidence is a bounded string suitable for the report pipeline."""
    app = create_app(pq_id_store=True)
    url, server, _ = _start_server(app)
    try:
        findings = await pq_brute.check(
            GraphQLClient(url),
            fuzz_rate=0,
            id_start=1,
            id_end=3,
        )
        finding = findings[0]
        assert isinstance(finding["evidence"], str)
        assert 0 < len(finding["evidence"]) <= 500
        assert "request_body" in finding["evidence"]
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_empty_range_returns_no_finding():
    """An inverted/empty range is a no-op (does not crash, does not probe)."""
    app = create_app(pq_id_store=True)
    url, server, _ = _start_server(app)
    try:
        findings = await pq_brute.check(
            GraphQLClient(url),
            fuzz_rate=0,
            id_start=10,
            id_end=5,
        )
        assert findings == []
    finally:
        server.should_exit = True


def test_pq_brute_is_opt_in_not_in_all():
    """pq-brute is a valid check, opt-in only, and NOT included in --checks all.

    The brute walk sends up to BRUTE_MAX_PROBES requests in a single
    invocation — far more than any check in 'all' — so it must be requested
    explicitly, the same way schema-fuzz and injection are.
    """
    from enshroud.cli import ALL_CHECKS, OPT_IN_CHECKS, VALID_CHECKS, parse_checks

    assert "pq-brute" in VALID_CHECKS
    assert "pq-brute" in OPT_IN_CHECKS
    assert "pq-brute" not in ALL_CHECKS
    assert "pq-brute" not in parse_checks("all")
    assert parse_checks("pq-brute") == ["pq-brute"]
