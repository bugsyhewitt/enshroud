"""Tests for the fragment-cycle check — cyclic-fragment validation bypass."""
from __future__ import annotations

import json
import socket
import threading
import time

import httpx
import pytest
import uvicorn

from enshroud.checks import fragment_cycle
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


# ── Unit tests for the rejection heuristic ──────────────────────────────────


def test_rejected_cycle_detects_cycle_error():
    resp = {
        "errors": [
            {"message": "Cannot spread fragment 'A' within itself via 'B'."}
        ]
    }
    assert fragment_cycle._rejected_cycle(resp) is True


def test_rejected_cycle_detects_complexity_error():
    resp = {"errors": [{"message": "Query complexity 9000 exceeds maximum."}]}
    assert fragment_cycle._rejected_cycle(resp) is True


def test_rejected_cycle_false_on_data():
    resp = {"data": {"__typename": "Query"}}
    assert fragment_cycle._rejected_cycle(resp) is False


def test_rejected_cycle_false_on_unrelated_error():
    resp = {"errors": [{"message": "Some unrelated runtime error."}]}
    assert fragment_cycle._rejected_cycle(resp) is False


def test_probe_queries_are_cyclic_and_typename_only():
    # Both probes must be read-only (only __typename) and contain a self/mutual
    # fragment reference, so they exercise the cycle path, not the field-dup one.
    assert "...A" in fragment_cycle._TWO_FRAGMENT_CYCLE
    assert "...B" in fragment_cycle._TWO_FRAGMENT_CYCLE
    assert "...S } fragment S" in fragment_cycle._SELF_REFERENTIAL
    for probe in (
        fragment_cycle._TWO_FRAGMENT_CYCLE,
        fragment_cycle._SELF_REFERENTIAL,
    ):
        # Only the __typename meta-field is selected — nothing is mutated.
        assert "mutation" not in probe.lower()
        assert "__typename" in probe


# ── Integration tests against a live server ─────────────────────────────────


@pytest.mark.asyncio
async def test_fragment_cycle_accepted_fires_medium():
    # Default mock is a non-validating executor: it accepts cyclic fragments.
    app = create_app(fragment_cycle_validation=False)
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await fragment_cycle.check(client)
        assert len(findings) == 1
        finding = findings[0]
        assert finding["category"] == "fragment_cycle_dos"
        assert finding["severity"] == "MEDIUM"
        # Both probes are cyclic and should be accepted by the vulnerable server.
        assert set(finding["accepted_vectors"]) == {
            "two_fragment_cycle",
            "self_referential_fragment",
        }
        assert finding["crashed_vectors"] == []
        evidence = json.loads(finding["evidence"])
        assert "two_fragment_cycle" in evidence["accepted_vectors"]
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_fragment_cycle_validating_server_silent():
    # A spec-compliant validator rejects cyclic fragments with a cycle error.
    app = create_app(fragment_cycle_validation=True)
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await fragment_cycle.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_fragment_cycle_transport_crash_counts(monkeypatch):
    # A timeout on a tiny cyclic document is treated as a crash (the server tried
    # to expand the cycle and choked), which fires the finding via crashed_vectors.
    client = GraphQLClient("http://127.0.0.1:1/graphql")

    async def fake_query(query, variables=None):
        raise httpx.TimeoutException("simulated expansion timeout")

    monkeypatch.setattr(client, "query", fake_query)
    findings = await fragment_cycle.check(client)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["category"] == "fragment_cycle_dos"
    assert finding["accepted_vectors"] == []
    assert set(finding["crashed_vectors"]) == {
        "two_fragment_cycle",
        "self_referential_fragment",
    }
    assert "unbounded fragment" in finding["description"]


@pytest.mark.asyncio
async def test_fragment_cycle_generic_error_silent(monkeypatch):
    # A non-timeout transport error (e.g. 400) means the server rejected the
    # request — no finding.
    client = GraphQLClient("http://127.0.0.1:1/graphql")

    async def fake_query(query, variables=None):
        raise httpx.HTTPStatusError(
            "400", request=None, response=None  # type: ignore[arg-type]
        )

    monkeypatch.setattr(client, "query", fake_query)
    findings = await fragment_cycle.check(client)
    assert findings == []


def test_fragment_cycle_in_all_checks():
    from enshroud.cli import ALL_CHECKS, VALID_CHECKS, parse_checks

    assert "fragment-cycle" in ALL_CHECKS
    assert "fragment-cycle" in VALID_CHECKS
    assert "fragment-cycle" in parse_checks("all")
    assert parse_checks("fragment-cycle") == ["fragment-cycle"]
