"""Tests for the operation-name-enum check (name-keyed persisted-operation registry)."""
from __future__ import annotations

import json
import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import operation_name_enum
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
async def test_finding_when_name_registry_populated():
    """Name-keyed registry containing a guessable name → MEDIUM finding."""
    app = create_app(op_name_registry=["Me"])
    url, server, _ = _start_server(app)
    try:
        findings = await operation_name_enum.check(GraphQLClient(url))
        categories = [f["category"] for f in findings]
        assert "persisted_operation_name_enumeration" in categories
        finding = next(
            f for f in findings
            if f["category"] == "persisted_operation_name_enumeration"
        )
        assert finding["severity"] == "MEDIUM"
        # The reproduction must reference the operationName-only nature of
        # the probe.
        assert "operationName" in finding["reproduction"]
        assert finding["probe_operation_name"] == "Me"
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_no_finding_when_registry_empty():
    """Empty registry (default) → no finding (secure posture)."""
    app = create_app()  # op_name_registry defaults to None / empty
    url, server, _ = _start_server(app)
    try:
        findings = await operation_name_enum.check(GraphQLClient(url))
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_no_finding_against_hash_keyed_apq_only():
    """A pure APQ (hash-keyed) server has no name registry → no finding.

    Differential guarantee against the APQ family: APQ keys on the unguessable
    SHA-256 hash of the query text, never on the operation name. An APQ-enabled
    server with no name registry must yield no finding here, so this check
    never double-counts the APQ checks.
    """
    app = create_app(apq_enabled=True, apq_serve_over_get=True)
    url, server, _ = _start_server(app)
    try:
        findings = await operation_name_enum.check(GraphQLClient(url))
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_no_finding_against_id_keyed_pq_store_only():
    """An ID-keyed pq store has no name registry → no finding.

    Differential guarantee against `pq-enum`: ID-only requests carry an `id`
    / `documentId` / `extensions.persistedQuery.id`. A server that only honours
    the ID transport must reject a bare `operationName` lookup and yield no
    finding here, so this check never double-counts `pq-enum`.
    """
    app = create_app(pq_id_store=True)
    url, server, _ = _start_server(app)
    try:
        findings = await operation_name_enum.check(GraphQLClient(url))
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_no_finding_when_registry_name_not_in_probe_list():
    """A registry whose names are not in the probe wordlist → no finding.

    The check fires only on guessable, conventional names. A registry whose
    operations carry idiosyncratic names an attacker would not try first must
    not produce a false positive.
    """
    app = create_app(op_name_registry=["CompanyInternalOpaqueOperationName"])
    url, server, _ = _start_server(app)
    try:
        findings = await operation_name_enum.check(GraphQLClient(url))
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_only_one_finding_even_with_many_hits():
    """The check stops at the first confirmed signal (no endpoint hammering)."""
    app = create_app(
        op_name_registry=["IntrospectionQuery", "Login", "Me", "HealthCheck", "GetUser"]
    )
    url, server, _ = _start_server(app)
    try:
        findings = await operation_name_enum.check(GraphQLClient(url))
        assert len(findings) == 1
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_evidence_is_truncated_string():
    """Evidence is a bounded string suitable for the report pipeline."""
    app = create_app(op_name_registry=["Login"])
    url, server, _ = _start_server(app)
    try:
        findings = await operation_name_enum.check(GraphQLClient(url))
        finding = findings[0]
        assert isinstance(finding["evidence"], str)
        assert 0 < len(finding["evidence"]) <= 500
        # Evidence captures the name-only request body that was executed.
        assert "request_body" in finding["evidence"]
        assert "operationName" in finding["evidence"]
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_probe_never_sends_a_query_body_id_or_hash():
    """Every probe shape the check emits must omit `query`, `id`, `documentId`,
    and `extensions.persistedQuery`.

    Guards the read-only contract and the strict differential against APQ /
    pq-enum: this check must only ask the server to run an *already-registered*
    operation by name, never supply an operation of its own choosing or
    overlap with the hash- or ID-keyed transports.
    """
    for name in operation_name_enum._PROBE_NAMES:
        payload = operation_name_enum._name_only_payload(name)
        assert "query" not in payload
        assert "id" not in payload
        assert "documentId" not in payload
        assert "extensions" not in payload
        assert payload.get("operationName") == name
        # The body is JSON-serialisable (it is sent verbatim over the wire).
        json.dumps(payload)


def test_operation_name_enum_in_all_checks_and_registered():
    """operation-name-enum is in --checks all, valid, and has a check_map entry."""
    from enshroud.cli import ALL_CHECKS, VALID_CHECKS, parse_checks

    assert "operation-name-enum" in ALL_CHECKS
    assert "operation-name-enum" in VALID_CHECKS
    assert "operation-name-enum" in parse_checks("all")
