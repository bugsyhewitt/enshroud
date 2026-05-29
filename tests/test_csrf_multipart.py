"""Tests for the csrf-multipart check (multipart/form-data + text/plain CSRF)."""
from __future__ import annotations

import json
import socket
import threading
import time

import httpx
import pytest
import uvicorn

from enshroud.checks import csrf_multipart
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


# ── Unit tests for the helpers ──────────────────────────────────────────────


def test_build_mutation_uses_discovered_field():
    assert csrf_multipart._build_mutation("deleteUser") == "mutation { deleteUser }"


def test_build_mutation_falls_back_to_synthetic_probe():
    out = csrf_multipart._build_mutation(None)
    assert out == csrf_multipart.SYNTHETIC_MUTATION
    assert "mutation" in out
    assert "__typename" in out


def test_is_accepted_true_on_2xx_with_data():
    resp = httpx.Response(200, json={"data": {"__typename": "Mutation"}})
    assert csrf_multipart._is_accepted(resp) is True


def test_is_accepted_false_on_errors_only():
    resp = httpx.Response(
        200, json={"errors": [{"message": "requires application/json"}]}
    )
    assert csrf_multipart._is_accepted(resp) is False


def test_is_accepted_false_on_null_data():
    resp = httpx.Response(200, json={"data": None})
    assert csrf_multipart._is_accepted(resp) is False


def test_is_accepted_false_on_4xx():
    resp = httpx.Response(400, json={"data": {"__typename": "Mutation"}})
    assert csrf_multipart._is_accepted(resp) is False


def test_finding_shape_is_high_csrf():
    finding = csrf_multipart._finding(
        vector="multipart/form-data POST",
        evidence="{}",
        mutation="mutation { x }",
        synthetic=False,
    )
    assert finding["category"] == "csrf_via_content_type"
    assert finding["severity"] == "HIGH"
    assert finding["vector"] == "multipart/form-data POST"
    assert "multipart/form-data" in finding["title"]


def test_finding_synthetic_note():
    finding = csrf_multipart._finding(
        vector="text/plain POST",
        evidence="{}",
        mutation=csrf_multipart.SYNTHETIC_MUTATION,
        synthetic=True,
    )
    assert "synthetic" in finding["description"]


# ── Integration tests against a live server ─────────────────────────────────


@pytest.mark.asyncio
async def test_both_transports_vulnerable_fires_two_findings():
    """A server accepting multipart and text/plain → two HIGH findings."""
    app = create_app(
        introspection_enabled=True,
        dangerous_mutations=["deleteUser"],
        accept_multipart_post=True,
        accept_text_plain_post=True,
    )
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await csrf_multipart.check(client)
        assert len(findings) == 2
        vectors = {f["vector"] for f in findings}
        assert "multipart/form-data POST" in vectors
        assert "text/plain POST" in vectors
        for f in findings:
            assert f["category"] == "csrf_via_content_type"
            assert f["severity"] == "HIGH"
            evidence = json.loads(f["evidence"])
            assert evidence["response_status"] == 200
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_only_multipart_vulnerable_fires_one_finding():
    """multipart accepted but text/plain rejected → exactly one finding."""
    app = create_app(
        introspection_enabled=True,
        dangerous_mutations=["deleteUser"],
        accept_multipart_post=True,
        accept_text_plain_post=False,
    )
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await csrf_multipart.check(client)
        assert len(findings) == 1
        assert findings[0]["vector"] == "multipart/form-data POST"
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_csrf_safe_server_no_finding():
    """A server requiring application/json for all transports → no finding."""
    app = create_app(
        introspection_enabled=True,
        dangerous_mutations=["deleteUser"],
        accept_multipart_post=False,
        accept_text_plain_post=False,
    )
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await csrf_multipart.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_uses_synthetic_probe_when_introspection_disabled():
    """No introspection → synthetic __typename mutation still detects the bypass."""
    app = create_app(
        introspection_enabled=False,
        accept_multipart_post=True,
        accept_text_plain_post=True,
    )
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await csrf_multipart.check(client)
        assert len(findings) == 2
        for f in findings:
            assert "synthetic" in f["description"]
    finally:
        server.should_exit = True


def test_csrf_multipart_in_all_checks():
    from enshroud.cli import ALL_CHECKS, VALID_CHECKS, parse_checks

    assert "csrf-multipart" in ALL_CHECKS
    assert "csrf-multipart" in VALID_CHECKS
    assert "csrf-multipart" in parse_checks("all")
    assert parse_checks("csrf-multipart") == ["csrf-multipart"]


# ── Client transport unit tests ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_post_multipart_sends_multipart_content_type():
    """post_multipart issues a multipart/form-data body the server can parse."""
    app = create_app(accept_multipart_post=True)
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        resp = await client.post_multipart("mutation { x }")
        assert resp.status_code == 200
        assert resp.json()["data"] is not None
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_post_text_plain_sends_text_plain_content_type():
    """post_text_plain labels a JSON body as text/plain."""
    app = create_app(accept_text_plain_post=True)
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        resp = await client.post_text_plain("mutation { x }")
        assert resp.status_code == 200
        assert resp.json()["data"] is not None
    finally:
        server.should_exit = True
