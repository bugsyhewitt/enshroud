"""Tests for the field-authz (field-level authorization) check.

Covers packet §11 criterion 5 (field over-fetch confirmed; gated → not
vulnerable) and the bounded-benign discipline:
  * confirmed only when sensitive fields are returned NON-NULL
  * a server that nulls/gates them → no finding
  * inert without ``--active`` and without targeting
  * a single benign request; sensitive VALUES redacted in the evidence
"""
from __future__ import annotations

import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import field_authz
from enshroud.client import GraphQLClient
from tests.fixtures.mock_graphql_server import create_app


def _start_server(app, host: str = "127.0.0.1"):
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


def _authz_cfg(gated: bool):
    return {
        "query_field": "me",
        "public_fields": {"id": "self", "username": "alice"},
        "sensitive_fields": {
            "ssn": "999-99-9999",
            "creditCard": "4111111111111111",
            "passwordHash": "$2b$12$abcdef",
        },
        "gated": gated,
    }


# ── unit ──────────────────────────────────────────────────────────────────────

def test_build_overfetch_query_selects_id_and_sensitive():
    q = field_authz.build_overfetch_query("me", ["ssn", "creditCard"])
    assert "{ me {" in q
    assert "id" in q and "ssn" in q and "creditCard" in q


def test_leaked_sensitive_ignores_null():
    obj = {"id": "1", "ssn": "x", "creditCard": None, "passwordHash": ""}
    leaked = field_authz._leaked_sensitive(obj, ["ssn", "creditCard", "passwordHash"])
    assert leaked == ["ssn"]


# ── gating / fail-closed ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_inert_without_active():
    app = create_app(field_authz=_authz_cfg(gated=False))
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await field_authz.check(
            client, active=False, query_field="me", sensitive_fields=["ssn"]
        )
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_inert_without_sensitive_fields():
    app = create_app(field_authz=_authz_cfg(gated=False))
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await field_authz.check(
            client, active=True, query_field="me", sensitive_fields=[]
        )
        assert findings == []
    finally:
        server.should_exit = True


# ── confirmation behaviour ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_confirmed_when_sensitive_fields_leak():
    app = create_app(field_authz=_authz_cfg(gated=False))
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await field_authz.check(
            client,
            active=True,
            query_field="me",
            sensitive_fields=["ssn", "creditCard", "passwordHash"],
        )
        assert len(findings) == 1
        f = findings[0]
        assert f["category"] == "field_level_authz_missing"
        assert f["severity"] == "HIGH"            # PII-shaped → HIGH
        assert f["owasp"] == ["API3:2023"]
        assert "CWE-200" in f["cwe"]
        assert set(f["leaked_fields"]) == {"ssn", "creditCard", "passwordHash"}
        # Values must be redacted in evidence.
        assert "999-99-9999" not in f["evidence"]
        assert "4111111111111111" not in f["evidence"]
        assert "<redacted>" in f["evidence"]
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_not_confirmed_when_gated():
    app = create_app(field_authz=_authz_cfg(gated=True))
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await field_authz.check(
            client,
            active=True,
            query_field="me",
            sensitive_fields=["ssn", "creditCard", "passwordHash"],
        )
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_sends_one_request(monkeypatch):
    calls = {"n": 0}

    async def counting_query(self, query, variables=None):
        calls["n"] += 1
        return {"data": {"me": {"id": "1", "ssn": "x"}}}

    monkeypatch.setattr(GraphQLClient, "query", counting_query)
    client = GraphQLClient("http://x/graphql")
    findings = await field_authz.check(
        client, active=True, query_field="me", sensitive_fields=["ssn"]
    )
    assert len(findings) == 1
    assert calls["n"] == 1
