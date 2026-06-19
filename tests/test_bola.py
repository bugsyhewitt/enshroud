"""Tests for the bola (object-level authorization) check.

Covers the packet §11 acceptance criteria and the Appendix K bounded-benign
invariants for object-level BOLA:
  * confirmed only when ANOTHER object's data is returned (criterion 5)
  * returning the caller's OWN object is NOT BOLA (anti-pattern A5 / Appendix K
    ``test_bola_requires_unauthorized_data``)
  * a server that enforces object authz → no finding
  * the check is inert without ``--active`` and without full targeting
  * exactly ONE request is sent (hard cap, no enumeration — A8)
  * sensitive field VALUES are redacted in the evidence
"""
from __future__ import annotations

import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import bola
from enshroud.client import GraphQLClient
from tests.fixtures.mock_graphql_server import create_app


# ── helpers ──────────────────────────────────────────────────────────────────

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


def _bola_cfg(enforce: bool):
    """A mock with a `user(id)` field, two objects, owned by two sessions."""
    return {
        "query_field": "user",
        "id_arg": "id",
        "objects": {
            "1": {"id": "1", "email": "me@example.com"},
            "2": {"id": "2", "email": "victim@example.com", "ssn": "999-99-9999"},
        },
        "session_header": "authorization",
        "owner_of": {"1": "Bearer tokA", "2": "Bearer tokB"},
        "enforce_authz": enforce,
    }


# ── unit tests (no server) ─────────────────────────────────────────────────────

def test_build_bola_query_includes_id_and_swaps_other():
    q = bola.build_bola_query("user", "id", "2", ["email"])
    assert 'user(id: "2")' in q
    assert "id" in q and "email" in q


def test_redact_masks_sensitive_values():
    out = bola._redact({"id": "2", "email": "v@x.com", "ssn": "1", "name": "Bob"})
    assert out["id"] == "2"            # identifier preserved (the proof)
    assert out["email"] == "<redacted>"
    assert out["ssn"] == "<redacted>"
    assert out["name"] == "Bob"        # non-sensitive preserved


# ── gating / fail-closed ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_inert_without_active():
    app = create_app(bola_object=_bola_cfg(enforce=False))
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url, auth_header="Authorization: Bearer tokA")
        findings = await bola.check(
            client, active=False, query_field="user", other_id="2"
        )
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_inert_without_target():
    app = create_app(bola_object=_bola_cfg(enforce=False))
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url, auth_header="Authorization: Bearer tokA")
        # active but no other_id → nothing to read, no finding.
        findings = await bola.check(client, active=True, query_field="user")
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_same_id_is_not_bola():
    app = create_app(bola_object=_bola_cfg(enforce=False))
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url, auth_header="Authorization: Bearer tokA")
        findings = await bola.check(
            client, active=True, query_field="user", my_id="2", other_id="2"
        )
        assert findings == []
    finally:
        server.should_exit = True


# ── confirmation behaviour ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_confirmed_when_other_object_returned():
    # authz NOT enforced → caller (tokA, owns id 1) reads id 2 → BOLA confirmed.
    app = create_app(bola_object=_bola_cfg(enforce=False))
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url, auth_header="Authorization: Bearer tokA")
        findings = await bola.check(
            client,
            active=True,
            query_field="user",
            id_arg="id",
            my_id="1",
            other_id="2",
            extra_fields=["email", "ssn"],
        )
        assert len(findings) == 1
        f = findings[0]
        assert f["category"] == "bola_object_authz_missing"
        assert f["severity"] == "HIGH"
        assert f["owasp"] == ["API1:2023"]
        assert "CWE-639" in f["cwe"]
        assert f["other_id"] == "2"
        # Sensitive values must be redacted in the evidence.
        assert "999-99-9999" not in f["evidence"]
        assert "victim@example.com" not in f["evidence"]
        assert "<redacted>" in f["evidence"]
        # The leaked-fields list records WHAT was exposed (names, not values).
        assert "ssn" in f["leaked_fields"]
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_not_confirmed_when_authz_enforced():
    # authz enforced → caller (tokA) cannot read id 2 → FORBIDDEN → no finding.
    app = create_app(bola_object=_bola_cfg(enforce=True))
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url, auth_header="Authorization: Bearer tokA")
        findings = await bola.check(
            client, active=True, query_field="user", my_id="1", other_id="2"
        )
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_own_object_returned_is_not_confirmed(monkeypatch):
    """Appendix K invariant: a server returning MY own id is NOT BOLA (A5).

    Even if the server hands back an object, if it is the caller's own object
    (id == my_id, != other_id) the check must not fire.
    """
    async def fake_query(self, query, variables=None):
        # Server ignores the requested id and returns the caller's own object.
        return {"data": {"user": {"id": "1", "email": "me@example.com"}}}

    monkeypatch.setattr(GraphQLClient, "query", fake_query)
    client = GraphQLClient("http://x/graphql")
    findings = await bola.check(
        client, active=True, query_field="user", my_id="1", other_id="2"
    )
    assert findings == []


@pytest.mark.asyncio
async def test_sends_exactly_one_request(monkeypatch):
    """Hard cap (A8): confirmation is a single benign request, never enumeration."""
    calls = {"n": 0}

    async def counting_query(self, query, variables=None):
        calls["n"] += 1
        return {"data": {"user": {"id": "2", "email": "v@x.com"}}}

    monkeypatch.setattr(GraphQLClient, "query", counting_query)
    client = GraphQLClient("http://x/graphql")
    findings = await bola.check(
        client, active=True, query_field="user", my_id="1", other_id="2"
    )
    assert len(findings) == 1
    assert calls["n"] == 1   # exactly one request — no ID-range sweep
