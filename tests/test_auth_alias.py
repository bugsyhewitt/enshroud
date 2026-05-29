"""Tests for the auth-alias (authorization bypass via field aliasing) check."""
from __future__ import annotations

import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import auth_alias
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
async def test_no_finding_when_no_protected_field():
    """A server with no aliased-auth bug produces no findings."""
    app = create_app(alias_auth_bypass=None)
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await auth_alias.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_detects_alias_bypass():
    """Field denied by name but resolvable when aliased → HIGH finding."""
    # Authorization is keyed on the response key. `secrets` is denied directly,
    # but aliasing it changes the response key and bypasses the control.
    app = create_app(
        introspection_enabled=True,
        alias_auth_bypass={"field": "secrets", "denied_key": "secrets"},
    )
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await auth_alias.check(client)
        categories = [f["category"] for f in findings]
        assert "authz_bypass_via_alias" in categories
        finding = next(
            f for f in findings if f["category"] == "authz_bypass_via_alias"
        )
        assert finding["severity"] == "HIGH"
        assert finding["field"] == "secrets"
        # Evidence carries both the denied and the bypassing response.
        assert "secrets" in finding["evidence"]
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_falls_back_to_default_candidates_without_introspection():
    """When introspection is off, the check probes its bundled candidate list."""
    app = create_app(
        introspection_enabled=False,
        alias_auth_bypass={"field": "secrets", "denied_key": "secrets"},
    )
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await auth_alias.check(client)
        categories = [f["category"] for f in findings]
        assert "authz_bypass_via_alias" in categories
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_no_finding_when_field_denied_under_any_key():
    """A server that denies the field under EVERY response key is not vulnerable.

    Setting denied_key to the alias probe key means both the direct and the
    aliased request are denied → no differential → no finding.
    """
    app = create_app(
        introspection_enabled=True,
        alias_auth_bypass={
            "field": "secrets",
            # Deny exactly the alias the check uses, so the aliased probe is
            # also denied; the direct probe (key == field name) then resolves.
            "denied_key": auth_alias.ALIAS_KEY,
        },
    )
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await auth_alias.check(client)
        # The bypass signal requires direct-denied AND aliased-allowed. Here it
        # is the reverse (direct allowed, aliased denied), so nothing fires.
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_validation_error_is_not_a_denial():
    """A plain 'cannot query field' error must not be treated as a denial."""
    # No protected field configured and introspection off: the default
    # candidates all hit the server's generic handler, which never returns an
    # authorization error, so the check stays silent (no false positive on
    # ordinary validation errors).
    app = create_app(introspection_enabled=False, alias_auth_bypass=None)
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await auth_alias.check(client)
        assert findings == []
    finally:
        server.should_exit = True


def test_is_auth_denial_helper():
    """The denial classifier matches auth markers but not validation errors."""
    assert auth_alias._is_auth_denial(
        {"errors": [{"message": "Not authorized to access field \"x\"."}]}
    )
    assert auth_alias._is_auth_denial(
        {"errors": [{"message": "boom", "extensions": {"code": "FORBIDDEN"}}]}
    )
    # A field-does-not-exist validation error is NOT a denial.
    assert not auth_alias._is_auth_denial(
        {"errors": [{"message": "Cannot query field \"x\" on type \"Query\"."}]}
    )
    # No errors at all is not a denial.
    assert not auth_alias._is_auth_denial({"data": {"x": {"__typename": "Y"}}})


def test_auth_alias_in_default_checks():
    """auth-alias is part of --checks all (read-only, side-effect free)."""
    from enshroud.cli import ALL_CHECKS, OPT_IN_CHECKS, VALID_CHECKS, parse_checks

    assert "auth-alias" in ALL_CHECKS
    assert "auth-alias" not in OPT_IN_CHECKS
    assert "auth-alias" in VALID_CHECKS
    assert "auth-alias" in parse_checks("all")
