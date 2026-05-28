"""Tests for the GraphQL-over-WebSocket subscription check."""
from __future__ import annotations

import pytest

from enshroud.checks import websocket
from enshroud.client import GraphQLClient, http_to_ws_url
from tests.fixtures.mock_ws_server import MockWSServer, WSServerConfig


# ── URL conversion ──────────────────────────────────────────────────────────────

def test_http_to_ws_url_conversion():
    assert http_to_ws_url("http://api.example.com/graphql") == "ws://api.example.com/graphql"
    assert http_to_ws_url("https://api.example.com/graphql") == "wss://api.example.com/graphql"
    # Already ws(s) → unchanged.
    assert http_to_ws_url("ws://x/graphql") == "ws://x/graphql"
    assert http_to_ws_url("wss://x/graphql") == "wss://x/graphql"
    # Path and port preserved.
    assert (
        http_to_ws_url("https://api.example.com:8443/v2/graphql")
        == "wss://api.example.com:8443/v2/graphql"
    )


# ── opt-in registration ───────────────────────────────────────────────────────────

def test_websocket_is_opt_in_not_in_all():
    from enshroud.cli import OPT_IN_CHECKS, VALID_CHECKS, parse_checks

    assert "websocket" in OPT_IN_CHECKS
    assert "websocket" in VALID_CHECKS
    assert "websocket" not in parse_checks("all")
    assert parse_checks("websocket") == ["websocket"]


# ── behavioural tests against the mock WS server ───────────────────────────────────

@pytest.mark.asyncio
async def test_unauthenticated_subscription_flagged():
    """A server that acks an unauth connection_init must produce a HIGH finding."""
    cfg = WSServerConfig(require_auth=False, validate_origin=True)
    with MockWSServer(cfg) as srv:
        client = GraphQLClient(srv.http_url)
        findings = await websocket.check(client)
        categories = [f["category"] for f in findings]
        assert "websocket_unauth_subscription" in categories
        f = next(x for x in findings if x["category"] == "websocket_unauth_subscription")
        assert f["severity"] == "HIGH"
        assert "connection_ack" in f["evidence"] or "connection_init" in f["evidence"]


@pytest.mark.asyncio
async def test_auth_required_produces_no_unauth_finding():
    """A server that requires auth on connection_init yields no findings."""
    cfg = WSServerConfig(require_auth=True)
    with MockWSServer(cfg) as srv:
        client = GraphQLClient(srv.http_url)
        findings = await websocket.check(client)
        categories = [f["category"] for f in findings]
        assert "websocket_unauth_subscription" not in categories
        # With no ack, the check returns nothing at all.
        assert findings == []


@pytest.mark.asyncio
async def test_introspection_over_ws_flagged():
    """When operations return data over WS, flag introspection reachability."""
    cfg = WSServerConfig(require_auth=False, allow_operations=True)
    with MockWSServer(cfg) as srv:
        client = GraphQLClient(srv.http_url)
        findings = await websocket.check(client)
        categories = [f["category"] for f in findings]
        assert "websocket_introspection" in categories
        f = next(x for x in findings if x["category"] == "websocket_introspection")
        assert f["severity"] == "MEDIUM"


@pytest.mark.asyncio
async def test_operations_rejected_no_introspection_finding():
    """If the server rejects operations, no introspection finding fires."""
    cfg = WSServerConfig(require_auth=False, allow_operations=False)
    with MockWSServer(cfg) as srv:
        client = GraphQLClient(srv.http_url)
        findings = await websocket.check(client)
        categories = [f["category"] for f in findings]
        assert "websocket_introspection" not in categories
        # Unauth ack still fires.
        assert "websocket_unauth_subscription" in categories


@pytest.mark.asyncio
async def test_plain_ws_no_tls_flagged():
    """A plaintext ws:// endpoint that connects must raise websocket_no_tls."""
    cfg = WSServerConfig(require_auth=False)
    with MockWSServer(cfg) as srv:
        client = GraphQLClient(srv.http_url)  # http_url → ws:// (no TLS)
        findings = await websocket.check(client)
        categories = [f["category"] for f in findings]
        assert "websocket_no_tls" in categories
        f = next(x for x in findings if x["category"] == "websocket_no_tls")
        assert f["severity"] == "MEDIUM"


@pytest.mark.asyncio
async def test_cswsh_flagged_when_origin_not_validated():
    """A server that accepts a cross-origin handshake must raise websocket_cswsh."""
    cfg = WSServerConfig(require_auth=False, validate_origin=False)
    with MockWSServer(cfg) as srv:
        client = GraphQLClient(srv.http_url)
        findings = await websocket.check(client)
        categories = [f["category"] for f in findings]
        assert "websocket_cswsh" in categories
        f = next(x for x in findings if x["category"] == "websocket_cswsh")
        assert f["severity"] == "HIGH"


@pytest.mark.asyncio
async def test_cswsh_not_flagged_when_origin_validated():
    """A server that validates Origin must NOT raise the CSWSH finding."""
    cfg = WSServerConfig(require_auth=False, validate_origin=True)
    with MockWSServer(cfg) as srv:
        client = GraphQLClient(srv.http_url)
        findings = await websocket.check(client)
        categories = [f["category"] for f in findings]
        # The evil-origin probe is rejected → no CSWSH finding.
        assert "websocket_cswsh" not in categories
        # But the same-origin unauth probe still acks.
        assert "websocket_unauth_subscription" in categories


@pytest.mark.asyncio
async def test_no_ws_endpoint_produces_no_findings():
    """Pointing the check at a port with no WS server yields no findings (no crash)."""
    # Bind a port then immediately free it so nothing is listening.
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    client = GraphQLClient(f"http://127.0.0.1:{port}/graphql", timeout=2)
    findings = await websocket.check(client)
    assert findings == []


@pytest.mark.asyncio
async def test_legacy_subscriptions_transport_ws_protocol():
    """The check works when only the legacy graphql-ws subprotocol is offered."""
    cfg = WSServerConfig(
        require_auth=False,
        supported_subprotocols=("graphql-ws",),
        validate_origin=True,
    )
    with MockWSServer(cfg) as srv:
        client = GraphQLClient(srv.http_url)
        findings = await websocket.check(client)
        categories = [f["category"] for f in findings]
        assert "websocket_unauth_subscription" in categories
        # Legacy protocol uses `start`/`data`; introspection still reachable.
        assert "websocket_introspection" in categories
