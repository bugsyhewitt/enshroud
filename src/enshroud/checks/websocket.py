"""GraphQL-over-WebSocket subscription attack-surface check.

GraphQL subscriptions are usually served over WebSocket using one of two
protocols — `graphql-transport-ws` (the modern graphql-ws library) or
`graphql-ws` (the legacy subscriptions-transport-ws library). These connections
have a security model distinct from the HTTP endpoint:

  * the `connection_init` handshake is the only auth gate, and many servers
    accept it with no token at all (unauthenticated subscription access);
  * introspection runs over the socket just like over HTTP, leaking the schema
    even when the HTTP endpoint is locked down;
  * WebSocket upgrades are not subject to the same-origin policy, so a missing
    Origin check enables Cross-Site WebSocket Hijacking (CSWSH);
  * a plain `ws://` (non-TLS) endpoint exposes the whole session to MITM.

This check is opt-in (not part of ``--checks all``) because it requires a
WebSocket round-trip that is slower and noisier than the HTTP probes, and many
GraphQL endpoints do not serve subscriptions at all.
"""
from __future__ import annotations

import json
from typing import Any

from enshroud.client import (
    SUBPROTOCOL_GRAPHQL_TRANSPORT_WS,
    SUBPROTOCOL_SUBSCRIPTIONS_TRANSPORT_WS,
    GraphQLClient,
    WebSocketProbe,
)

# A schema introspection probe small enough to confirm introspection-over-WS
# without pulling the entire type graph.
_INTROSPECTION_OP = "subscription { __typename }"
_INTROSPECTION_QUERY = "query { __schema { queryType { name } } }"

# A clearly cross-origin value for the CSWSH probe.
_EVIL_ORIGIN = "https://evil.example.com"

_SUBPROTOCOLS = (
    SUBPROTOCOL_GRAPHQL_TRANSPORT_WS,
    SUBPROTOCOL_SUBSCRIPTIONS_TRANSPORT_WS,
)


def _truncate(text: str, limit: int = 500) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Probe the GraphQL-over-WebSocket attack surface.

    Returns an empty list when no WebSocket GraphQL endpoint can be reached, so a
    target that only speaks HTTP produces no false positives.
    """
    findings: list[dict[str, Any]] = []

    probe = WebSocketProbe(
        endpoint=client.endpoint,
        auth_header=_format_auth_header(client),
        timeout=client.timeout,
    )

    # ── Step 1: find a working subprotocol with an *unauthenticated* init ──────
    # We deliberately send connection_init with no auth payload and no auth
    # header to test whether the server gates the handshake.
    accepted = None
    for sub in _SUBPROTOCOLS:
        result = await probe.probe(subprotocol=sub, init_payload={})
        if result.connection_ack:
            accepted = (sub, result)
            break

    if accepted is None:
        # Either no WS endpoint, or it requires auth to ack. No finding either
        # way — the absence of an unauthenticated ack is the secure behaviour.
        return findings

    subprotocol, ack_result = accepted

    findings.append(
        {
            "category": "websocket_unauth_subscription",
            "severity": "HIGH",
            "title": "GraphQL WebSocket Accepts Unauthenticated Subscriptions",
            "evidence": _truncate(
                json.dumps(
                    {
                        "ws_url": probe.ws_url,
                        "subprotocol": subprotocol,
                        "connection_init_payload": {},
                        "server_messages": ack_result.messages,
                    }
                )
            ),
            "description": (
                "The GraphQL WebSocket endpoint returned `connection_ack` in "
                "response to a `connection_init` message that carried no "
                "authentication credentials. The subscription channel can be "
                "opened by any anonymous client."
            ),
            "reproduction": (
                f"Open a WebSocket to `{probe.ws_url}` with "
                f"`Sec-WebSocket-Protocol: {subprotocol}`, then send "
                '`{"type": "connection_init", "payload": {}}` with no auth '
                "header. The server replies "
                '`{"type": "connection_ack"}`.'
            ),
            "impact": (
                "Unauthenticated clients can establish subscription channels and "
                "receive real-time event data. Combined with broken function- or "
                "object-level authorization, this leaks sensitive events "
                "(BFLA/BOLA) to anyone on the network."
            ),
            "remediation": (
                "Authenticate the WebSocket during the `connection_init` "
                "handshake (validate a token in `payload`) and reject the "
                "connection with code 4401/4403 when it is missing or invalid. "
                "Re-check authorization for every subscription operation, not "
                "just at connect time."
            ),
        }
    )

    # ── Step 2: introspection over the WebSocket ───────────────────────────────
    intro = await probe.probe(
        subprotocol=subprotocol,
        init_payload={},
        operation=_INTROSPECTION_OP,
    )
    if intro.operation_response_type in ("next", "data"):
        findings.append(
            {
                "category": "websocket_introspection",
                "severity": "MEDIUM",
                "title": "GraphQL Schema Reachable Over WebSocket",
                "evidence": _truncate(
                    json.dumps(
                        {
                            "operation": _INTROSPECTION_OP,
                            "response_type": intro.operation_response_type,
                            "payload": intro.operation_payload,
                        }
                    )
                ),
                "description": (
                    "An operation sent over the WebSocket subscription channel "
                    "returned data rather than being rejected, confirming the "
                    "subscription transport executes operations. Schema and "
                    "field information is reachable over the socket even if the "
                    "HTTP endpoint restricts introspection."
                ),
                "reproduction": (
                    f"Over the WebSocket at `{probe.ws_url}`, after "
                    "`connection_ack`, send a `subscribe` (or legacy `start`) "
                    f'message with `payload.query` set to `{_INTROSPECTION_QUERY}` '
                    "and observe the returned schema data."
                ),
                "impact": (
                    "The WebSocket channel exposes schema and operation "
                    "execution that may be blocked on the HTTP endpoint, giving "
                    "an attacker a second, less-monitored path to enumerate the "
                    "API."
                ),
                "remediation": (
                    "Apply the same introspection, depth, and authorization "
                    "controls to the WebSocket transport as to the HTTP "
                    "endpoint. Disable introspection over subscriptions in "
                    "production."
                ),
            }
        )

    # ── Step 3: missing TLS on the WebSocket (ws:// accepted) ──────────────────
    if not probe.is_tls and ack_result.connected:
        findings.append(
            {
                "category": "websocket_no_tls",
                "severity": "MEDIUM",
                "title": "GraphQL WebSocket Served Over Plaintext ws://",
                "evidence": _truncate(
                    json.dumps(
                        {"ws_url": probe.ws_url, "tls": False, "connected": True}
                    )
                ),
                "description": (
                    "The GraphQL subscription endpoint accepted a connection "
                    "over plaintext `ws://`. Subscription traffic — including "
                    "any auth token sent in `connection_init` and all real-time "
                    "event data — travels unencrypted."
                ),
                "reproduction": (
                    f"Connect to `{probe.ws_url}` (note the `ws://` scheme) and "
                    "complete the GraphQL handshake. The plaintext upgrade "
                    "succeeds."
                ),
                "impact": (
                    "An on-path attacker can read or tamper with subscription "
                    "data and steal credentials passed during the handshake "
                    "(MITM). Mirrors CVE-2024-54147, where missing WebSocket TLS "
                    "validation enabled interception."
                ),
                "remediation": (
                    "Serve subscriptions only over `wss://` (TLS) and redirect "
                    "or refuse plaintext `ws://` upgrades. Enforce HSTS so "
                    "browsers never downgrade."
                ),
            }
        )

    # ── Step 4: Cross-Site WebSocket Hijacking (no Origin check) ───────────────
    cswsh = await probe.probe(
        subprotocol=subprotocol,
        init_payload={},
        origin=_EVIL_ORIGIN,
    )
    if cswsh.connection_ack:
        findings.append(
            {
                "category": "websocket_cswsh",
                "severity": "HIGH",
                "title": "GraphQL WebSocket Lacks Origin Validation (CSWSH)",
                "evidence": _truncate(
                    json.dumps(
                        {
                            "ws_url": probe.ws_url,
                            "origin_sent": _EVIL_ORIGIN,
                            "connection_ack": True,
                            "server_messages": cswsh.messages,
                        }
                    )
                ),
                "description": (
                    "The WebSocket endpoint completed the GraphQL handshake even "
                    "though the request carried a cross-origin "
                    f"`Origin: {_EVIL_ORIGIN}` header. WebSocket upgrades are "
                    "not covered by the same-origin policy, so a missing Origin "
                    "check enables Cross-Site WebSocket Hijacking (CSWSH)."
                ),
                "reproduction": (
                    f"Open a WebSocket to `{probe.ws_url}` with the header "
                    f"`Origin: {_EVIL_ORIGIN}` and complete the handshake. The "
                    "server accepts the cross-origin connection."
                ),
                "impact": (
                    "A malicious page can open an authenticated GraphQL "
                    "WebSocket in the victim's browser (riding their cookies), "
                    "then both send operations and read responses — a two-way "
                    "compromise more powerful than classic CSRF."
                ),
                "remediation": (
                    "Validate the `Origin` header on every WebSocket upgrade "
                    "against an allowlist of trusted origins and reject "
                    "mismatches. Do not rely on cookies alone for subscription "
                    "authentication; require an explicit token in "
                    "`connection_init`."
                ),
            }
        )

    return findings


def _format_auth_header(client: GraphQLClient) -> str | None:
    """Reconstruct an "Name: value" auth header from the client's headers.

    The HTTP client stores parsed headers; the WebSocketProbe re-parses the same
    "Name: value" form. We only forward an Authorization-style header so that the
    *unauthenticated* probes above stay unauthenticated by default.
    """
    for name, value in client.headers.items():
        if name.lower() == "authorization":
            return f"{name}: {value}"
    return None
