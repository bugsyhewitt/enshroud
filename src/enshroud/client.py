"""Async GraphQL HTTP client."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx


class GraphQLClient:
    """Async GraphQL client wrapping httpx."""

    def __init__(
        self,
        endpoint: str,
        auth_header: str | None = None,
        timeout: int = 10,
    ) -> None:
        self.endpoint = endpoint
        self.timeout = timeout
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if auth_header:
            # auth_header format: "Header-Name: value"
            if ":" in auth_header:
                name, _, value = auth_header.partition(":")
                headers[name.strip()] = value.strip()
        self.headers = headers

    async def query(self, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send a GraphQL query and return the parsed JSON response."""
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                self.endpoint,
                headers=self.headers,
                content=json.dumps(payload),
            )
            resp.raise_for_status()
            return resp.json()

    async def post_batch(self, queries: list[str]) -> httpx.Response:
        """Send a JSON-array batch of operations in a single HTTP request.

        Many GraphQL servers accept a top-level JSON array
        ``[{"query": "..."}, {"query": "..."}]`` and execute every operation in
        it, returning a parallel array of results. This transport-level batching
        is distinct from alias batching: it lets an attacker pack many *separate*
        operations (including repeated mutations) into one request, which is the
        classic vector for bypassing per-request rate limits on login / OTP /
        coupon mutations. Returns the raw httpx Response.
        """
        payload = [{"query": q} for q in queries]
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                self.endpoint,
                headers=self.headers,
                content=json.dumps(payload),
            )
            return resp

    async def options(self, extra_headers: dict[str, str] | None = None) -> httpx.Response:
        """Send an OPTIONS request."""
        headers = dict(self.headers)
        if extra_headers:
            headers.update(extra_headers)
        # Remove Content-Type for OPTIONS
        headers.pop("Content-Type", None)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.options(self.endpoint, headers=headers)
            return resp

    async def get_with_origin(self, origin: str) -> httpx.Response:
        """Send a GET request with a custom Origin header."""
        headers = dict(self.headers)
        headers["Origin"] = origin
        headers.pop("Content-Type", None)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(self.endpoint, headers=headers)
            return resp

    async def post_raw(
        self,
        query: str,
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Send a raw POST and return the httpx Response (not parsed)."""
        payload = {"query": query}
        headers = dict(self.headers)
        if extra_headers:
            headers.update(extra_headers)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                self.endpoint,
                headers=headers,
                content=json.dumps(payload),
            )
            return resp

    async def post_form(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """Send a query as application/x-www-form-urlencoded POST.

        Browsers can issue this content type without a CORS preflight, so a
        server that accepts mutations here is exposed to cross-site request
        forgery. Returns the raw httpx Response.
        """
        headers = dict(self.headers)
        # Override the JSON content type; httpx sets the form one from `data`.
        headers.pop("Content-Type", None)
        data: dict[str, str] = {"query": query}
        if variables:
            data["variables"] = json.dumps(variables)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                self.endpoint,
                headers=headers,
                data=data,
            )
            return resp

    async def get_query(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """Send a query via GET with the query string in the URL.

        GET requests are simple requests that bypass CORS preflight entirely.
        A server that executes mutations over GET is exposed to CSRF via
        `<img>` / `<script>` / link prefetch. Returns the raw httpx Response.
        """
        headers = dict(self.headers)
        headers.pop("Content-Type", None)
        params: dict[str, str] = {"query": query}
        if variables:
            params["variables"] = json.dumps(variables)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(
                self.endpoint,
                headers=headers,
                params=params,
            )
            return resp


# ── GraphQL-over-WebSocket support ─────────────────────────────────────────────

# The two GraphQL-over-WebSocket protocols, by their Sec-WebSocket-Protocol token.
# `graphql-transport-ws` is the modern graphql-ws protocol; `graphql-ws` is the
# legacy subscriptions-transport-ws protocol (yes, the names are confusingly
# swapped relative to the libraries).
SUBPROTOCOL_GRAPHQL_TRANSPORT_WS = "graphql-transport-ws"
SUBPROTOCOL_SUBSCRIPTIONS_TRANSPORT_WS = "graphql-ws"


def http_to_ws_url(endpoint: str) -> str:
    """Convert an http(s) endpoint URL to its ws(s) equivalent.

    http  -> ws, https -> wss. Already-ws(s) URLs pass through unchanged.
    """
    parsed = urlparse(endpoint)
    scheme = parsed.scheme.lower()
    if scheme == "http":
        scheme = "ws"
    elif scheme == "https":
        scheme = "wss"
    # ws/wss already correct; anything else left as-is.
    return urlunparse(parsed._replace(scheme=scheme))


@dataclass
class WebSocketProbeResult:
    """Outcome of a single GraphQL-over-WebSocket handshake probe."""

    connected: bool = False           # TCP/WS upgrade succeeded
    accepted_subprotocol: str | None = None
    connection_ack: bool = False      # server returned connection_ack
    init_payload_sent: dict[str, Any] | None = None
    origin_sent: str | None = None
    # Result of an attempted subscribe/operation over the socket.
    operation_response_type: str | None = None  # "next" | "data" | "error" | "complete" | None
    operation_payload: Any = None
    messages: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None          # transport-level failure description


class WebSocketProbe:
    """Drives GraphQL-over-WebSocket handshakes for the `websocket` check.

    Uses the `websockets` library (an optional dependency). Import is deferred so
    that installations without it can still run every HTTP-based check.
    """

    def __init__(
        self,
        endpoint: str,
        auth_header: str | None = None,
        timeout: int = 10,
    ) -> None:
        self.ws_url = http_to_ws_url(endpoint)
        self.timeout = timeout
        self.auth_value: str | None = None
        self.auth_name: str | None = None
        if auth_header and ":" in auth_header:
            name, _, value = auth_header.partition(":")
            self.auth_name = name.strip()
            self.auth_value = value.strip()

    @property
    def is_tls(self) -> bool:
        return self.ws_url.lower().startswith("wss://")

    async def probe(
        self,
        *,
        subprotocol: str = SUBPROTOCOL_GRAPHQL_TRANSPORT_WS,
        init_payload: dict[str, Any] | None = None,
        origin: str | None = None,
        operation: str | None = None,
    ) -> WebSocketProbeResult:
        """Open a WS connection, send connection_init, optionally run an operation.

        Returns a WebSocketProbeResult describing what the server did. Any
        transport error is captured in ``result.error`` rather than raised, so
        callers can treat a refused/unsupported endpoint as "no finding".
        """
        result = WebSocketProbeResult(
            init_payload_sent=init_payload, origin_sent=origin
        )
        try:
            import websockets
        except ImportError:  # pragma: no cover - exercised only without the dep
            result.error = (
                "the 'websockets' package is required for the websocket check "
                "(pip install enshroud[ws])"
            )
            return result

        extra_headers: dict[str, str] = {}
        if origin is not None:
            extra_headers["Origin"] = origin

        try:
            conn = websockets.connect(
                self.ws_url,
                subprotocols=[subprotocol],  # type: ignore[list-item]
                additional_headers=extra_headers or None,
                open_timeout=self.timeout,
                close_timeout=self.timeout,
            )
            async with conn as ws:
                result.connected = True
                result.accepted_subprotocol = (
                    str(ws.subprotocol) if ws.subprotocol else None
                )

                init_msg: dict[str, Any] = {"type": "connection_init"}
                if init_payload is not None:
                    init_msg["payload"] = init_payload
                await ws.send(json.dumps(init_msg))

                ack = await self._recv_json(ws)
                if ack is not None:
                    result.messages.append(ack)
                    if ack.get("type") in ("connection_ack",):
                        result.connection_ack = True

                if result.connection_ack and operation is not None:
                    await self._run_operation(ws, result, operation, subprotocol)

                return result
        except Exception as exc:  # noqa: BLE001 - any transport error => no finding
            result.error = f"{type(exc).__name__}: {exc}"
            return result

    async def _run_operation(
        self,
        ws: Any,
        result: WebSocketProbeResult,
        operation: str,
        subprotocol: str,
    ) -> None:
        """Send one subscribe/start operation and capture the first data/error."""
        if subprotocol == SUBPROTOCOL_SUBSCRIPTIONS_TRANSPORT_WS:
            op_msg = {"id": "1", "type": "start", "payload": {"query": operation}}
        else:
            op_msg = {"id": "1", "type": "subscribe", "payload": {"query": operation}}
        await ws.send(json.dumps(op_msg))

        # Read a couple of frames looking for next/data/error.
        for _ in range(3):
            msg = await self._recv_json(ws)
            if msg is None:
                break
            result.messages.append(msg)
            mtype = msg.get("type")
            if mtype in ("next", "data", "error"):
                result.operation_response_type = mtype
                result.operation_payload = msg.get("payload")
                break
            if mtype == "complete":
                result.operation_response_type = "complete"
                break

    async def _recv_json(self, ws: Any) -> dict[str, Any] | None:
        """Receive one frame and JSON-decode it; None on timeout/decode failure."""
        import asyncio

        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=self.timeout)
        except Exception:
            return None
        try:
            data = json.loads(raw)
        except Exception:
            return None
        return data if isinstance(data, dict) else None
