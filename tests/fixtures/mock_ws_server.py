"""Mock GraphQL-over-WebSocket server for testing the `websocket` check.

Implements just enough of the `graphql-transport-ws` and legacy `graphql-ws`
(subscriptions-transport-ws) protocols to exercise enshroud's WebSocket probes.
Behaviour is configurable per server so individual tests can simulate secure
and insecure endpoints.

Runs on the `websockets` library's own asyncio server in a background thread.
"""
from __future__ import annotations

import asyncio
import json
import socket
import threading
from dataclasses import dataclass
from typing import Any


@dataclass
class WSServerConfig:
    """Toggles describing how the mock WebSocket server behaves."""

    # Accept connection_init without auth (insecure) vs require a token.
    require_auth: bool = False
    # Validate the Origin header against an allowlist (secure) vs accept any.
    validate_origin: bool = True
    allowed_origins: tuple[str, ...] = ("https://app.example.com",)
    # Return data for subscription operations (introspection-over-WS reachable).
    allow_operations: bool = True
    # Subprotocols the server will negotiate.
    supported_subprotocols: tuple[str, ...] = (
        "graphql-transport-ws",
        "graphql-ws",
    )


class MockWSServer:
    """A threaded mock GraphQL WebSocket server.

    Use as a context manager; ``.ws_url`` / ``.http_url`` give the endpoints.
    The handshake URL path is ``/graphql``.
    """

    def __init__(self, config: WSServerConfig | None = None, host: str = "127.0.0.1") -> None:
        self.config = config or WSServerConfig()
        self.host = host
        self.port = self._free_port(host)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._stop = threading.Event()

    @staticmethod
    def _free_port(host: str) -> int:
        s = socket.socket()
        s.bind((host, 0))
        port = s.getsockname()[1]
        s.close()
        return port

    @property
    def ws_url(self) -> str:
        return f"ws://{self.host}:{self.port}/graphql"

    @property
    def http_url(self) -> str:
        # enshroud is configured with the http(s) endpoint; the probe derives ws.
        return f"http://{self.host}:{self.port}/graphql"

    # ── handler ────────────────────────────────────────────────────────────────

    async def _handler(self, ws: Any) -> None:
        cfg = self.config

        # Origin validation (CSWSH defence). websockets exposes request headers
        # via ws.request.headers (newer API).
        origin = None
        request = getattr(ws, "request", None)
        if request is not None:
            origin = request.headers.get("Origin")
        if cfg.validate_origin:
            if origin is not None and origin not in cfg.allowed_origins:
                await ws.close(code=4403, reason="forbidden origin")
                return

        # connection_init handshake.
        try:
            raw = await ws.recv()
        except Exception:
            return
        try:
            msg = json.loads(raw)
        except Exception:
            await ws.close(code=4400, reason="bad message")
            return

        if msg.get("type") != "connection_init":
            await ws.close(code=4400, reason="expected connection_init")
            return

        if cfg.require_auth:
            payload = msg.get("payload") or {}
            token = payload.get("authorization") or payload.get("Authorization")
            if not token:
                await ws.close(code=4401, reason="unauthorized")
                return

        await ws.send(json.dumps({"type": "connection_ack"}))

        # Operation loop.
        while True:
            try:
                raw = await ws.recv()
            except Exception:
                return
            try:
                op = json.loads(raw)
            except Exception:
                continue
            mtype = op.get("type")
            if mtype in ("subscribe", "start"):
                op_id = op.get("id", "1")
                if cfg.allow_operations:
                    next_type = "next" if mtype == "subscribe" else "data"
                    await ws.send(
                        json.dumps(
                            {
                                "id": op_id,
                                "type": next_type,
                                "payload": {
                                    "data": {
                                        "__schema": {"queryType": {"name": "Query"}}
                                    }
                                },
                            }
                        )
                    )
                    complete_type = (
                        "complete" if mtype == "subscribe" else "complete"
                    )
                    await ws.send(json.dumps({"id": op_id, "type": complete_type}))
                else:
                    await ws.send(
                        json.dumps(
                            {
                                "id": op_id,
                                "type": "error",
                                "payload": [{"message": "operation rejected"}],
                            }
                        )
                    )
            elif mtype in ("complete", "stop", "connection_terminate"):
                return

    # ── lifecycle ────────────────────────────────────────────────────────────────

    def _run(self) -> None:
        import websockets

        async def main() -> None:
            self._loop = asyncio.get_running_loop()
            async with websockets.serve(
                self._handler,
                self.host,
                self.port,
                subprotocols=list(self.config.supported_subprotocols),  # type: ignore[arg-type]
            ):
                self._ready.set()
                # Run until stop() is signalled.
                while not self._stop.is_set():
                    await asyncio.sleep(0.05)

        asyncio.run(main())

    def __enter__(self) -> "MockWSServer":
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=10):
            raise RuntimeError("mock WS server did not start")
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
