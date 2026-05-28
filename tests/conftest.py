"""pytest configuration: starts mock GraphQL server on an ephemeral port."""
from __future__ import annotations

import socket
import threading
import time

import pytest
import uvicorn

from tests.fixtures.mock_graphql_server import create_app


def _get_free_port() -> int:
    """Find a free ephemeral port."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _ServerThread(threading.Thread):
    def __init__(self, app, host: str, port: int) -> None:
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        config = uvicorn.Config(app, host=host, port=port, log_level="error")
        self.server = uvicorn.Server(config)

    def run(self) -> None:
        self.server.run()

    def stop(self) -> None:
        self.server.should_exit = True


@pytest.fixture(scope="session")
def mock_server():
    """Start a mock GraphQL server with all modes enabled. Returns (host, port)."""
    host = "127.0.0.1"
    port = _get_free_port()

    app = create_app(
        introspection_enabled=True,
        depth_limit=None,      # no depth limit — will trigger finding
        batch_limit=None,      # no batch limit — will trigger finding
        suggestions_enabled=True,
        dangerous_mutations=["deleteUser", "removeAccount", "adminReset"],
        cors_misconfigured=True,
        array_batch_enabled=True,  # exercise the batch-array check
    )

    thread = _ServerThread(app, host, port)
    thread.start()

    # Wait for the server to be ready
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            s = socket.create_connection((host, port), timeout=0.5)
            s.close()
            break
        except OSError:
            time.sleep(0.05)
    else:
        raise RuntimeError(f"Mock server did not start on {host}:{port}")

    yield host, port

    thread.stop()


@pytest.fixture(scope="session")
def mock_url(mock_server):
    """Return the full URL of the mock GraphQL server."""
    host, port = mock_server
    return f"http://{host}:{port}/graphql"


@pytest.fixture(scope="session")
def scope_file():
    """Return the path to the test scope file."""
    import os
    return os.path.join(os.path.dirname(__file__), "fixtures", "scope.txt")
