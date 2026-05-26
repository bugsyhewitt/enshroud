"""Tests for depth DoS check."""
import pytest

from enshroud.checks import depth_dos
from enshroud.client import GraphQLClient


@pytest.mark.asyncio
async def test_depth_dos_no_limit(mock_url):
    client = GraphQLClient(mock_url)
    findings = await depth_dos.check(client)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["category"] == "depth_dos"
    assert finding["severity"] == "LOW"
    assert finding["max_depth_accepted"] == 15


@pytest.mark.asyncio
async def test_depth_dos_with_limit(mock_server):
    """Server with depth limit should produce no findings."""
    from tests.fixtures.mock_graphql_server import create_app
    import uvicorn, socket, threading, time

    host = "127.0.0.1"
    s = socket.socket()
    s.bind((host, 0))
    port = s.getsockname()[1]
    s.close()

    app = create_app(depth_limit=5)
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

    url = f"http://{host}:{port}/graphql"
    client = GraphQLClient(url)
    findings = await depth_dos.check(client)
    assert findings == []

    server.should_exit = True
