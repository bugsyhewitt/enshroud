"""Tests for alias batching check."""
import pytest

from enshroud.checks import alias_batch
from enshroud.client import GraphQLClient


@pytest.mark.asyncio
async def test_alias_batch_no_limit(mock_url):
    client = GraphQLClient(mock_url)
    findings = await alias_batch.check(client)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["category"] == "alias_batching"
    assert finding["severity"] == "MEDIUM"
    assert finding["queries_per_request_accepted"] == 100


@pytest.mark.asyncio
async def test_alias_batch_with_limit(mock_server):
    """Server with batch limit should produce no findings."""
    from tests.fixtures.mock_graphql_server import create_app
    import uvicorn, socket, threading, time

    host = "127.0.0.1"
    s = socket.socket()
    s.bind((host, 0))
    port = s.getsockname()[1]
    s.close()

    app = create_app(batch_limit=10)
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
    findings = await alias_batch.check(client)
    assert findings == []

    server.should_exit = True
