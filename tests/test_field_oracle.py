"""Tests for field oracle check."""
import pytest

from enshroud.checks import field_oracle
from enshroud.client import GraphQLClient


@pytest.mark.asyncio
async def test_field_oracle_with_suggestions(mock_url):
    client = GraphQLClient(mock_url)
    findings = await field_oracle.check(client)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["category"] == "field_suggestion_oracle"
    assert finding["severity"] == "LOW"
    assert isinstance(finding["extracted_fields"], list)
    assert len(finding["extracted_fields"]) > 0


@pytest.mark.asyncio
async def test_field_oracle_no_suggestions(mock_server):
    """Server without suggestions should produce no findings."""
    from tests.fixtures.mock_graphql_server import create_app
    import uvicorn, socket, threading, time

    host = "127.0.0.1"
    s = socket.socket()
    s.bind((host, 0))
    port = s.getsockname()[1]
    s.close()

    app = create_app(suggestions_enabled=False)
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
    findings = await field_oracle.check(client)
    assert findings == []

    server.should_exit = True
