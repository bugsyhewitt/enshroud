"""Tests for mutation enumeration check."""
import pytest

from enshroud.checks import mutation_enum
from enshroud.client import GraphQLClient


@pytest.mark.asyncio
async def test_mutation_enum_finds_dangerous(mock_url):
    client = GraphQLClient(mock_url)
    findings = await mutation_enum.check(client)
    assert len(findings) >= 1
    categories = [f["category"] for f in findings]
    assert all(c == "dangerous_mutation_exposed" for c in categories)
    mutation_names = [f["mutation_name"] for f in findings]
    # Mock server exposes deleteUser, removeAccount, adminReset
    assert any("delete" in n.lower() or "remove" in n.lower() or "admin" in n.lower()
               for n in mutation_names)


@pytest.mark.asyncio
async def test_mutation_enum_no_dangerous(mock_server):
    """Server with no dangerous mutations should produce no findings."""
    from tests.fixtures.mock_graphql_server import create_app
    import uvicorn, socket, threading, time

    host = "127.0.0.1"
    s = socket.socket()
    s.bind((host, 0))
    port = s.getsockname()[1]
    s.close()

    app = create_app(dangerous_mutations=["getUser", "listItems"])
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
    findings = await mutation_enum.check(client)
    assert findings == []

    server.should_exit = True
