"""Tests for the JSON-array batching check."""
from __future__ import annotations

import json
import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import batch_array
from enshroud.client import GraphQLClient
from tests.fixtures.mock_graphql_server import create_app


def _start_server(app) -> tuple[str, int, uvicorn.Server]:
    host = "127.0.0.1"
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
    return host, port, server


@pytest.mark.asyncio
async def test_batch_array_enabled_fires_high(mock_url):
    """The session mock has array batching on → one HIGH finding."""
    client = GraphQLClient(mock_url)
    findings = await batch_array.check(client)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["category"] == "array_batching"
    assert finding["severity"] == "HIGH"
    assert finding["operations_per_request_accepted"] == batch_array.BATCH_SIZE
    # Evidence records that every operation came back.
    evidence = json.loads(finding["evidence"])
    assert evidence["results_returned"] == batch_array.BATCH_SIZE


@pytest.mark.asyncio
async def test_batch_array_disabled_no_finding():
    """A server that rejects array batches produces no finding."""
    app = create_app(array_batch_enabled=False)
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await batch_array.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_batch_array_partial_execution_no_finding():
    """A server returning fewer results than sent does not trip the check."""

    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse

    app = FastAPI()

    @app.post("/graphql")
    async def graphql(request: Request) -> JSONResponse:
        body = await request.json()
        if isinstance(body, list):
            # Execute only the first operation, ignore the rest.
            return JSONResponse(content=[{"data": {"__typename": "Query"}}])
        return JSONResponse(content={"data": {"__typename": "Query"}})

    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await batch_array.check(client)
        assert findings == []
    finally:
        server.should_exit = True


def test_batch_array_in_all_checks():
    """batch-array is part of the default 'all' set and a valid check."""
    from enshroud.cli import ALL_CHECKS, VALID_CHECKS, parse_checks

    assert "batch-array" in ALL_CHECKS
    assert "batch-array" in VALID_CHECKS
    assert "batch-array" in parse_checks("all")
    assert parse_checks("batch-array") == ["batch-array"]


@pytest.mark.asyncio
async def test_post_batch_sends_json_array(mock_url):
    """The client's post_batch helper sends a JSON array body."""
    client = GraphQLClient(mock_url)
    resp = await client.post_batch(["{ __typename }", "{ __typename }"])
    body = resp.json()
    assert isinstance(body, list)
    assert len(body) == 2
