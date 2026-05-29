"""Tests for the query-get check (read-query execution over a cacheable GET)."""
from __future__ import annotations

import json
import socket
import threading
import time
from contextlib import contextmanager

import pytest
import uvicorn

from enshroud.checks import query_get
from enshroud.client import GraphQLClient
from tests.fixtures.mock_graphql_server import create_app


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@contextmanager
def running_server(app):
    """Start a uvicorn server for `app` on an ephemeral port; yield its URL."""
    host = "127.0.0.1"
    port = _free_port()
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
    else:
        raise RuntimeError(f"Mock server did not start on {host}:{port}")

    try:
        yield f"http://{host}:{port}/graphql"
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_query_get_read_query_executed_fires():
    """A server that executes a read query over GET → finding fires (LOW)."""
    app = create_app(
        introspection_enabled=True,
        accept_get_read_query=True,
    )
    with running_server(app) as url:
        client = GraphQLClient(url)
        findings = await query_get.check(client)

    assert len(findings) == 1
    finding = findings[0]
    assert finding["category"] == "query_execution_over_get"
    assert finding["severity"] == "LOW"
    evidence = json.loads(finding["evidence"])
    assert evidence["request_method"] == "GET"
    assert evidence["probe_query"] == "{ __typename }"
    assert 200 <= evidence["response_status"] < 300
    assert "data" in evidence["response_body_prefix"]


@pytest.mark.asyncio
async def test_query_get_read_query_rejected_no_finding():
    """A server that rejects read queries over GET (POST-only) → no finding."""
    app = create_app(
        introspection_enabled=True,
        accept_get_read_query=False,
    )
    with running_server(app) as url:
        client = GraphQLClient(url)
        findings = await query_get.check(client)

    assert findings == []


@pytest.mark.asyncio
async def test_query_get_is_read_only_uses_typename_probe():
    """The probe is a benign non-mutation `{ __typename }` read query.

    A server that *rejects mutations* over GET but *serves read queries* (the
    common CSRF-safe-but-cacheable posture) must still fire query-get: the
    finding depends on read-query execution, not on the higher-severity GET
    mutation case the csrf check owns.
    """
    app = create_app(
        introspection_enabled=True,
        accept_get_query=False,        # mutations over GET rejected (CSRF-safe)
        accept_get_read_query=True,    # read queries over GET still served
    )
    with running_server(app) as url:
        client = GraphQLClient(url)
        findings = await query_get.check(client)

    assert len(findings) == 1
    assert findings[0]["category"] == "query_execution_over_get"
    # The probe must be a read query, never a mutation.
    evidence = json.loads(findings[0]["evidence"])
    assert "mutation" not in evidence["probe_query"].lower()


@pytest.mark.asyncio
async def test_query_get_finding_shape_has_required_fields():
    """The finding carries every field the H1-markdown / JSON pipeline expects."""
    app = create_app(accept_get_read_query=True)
    with running_server(app) as url:
        client = GraphQLClient(url)
        findings = await query_get.check(client)

    assert len(findings) == 1
    finding = findings[0]
    for key in (
        "category",
        "severity",
        "title",
        "evidence",
        "description",
        "reproduction",
        "impact",
        "remediation",
    ):
        assert key in finding, f"missing {key}"
    # Differential clarity: the finding text must distinguish itself from the
    # csrf (GET mutation) and apq-get (persisted) checks.
    assert "csrf" in finding["description"].lower()
    assert "apq-get" in finding["description"].lower()


@pytest.mark.asyncio
async def test_query_get_in_default_all_checks():
    """query-get is wired into the default `--checks all` set."""
    from enshroud.cli import ALL_CHECKS, VALID_CHECKS, parse_checks

    assert "query-get" in ALL_CHECKS
    assert "query-get" in VALID_CHECKS
    assert "query-get" in parse_checks("all")
    assert parse_checks("query-get") == ["query-get"]
