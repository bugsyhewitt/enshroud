"""Tests for CSRF via content-type bypass check."""
from __future__ import annotations

import json
import socket
import threading
import time
from contextlib import contextmanager

import pytest
import uvicorn

from enshroud.checks import csrf
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
async def test_csrf_form_post_accepted_fires():
    """Form-encoded POST accepted → finding fires for that vector."""
    app = create_app(
        introspection_enabled=True,
        dangerous_mutations=["deleteUser"],
        accept_form_post=True,
        accept_get_query=False,
    )
    with running_server(app) as url:
        client = GraphQLClient(url)
        findings = await csrf.check(client)

    vectors = {f["vector"] for f in findings}
    assert "application/x-www-form-urlencoded POST" in vectors
    assert "GET request" not in vectors
    form_finding = next(
        f for f in findings if f["vector"] == "application/x-www-form-urlencoded POST"
    )
    assert form_finding["category"] == "csrf_via_content_type"
    assert form_finding["severity"] == "HIGH"
    evidence = json.loads(form_finding["evidence"])
    assert evidence["request_method"] == "POST"
    assert evidence["request_content_type"] == "application/x-www-form-urlencoded"
    assert 200 <= evidence["response_status"] < 300
    assert "data" in evidence["response_body_prefix"]


@pytest.mark.asyncio
async def test_csrf_get_mutation_accepted_fires():
    """GET mutation accepted → finding fires for the GET vector."""
    app = create_app(
        introspection_enabled=True,
        dangerous_mutations=["deleteUser"],
        accept_form_post=False,
        accept_get_query=True,
    )
    with running_server(app) as url:
        client = GraphQLClient(url)
        findings = await csrf.check(client)

    vectors = {f["vector"] for f in findings}
    assert "GET request" in vectors
    assert "application/x-www-form-urlencoded POST" not in vectors
    get_finding = next(f for f in findings if f["vector"] == "GET request")
    assert get_finding["category"] == "csrf_via_content_type"
    assert get_finding["severity"] == "HIGH"
    evidence = json.loads(get_finding["evidence"])
    assert evidence["request_method"] == "GET"
    assert 200 <= evidence["response_status"] < 300


@pytest.mark.asyncio
async def test_csrf_both_accepted_two_findings():
    """Both vectors accepted → two findings."""
    app = create_app(
        introspection_enabled=True,
        dangerous_mutations=["deleteUser"],
        accept_form_post=True,
        accept_get_query=True,
    )
    with running_server(app) as url:
        client = GraphQLClient(url)
        findings = await csrf.check(client)

    vectors = {f["vector"] for f in findings}
    assert vectors == {"application/x-www-form-urlencoded POST", "GET request"}


@pytest.mark.asyncio
async def test_csrf_both_rejected_no_finding(mock_url):
    """Both vectors rejected (CSRF-safe server) → no findings.

    The session `mock_url` server uses the defaults accept_form_post=False and
    accept_get_query=False, so it represents a properly configured endpoint.
    """
    client = GraphQLClient(mock_url)
    findings = await csrf.check(client)
    assert findings == []


@pytest.mark.asyncio
async def test_csrf_introspection_disabled_uses_synthetic_no_false_positive():
    """Introspection disabled (no mutation discoverable):

    - the check falls back to a synthetic probe mutation,
    - a CSRF-safe server still yields no finding (no false positive).
    """
    app = create_app(
        introspection_enabled=False,
        accept_form_post=False,
        accept_get_query=False,
    )
    with running_server(app) as url:
        client = GraphQLClient(url)
        findings = await csrf.check(client)
    assert findings == []


@pytest.mark.asyncio
async def test_csrf_introspection_disabled_synthetic_fires_when_accepted():
    """Introspection disabled but server accepts form POST → synthetic probe fires
    and the finding is flagged as using a synthetic probe."""
    app = create_app(
        introspection_enabled=False,
        accept_form_post=True,
        accept_get_query=False,
    )
    with running_server(app) as url:
        client = GraphQLClient(url)
        findings = await csrf.check(client)

    assert len(findings) == 1
    finding = findings[0]
    assert finding["category"] == "csrf_via_content_type"
    assert finding["severity"] == "HIGH"
    # The synthetic-probe note must be present in the description.
    assert "synthetic" in finding["description"].lower()
