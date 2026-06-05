"""Tests for the response-cache-poison check.

The check has two sub-checks:
1. Baseline GET execution (precondition: server accepts GET read queries).
2. Alias-variant GET execution (probe: server also executes aliased GET queries).

A finding fires only when both sub-checks succeed (both return 2xx with `data`).
No finding fires when the server rejects GET, returns errors for the aliased
variant, or fails at the transport layer.
"""
from __future__ import annotations

import socket
import threading
import time
from contextlib import contextmanager

import pytest

from enshroud.checks import response_cache_poison
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
    import uvicorn

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


# ---------------------------------------------------------------------------
# Finding cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fires_when_server_accepts_get_and_alias_variant():
    """Server accepts both baseline and alias GET queries -> finding fires (LOW)."""
    app = create_app(
        introspection_enabled=True,
        accept_get_read_query=True,
    )
    with running_server(app) as url:
        client = GraphQLClient(url)
        findings = await response_cache_poison.check(client)

    assert len(findings) == 1
    f = findings[0]
    assert f["category"] == "response_cache_poison_surface"
    assert f["severity"] == "LOW"
    assert "cache" in f["title"].lower()


@pytest.mark.asyncio
async def test_finding_has_required_fields():
    """Finding structure includes all expected keys."""
    app = create_app(accept_get_read_query=True)
    with running_server(app) as url:
        client = GraphQLClient(url)
        findings = await response_cache_poison.check(client)

    assert len(findings) == 1
    f = findings[0]
    assert "category" in f
    assert "severity" in f
    assert "title" in f
    assert "baseline_query" in f
    assert "alias_query" in f
    assert "baseline_status" in f
    assert "alias_status" in f
    assert "description" in f
    assert "reproduction" in f
    assert "impact" in f
    assert "remediation" in f
    assert "evidence" in f


@pytest.mark.asyncio
async def test_finding_references_alias_key():
    """Finding description mentions the aliased probe key."""
    app = create_app(accept_get_read_query=True)
    with running_server(app) as url:
        client = GraphQLClient(url)
        findings = await response_cache_poison.check(client)

    f = findings[0]
    assert response_cache_poison._ALIAS_KEY in f["alias_query"]
    assert "alias" in f["description"].lower()


# ---------------------------------------------------------------------------
# No-finding cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_finding_when_server_rejects_get():
    """Server returns 405 for GET read queries -> no finding."""
    app = create_app(accept_get_read_query=False)
    with running_server(app) as url:
        client = GraphQLClient(url)
        findings = await response_cache_poison.check(client)

    assert findings == []


# ---------------------------------------------------------------------------
# Module / severity constants
# ---------------------------------------------------------------------------


def test_category_constant():
    """The CATEGORY constant matches the expected string."""
    assert response_cache_poison.CATEGORY == "response_cache_poison_surface"


def test_severity_constant():
    """The SEVERITY constant is LOW."""
    assert response_cache_poison.SEVERITY == "LOW"


def test_baseline_and_alias_queries_differ():
    """The two probe queries are syntactically different URLs."""
    assert response_cache_poison._BASELINE_QUERY != response_cache_poison._ALIAS_QUERY


def test_alias_key_present_in_alias_query():
    """The alias-variant query contains the probe alias key."""
    assert response_cache_poison._ALIAS_KEY in response_cache_poison._ALIAS_QUERY


# ---------------------------------------------------------------------------
# CLI registration
# ---------------------------------------------------------------------------


def test_response_cache_poison_in_all_checks():
    """response-cache-poison must be in ALL_CHECKS (included in 'all')."""
    from enshroud.cli import ALL_CHECKS
    assert "response-cache-poison" in ALL_CHECKS


def test_response_cache_poison_in_valid_checks():
    """response-cache-poison must be in VALID_CHECKS."""
    from enshroud.cli import VALID_CHECKS
    assert "response-cache-poison" in VALID_CHECKS


def test_response_cache_poison_not_in_opt_in():
    """response-cache-poison is a standard (non-opt-in) check."""
    from enshroud.cli import OPT_IN_CHECKS
    assert "response-cache-poison" not in OPT_IN_CHECKS
