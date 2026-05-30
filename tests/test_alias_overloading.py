"""Tests for the alias-overloading check.

Covers the differential contract:

* Fires only when a real, argless top-level query field is discoverable AND
  the server executes every aliased copy of it.
* Stays silent when no real query field is available (the
  ``__typename``-only mock is the no-false-positive baseline).
* Stays silent when the server enforces a per-real-field alias cap
  (alias-aware cost analysis).
* Differential against ``alias-batch``: a server that triggers alias-batch on
  ``__typename`` does not, by itself, trigger this check — and vice versa.
* Probe stays read-only: the discovered field is argless and only
  ``__typename`` is selected under it.
"""
from __future__ import annotations

import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import alias_overloading
from enshroud.client import GraphQLClient
from tests.fixtures.mock_graphql_server import create_app


def _start_server(app, host: str = "127.0.0.1") -> tuple[str, uvicorn.Server, threading.Thread]:
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

    return f"http://{host}:{port}/graphql", server, thread


@pytest.mark.asyncio
async def test_finding_when_real_field_overload_uncapped():
    """Real argless field present + no per-field cap → MEDIUM finding."""
    app = create_app(
        alias_overload_fields=["login"],
        alias_overload_real_field_cap=None,
    )
    url, server, _ = _start_server(app)
    try:
        findings = await alias_overloading.check(GraphQLClient(url))
        categories = [f["category"] for f in findings]
        assert "alias_overloading" in categories
        finding = next(f for f in findings if f["category"] == "alias_overloading")
        assert finding["severity"] == "MEDIUM"
        assert finding["probe_field"] == "login"
        assert finding["aliased_copies_executed"] == alias_overloading.ALIAS_COUNT
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_no_finding_when_per_field_cap_enforced():
    """Server caps aliased copies of a real field → check stays silent."""
    app = create_app(
        alias_overload_fields=["login"],
        alias_overload_real_field_cap=5,
    )
    url, server, _ = _start_server(app)
    try:
        findings = await alias_overloading.check(GraphQLClient(url))
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_no_finding_when_no_real_field_introspectable(mock_url):
    """Default mock has only `__typename` query-type field → silent.

    This is the no-false-positive baseline: a server that exposes no
    non-meta top-level query field gives the check no probe target, and
    re-using ``__typename`` would duplicate ``alias-batch``.
    """
    findings = await alias_overloading.check(GraphQLClient(mock_url))
    assert findings == []


@pytest.mark.asyncio
async def test_no_finding_when_introspection_disabled():
    """Introspection disabled → no candidate → silent."""
    app = create_app(
        introspection_enabled=False,
        alias_overload_fields=["login"],
    )
    url, server, _ = _start_server(app)
    try:
        findings = await alias_overloading.check(GraphQLClient(url))
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_differential_against_alias_batch_metafield_only():
    """alias-batch fires on __typename breadth; alias-overloading must not.

    Differential guarantee: a server that is wide open to ``alias-batch``
    (no batch_limit, only `__typename` exposed) gives ``alias-overloading``
    no real-field probe target and must produce no finding here. This
    confirms the two checks measure independent signals.
    """
    from enshroud.checks import alias_batch

    app = create_app(batch_limit=None)  # alias-batch will fire
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        batch_findings = await alias_batch.check(client)
        overload_findings = await alias_overloading.check(client)
        assert any(f["category"] == "alias_batching" for f in batch_findings)
        assert overload_findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_probe_uses_only_typename_subselection():
    """The built probe selects only `__typename` under the aliased field.

    Guards the read-only contract: no real sub-fields and no resolver args
    are supplied, so even if the discovered field is a mutation-shaped query
    field with side-effecting resolvers, the probe cannot trigger them.
    """
    query = alias_overloading._build_overload_query("login", 3)
    # Exactly three aliased copies, each selecting only __typename.
    assert query.count("login { __typename }") == 3
    assert "enshroudOverloadAlias1: login" in query
    assert "enshroudOverloadAlias3: login" in query
    # No other sub-selection ever appears.
    assert "(" not in query  # no arguments
    assert query.count("__typename") == 3


def test_discover_skips_meta_and_argful_fields():
    """The discovery helper rejects meta-fields and any field with args."""
    intro = {
        "data": {
            "__schema": {
                "queryType": {
                    "fields": [
                        {"name": "__typename", "args": []},
                        {"name": "__type", "args": [{"name": "name"}]},
                        {"name": "userById", "args": [{"name": "id"}]},
                        {"name": "currentUser", "args": []},
                    ]
                }
            }
        }
    }
    assert (
        alias_overloading._discover_argless_real_field(intro) == "currentUser"
    )


def test_discover_returns_none_when_only_meta_fields():
    """Only meta-fields available → no probe target."""
    intro = {
        "data": {
            "__schema": {
                "queryType": {
                    "fields": [{"name": "__typename", "args": []}]
                }
            }
        }
    }
    assert alias_overloading._discover_argless_real_field(intro) is None


def test_discover_returns_none_when_only_argful_fields():
    """Every real field requires args → no read-only probe target."""
    intro = {
        "data": {
            "__schema": {
                "queryType": {
                    "fields": [
                        {"name": "userById", "args": [{"name": "id"}]},
                    ]
                }
            }
        }
    }
    assert alias_overloading._discover_argless_real_field(intro) is None


@pytest.mark.asyncio
async def test_evidence_truncated_and_carries_probe_metadata():
    """Evidence is a bounded JSON string and carries the probe field name."""
    app = create_app(alias_overload_fields=["login"])
    url, server, _ = _start_server(app)
    try:
        findings = await alias_overloading.check(GraphQLClient(url))
        finding = findings[0]
        assert isinstance(finding["evidence"], str)
        assert 0 < len(finding["evidence"]) <= 600
        assert "login" in finding["evidence"]
        assert "probe_field" in finding["evidence"]
    finally:
        server.should_exit = True


def test_alias_overloading_in_all_checks_and_registered():
    """alias-overloading is in --checks all, valid, and has a check_map entry."""
    from enshroud.cli import ALL_CHECKS, VALID_CHECKS, parse_checks

    assert "alias-overloading" in ALL_CHECKS
    assert "alias-overloading" in VALID_CHECKS
    assert "alias-overloading" in parse_checks("all")
