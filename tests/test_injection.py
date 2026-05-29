"""Tests for the SQL/NoSQL injection probing check."""
from __future__ import annotations

import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import injection
from enshroud.client import GraphQLClient
from tests.fixtures.mock_graphql_server import create_app


# ── helpers ──────────────────────────────────────────────────────────────────

def _start_server(app, host: str = "127.0.0.1"):
    """Start a FastAPI app on a random free port; return (url, server, thread)."""
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


# ── unit tests: pure helpers (no server) ──────────────────────────────────────

def test_scalar_name_resolves_non_null_wrapper():
    non_null_string = {"kind": "NON_NULL", "name": None, "ofType": {"kind": "SCALAR", "name": "String"}}
    assert injection._scalar_name(non_null_string) == "String"
    assert injection._scalar_name({"kind": "SCALAR", "name": "Int"}) == "Int"
    # Lists / input objects are not fuzzable scalars.
    assert injection._scalar_name({"kind": "LIST", "name": None}) is None
    assert injection._scalar_name(None) is None


def test_enumerate_fuzzable_args_picks_string_int_only():
    schema = {
        "queryType": {
            "fields": [
                {
                    "name": "search",
                    "args": [
                        {"name": "term", "type": {"kind": "SCALAR", "name": "String"}},
                        {"name": "page", "type": {"kind": "SCALAR", "name": "Int"}},
                        {"name": "active", "type": {"kind": "SCALAR", "name": "Boolean"}},
                        {"name": "filter", "type": {"kind": "INPUT_OBJECT", "name": "Filter"}},
                    ],
                }
            ]
        },
        "mutationType": {
            "fields": [
                {
                    "name": "rename",
                    "args": [
                        {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}},
                    ],
                }
            ]
        },
    }
    targets = injection.enumerate_fuzzable_args(schema)
    pairs = {(t["operation"], t["field"], t["arg"]) for t in targets}
    assert ("query", "search", "term") in pairs
    assert ("query", "search", "page") in pairs
    assert ("mutation", "rename", "id") in pairs
    # Boolean and input-object args are skipped.
    assert ("query", "search", "active") not in pairs
    assert ("query", "search", "filter") not in pairs


def test_detect_dbms_error_matches_known_engines():
    assert injection.detect_dbms_error("You have an error in your SQL syntax") == "MySQL"
    assert injection.detect_dbms_error("syntax error at or near \"'\"") == "PostgreSQL"
    assert injection.detect_dbms_error("Unclosed quotation mark after the character string") == "MSSQL"
    assert injection.detect_dbms_error("MongoError: unknown operator: $gt") == "MongoDB"
    assert injection.detect_dbms_error("just a normal response") is None
    assert injection.detect_dbms_error("") is None


def test_build_probe_query_quotes_strings_and_escapes():
    target = {"operation": "query", "field": "search", "arg": "term", "scalar": "String"}
    q = injection.build_probe_query(target, "a'b")
    assert "search(term: \"a'b\")" in q
    assert "__typename" in q
    # Int args are sent unquoted.
    int_target = {"operation": "query", "field": "byId", "arg": "id", "scalar": "Int"}
    qi = injection.build_probe_query(int_target, "1 OR 1=1")
    assert "byId(id: 1 OR 1=1)" in qi


# ── integration tests: against the mock server ────────────────────────────────

@pytest.mark.asyncio
async def test_no_findings_when_introspection_disabled():
    app = create_app(introspection_enabled=False, injectable_arg={
        "field": "searchUsers", "arg": "filter", "dbms_error": "You have an error in your SQL syntax",
    })
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await injection.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_no_findings_when_no_injectable_arg():
    # Introspection on but no injectable arg exposed → nothing fuzzable, no error.
    app = create_app(introspection_enabled=True, injectable_arg=None)
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await injection.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_detects_sql_injection_signal():
    app = create_app(
        introspection_enabled=True,
        injectable_arg={
            "field": "searchUsers",
            "arg": "filter",
            "dbms_error": "You have an error in your SQL syntax; check the manual",
        },
    )
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await injection.check(client)
        assert len(findings) == 1
        f = findings[0]
        assert f["category"] == "sql_injection_signal"
        assert f["severity"] == "CRITICAL"
        assert f["field"] == "searchUsers"
        assert f["argument"] == "filter"
        assert f["dbms"] == "MySQL"
        assert "payload" in f
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_detects_nosql_injection_signal():
    app = create_app(
        introspection_enabled=True,
        injectable_arg={
            "field": "searchUsers",
            "arg": "filter",
            "dbms_error": "MongoError: unknown operator: $gt",
        },
    )
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await injection.check(client)
        assert len(findings) == 1
        assert findings[0]["category"] == "nosql_injection_signal"
        assert findings[0]["dbms"] == "MongoDB"
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_no_false_positive_on_safe_backend():
    # Injectable arg exists but the backend never returns a DBMS error.
    app = create_app(
        introspection_enabled=True,
        injectable_arg={
            "field": "searchUsers",
            "arg": "filter",
            "dbms_error": None,
        },
    )
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await injection.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_time_based_only_when_active():
    app = create_app(
        introspection_enabled=True,
        injectable_arg={
            "field": "searchUsers",
            "arg": "filter",
            "dbms_error": None,
            "time_based": True,
        },
    )
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url, timeout=15)
        # Without --active, time-based probing is skipped → no findings.
        passive = await injection.check(client, active=False)
        assert passive == []
        # With --active, the controllable delay is detected.
        active = await injection.check(client, active=True)
        assert len(active) == 1
        assert active[0]["category"] == "sql_injection_signal"
        assert "time-based" in active[0]["dbms"]
        # Evidence now records the zero-delay control measurement alongside the
        # clean baseline and the slow payload, proving the delay is controllable.
        assert "control(pg_sleep(0))" in active[0]["evidence"]
        assert "delta vs control" in active[0]["evidence"]
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_time_based_no_false_positive_on_uniformly_slow_endpoint():
    # The endpoint is slow for EVERY request (busy backend / tarpit), but the
    # delay is not payload-controlled: pg_sleep(0) is just as slow as pg_sleep(3).
    # A correct check must compare the slow payload against the zero-delay control
    # and suppress the finding — otherwise it fires a CRITICAL false positive.
    app = create_app(
        introspection_enabled=True,
        injectable_arg={
            "field": "searchUsers",
            "arg": "filter",
            "dbms_error": None,
            # No "time_based": the endpoint does not honour the requested sleep.
            "uniform_delay": 3.0,
        },
    )
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url, timeout=15)
        findings = await injection.check(client, active=True)
        # Slow payload ≈ control ≈ baseline (all uniformly ~3s) → no signal.
        assert findings == []
    finally:
        server.should_exit = True


def test_time_finding_records_control_in_evidence():
    # Unit test of the finding builder: the control measurement and both deltas
    # must be present so a hunter can see the differential that justified firing.
    target = {"operation": "query", "field": "search", "arg": "term", "scalar": "String"}
    f = injection._time_finding(target, baseline=0.10, slow=3.30, control=0.20)
    assert f["category"] == "sql_injection_signal"
    assert f["severity"] == "CRITICAL"
    assert "baseline=0.10s" in f["evidence"]
    assert "control(pg_sleep(0))=0.20s" in f["evidence"]
    assert "delta vs control 3.10s" in f["evidence"]
    assert "delta vs baseline 3.20s" in f["evidence"]
