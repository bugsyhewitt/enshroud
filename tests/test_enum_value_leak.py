"""Tests for the enum-value suggestion-oracle leak check."""
import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import enum_value_leak
from enshroud.client import GraphQLClient
from tests.fixtures.mock_graphql_server import create_app


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _start(app):
    """Start app on an ephemeral port; return (url, server)."""
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
    return f"http://{host}:{port}/graphql", server


# ---------------------------------------------------------------------------
# Live mock-server tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enum_value_leak_vulnerable():
    """Mock with enum field + suggestions on → finding returned."""
    app = create_app(
        enum_field="usersByStatus",
        enum_arg="status",
        enum_type_name="UserStatus",
        enum_values=["ACTIVE", "INACTIVE", "PENDING"],
        enum_value_suggestions_enabled=True,
    )
    url, server = _start(app)
    try:
        client = GraphQLClient(url)
        findings = await enum_value_leak.check(client)
        assert len(findings) == 1
        f = findings[0]
        assert f["category"] == "enum_value_oracle_leak"
        assert f["severity"] == "LOW"
        assert f["enum_type"] == "UserStatus"
        assert f["field"] == "usersByStatus"
        assert f["argument"] == "status"
        assert "ACTIVE" in f["leaked_values"]
        assert len(f["evidence"]) <= enum_value_leak.EVIDENCE_MAX_LEN
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_enum_value_leak_hardened_no_finding():
    """Mock with suggestions suppressed → no finding."""
    app = create_app(
        enum_field="usersByStatus",
        enum_arg="status",
        enum_type_name="UserStatus",
        enum_values=["ACTIVE", "INACTIVE", "PENDING"],
        enum_value_suggestions_enabled=False,
    )
    url, server = _start(app)
    try:
        client = GraphQLClient(url)
        findings = await enum_value_leak.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_enum_value_leak_no_enum_arg_no_finding():
    """Mock with no enum-typed argument → no finding (check stays silent)."""
    app = create_app()  # no enum_field configured
    url, server = _start(app)
    try:
        client = GraphQLClient(url)
        findings = await enum_value_leak.check(client)
        assert findings == []
    finally:
        server.should_exit = True


# ---------------------------------------------------------------------------
# Stub-client unit tests (angr-free / server-free)
# ---------------------------------------------------------------------------


def _schema_resp(
    field: str, arg: str, enum_type: str
) -> dict:
    """Build a fake __schema introspection response."""
    return {
        "data": {
            "__schema": {
                "queryType": {
                    "fields": [
                        {
                            "name": field,
                            "args": [
                                {
                                    "name": arg,
                                    "type": {
                                        "kind": "ENUM",
                                        "name": enum_type,
                                        "ofType": None,
                                    },
                                }
                            ],
                        }
                    ]
                }
            }
        }
    }


def _enum_values_resp(values: list[str]) -> dict:
    """Build a fake __type enumValues response."""
    return {
        "data": {
            "__type": {"enumValues": [{"name": v} for v in values]}
        }
    }


def _error_resp(msg: str) -> dict:
    return {"errors": [{"message": msg}]}


class _StubClient:
    """Configurable stub client for unit tests."""

    def __init__(self, responses: list[dict]):
        self._responses = iter(responses)

    async def query(self, q: str) -> dict:
        return next(self._responses)


@pytest.mark.asyncio
async def test_stub_fires_on_suggestion():
    """Stub with valid suggestion response → finding with leaked value."""
    client = _StubClient(
        [
            _schema_resp("usersByStatus", "status", "UserStatus"),
            _enum_values_resp(["ACTIVE", "INACTIVE"]),
            _error_resp(
                'Expected type "UserStatus", found ACTIV. '
                'Did you mean the enum value "ACTIVE"?'
            ),
        ]
    )
    findings = await enum_value_leak.check(client)
    assert len(findings) == 1
    f = findings[0]
    assert f["category"] == "enum_value_oracle_leak"
    assert "ACTIVE" in f["leaked_values"]


@pytest.mark.asyncio
async def test_stub_no_suggestion_no_finding():
    """Stub whose error carries no Did you mean → no finding."""
    client = _StubClient(
        [
            _schema_resp("usersByStatus", "status", "UserStatus"),
            _enum_values_resp(["ACTIVE", "INACTIVE"]),
            _error_resp('Expected type "UserStatus", found ACTIV.'),
        ]
    )
    findings = await enum_value_leak.check(client)
    assert findings == []


@pytest.mark.asyncio
async def test_stub_no_enum_arg_no_finding():
    """Introspection returns only non-enum fields → no finding."""
    client = _StubClient(
        [
            {
                "data": {
                    "__schema": {
                        "queryType": {
                            "fields": [
                                {
                                    "name": "user",
                                    "args": [
                                        {
                                            "name": "id",
                                            "type": {
                                                "kind": "SCALAR",
                                                "name": "ID",
                                                "ofType": None,
                                            },
                                        }
                                    ],
                                }
                            ]
                        }
                    }
                }
            }
        ]
    )
    findings = await enum_value_leak.check(client)
    assert findings == []


@pytest.mark.asyncio
async def test_stub_introspection_disabled_no_finding():
    """No __schema data (introspection disabled) → no finding."""
    client = _StubClient(
        [{"errors": [{"message": "Introspection is disabled"}]}]
    )
    findings = await enum_value_leak.check(client)
    assert findings == []


@pytest.mark.asyncio
async def test_stub_transport_error_no_finding():
    """Transport error at first request → silent no finding."""

    class _BoomClient:
        async def query(self, q: str) -> dict:
            raise RuntimeError("network error")

    findings = await enum_value_leak.check(_BoomClient())
    assert findings == []


@pytest.mark.asyncio
async def test_stub_non_null_wrapped_enum_found():
    """NON_NULL-wrapped enum arg is discovered via _unwrap_type."""
    schema = {
        "data": {
            "__schema": {
                "queryType": {
                    "fields": [
                        {
                            "name": "filterItems",
                            "args": [
                                {
                                    "name": "kind",
                                    "type": {
                                        "kind": "NON_NULL",
                                        "name": None,
                                        "ofType": {
                                            "kind": "ENUM",
                                            "name": "ItemKind",
                                            "ofType": None,
                                        },
                                    },
                                }
                            ],
                        }
                    ]
                }
            }
        }
    }
    client = _StubClient(
        [
            schema,
            _enum_values_resp(["GADGET", "WIDGET"]),
            _error_resp(
                'Expected type "ItemKind", found GADGE. '
                'Did you mean the enum value "GADGET"?'
            ),
        ]
    )
    findings = await enum_value_leak.check(client)
    assert len(findings) == 1
    assert findings[0]["enum_type"] == "ItemKind"
    assert "GADGET" in findings[0]["leaked_values"]


# ---------------------------------------------------------------------------
# Pure-function unit tests (no async / no network)
# ---------------------------------------------------------------------------


def test_unwrap_type_non_null():
    t = {"kind": "NON_NULL", "name": None, "ofType": {"kind": "ENUM", "name": "S", "ofType": None}}
    assert enum_value_leak._unwrap_type(t) == {"kind": "ENUM", "name": "S", "ofType": None}


def test_unwrap_type_plain():
    t = {"kind": "ENUM", "name": "Status", "ofType": None}
    assert enum_value_leak._unwrap_type(t) == t


def test_find_enum_arg_none_when_no_enum():
    schema = {
        "data": {
            "__schema": {
                "queryType": {
                    "fields": [
                        {
                            "name": "user",
                            "args": [{"name": "id", "type": {"kind": "SCALAR", "name": "ID", "ofType": None}}],
                        }
                    ]
                }
            }
        }
    }
    assert enum_value_leak._find_enum_arg(schema) is None


def test_find_enum_arg_returns_first():
    schema = _schema_resp("byStatus", "status", "StatusEnum")
    result = enum_value_leak._find_enum_arg(schema)
    assert result == ("byStatus", "status", "StatusEnum")


def test_extract_suggestions_quoted():
    msg = 'Expected type "S", found X. Did you mean the enum value "ACTIVE"?'
    assert enum_value_leak._extract_suggestions(msg) == ["ACTIVE"]


def test_extract_suggestions_unquoted():
    msg = "Did you mean the enum value ACTIVE or INACTIVE?"
    assert enum_value_leak._extract_suggestions(msg) == ["ACTIVE", "INACTIVE"]


def test_extract_suggestions_empty():
    assert enum_value_leak._extract_suggestions("some random error") == []


def test_extract_suggestions_dedup():
    msg = "Did you mean ACTIVE? Did you mean ACTIVE?"
    assert enum_value_leak._extract_suggestions(msg) == ["ACTIVE"]
