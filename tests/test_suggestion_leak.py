"""Tests for the suggestion-leak (argument-name / type-name oracle) check."""
import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import suggestion_leak
from enshroud.client import GraphQLClient
from tests.fixtures.mock_graphql_server import create_app


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _start(app):
    """Start an app on an ephemeral port; return (url, server)."""
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


@pytest.mark.asyncio
async def test_suggestion_leak_both_axes_vulnerable():
    """Default mock (suggestions on) → finding lists both leaked axes."""
    app = create_app()  # suggestions_enabled=True by default
    url, server = _start(app)
    try:
        client = GraphQLClient(url)
        findings = await suggestion_leak.check(client)
        assert len(findings) == 1
        f = findings[0]
        assert f["category"] == "suggestion_oracle_leak"
        assert f["severity"] == "LOW"
        assert "argument_name" in f["leaked_axes"]
        assert "type_name" in f["leaked_axes"]
        # Human-readable labels surface both rule names so the report is
        # actionable without consulting the source.
        assert any("KnownArgumentNamesRule" in lbl for lbl in f["leaked_axis_labels"])
        assert any("KnownTypeNamesRule" in lbl for lbl in f["leaked_axis_labels"])
        assert len(f["evidence"]) <= suggestion_leak.EVIDENCE_MAX_LEN
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_suggestion_leak_fully_hardened_no_finding():
    """Server with every suggestion axis suppressed → no finding."""
    app = create_app(suggestions_enabled=False, arg_type_suggestions_enabled=False)
    url, server = _start(app)
    try:
        client = GraphQLClient(url)
        findings = await suggestion_leak.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_suggestion_leak_partial_hardening_field_axis_only():
    """The documented partial-hardening misconfiguration must still fire.

    Operator strips `Did you mean` only from `Cannot query field` errors via
    `formatError` regex — argument-name and type-name axes still leak. The
    `field-oracle` check would return no finding here; `suggestion-leak` must
    catch the gap.
    """
    app = create_app(
        suggestions_enabled=False,           # field axis hardened
        arg_type_suggestions_enabled=True,   # arg / type axes still leak
    )
    url, server = _start(app)
    try:
        client = GraphQLClient(url)
        findings = await suggestion_leak.check(client)
        assert len(findings) == 1
        f = findings[0]
        assert set(f["leaked_axes"]) == {"argument_name", "type_name"}
    finally:
        server.should_exit = True


def test_extract_suggested_identifiers_single_token():
    """Bare and quoted forms both yield the identifier; dedup preserves order."""
    msg = 'Unknown argument "naem" on field "Query.__type". Did you mean "name"?'
    assert suggestion_leak._extract_suggested_identifiers(msg) == ["name"]


def test_extract_suggested_identifiers_no_hint():
    """A hardened error message yields no identifiers."""
    msg = 'Unknown argument "naem" on field "Query.__type".'
    assert suggestion_leak._extract_suggested_identifiers(msg) == []


def test_extract_suggested_identifiers_dedup_order_preserved():
    """Repeated identifiers across multiple hints are deduplicated, order kept."""
    msg = 'Did you mean "id"? Maybe also: Did you mean "name"? Did you mean "id"?'
    assert suggestion_leak._extract_suggested_identifiers(msg) == ["id", "name"]


def test_suggestion_signal_requires_expected_real():
    """The differential anchor: only fires when the known real id is surfaced.

    A generic ``Did you mean ...`` referencing something unrelated to the
    probe is not a signal — this is what keeps the check from false-positive
    on suggestion text that has nothing to do with our typo'd probe shape.
    """
    fired, extracted = suggestion_leak._suggestion_signal(
        {"errors": [{"message": 'Did you mean "name"?'}]},
        expected_real="name",
    )
    assert fired is True
    assert "name" in extracted

    fired, extracted = suggestion_leak._suggestion_signal(
        {"errors": [{"message": 'Did you mean "somethingElse"?'}]},
        expected_real="name",
    )
    assert fired is False
    assert "somethingElse" in extracted  # captured for evidence but does not fire


def test_suggestion_signal_no_errors_array():
    """A response without errors never fires the signal."""
    fired, extracted = suggestion_leak._suggestion_signal(
        {"data": {"__type": {"name": "Query"}}},
        expected_real="name",
    )
    assert fired is False
    assert extracted == []


def test_probe_shapes_are_read_only_validation_halts():
    """Both probes halt at validation — no resolver invocation, no mutation."""
    # Argument-name probe selects only the introspection meta-field with a
    # typo'd argument; never reaches a resolver.
    assert "naem" in suggestion_leak.ARG_PROBE
    assert "mutation" not in suggestion_leak.ARG_PROBE.lower()
    # Type-name probe is an inline fragment on an undefined type; the
    # fragment is never spread because validation rejects the condition.
    assert "Queryy" in suggestion_leak.TYPE_PROBE
    assert "mutation" not in suggestion_leak.TYPE_PROBE.lower()
    # No field aliases that the mock's generic `(\w+)\s*:\s*__typename`
    # echoer would expand and accidentally trip the check on a hardened server.
    assert ": __typename" not in suggestion_leak.ARG_PROBE
    assert ": __typename" not in suggestion_leak.TYPE_PROBE


@pytest.mark.asyncio
async def test_only_argument_axis_fires(monkeypatch):
    """Per-axis granularity: stub a server that leaks arg suggestion only."""
    class _StubClient:
        async def query(self, q):
            if "naem" in q:
                return {
                    "errors": [
                        {
                            "message": (
                                'Unknown argument "naem" on field '
                                '"Query.__type". Did you mean "name"?'
                            )
                        }
                    ]
                }
            if "Queryy" in q:
                # Hardened on this axis — error but no hint.
                return {"errors": [{"message": 'Unknown type "Queryy".'}]}
            return {"data": {}}

    findings = await suggestion_leak.check(_StubClient())  # type: ignore[arg-type]
    assert len(findings) == 1
    f = findings[0]
    assert f["leaked_axes"] == ["argument_name"]


@pytest.mark.asyncio
async def test_only_type_axis_fires():
    """Per-axis granularity: stub a server that leaks type suggestion only."""
    class _StubClient:
        async def query(self, q):
            if "naem" in q:
                return {
                    "errors": [
                        {"message": 'Unknown argument "naem" on field "Query.__type".'}
                    ]
                }
            if "Queryy" in q:
                return {
                    "errors": [
                        {"message": 'Unknown type "Queryy". Did you mean "Query"?'}
                    ]
                }
            return {"data": {}}

    findings = await suggestion_leak.check(_StubClient())  # type: ignore[arg-type]
    assert len(findings) == 1
    f = findings[0]
    assert f["leaked_axes"] == ["type_name"]


@pytest.mark.asyncio
async def test_transport_error_is_silent():
    """A probe that raises during transport is silently skipped (no finding)."""
    class _BoomClient:
        async def query(self, q):
            raise RuntimeError("network down")

    findings = await suggestion_leak.check(_BoomClient())  # type: ignore[arg-type]
    assert findings == []


@pytest.mark.asyncio
async def test_default_mock_does_not_trip_field_oracle_when_isolated():
    """Regression: the new mock handlers must not collide with field-oracle.

    The argument-name and type-name probes contain neither
    `nonExistentFieldXyzzy` nor a `(\\w+)\\s*:\\s*__typename` alias, so the
    field-oracle handler and the generic alias echoer must not see them.
    """
    from enshroud.checks import field_oracle

    app = create_app()
    url, server = _start(app)
    try:
        client = GraphQLClient(url)
        # field-oracle still fires on the default mock (its own probe is
        # specifically supported); we just confirm suggestion-leak's probes
        # don't preempt it.
        field_findings = await field_oracle.check(client)
        assert len(field_findings) == 1
        # And suggestion-leak fires independently on the same default mock.
        sl_findings = await suggestion_leak.check(client)
        assert len(sl_findings) == 1
    finally:
        server.should_exit = True
