"""Tests for the mutation-allowlist-bypass check (operation-type confusion)."""
from __future__ import annotations

import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import mutation_allowlist_bypass
from enshroud.client import GraphQLClient
from tests.fixtures.mock_graphql_server import create_app


# ── helpers ──────────────────────────────────────────────────────────────────

def _start_server(app, host: str = "127.0.0.1") -> tuple[str, uvicorn.Server, threading.Thread]:
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


# ── tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_finding_when_introspection_disabled():
    """Without introspection the check cannot enumerate mutations → silent."""
    app = create_app(introspection_enabled=False)
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await mutation_allowlist_bypass.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_no_finding_when_no_mutations():
    """A schema with no mutations is not a candidate for the bypass."""
    app = create_app(
        introspection_enabled=True,
        dangerous_mutations=[],
    )
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await mutation_allowlist_bypass.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_no_finding_on_spec_correct_server():
    """A server that rejects mutations under query{} produces no finding.

    Mutations exist and carry required arguments, but the executor enforces
    the operation type — `query { deleteUser ... }` is rejected with
    "Cannot query field on type Query". The bypass signal never fires.
    """
    app = create_app(
        introspection_enabled=True,
        dangerous_mutations=["deleteUser"],
        mutation_arg_signature={
            "deleteUser": [{"name": "id", "type": "ID", "required": True}]
        },
        op_type_confusion=False,
    )
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await mutation_allowlist_bypass.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_detects_op_type_confusion_bypass():
    """A vulnerable server that resolves mutations under query{} → HIGH finding.

    The probe omits the required arg, so the resolver never runs — the
    executor halts at argument validation and returns the "argument is
    required" error the check reads as the bypass signal.
    """
    app = create_app(
        introspection_enabled=True,
        dangerous_mutations=["deleteUser"],
        mutation_arg_signature={
            "deleteUser": [{"name": "id", "type": "ID", "required": True}]
        },
        op_type_confusion=True,
    )
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await mutation_allowlist_bypass.check(client)
        categories = [f["category"] for f in findings]
        assert "mutation_allowlist_bypass_via_op_type" in categories
        finding = next(
            f for f in findings
            if f["category"] == "mutation_allowlist_bypass_via_op_type"
        )
        assert finding["severity"] == "HIGH"
        assert finding["mutation_name"] == "deleteUser"
        # Evidence references both the probe document and the response.
        assert "deleteUser" in finding["evidence"]
        # The probe is a `query` operation, not a `mutation`.
        assert "EnshroudOpTypeConfusion" in finding["evidence"]
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_skips_mutations_without_required_args():
    """A mutation with only optional args is unsafe to probe — must be skipped.

    Probing a no-required-arg mutation could execute the mutation. The
    check must filter these out and stay silent when no required-arg
    mutation exists in the schema.
    """
    app = create_app(
        introspection_enabled=True,
        dangerous_mutations=["logout"],
        mutation_arg_signature={
            # Argument exists but is NOT required (NON_NULL=False).
            "logout": [{"name": "everywhere", "type": "Boolean", "required": False}]
        },
        op_type_confusion=True,  # server is vulnerable, but check still skips
    )
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await mutation_allowlist_bypass.check(client)
        # Even though the server would expose the bypass, the check refuses
        # to probe a mutation whose resolver could run without an argument.
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_only_one_finding_per_run():
    """One representative finding is enough — the check stops at first hit."""
    app = create_app(
        introspection_enabled=True,
        dangerous_mutations=["deleteUser", "transferFunds", "adminRevoke"],
        mutation_arg_signature={
            "deleteUser": [{"name": "id", "type": "ID", "required": True}],
            "transferFunds": [{"name": "amount", "type": "Int", "required": True}],
            "adminRevoke": [{"name": "userId", "type": "ID", "required": True}],
        },
        op_type_confusion=True,
    )
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await mutation_allowlist_bypass.check(client)
        # Each mutation would produce the same bug-class signal; the check
        # reports one representative finding and stops.
        bypass_findings = [
            f for f in findings
            if f["category"] == "mutation_allowlist_bypass_via_op_type"
        ]
        assert len(bypass_findings) == 1
    finally:
        server.should_exit = True


def test_unwrap_type_handles_non_null():
    """The type-unwrapper recognises NON_NULL as 'required'."""
    nn = {"kind": "NON_NULL", "name": None,
          "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None}}
    is_required, _ = mutation_allowlist_bypass._unwrap_type(nn)
    assert is_required is True


def test_unwrap_type_handles_nullable():
    """A bare scalar (no NON_NULL wrapper) is NOT required."""
    plain = {"kind": "SCALAR", "name": "String", "ofType": None}
    is_required, _ = mutation_allowlist_bypass._unwrap_type(plain)
    assert is_required is False


def test_unwrap_type_handles_none():
    """A missing type reference is treated as not-required (defensive)."""
    is_required, _ = mutation_allowlist_bypass._unwrap_type(None)
    assert is_required is False


def test_has_required_arg_true_when_any_arg_required():
    """A mutation with at least one NON_NULL arg counts as 'has required'."""
    field = {
        "name": "x",
        "args": [
            {"name": "opt", "type": {"kind": "SCALAR", "name": "String", "ofType": None}},
            {"name": "req", "type": {
                "kind": "NON_NULL", "name": None,
                "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None},
            }},
        ],
    }
    assert mutation_allowlist_bypass._has_required_arg(field) is True


def test_has_required_arg_false_when_no_args():
    """A mutation with no args at all cannot be safely probed."""
    field = {"name": "logout", "args": []}
    assert mutation_allowlist_bypass._has_required_arg(field) is False


def test_has_required_arg_false_when_all_optional():
    """A mutation with only optional args cannot be safely probed."""
    field = {
        "name": "ping",
        "args": [
            {"name": "echo", "type": {"kind": "SCALAR", "name": "String", "ofType": None}}
        ],
    }
    assert mutation_allowlist_bypass._has_required_arg(field) is False


def test_arg_error_classifier_matches_required_argument_error():
    """The 'argument is required' wording is recognised as the bypass signal."""
    resp = {
        "errors": [
            {"message": 'Field "deleteUser" argument "id" of type "ID!" is required, but it was not provided.'}
        ]
    }
    assert mutation_allowlist_bypass._looks_like_resolved_field_arg_error(
        resp, "deleteUser"
    ) is True


def test_arg_error_classifier_ignores_cannot_query_field():
    """The 'cannot query field on Query' rejection is NOT a bypass."""
    resp = {
        "errors": [
            {"message": 'Cannot query field "deleteUser" on type "Query".'}
        ]
    }
    assert mutation_allowlist_bypass._looks_like_resolved_field_arg_error(
        resp, "deleteUser"
    ) is False


def test_arg_error_classifier_ignores_data_response():
    """A successful data response is not the bypass signal."""
    resp = {"data": {"deleteUser": {"__typename": "Mutation"}}}
    assert mutation_allowlist_bypass._looks_like_resolved_field_arg_error(
        resp, "deleteUser"
    ) is False


def test_arg_error_classifier_rejection_overrides_other_errors():
    """If any error message is the secure rejection, the response is safe.

    A defensive case: a server returning multiple errors where one is the
    "cannot query field on Query" rejection is NOT vulnerable, even if
    another error happens to mention 'required argument'.
    """
    resp = {
        "errors": [
            {"message": 'Cannot query field "deleteUser" on type "Query".'},
            {"message": 'argument "id" of type "ID!" is required'},
        ]
    }
    assert mutation_allowlist_bypass._looks_like_resolved_field_arg_error(
        resp, "deleteUser"
    ) is False


def test_mutation_allowlist_bypass_in_default_checks():
    """mutation-allowlist-bypass is part of --checks all (read-only by design)."""
    from enshroud.cli import ALL_CHECKS, OPT_IN_CHECKS, VALID_CHECKS, parse_checks

    assert "mutation-allowlist-bypass" in ALL_CHECKS
    assert "mutation-allowlist-bypass" not in OPT_IN_CHECKS
    assert "mutation-allowlist-bypass" in VALID_CHECKS
    assert "mutation-allowlist-bypass" in parse_checks("all")
