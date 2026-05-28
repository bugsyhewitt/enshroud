"""Tests for the schema-fuzz (Clairvoyance-style) check."""
from __future__ import annotations

import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import schema_fuzz
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


# Small wordlist used across tests so probing is fast and deterministic.
_WORDLIST = ["user", "users", "admin", "account", "product", "orders", "zzznope"]


# ── unit tests (no server) ─────────────────────────────────────────────────────

def test_load_wordlist_returns_field_names():
    words = schema_fuzz.load_wordlist()
    assert isinstance(words, list)
    assert len(words) > 50  # bundled list is non-trivial
    # Comments and blanks stripped; only valid identifiers remain.
    assert all(w and not w.startswith("#") for w in words)
    assert "user" in words
    assert "admin" in words


def test_load_wordlist_deduplicates():
    words = schema_fuzz.load_wordlist()
    assert len(words) == len(set(words))


def test_extract_suggestions_quoted():
    msg = 'Cannot query field "usr" on type "Query". Did you mean "user" or "users"?'
    assert sorted(schema_fuzz._extract_suggestions(msg)) == ["user", "users"]


def test_extract_suggestions_none():
    msg = 'Cannot query field "zzz" on type "Query".'
    assert schema_fuzz._extract_suggestions(msg) == []


def test_classify_data_confirms_field():
    confirmed, suggestions = schema_fuzz._classify(
        {"data": {"user": {"__typename": "User"}}}, "user"
    )
    assert confirmed is True
    assert suggestions == []


def test_classify_selection_required_confirms_field():
    resp = {
        "errors": [
            {"message": "Field \"user\" must have a selection of subfields."}
        ]
    }
    confirmed, suggestions = schema_fuzz._classify(resp, "user")
    assert confirmed is True


def test_classify_cannot_query_does_not_confirm():
    resp = {"errors": [{"message": 'Cannot query field "zzz" on type "Query".'}]}
    confirmed, suggestions = schema_fuzz._classify(resp, "zzz")
    assert confirmed is False
    assert suggestions == []


# ── integration tests (mock server) ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_finding_when_oracle_silent():
    """Server with suggestions disabled and no overlapping fields → no finding."""
    app = create_app(suggestions_enabled=False, schema_fields=["wholly", "unrelated"])
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await schema_fuzz.check(
            client, fuzz_rate=0, wordlist=["nope", "missing"]
        )
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_reconstructs_fields_via_data():
    """Real fields in the wordlist are confirmed when the server returns data."""
    app = create_app(
        suggestions_enabled=False,
        schema_fields=["user", "admin", "product"],
    )
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await schema_fuzz.check(client, fuzz_rate=0, wordlist=_WORDLIST)
        assert len(findings) == 1
        f = findings[0]
        assert f["category"] == "schema_reconstructed"
        recovered = set(f["reconstructed_fields"])
        assert {"user", "admin", "product"} <= recovered
        assert "zzznope" not in recovered
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_reconstructs_fields_via_suggestion_oracle():
    """Fields not in the wordlist are recovered from 'Did you mean' hints."""
    # 'users' is a real field but NOT in our probe list; probing 'user' should
    # leak it via the suggestion oracle.
    app = create_app(suggestions_enabled=True, schema_fields=["users", "accounts"])
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await schema_fuzz.check(
            client, fuzz_rate=0, wordlist=["user", "account"]
        )
        assert len(findings) == 1
        recovered = set(findings[0]["reconstructed_fields"])
        # Suggestions surfaced the real names.
        assert "users" in recovered
        assert "accounts" in recovered
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_sensitive_field_escalates_to_medium():
    """Recovering an admin/secret field raises severity to MEDIUM."""
    app = create_app(suggestions_enabled=False, schema_fields=["adminUsers", "user"])
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await schema_fuzz.check(
            client, fuzz_rate=0, wordlist=["adminUsers", "user"]
        )
        assert len(findings) == 1
        f = findings[0]
        assert f["severity"] == "MEDIUM"
        assert "adminUsers" in f["sensitive_fields"]
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_low_severity_when_no_sensitive_fields():
    """Only benign fields recovered → LOW severity."""
    app = create_app(suggestions_enabled=False, schema_fields=["user", "product"])
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await schema_fuzz.check(
            client, fuzz_rate=0, wordlist=["user", "product"]
        )
        assert len(findings) == 1
        assert findings[0]["severity"] == "LOW"
        assert findings[0]["sensitive_fields"] == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_finding_includes_evidence_and_probe_count():
    app = create_app(suggestions_enabled=False, schema_fields=["user"])
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await schema_fuzz.check(
            client, fuzz_rate=0, wordlist=["user", "missing"]
        )
        f = findings[0]
        assert f["probes_sent"] >= 2
        assert isinstance(f["evidence"], str) and f["evidence"]
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_empty_wordlist_produces_no_finding():
    app = create_app(schema_fields=["user"])
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await schema_fuzz.check(client, fuzz_rate=0, wordlist=[])
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_fuzz_rate_throttles_requests():
    """A low fuzz-rate should measurably slow probing (delay between probes)."""
    app = create_app(suggestions_enabled=False, schema_fields=["user"])
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        start = time.monotonic()
        # 3 probes at 20 rps → ~2 inter-probe delays of 0.05s ≈ >=0.08s.
        await schema_fuzz.check(
            client, fuzz_rate=20.0, wordlist=["a", "b", "c"]
        )
        elapsed = time.monotonic() - start
        assert elapsed >= 0.08
    finally:
        server.should_exit = True
