"""Tests for the schema-export (InQL/Voyager artifact + argument inference) check.

Covers packet §11 criterion 2 (reconstruct schema with introspection disabled,
emit InQL-compatible JSON) and Appendix D (argument inference):
  * reconstructs query fields from the suggestion oracle and renders a standard
    introspection-result JSON document
  * recovers argument names via the argument-suggestion oracle
  * writes the artifact to --schema-out when given
  * degrades to no finding when the oracle is silent
  * the emitted JSON has the canonical ``data.__schema`` shape InQL/Voyager parse
"""
from __future__ import annotations

import json
import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import schema_export
from enshroud.client import GraphQLClient
from tests.fixtures.mock_graphql_server import create_app


def _start_server(app, host: str = "127.0.0.1"):
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


# ── unit tests ──────────────────────────────────────────────────────────────────

def test_extract_arg_suggestions_quoted():
    msg = 'Unknown argument "idd" on field "Query.user". Did you mean "id"?'
    assert schema_export._extract_arg_suggestions(msg) == ["id"]


def test_extract_arg_suggestions_none_for_field_error():
    # A field-suggestion message must NOT be parsed as an argument suggestion.
    msg = 'Cannot query field "usr" on type "Query". Did you mean "user"?'
    assert schema_export._extract_arg_suggestions(msg) == []


def test_build_artifact_is_valid_introspection_shape():
    art = schema_export.build_introspection_artifact(
        ["user", "users"], {"user": ["id"]}
    )
    schema = art["data"]["__schema"]
    assert schema["queryType"] == {"name": "Query"}
    assert isinstance(schema["types"], list)
    qtype = schema["types"][0]
    assert qtype["name"] == "Query" and qtype["kind"] == "OBJECT"
    names = {f["name"] for f in qtype["fields"]}
    assert {"user", "users"} <= names
    # The user field carries the inferred 'id' argument.
    user = next(f for f in qtype["fields"] if f["name"] == "user")
    assert [a["name"] for a in user["args"]] == ["id"]
    # Round-trips as JSON (consumable by InQL / Voyager).
    assert json.loads(json.dumps(art)) == art


# ── integration tests ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_finding_when_oracle_silent():
    app = create_app(suggestions_enabled=False, schema_fields=["wholly", "unrelated"])
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await schema_export.check(
            client, fuzz_rate=0, wordlist=["nope", "missing"], infer_args=False
        )
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_reconstructs_via_data_and_emits_artifact():
    """Real fields present in the wordlist are confirmed (data path) and exported."""
    app = create_app(suggestions_enabled=False, schema_fields=["user", "account", "product"])
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await schema_export.check(
            client,
            fuzz_rate=0,
            wordlist=["user", "account", "product", "zzznope"],
            infer_args=False,
        )
        assert len(findings) == 1
        f = findings[0]
        assert f["category"] == "schema_artifact_reconstructed"
        assert f["owasp"] == ["API3:2023"]
        recovered = set(f["reconstructed_fields"])
        assert {"user", "account", "product"} <= recovered
        assert "zzznope" not in recovered
        # The artifact is a standard introspection result.
        art = f["schema_artifact"]
        assert "__schema" in art["data"]
        field_names = {fl["name"] for fl in art["data"]["__schema"]["types"][0]["fields"]}
        assert {"user", "account", "product"} <= field_names
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_reconstructs_via_suggestion_oracle():
    """Fields NOT in the wordlist are recovered from 'Did you mean' hints."""
    # 'users'/'accounts' are real but absent from the probe list; probing the
    # near-miss 'user'/'account' leaks them via the suggestion oracle.
    app = create_app(suggestions_enabled=True, schema_fields=["users", "accounts"])
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await schema_export.check(
            client, fuzz_rate=0, wordlist=["user", "account"], infer_args=False
        )
        assert len(findings) == 1
        recovered = set(findings[0]["reconstructed_fields"])
        assert "users" in recovered
        assert "accounts" in recovered
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_argument_inference_recovers_arg_names():
    # 'user' is a real field; its real arg is 'id'. arg_suggestions makes the
    # mock leak 'id' when a near-miss argument name is probed (Appendix D).
    app = create_app(
        suggestions_enabled=True,
        schema_fields=["user"],
        arg_suggestions={"user": ["id"]},
    )
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await schema_export.check(
            client, fuzz_rate=0, wordlist=["user"], infer_args=True
        )
        assert len(findings) == 1
        f = findings[0]
        assert "user" in f["field_arguments"]
        assert "id" in f["field_arguments"]["user"]
        # The inferred argument appears in the exported artifact.
        art = f["schema_artifact"]
        user = next(
            fl for fl in art["data"]["__schema"]["types"][0]["fields"]
            if fl["name"] == "user"
        )
        assert "id" in [a["name"] for a in user["args"]]
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_writes_artifact_to_file(tmp_path):
    app = create_app(suggestions_enabled=False, schema_fields=["user", "product"])
    url, server, _ = _start_server(app)
    out = tmp_path / "schema.json"
    try:
        client = GraphQLClient(url)
        findings = await schema_export.check(
            client,
            fuzz_rate=0,
            wordlist=["user", "product"],
            schema_out=str(out),
            infer_args=False,
        )
        assert len(findings) == 1
        assert findings[0]["schema_out"] == str(out)
        assert out.exists()
        on_disk = json.loads(out.read_text())
        assert "__schema" in on_disk["data"]
        names = {fl["name"] for fl in on_disk["data"]["__schema"]["types"][0]["fields"]}
        assert {"user", "product"} <= names
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_empty_wordlist_no_finding():
    app = create_app(schema_fields=["user"])
    url, server, _ = _start_server(app)
    try:
        client = GraphQLClient(url)
        findings = await schema_export.check(client, fuzz_rate=0, wordlist=[])
        assert findings == []
    finally:
        server.should_exit = True
