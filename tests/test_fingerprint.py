"""Tests for the GraphQL engine fingerprinting check."""
from __future__ import annotations

import json
import socket
import threading
import time
from contextlib import contextmanager

import pytest
import uvicorn

from enshroud.checks import fingerprint
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


# --- signature loading & matching (pure-unit, no network) ------------------


def test_signatures_load_and_are_well_formed():
    sigs = fingerprint.load_signatures()
    assert sigs.get("engines"), "expected bundled engine signatures to load"
    names = {e["name"] for e in sigs["engines"]}
    # The ranking requires at least these engines to ship.
    for required in ["apollo", "graphene", "strawberry", "hasura", "wpgraphql"]:
        assert required in names, f"missing required engine signature: {required}"
    for engine in sigs["engines"]:
        assert "name" in engine
        assert "match" in engine
        assert "known_default_insecure_behaviors" in engine


def test_identify_engine_matches_hasura_header_corpus():
    sigs = fingerprint.load_signatures()
    corpus = "HTTP 200\nx-hasura-role: anonymous\n{\"errors\":[{\"message\":\"boom\"}]}"
    engine = fingerprint.identify_engine(corpus, sigs)
    assert engine is not None
    assert engine["name"] == "hasura"


def test_identify_engine_returns_none_for_unknown():
    sigs = fingerprint.load_signatures()
    corpus = "HTTP 200\ncontent-type: application/json\n{\"data\":{\"__typename\":\"Query\"}}"
    engine = fingerprint.identify_engine(corpus, sigs)
    assert engine is None


def test_engine_matches_requires_a_pattern():
    # An engine with empty match config never matches.
    assert fingerprint._engine_matches("anything", {"match": {"all": [], "any": []}}) is False


# --- end-to-end against the mock server ------------------------------------


@pytest.mark.asyncio
async def test_fingerprint_apollo_identified():
    app = create_app(engine="apollo")
    with running_server(app) as url:
        client = GraphQLClient(url)
        findings = await fingerprint.check(client)

    assert len(findings) == 1
    f = findings[0]
    assert f["category"] == "engine_identified"
    assert f["severity"] == "INFO"
    assert f["engine_name"] == "apollo"
    assert f["known_default_insecure_behaviors"], "expected catalogued behaviours"
    # Evidence is JSON with the matched engine + the probes that were sent.
    ev = json.loads(f["evidence"])
    assert ev["matched_engine"] == "apollo"
    assert ev["probes"], "expected probe evidence to be recorded"


@pytest.mark.asyncio
async def test_fingerprint_hasura_identified_via_header():
    app = create_app(engine="hasura")
    with running_server(app) as url:
        client = GraphQLClient(url)
        findings = await fingerprint.check(client)

    assert len(findings) == 1
    assert findings[0]["engine_name"] == "hasura"


@pytest.mark.asyncio
async def test_fingerprint_wpgraphql_identified():
    app = create_app(engine="wpgraphql")
    with running_server(app) as url:
        client = GraphQLClient(url)
        findings = await fingerprint.check(client)

    assert len(findings) == 1
    assert findings[0]["engine_name"] == "wpgraphql"


@pytest.mark.asyncio
async def test_fingerprint_unknown_engine_no_finding():
    # Default mock server returns generic data with no engine-identifying
    # error wording or headers -> no false-positive fingerprint.
    app = create_app(
        engine=None,
        introspection_enabled=False,
        suggestions_enabled=False,
        cors_misconfigured=False,
    )
    with running_server(app) as url:
        client = GraphQLClient(url)
        findings = await fingerprint.check(client)

    assert findings == []


@pytest.mark.asyncio
async def test_fingerprint_emits_at_most_one_finding():
    app = create_app(engine="graphene")
    with running_server(app) as url:
        client = GraphQLClient(url)
        findings = await fingerprint.check(client)
    assert len(findings) <= 1
    if findings:
        assert findings[0]["engine_name"] == "graphene"
