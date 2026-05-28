"""Tests for fingerprint-informed finding correlation (POST_V01 #2)."""
from __future__ import annotations

import socket
import threading
import time
from contextlib import contextmanager

import pytest
import uvicorn

from enshroud.cli import run_checks
from enshroud.client import GraphQLClient
from enshroud.correlate import correlate_findings
from enshroud.output import render_h1md
from tests.fixtures.mock_graphql_server import create_app


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@contextmanager
def running_server(app):
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


# --- pure-unit correlation logic (no network) ------------------------------


def _engine_finding(name="graphene", behaviors=None):
    return {
        "category": "engine_identified",
        "severity": "INFO",
        "engine_name": name,
        "engine_display_name": "Graphene (Python)",
        "known_default_insecure_behaviors": behaviors
        or [
            "Introspection enabled by default, not gated on environment",
            "Field suggestions enabled by default, leaking schema names",
        ],
    }


def test_no_engine_finding_is_noop():
    findings = [
        {"category": "introspection_enabled", "severity": "MEDIUM", "impact": "x"}
    ]
    out = correlate_findings(findings)
    assert len(out) == 1
    assert "engine_context" not in out[0]


def test_unknown_engine_is_noop():
    engine = _engine_finding(name=None)
    findings = [engine, {"category": "introspection_enabled", "impact": "x"}]
    out = correlate_findings(findings)
    assert all("engine_context" not in f for f in out)


def test_introspection_correlates_to_graphene_default():
    findings = [
        _engine_finding(),
        {
            "category": "introspection_enabled",
            "severity": "MEDIUM",
            "impact": "An attacker can enumerate the schema.",
        },
    ]
    out = correlate_findings(findings)
    intro = next(f for f in out if f["category"] == "introspection_enabled")
    ctx = intro["engine_context"]
    assert ctx["engine_name"] == "graphene"
    assert ctx["confidence"] == "expected-default"
    assert any("introspection" in b.lower() for b in ctx["matched_behaviors"])
    # Impact text is extended, not replaced.
    assert intro["impact"].startswith("An attacker can enumerate the schema.")
    assert "Engine correlation" in intro["impact"]


def test_field_oracle_correlates_via_suggestions_behavior():
    findings = [
        _engine_finding(),
        {"category": "field_suggestion_oracle", "severity": "LOW", "impact": "y"},
    ]
    out = correlate_findings(findings)
    oracle = next(f for f in out if f["category"] == "field_suggestion_oracle")
    assert "engine_context" in oracle
    assert oracle["engine_context"]["confidence"] == "expected-default"


def test_uncorrelated_category_is_left_untouched():
    findings = [
        _engine_finding(),
        # Hasura-only behaviour set has nothing about CORS.
        {"category": "cors_misconfiguration", "severity": "HIGH", "impact": "z"},
    ]
    out = correlate_findings(findings)
    cors = next(f for f in out if f["category"] == "cors_misconfiguration")
    assert "engine_context" not in cors
    assert cors["impact"] == "z"


def test_engine_identified_finding_itself_not_annotated():
    findings = [_engine_finding()]
    out = correlate_findings(findings)
    assert "engine_context" not in out[0]


def test_correlation_does_not_mutate_input():
    original = {
        "category": "introspection_enabled",
        "severity": "MEDIUM",
        "impact": "orig",
    }
    findings = [_engine_finding(), original]
    correlate_findings(findings)
    # Original object is untouched (annotation happens on a copy).
    assert "engine_context" not in original
    assert original["impact"] == "orig"


def test_apq_unrestricted_registration_correlates_to_apollo():
    engine = _engine_finding(
        name="apollo",
        behaviors=[
            "APQ (automatic persisted queries) may allow unauthenticated cache population"
        ],
    )
    engine["engine_name"] = "apollo"
    findings = [
        engine,
        {"category": "apq_unrestricted_registration", "severity": "MEDIUM", "impact": "a"},
    ]
    out = correlate_findings(findings)
    apq = next(f for f in out if f["category"] == "apq_unrestricted_registration")
    assert "engine_context" in apq


# --- output rendering -------------------------------------------------------


def test_h1md_renders_engine_correlation_section():
    finding = {
        "category": "introspection_enabled",
        "severity": "MEDIUM",
        "title": "Introspection Enabled",
        "impact": "base impact",
        "engine_context": {
            "engine_name": "graphene",
            "engine_display_name": "Graphene (Python)",
            "confidence": "expected-default",
            "matched_behaviors": ["Introspection enabled by default"],
            "note": "expected default note",
        },
    }
    md = render_h1md([finding])
    assert "## Engine Correlation" in md
    assert "Graphene (Python)" in md
    assert "expected-default" in md
    assert "Introspection enabled by default" in md


def test_h1md_without_engine_context_has_no_correlation_section():
    finding = {
        "category": "introspection_enabled",
        "severity": "MEDIUM",
        "title": "Introspection Enabled",
        "impact": "base impact",
    }
    md = render_h1md([finding])
    assert "## Engine Correlation" not in md


# --- end-to-end through run_checks ------------------------------------------


@pytest.mark.asyncio
async def test_run_checks_correlates_introspection_with_graphene():
    # Graphene engine + introspection enabled: the introspection finding should
    # be annotated with engine context after correlation.
    app = create_app(engine="graphene", introspection_enabled=True)
    with running_server(app) as url:
        client = GraphQLClient(url)
        findings = await run_checks(["fingerprint", "introspection"], client)

    intro = [f for f in findings if f["category"] == "introspection_enabled"]
    assert intro, "expected an introspection finding"
    assert "engine_context" in intro[0]
    assert intro[0]["engine_context"]["engine_name"] == "graphene"


@pytest.mark.asyncio
async def test_run_checks_no_fingerprint_no_correlation():
    # Without the fingerprint check, no engine context is attached.
    app = create_app(engine="graphene", introspection_enabled=True)
    with running_server(app) as url:
        client = GraphQLClient(url)
        findings = await run_checks(["introspection"], client)

    intro = [f for f in findings if f["category"] == "introspection_enabled"]
    assert intro
    assert "engine_context" not in intro[0]
