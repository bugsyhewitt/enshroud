"""Tests for the cookie-posture check (POST_V01 #10)."""
from __future__ import annotations

import json
import socket
import threading
import time

import pytest
import uvicorn

from enshroud.checks import cookie_posture
from enshroud.client import GraphQLClient
from tests.fixtures.mock_graphql_server import create_app


def _start_server(app) -> tuple[str, int, uvicorn.Server]:
    host = "127.0.0.1"
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
    return host, port, server


# ── Unit tests for the attribute parser / evaluator ─────────────────────────


def test_parse_attributes_extracts_name_and_flags():
    name, attrs = cookie_posture._parse_attributes(
        "sid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"
    )
    assert name == "sid"
    assert "secure" in attrs
    assert "httponly" in attrs
    assert attrs["samesite"] == "lax"
    assert attrs["path"] == "/"


def test_evaluate_hardened_cookie_is_clean():
    record = cookie_posture._evaluate_cookie(
        "sid=abc; Path=/; Secure; HttpOnly; SameSite=Strict"
    )
    assert record is None


def test_evaluate_samesite_none_is_flagged():
    record = cookie_posture._evaluate_cookie(
        "sid=abc; Path=/; Secure; HttpOnly; SameSite=None"
    )
    assert record is not None
    assert record["name"] == "sid"
    assert any("SameSite=None" in issue for issue in record["issues"])


def test_evaluate_missing_samesite_secure_httponly():
    record = cookie_posture._evaluate_cookie("sid=abc; Path=/")
    assert record is not None
    joined = " ".join(record["issues"])
    assert "SameSite" in joined
    assert "Secure" in joined
    assert "HttpOnly" in joined


# ── Integration tests against a live server ─────────────────────────────────


@pytest.mark.asyncio
async def test_cookie_posture_weak_cookie_fires_medium():
    app = create_app(set_cookies=["session=xyz; Path=/; SameSite=None"])
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await cookie_posture.check(client)
        assert len(findings) == 1
        finding = findings[0]
        assert finding["category"] == "insecure_cookie_posture"
        assert finding["severity"] == "MEDIUM"
        evidence = json.loads(finding["evidence"])
        assert "session" in evidence["weaknesses"]
        # SameSite=None and missing Secure/HttpOnly should all be reported.
        issues = " ".join(evidence["weaknesses"]["session"])
        assert "SameSite=None" in issues
        assert "Secure" in issues
        assert "HttpOnly" in issues
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_cookie_posture_hardened_cookie_no_finding():
    app = create_app(
        set_cookies=["session=xyz; Path=/; Secure; HttpOnly; SameSite=Lax"]
    )
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await cookie_posture.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_cookie_posture_no_cookies_no_finding():
    app = create_app(set_cookies=None)
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await cookie_posture.check(client)
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_cookie_posture_evaluates_multiple_cookies():
    app = create_app(
        set_cookies=[
            "session=xyz; Path=/; Secure; HttpOnly; SameSite=Strict",  # clean
            "tracker=t1; Path=/",  # weak
        ]
    )
    host, port, server = _start_server(app)
    try:
        url = f"http://{host}:{port}/graphql"
        client = GraphQLClient(url)
        findings = await cookie_posture.check(client)
        assert len(findings) == 1
        evidence = json.loads(findings[0]["evidence"])
        # Only the weak cookie is reported; the hardened one is silent.
        assert "tracker" in evidence["weaknesses"]
        assert "session" not in evidence["weaknesses"]
    finally:
        server.should_exit = True


def test_cookie_posture_in_all_checks():
    from enshroud.cli import ALL_CHECKS, VALID_CHECKS, parse_checks

    assert "cookie-posture" in ALL_CHECKS
    assert "cookie-posture" in VALID_CHECKS
    assert "cookie-posture" in parse_checks("all")
    assert parse_checks("cookie-posture") == ["cookie-posture"]
