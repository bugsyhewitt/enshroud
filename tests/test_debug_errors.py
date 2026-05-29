"""Tests for the verbose / development-mode error disclosure check."""
from __future__ import annotations

import socket
import threading
import time

import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from enshroud.checks import debug_errors
from enshroud.client import GraphQLClient


# ── unit tests for the pure detection heuristic ───────────────────────────────


def test_scan_errors_detects_node_stack_trace():
    body = {
        "errors": [
            {
                "message": (
                    "Cannot read property 'id' of undefined\n"
                    "    at resolveUser (/srv/app/resolvers/user.js:42:17)\n"
                    "    at executeField (/srv/app/node_modules/graphql/execute.js:1:1)"
                )
            }
        ]
    }
    signals = debug_errors.scan_errors(body)
    assert "stack_trace" in signals
    assert "source_file_path" in signals


def test_scan_errors_detects_python_traceback():
    body = {
        "errors": [
            {
                "message": (
                    "Traceback (most recent call last):\n"
                    '  File "/home/app/schema.py", line 88, in resolve_user\n'
                    "KeyError: 'id'"
                )
            }
        ]
    }
    signals = debug_errors.scan_errors(body)
    assert "stack_trace" in signals
    assert "source_file_path" in signals


def test_scan_errors_detects_extension_stacktrace():
    body = {
        "errors": [
            {
                "message": "Unexpected error.",
                "extensions": {
                    "code": "INTERNAL_SERVER_ERROR",
                    "stacktrace": [
                        "Error: boom",
                        "    at Object.<anonymous> (/app/index.js:1:1)",
                    ],
                },
            }
        ]
    }
    signals = debug_errors.scan_errors(body)
    assert "extension:stacktrace" in signals


def test_scan_errors_detects_sql_fragment():
    body = {
        "errors": [
            {
                "message": (
                    'syntax error at or near "FROM" '
                    "in SELECT id, email FROM users WHERE id = $1"
                )
            }
        ]
    }
    signals = debug_errors.scan_errors(body)
    assert "sql_fragment" in signals


def test_scan_errors_detects_internal_host():
    body = {
        "errors": [
            {
                "message": (
                    "could not connect to "
                    "postgres://admin@10.0.4.12:5432/prod"
                )
            }
        ]
    }
    signals = debug_errors.scan_errors(body)
    assert "internal_host" in signals


def test_scan_errors_detects_framework_version():
    body = {
        "errors": [
            {"message": "graphql-core 3.2.3 could not parse the document"}
        ]
    }
    signals = debug_errors.scan_errors(body)
    assert "framework_version" in signals


def test_scan_errors_clean_validation_error_is_silent():
    """A normalised validation error must not be flagged."""
    body = {
        "errors": [
            {
                "message": (
                    "Cannot query field \"foo\" on type \"Query\"."
                ),
                "locations": [{"line": 1, "column": 3}],
            }
        ]
    }
    assert debug_errors.scan_errors(body) == []


def test_scan_errors_did_you_mean_is_silent():
    """Field-suggestion text belongs to field_oracle, not here — no overlap."""
    body = {
        "errors": [
            {"message": 'Cannot query field "usr". Did you mean "user"?'}
        ]
    }
    assert debug_errors.scan_errors(body) == []


def test_scan_errors_handles_batched_array_body():
    body = [
        {"data": {"__typename": "Query"}},
        {"errors": [{"message": "boom at handler (/srv/app/a.js:1:2)"}]},
    ]
    signals = debug_errors.scan_errors(body)
    assert "stack_trace" in signals


def test_scan_errors_handles_no_errors():
    assert debug_errors.scan_errors({"data": {"__typename": "Query"}}) == []
    assert debug_errors.scan_errors({}) == []
    assert debug_errors.scan_errors([]) == []


def test_severity_high_value_signals_are_medium():
    assert debug_errors._severity_for(["stack_trace"]) == "MEDIUM"
    assert debug_errors._severity_for(["source_file_path"]) == "MEDIUM"
    assert debug_errors._severity_for(["extension:stacktrace"]) == "MEDIUM"
    assert debug_errors._severity_for(["sql_fragment"]) == "MEDIUM"


def test_severity_version_only_is_low():
    assert debug_errors._severity_for(["framework_version"]) == "LOW"


# ── integration tests against a tiny mock endpoint ────────────────────────────


def _start(app) -> tuple[str, uvicorn.Server]:
    host = "127.0.0.1"
    s = socket.socket()
    s.bind((host, 0))
    port = s.getsockname()[1]
    s.close()
    config = uvicorn.Config(app, host=host, port=port, log_level="error")
    server = uvicorn.Server(config)
    threading.Thread(target=server.run, daemon=True).start()
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            c = socket.create_connection((host, port), timeout=0.5)
            c.close()
            break
        except OSError:
            time.sleep(0.05)
    return f"http://{host}:{port}/graphql", server


def _make_app(*, debug: bool) -> FastAPI:
    app = FastAPI()

    @app.post("/graphql")
    async def graphql(request: Request) -> JSONResponse:  # noqa: ANN001
        await request.body()  # consume; we always answer with a syntax error
        if debug:
            return JSONResponse(
                content={
                    "errors": [
                        {
                            "message": "Syntax Error: Expected Name, found <EOF>.",
                            "extensions": {
                                "code": "GRAPHQL_PARSE_FAILED",
                                "stacktrace": [
                                    "GraphQLError: Syntax Error",
                                    "    at syntaxError (/srv/app/node_modules/"
                                    "graphql/error/syntaxError.js:15:10)",
                                ],
                            },
                        }
                    ]
                }
            )
        # Production-safe: normalised message, no internals.
        return JSONResponse(
            content={
                "errors": [
                    {"message": "Syntax Error: Expected Name, found <EOF>."}
                ]
            }
        )

    return app


@pytest.mark.asyncio
async def test_check_flags_debug_endpoint():
    url, server = _start(_make_app(debug=True))
    try:
        findings = await debug_errors.check(GraphQLClient(url))
        assert len(findings) == 1
        f = findings[0]
        assert f["category"] == "verbose_error_disclosure"
        assert f["severity"] == "MEDIUM"
        assert "extension:stacktrace" in f["leaked_signals"]
        assert "evidence" in f and f["evidence"]
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_check_silent_on_production_endpoint():
    url, server = _start(_make_app(debug=False))
    try:
        findings = await debug_errors.check(GraphQLClient(url))
        assert findings == []
    finally:
        server.should_exit = True


@pytest.mark.asyncio
async def test_check_silent_against_clean_mock_server(mock_url):
    """The shared mock server returns normalised errors → no false positive."""
    findings = await debug_errors.check(GraphQLClient(mock_url))
    assert findings == []


def test_probe_query_is_read_only_and_malformed():
    # Read-only: only references __typename, no mutation keyword.
    assert "mutation" not in debug_errors.PROBE_QUERY.lower()
    # Malformed: an unbalanced brace forces the parser error path.
    assert debug_errors.PROBE_QUERY.count("{") != debug_errors.PROBE_QUERY.count("}")
