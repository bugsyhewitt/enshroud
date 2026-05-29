"""Verbose / development-mode error disclosure check.

Most GraphQL engines ship a "development" error mode that, when accidentally
left enabled in production, attaches a full server-side stack trace, source
file paths, framework version strings, and the underlying exception class to
every error response. Apollo Server and graphql-js put this under
``errors[].extensions.stacktrace`` / ``extensions.exception``; graphene,
strawberry, and Mercurius leak it inline in the error ``message``; many WAFs
and ORMs surface raw SQL or internal hostnames the same way.

This is a distinct, frequently-disclosed bug-bounty finding (OWASP GraphQL
cheatsheet: *Disable Introspection & Field Suggestions & Stack Traces*; OWASP
API Security *Improper Error Handling*). It is NOT the same as:

  * ``fingerprint`` — which matches error *wording* to identify the engine but
    treats verbose errors as recon, not as a vulnerability in their own right;
  * ``field_oracle`` — which extracts "Did you mean" field-name suggestions only.

What this check flags is the leakage of *internal implementation detail* —
stack frames, absolute file paths, exception types, framework versions, SQL,
and internal network identifiers — which tells an attacker exactly which code
path, library version, and infrastructure they are hitting and often hands them
ready-made exploitation primitives (path traversal targets, known-CVE versions,
SQL injection confirmation).

Detection is read-only and side-effect free: the probe sends a syntactically
broken query that forces the server through its error-formatting path, then
scans the structured error objects for disclosure signals. A server that
returns a clean, normalised error (just a message, no extensions, no internals)
produces no finding.
"""
from __future__ import annotations

import json
import re
from typing import Any

from enshroud.client import GraphQLClient

# A deliberately malformed query. The unterminated/garbage selection forces the
# parser/validator down its error path on essentially every engine, which is
# where development-mode formatters attach their stack traces.
PROBE_QUERY = "query { __typename "  # missing closing brace -> syntax error

# How much of the raw response body to retain as evidence.
EVIDENCE_BODY_LEN = 800

# ── disclosure signal patterns ────────────────────────────────────────────────
# Each tuple is (signal_name, compiled_regex). A match means the error response
# leaked that class of internal detail. Patterns are intentionally specific to
# avoid firing on ordinary, well-behaved GraphQL validation messages.

_SIGNAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Absolute source file paths: POSIX (/srv/app/schema.js:42) or Windows.
    (
        "source_file_path",
        re.compile(
            r"(?:/(?:home|srv|usr|opt|var|app|root)/[\w./-]+"
            r"|[A-Za-z]:\\[\w\\./ -]+)"
            r"\.(?:js|ts|py|rb|go|java|php|cs)\b"
        ),
    ),
    # Stack-trace frame markers from common runtimes.
    (
        "stack_trace",
        re.compile(
            r"(?:\bat\s+[\w.$<>]+\s*\([^)]*:\d+:\d+\)"      # Node: at fn (file:1:2)
            r"|File \"[^\"]+\", line \d+"                     # Python traceback
            r"|Traceback \(most recent call last\)"           # Python header
            r"|\bfrom [\w./-]+\.rb:\d+:in "                   # Ruby
            r"|goroutine \d+ \[)"                             # Go
        ),
    ),
    # Exception / error class names that should never reach a client.
    (
        "exception_class",
        re.compile(
            r"\b(?:[A-Za-z_][\w]*(?:Error|Exception)"
            r"|java\.[\w.]+Exception"
            r"|System\.[\w.]+Exception)\b"
            r"(?=:|\s+at\s|\s*\n|\s*\()"
        ),
    ),
    # Raw SQL surfacing through an ORM/db driver error.
    (
        "sql_fragment",
        re.compile(
            r"\b(?:SELECT\s+.+\s+FROM\s+\w"
            r"|INSERT\s+INTO\s+\w"
            r"|UPDATE\s+\w+\s+SET\s"
            r"|syntax error at or near"
            r"|SQLSTATE\[)",
            re.IGNORECASE,
        ),
    ),
    # Internal hostnames / private-range IPs / DB connection strings.
    (
        "internal_host",
        re.compile(
            r"(?:\b(?:postgres|postgresql|mysql|mongodb|redis|amqp)://[^\s\"']+"
            r"|\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}"
            r"|\b[\w-]+\.(?:internal|local|svc\.cluster\.local)\b)"
        ),
    ),
    # Framework / library version strings (e.g. "graphql-core 3.2.3").
    (
        "framework_version",
        re.compile(
            r"\b(?:graphql(?:-core|-js|-ruby|-yoga)?|apollo|graphene|strawberry"
            r"|mercurius|hasura|express|fastapi|django|rails)"
            r"[\s/@v-]+\d+\.\d+(?:\.\d+)?",
            re.IGNORECASE,
        ),
    ),
]

# Structured-extension keys that engines populate only in development mode.
_DEBUG_EXTENSION_KEYS = ("stacktrace", "exception", "debug", "serviceName")


def _scan_text(text: str) -> list[str]:
    """Return the names of every disclosure signal found in *text*."""
    signals: list[str] = []
    for name, pattern in _SIGNAL_PATTERNS:
        if pattern.search(text):
            signals.append(name)
    return signals


def _scan_extensions(extensions: Any) -> list[str]:
    """Return signals derived from a GraphQL error's ``extensions`` object."""
    signals: list[str] = []
    if not isinstance(extensions, dict):
        return signals
    for key in _DEBUG_EXTENSION_KEYS:
        if key in extensions and extensions[key]:
            signals.append(f"extension:{key}")
    return signals


def scan_errors(body: Any) -> list[str]:
    """Scan a parsed GraphQL response body for verbose-error disclosure signals.

    Pure function (no I/O) so the detection heuristic is unit-testable. Accepts
    the already-decoded JSON body (a dict, or a list for batched responses) and
    returns the sorted, de-duplicated list of signal names found across every
    error object's ``message`` and ``extensions``.
    """
    errors: list[Any] = []
    if isinstance(body, dict):
        errors = body.get("errors") or []
    elif isinstance(body, list):
        for item in body:
            if isinstance(item, dict):
                errors.extend(item.get("errors") or [])

    found: set[str] = set()
    for err in errors:
        if not isinstance(err, dict):
            continue
        message = err.get("message")
        if isinstance(message, str):
            found.update(_scan_text(message))
        found.update(_scan_extensions(err.get("extensions")))
    return sorted(found)


def _severity_for(signals: list[str]) -> str:
    """Map the set of leaked signals to a severity.

    A bare framework-version string is informative; stack traces, source paths,
    SQL, internal hosts, or a populated debug extension are materially more
    serious because they directly aid exploitation.
    """
    high_value = {
        "stack_trace",
        "source_file_path",
        "sql_fragment",
        "internal_host",
        "extension:stacktrace",
        "extension:exception",
        "extension:debug",
    }
    if any(s in high_value for s in signals):
        return "MEDIUM"
    return "LOW"


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Check whether the endpoint leaks development-mode error detail."""
    findings: list[dict[str, Any]] = []

    try:
        resp = await client.post_raw(PROBE_QUERY)
    except Exception:
        return findings

    body_text = resp.text or ""
    try:
        body = resp.json()
    except (json.JSONDecodeError, ValueError):
        return findings

    signals = scan_errors(body)
    if not signals:
        return findings

    severity = _severity_for(signals)
    findings.append(
        {
            "category": "verbose_error_disclosure",
            "severity": severity,
            "title": "GraphQL Verbose / Development-Mode Error Disclosure",
            "leaked_signals": signals,
            "evidence": body_text[:EVIDENCE_BODY_LEN],
            "description": (
                "A malformed query elicited an error response that leaked "
                "internal server detail rather than a normalised error message. "
                "The response exposed: "
                + ", ".join(signals)
                + ". This indicates the GraphQL engine is running in a "
                "development/debug error mode in production, attaching stack "
                "traces, source paths, exception classes, framework versions, "
                "SQL, or internal host identifiers to client-facing errors."
            ),
            "reproduction": (
                'Send a syntactically invalid query such as `{"query": "'
                + PROBE_QUERY.replace('"', '\\"')
                + '"}` and inspect the `errors[].message` and '
                "`errors[].extensions` of the response for stack traces, "
                "absolute file paths, exception class names, or a populated "
                "`extensions.stacktrace` / `extensions.exception` object."
            ),
            "impact": (
                "Verbose errors hand an attacker a map of the server internals: "
                "exact library versions to look up known CVEs, source file paths "
                "for path-traversal and source-disclosure targets, confirmation "
                "of SQL injection via leaked queries, and internal hostnames/IPs "
                "for lateral movement and SSRF targeting."
            ),
            "remediation": (
                "Disable development/debug error formatting in production. Apollo "
                "Server: do not set `includeStacktraceInErrorResponses: true` (and "
                "ensure NODE_ENV=production). graphql-js: install a custom "
                "`formatError` that strips `extensions.stacktrace`/`exception`. "
                "Graphene/Strawberry/Django: set `DEBUG = False`. Return a "
                "generic, static error message to clients and log the detail "
                "server-side only."
            ),
        }
    )

    return findings
