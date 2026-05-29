"""SQL / NoSQL injection probing via GraphQL argument fuzzing.

This is the original niche of GraphQLmap (swisskyrepo), enshroud's predecessor.
The check enumerates query and mutation arguments via introspection, injects a
small list of classic SQL/NoSQL payloads into scalar String/Int arguments, and
flags any argument whose response surfaces a known DBMS error string.

Because it actively sends crafted payloads to the target, this check is opt-in:
it only runs when `--checks injection` is requested explicitly and is never part
of `--checks all`. Time-based (blind) probing is additionally gated behind the
`--active` flag, off by default, because it deliberately tries to make the
backend sleep.

Detection only — enshroud never attempts exploitation or data extraction. It
reports the argument name and the payload that triggered an error so a hunter
can verify and report manually.

References:
  * HackerOne report #435066 — SQLi in a GraphQL endpoint
  * OWASP WSTG v4.2 section 4.12.1 — Testing GraphQL
  * Escape.tech — "SQL Injection in GraphQL"
  * GraphQLmap (swisskyrepo) — predecessor tool
"""
from __future__ import annotations

import re
import time
from typing import Any

from enshroud.client import GraphQLClient

# Introspection query that enumerates query + mutation fields and their scalar
# argument types. We only need names and the (possibly wrapped) scalar type.
_ARG_INTROSPECTION = """
{
  __schema {
    queryType { name fields { name args { name type { kind name ofType { kind name } } } } }
    mutationType { name fields { name args { name type { kind name ofType { kind name } } } } }
  }
}
""".strip()

# Error-based payloads. Kept deliberately small to avoid a false-positive storm
# and to keep the request count bounded. Each is a string that, reflected into a
# vulnerable resolver, tends to break SQL/NoSQL syntax and surface a DBMS error.
_ERROR_PAYLOADS: list[str] = [
    "'",
    '"',
    "1 OR 1=1",
    "1' OR '1'='1",
    "\\",
    '{"$gt": ""}',  # NoSQL operator injection (Mongo-style)
]

# A single time-based payload, only sent when --active is passed. We measure the
# response-time delta versus a clean baseline request.
_TIME_PAYLOAD = "1'; SELECT pg_sleep(3)--"
_TIME_DELAY_SECONDS = 3.0
# A zero-delay control payload structurally identical to _TIME_PAYLOAD but asking
# the database to sleep for 0 seconds. A truly injectable argument responds fast
# to this and slow to _TIME_PAYLOAD; an endpoint that is simply slow for *every*
# request responds slow to both. Comparing the two payloads against each other
# (not just against a clean baseline) is what rules out the false positive.
_TIME_CONTROL_PAYLOAD = "1'; SELECT pg_sleep(0)--"
# Require the slow response to exceed the baseline by at least this margin before
# we call it a time-based signal, to absorb jitter.
_TIME_MARGIN_SECONDS = 2.0
# The slow payload must also beat the zero-delay control by at least this margin.
# This is the differential that proves the delay is payload-controlled rather
# than an endpoint that is uniformly slow (busy backend, tarpit, network jitter).
_TIME_CONTROL_MARGIN_SECONDS = 2.0

# Known DBMS error fingerprints (regex, case-insensitive). Drawn from sqlmap's
# error-detection corpus, trimmed to the highest-signal patterns per engine.
_DBMS_ERROR_PATTERNS: dict[str, list[str]] = {
    "MySQL": [
        r"you have an error in your sql syntax",
        r"warning:\s*mysql",
        r"valid mysql result",
        r"mysqli?_",
        r"unknown column '[^']+' in 'field list'",
    ],
    "PostgreSQL": [
        r"pg_query\(\)",
        r"pg_exec\(\)",
        r"postgresql.*error",
        r"unterminated quoted string at or near",
        r"syntax error at or near",
    ],
    "MSSQL": [
        r"microsoft sql server",
        r"odbc sql server driver",
        r"unclosed quotation mark after the character string",
        r"incorrect syntax near",
    ],
    "SQLite": [
        r"sqlite/jdbcdriver",
        r"sqlite3?::",
        r"sqlite_error",
        r"unrecognized token:",
        r"no such column",
    ],
    "Oracle": [
        r"ora-\d{5}",
        r"oracle error",
        r"quoted string not properly terminated",
    ],
    "MongoDB": [
        r"mongodb",
        r"mongoerror",
        r"\$where",
        r"bson",
        r"unknown operator: \$",
    ],
}


def _scalar_name(type_obj: dict[str, Any] | None) -> str | None:
    """Resolve a (possibly NON_NULL-wrapped) scalar type to its scalar name.

    Returns the scalar name (e.g. "String", "Int", "ID") or None when the type
    is not a plain scalar (lists, input objects, enums are skipped — we only
    fuzz scalar string/int-ish arguments).
    """
    if not type_obj:
        return None
    kind = type_obj.get("kind")
    name = type_obj.get("name")
    if kind == "SCALAR" and name:
        return name
    if kind == "NON_NULL":
        return _scalar_name(type_obj.get("ofType"))
    return None


def enumerate_fuzzable_args(schema: dict[str, Any]) -> list[dict[str, str]]:
    """Return a list of {operation, field, arg, scalar} entries worth fuzzing.

    Only String / ID / Int scalar arguments are returned, since those are where
    reflected SQL/NoSQL injection typically lands. Lists, enums, input objects,
    and booleans are skipped to keep the probe count low and the signal high.
    """
    fuzzable_scalars = {"String", "ID", "Int"}
    targets: list[dict[str, str]] = []

    for op_key, op_label in (("queryType", "query"), ("mutationType", "mutation")):
        op = schema.get(op_key) or {}
        for field in op.get("fields") or []:
            field_name = field.get("name")
            if not field_name:
                continue
            for arg in field.get("args") or []:
                arg_name = arg.get("name")
                scalar = _scalar_name(arg.get("type"))
                if arg_name and scalar in fuzzable_scalars:
                    targets.append(
                        {
                            "operation": op_label,
                            "field": field_name,
                            "arg": arg_name,
                            "scalar": scalar,
                        }
                    )
    return targets


def detect_dbms_error(text: str) -> str | None:
    """Return the DBMS name if `text` contains a known error fingerprint, else None."""
    if not text:
        return None
    for dbms, patterns in _DBMS_ERROR_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                return dbms
    return None


def _render_value(payload: str, scalar: str) -> str:
    """Render a payload as a GraphQL literal for the given scalar type.

    Int arguments cannot take a quoted string literal, so for Int we send the
    payload as an unquoted token (the server's parser will choke, which is itself
    the signal we want). String/ID arguments get a quoted, escaped literal.
    """
    if scalar == "Int":
        return payload
    escaped = payload.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def build_probe_query(target: dict[str, str], payload: str) -> str:
    """Build a minimal GraphQL operation that injects `payload` into one arg."""
    value = _render_value(payload, target["scalar"])
    # We request __typename as the selection set so the operation is valid for
    # object-returning fields; scalar-returning fields ignore it but most
    # GraphQL servers still parse/execute the arguments first.
    return (
        f'{target["operation"]} {{ {target["field"]}({target["arg"]}: {value}) '
        f"{{ __typename }} }}"
    )


def _response_text(resp: dict[str, Any]) -> str:
    """Flatten a GraphQL JSON response to a single searchable string."""
    import json as _json

    try:
        return _json.dumps(resp)
    except (TypeError, ValueError):
        return str(resp)


async def _send(client: GraphQLClient, query: str) -> tuple[str, float]:
    """Send a raw query, returning (response_text, elapsed_seconds).

    Uses post_raw so that non-2xx and error responses are captured rather than
    raising — injection signal frequently lives in a 200-with-errors or a 500.
    """
    start = time.monotonic()
    try:
        resp = await client.post_raw(query)
        elapsed = time.monotonic() - start
        return resp.text or "", elapsed
    except Exception:
        return "", time.monotonic() - start


def _error_finding(target: dict[str, str], payload: str, dbms: str, evidence: str) -> dict[str, Any]:
    category = (
        "nosql_injection_signal" if dbms == "MongoDB" else "sql_injection_signal"
    )
    return {
        "category": category,
        "severity": "CRITICAL",
        "title": f"Possible {dbms} Injection in {target['operation']} `{target['field']}`",
        "operation": target["operation"],
        "field": target["field"],
        "argument": target["arg"],
        "payload": payload,
        "dbms": dbms,
        "evidence": evidence[:500],
        "description": (
            f"Injecting `{payload}` into the `{target['arg']}` argument of "
            f"{target['operation']} `{target['field']}` caused the backend to "
            f"return a {dbms} error message. This strongly indicates the "
            "argument is concatenated into a database query without "
            "parameterisation, i.e. an injection vulnerability."
        ),
        "reproduction": (
            "Send the following operation and observe the DBMS error in the "
            f"response: {build_probe_query(target, payload)}"
        ),
        "impact": (
            "SQL/NoSQL injection in a GraphQL resolver typically allows reading "
            "or modifying arbitrary database records, authentication bypass, and "
            "in some configurations remote code execution. This is a CRITICAL "
            "finding. enshroud detected an error signal only — confirm and "
            "demonstrate impact manually before reporting."
        ),
        "remediation": (
            "Use parameterised queries / prepared statements in the resolver. "
            "Never interpolate GraphQL argument values directly into a database "
            "query string. For NoSQL, reject operator objects ($gt, $where, ...) "
            "in user-supplied scalar inputs."
        ),
    }


def _time_finding(
    target: dict[str, str],
    baseline: float,
    slow: float,
    control: float,
) -> dict[str, Any]:
    return {
        "category": "sql_injection_signal",
        "severity": "CRITICAL",
        "title": (
            f"Possible time-based blind SQL injection in "
            f"{target['operation']} `{target['field']}`"
        ),
        "operation": target["operation"],
        "field": target["field"],
        "argument": target["arg"],
        "payload": _TIME_PAYLOAD,
        "dbms": "unknown (time-based)",
        "evidence": (
            f"baseline={baseline:.2f}s, control(pg_sleep(0))={control:.2f}s, "
            f"payload(pg_sleep({_TIME_DELAY_SECONDS:.0f}))={slow:.2f}s "
            f"(delta vs baseline {slow - baseline:.2f}s, "
            f"delta vs control {slow - control:.2f}s, "
            f"expected ~{_TIME_DELAY_SECONDS:.0f}s)"
        ),
        "description": (
            f"Injecting a time-delay payload into the `{target['arg']}` argument "
            f"of {target['operation']} `{target['field']}` made the response "
            f"take {slow:.2f}s, versus a {baseline:.2f}s clean baseline and a "
            f"{control:.2f}s zero-delay control (an identical payload asking the "
            "database to sleep for 0 seconds). The delay tracking the requested "
            "sleep duration — not a uniformly slow endpoint — indicates blind "
            "SQL injection."
        ),
        "reproduction": (
            "Compare response times between a clean request and: "
            f"{build_probe_query(target, _TIME_PAYLOAD)}"
        ),
        "impact": (
            "Blind SQL injection allows data extraction one bit at a time and is "
            "a CRITICAL finding. Confirm by varying the sleep duration before "
            "reporting."
        ),
        "remediation": (
            "Use parameterised queries / prepared statements in the resolver and "
            "never interpolate argument values into SQL."
        ),
    }


async def check(
    client: GraphQLClient,
    *,
    active: bool = False,
) -> list[dict[str, Any]]:
    """Probe scalar arguments for SQL/NoSQL injection signal.

    Requires introspection to enumerate arguments; if introspection is disabled
    the check returns no findings (there is nothing to fuzz). Error-based
    detection always runs; time-based (blind) detection only runs when
    ``active=True`` (the ``--active`` CLI flag).
    """
    findings: list[dict[str, Any]] = []

    # ── enumerate arguments via introspection ──────────────────────────────
    try:
        resp = await client.query(_ARG_INTROSPECTION)
    except Exception:
        return findings

    schema = (resp.get("data") or {}).get("__schema")
    if not schema:
        # Introspection disabled or unexpected shape — nothing to fuzz.
        return findings

    targets = enumerate_fuzzable_args(schema)
    if not targets:
        return findings

    # Track which (field, arg) pairs already fired so we report each once.
    fired: set[tuple[str, str]] = set()

    for target in targets:
        key = (target["field"], target["arg"])
        if key in fired:
            continue

        # ── error-based probing ────────────────────────────────────────────
        for payload in _ERROR_PAYLOADS:
            text, _elapsed = await _send(client, build_probe_query(target, payload))
            dbms = detect_dbms_error(text)
            if dbms:
                findings.append(_error_finding(target, payload, dbms, text))
                fired.add(key)
                break

        if key in fired:
            continue

        # ── time-based probing (opt-in via --active) ───────────────────────
        if active:
            clean = build_probe_query(target, "1")
            _base_text, baseline = await _send(client, clean)
            # Zero-delay control: structurally identical sleep payload asking for
            # 0 seconds. Used to prove the delay is payload-controlled.
            _ctrl_text, control = await _send(
                client, build_probe_query(target, _TIME_CONTROL_PAYLOAD)
            )
            _slow_text, slow = await _send(
                client, build_probe_query(target, _TIME_PAYLOAD)
            )
            # Two gates must BOTH pass: the slow payload must beat (a) the clean
            # baseline and (b) the zero-delay control by the configured margins.
            # The control gate is what suppresses a uniformly-slow endpoint:
            # if the 0-second sleep is just as slow as the 3-second one, the delay
            # is not attacker-controlled and we do not fire.
            beats_baseline = slow - baseline >= _TIME_MARGIN_SECONDS
            beats_control = slow - control >= _TIME_CONTROL_MARGIN_SECONDS
            if beats_baseline and beats_control:
                findings.append(_time_finding(target, baseline, slow, control))
                fired.add(key)

    return findings
