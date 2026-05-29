"""Introspection recovered via a naive-filter bypass (differential).

The existing ``introspection`` check
(``src/enshroud/checks/introspection.py``) sends exactly one probe: a standard
``{ __schema { ... } }`` query over the default ``POST`` / ``application/json``
transport. If that one probe is rejected, it reports nothing — and concludes
the schema is protected.

But a very common production misconfiguration *blocks that one probe while
leaking the schema through a different, equivalent technique*. The block is
implemented as a naive guard rather than a proper "disable introspection"
executor option, so it only covers the exact shape the developer tested:

  * **Keyword deny-list (``__schema``-only).** The guard string-matches the
    literal ``__schema`` token and rejects it, but never inspects ``__type``.
    A ``{ __type(name: "Query") { name kind fields { name } } }`` query never
    contains ``__schema``, slips past the filter, and returns schema data —
    ``__type`` is a full introspection root field in its own right (it returns
    a ``__Type`` with its ``fields``), so this leaks the type graph
    field-by-field.

  * **Transport-scoped block (POST-only).** The guard is wired into the
    POST/JSON route handler only. The *same* ``{ __schema { ... } }`` query
    issued over ``GET`` (with the document in the ``query`` URL parameter) is
    handled by a different code path that never runs the guard, and returns the
    full schema.

  * **Top-level-selection block (fragment-spread bypass).** The guard inspects
    only the *top-level selection field names* of the operation and rejects a
    literal top-level ``__schema`` / ``__type`` meta-field, but never resolves
    fragment spreads. Moving the meta-field into a named fragment —
    ``query { ...F } fragment F on Query { __schema { ... } }`` — leaves only a
    ``...F`` spread at the operation's top level, so the guard sees no
    meta-field, the executor resolves the fragment normally, and the full
    schema is returned. This is the documented fragment-based introspection
    bypass for naive name-list filters.

This check is strictly **differential**, so it never overlaps with the
``introspection`` check and never false-positives on a correctly-hardened
server:

  1. It first confirms the *standard* probe (``POST`` ``__schema``) is
     **denied**. If standard introspection actually works, this check stays
     silent — that case is the ``introspection`` check's job, and reporting it
     here would be a duplicate.
  2. Only then does it try the two alternate techniques. A finding fires
     **only** when the standard probe was denied *and* an alternate technique
     returns introspection data.

A server that disables introspection *properly* (every transport, every root
field) denies the standard probe **and** both alternate probes, so this check
produces no finding. A server that simply has introspection on is caught by the
``introspection`` check and skipped here. The gap this fills is the in-between
state: "we turned introspection off" where the off-switch is a leaky guard.

Read-only: every probe is a ``__schema`` / ``__type`` query. No mutations, no
state change.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from enshroud.client import GraphQLClient

# Standard introspection probe (POST/JSON). Mirrors the `introspection` check so
# the "is the standard probe denied?" precondition matches that check's notion of
# introspection being unavailable on the default transport.
STANDARD_SCHEMA_QUERY = "{ __schema { queryType { name } } }"

# Alternate technique 1: `__type` is a distinct introspection root field that a
# `__schema`-keyword filter typically misses. Requesting its fields leaks the
# type graph one type at a time.
TYPE_PROBE_QUERY = '{ __type(name: "Query") { name kind fields { name } } }'

# Alternate technique 2: the standard `__schema` query, but issued over GET. A
# transport-scoped block that only guards POST leaves this path open.
GET_SCHEMA_QUERY = STANDARD_SCHEMA_QUERY

# Alternate technique 3: `__schema` reached through a named fragment spread. A
# guard that inspects only the operation's top-level selection field names sees
# `...EnshroudIntrospect` (a spread, not a meta-field) and lets it through; the
# executor resolves the fragment and returns the schema. Distinct field shape
# from the standard probe so a guard keyed on the literal top-level meta-field
# misses it.
FRAGMENT_SCHEMA_QUERY = (
    "query EnshroudIntrospect { ...EnshroudIntrospectFields } "
    "fragment EnshroudIntrospectFields on Query "
    "{ __schema { queryType { name } } }"
)

EVIDENCE_LEN = 400


def _has_introspection_data(body: Any) -> bool:
    """True when a parsed GraphQL response carries introspection data.

    Introspection data lives under ``data.__schema`` or ``data.__type`` and must
    be non-null. A response that is purely ``{"errors": [...]}`` (the block
    fired) or whose introspection key is ``null`` is *not* a leak.
    """
    if not isinstance(body, dict):
        return False
    data = body.get("data")
    if not isinstance(data, dict):
        return False
    schema = data.get("__schema")
    if isinstance(schema, dict) and schema:
        return True
    typ = data.get("__type")
    if isinstance(typ, dict) and typ:
        return True
    return False


def _response_body(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except (json.JSONDecodeError, ValueError):
        return None


def _evidence(technique: str, probe: str, body: Any) -> str:
    return json.dumps(
        {
            "technique": technique,
            "probe": probe,
            "response_prefix": json.dumps(body)[:EVIDENCE_LEN]
            if body is not None
            else "",
        }
    )


def _finding(technique: str, probe: str, evidence: str) -> dict[str, Any]:
    return {
        "category": "introspection_filter_bypass",
        "severity": "MEDIUM",
        "title": f"GraphQL Introspection Recovered via {technique}",
        "technique": technique,
        "evidence": evidence,
        "description": (
            "The endpoint rejects the standard introspection query "
            "(`{ __schema { ... } }` over POST/application/json) but still "
            f"returns schema data via {technique}. The introspection block is "
            "a naive guard that only covers the exact probe the developer "
            "tested, so an equivalent technique recovers the schema the block "
            "was meant to hide. This is distinct from introspection simply "
            "being enabled — the standard probe is denied here; only the "
            "alternate technique leaks."
        ),
        "reproduction": (
            f"Confirm the standard probe `{STANDARD_SCHEMA_QUERY}` is rejected, "
            f"then send `{probe}` via the {technique} path and observe a "
            "response containing introspection data (a non-null `__schema` or "
            "`__type`)."
        ),
        "impact": (
            "An attacker recovers the full GraphQL schema — types, fields, "
            "queries, and mutations — that the introspection block was intended "
            "to conceal, enabling the same API-surface enumeration and targeted "
            "attack crafting as fully-enabled introspection."
        ),
        "remediation": (
            "Disable introspection at the executor/validation layer (a single "
            "rule that rejects every `__schema` *and* `__type` meta-field on "
            "every transport), not via a per-string or per-route guard. Most "
            "GraphQL servers expose a single configuration flag for this; "
            "string-matching `__schema` or guarding only the POST handler is "
            "not sufficient."
        ),
    }


async def _standard_probe_denied(client: GraphQLClient) -> bool:
    """True when the standard POST `__schema` probe does NOT return schema data.

    Treats a connection error / non-2xx / errors-only / null-data response as
    "denied". Only a genuine `data.__schema` payload counts as introspection
    being available on the standard transport (in which case this check defers
    to the `introspection` check and returns no finding).
    """
    try:
        body = await client.query(STANDARD_SCHEMA_QUERY)
    except Exception:
        return True
    return not _has_introspection_data(body)


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Detect introspection recovered through a naive-filter bypass.

    Differential: fires only when the standard POST `__schema` probe is denied
    but an alternate technique (`__type` over POST, or `__schema` over GET)
    returns introspection data. Read-only.
    """
    findings: list[dict[str, Any]] = []

    # Precondition: standard introspection must be denied. If it works, the
    # `introspection` check owns that finding; reporting here would duplicate it.
    if not await _standard_probe_denied(client):
        return findings

    # Technique 1: `__type` root field over POST (defeats a `__schema`-keyword
    # deny-list).
    try:
        type_body = await client.query(TYPE_PROBE_QUERY)
    except Exception:
        type_body = None
    if _has_introspection_data(type_body):
        findings.append(
            _finding(
                technique="the `__type` root field (POST)",
                probe=TYPE_PROBE_QUERY,
                evidence=_evidence(
                    "the `__type` root field (POST)", TYPE_PROBE_QUERY, type_body
                ),
            )
        )

    # Technique 2: standard `__schema` query over GET (defeats a POST-only
    # block).
    try:
        get_resp = await client.get_query(GET_SCHEMA_QUERY)
        get_body = _response_body(get_resp)
        if not (200 <= get_resp.status_code < 300):
            get_body = None
    except Exception:
        get_body = None
    if _has_introspection_data(get_body):
        findings.append(
            _finding(
                technique="the GET transport",
                probe=GET_SCHEMA_QUERY,
                evidence=_evidence(
                    "the GET transport", GET_SCHEMA_QUERY, get_body
                ),
            )
        )

    # Technique 3: `__schema` reached through a named fragment spread (defeats a
    # guard that inspects only the operation's top-level selection field names).
    try:
        frag_body = await client.query(FRAGMENT_SCHEMA_QUERY)
    except Exception:
        frag_body = None
    if _has_introspection_data(frag_body):
        findings.append(
            _finding(
                technique="a named fragment spread (POST)",
                probe=FRAGMENT_SCHEMA_QUERY,
                evidence=_evidence(
                    "a named fragment spread (POST)",
                    FRAGMENT_SCHEMA_QUERY,
                    frag_body,
                ),
            )
        )

    return findings
