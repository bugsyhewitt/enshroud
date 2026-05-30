"""Persisted-query brute force over an ID-keyed document store (pq-brute).

This is the active, range-walking companion to the signal-only ``pq-enum``
check. ``pq-enum`` probes three guessable IDs (``1``, ``2``, ``100``) across
three transports and returns on the first hit — its job is to report *that* an
ID-keyed persisted-query store exists, not *what* it contains. ``pq-brute``
turns that signal into an enumeration primitive: it walks a bounded range of
integer identifiers and records every ID that resolves to a real GraphQL
``data`` response, surfacing the actual catalogue of registered operations an
unauthenticated attacker can replay.

The check shares ``pq-enum``'s differential, read-only contract:

  * Probes carry **no** ``query`` body — the server can only respond with data
    if it executes an operation it has already registered under that ID. The
    check never supplies (and thereby executes) an operation of its own
    choosing.
  * Probes use a single transport — ``extensions.persistedQuery.id`` with no
    ``sha256Hash`` — chosen because (a) it is the transport ``pq-enum`` is most
    likely to have already confirmed and (b) it never collides with a real APQ
    hash registration.
  * A finding fires only when one or more IDs return a top-level ``data``
    response. A server with no ID-keyed store (returns
    ``PersistedQueryNotFound`` / 400 / a non-``data`` body for every probe)
    produces no finding.

The check is shipped as an **opt-in** (``--checks pq-brute``, not in
``--checks all``) because it sends up to ``BRUTE_MAX_PROBES`` requests in a
single invocation — orders of magnitude more than any check in ``all`` — and
because it is the kind of active enumeration a hunter wants to run
deliberately, against a confirmed-in-scope target, with the ``--fuzz-rate``
they have negotiated with the program. The rate is shared with ``schema-fuzz``
because both checks share the same "bounded, paced enumeration of a leaky
oracle" shape.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx

from enshroud.client import GraphQLClient

# Bounded ID range to walk. IDs 1..200 covers the small-integer ID space most
# bespoke gateways, Relay persisted-query lists and trusted-documents builds
# allocate in (build numbers, sequential operation indices) without dragging
# scans past the point where the marginal probe stops finding new operations.
BRUTE_ID_START = 1
BRUTE_ID_END = 200

# Hard cap on probes. Defends against an operator passing a wider range in a
# future flag and turning the check into an unbounded sweep.
BRUTE_MAX_PROBES = 500

# Default probe rate, mirroring schema-fuzz so the same --fuzz-rate flag tames
# both checks. <= 0 disables throttling.
DEFAULT_FUZZ_RATE = 5.0

_EVIDENCE_LEN = 500

# Cap on how many enumerated IDs we attach to the finding's evidence array, so
# a wildly permissive store (every ID returns data) does not produce a
# multi-megabyte finding object.
_MAX_REPORTED_IDS = 100


def _id_payload(doc_id: str) -> dict[str, Any]:
    """Return the ``extensions.persistedQuery.id`` probe body.

    Carries no ``query`` and no ``sha256Hash`` so the server can only respond
    with data by executing an operation it has already registered under that
    identifier.
    """
    return {"extensions": {"persistedQuery": {"version": 1, "id": doc_id}}}


async def _post_json(
    client: GraphQLClient, body: dict[str, Any]
) -> httpx.Response:
    """POST a raw JSON body to the endpoint, bypassing the query() helper."""
    async with httpx.AsyncClient(timeout=client.timeout) as http:
        resp = await http.post(
            client.endpoint,
            headers=client.headers,
            content=json.dumps(body),
        )
    return resp


def _is_persisted_query_not_found(body: dict[str, Any]) -> bool:
    """True when the body carries a PersistedQueryNotFound error (APQ signal)."""
    errors = body.get("errors") or []
    return any(
        "PersistedQueryNotFound"
        in (e.get("extensions", {}).get("code", "") or "")
        or "PersistedQueryNotFound" in (e.get("message") or "")
        for e in errors
    )


def _executed_from_id(resp: httpx.Response) -> bool:
    """True when an ID-only request returned real GraphQL ``data``.

    Mirrors ``pq_enum._executed_from_id``: the finding requires actual
    execution — a 200 response whose body has a non-null top-level ``data``
    key and is **not** a PersistedQueryNotFound.
    """
    if resp.status_code != 200:
        return False
    try:
        body = resp.json()
    except Exception:
        return False
    if not isinstance(body, dict):
        return False
    if _is_persisted_query_not_found(body):
        return False
    return body.get("data") is not None


async def check(
    client: GraphQLClient,
    *,
    fuzz_rate: float = DEFAULT_FUZZ_RATE,
    id_start: int = BRUTE_ID_START,
    id_end: int = BRUTE_ID_END,
) -> list[dict[str, Any]]:
    """Brute-force a bounded integer-ID space against an ID-keyed PQ store.

    Args:
        client: the GraphQL client (scope already validated by the CLI).
        fuzz_rate: max probes per second; <= 0 disables throttling.
        id_start / id_end: inclusive integer ID range to walk. Capped by
            ``BRUTE_MAX_PROBES`` regardless of the requested width.
    """
    findings: list[dict[str, Any]] = []

    if id_end < id_start:
        return findings

    span = min(id_end - id_start + 1, BRUTE_MAX_PROBES)
    delay = (1.0 / fuzz_rate) if fuzz_rate and fuzz_rate > 0 else 0.0

    enumerated_ids: list[str] = []
    sample_evidence: dict[str, Any] | None = None
    probes_sent = 0

    for offset in range(span):
        doc_id = str(id_start + offset)
        payload = _id_payload(doc_id)

        try:
            resp = await _post_json(client, payload)
        except Exception:
            probes_sent += 1
            if delay and offset + 1 < span:
                await asyncio.sleep(delay)
            continue

        probes_sent += 1
        if _executed_from_id(resp):
            if len(enumerated_ids) < _MAX_REPORTED_IDS:
                enumerated_ids.append(doc_id)
            if sample_evidence is None:
                sample_evidence = {
                    "request_body": payload,
                    "status_code": resp.status_code,
                    "response_body": resp.text[:_EVIDENCE_LEN],
                }

        if delay and offset + 1 < span:
            await asyncio.sleep(delay)

    if not enumerated_ids:
        return findings

    evidence_str = json.dumps(sample_evidence or {})[:_EVIDENCE_LEN]

    findings.append(
        {
            "category": "persisted_query_id_brute_force",
            "severity": "HIGH",
            "title": (
                "Persisted Operations Enumerable via Document-ID Brute Force"
            ),
            "evidence": evidence_str,
            "enumerated_ids": enumerated_ids,
            "enumerated_count": len(enumerated_ids),
            "probes_sent": probes_sent,
            "id_range": [id_start, id_start + span - 1],
            "description": (
                f"Walking integer document IDs {id_start}..{id_start + span - 1} "
                f"with no query body recovered {len(enumerated_ids)} "
                "registered GraphQL operation(s) — each ID returned a "
                "top-level `data` response, confirming the server resolved and "
                "executed an operation that was registered under that "
                "identifier. Unlike the `pq-enum` signal check (three probes, "
                "first-hit-and-stop), this brute-force enumerates the actual "
                "catalogue of operation IDs an unauthenticated client can "
                "replay. Unlike Automatic Persisted Queries — whose cache is "
                "keyed by the unguessable SHA-256 hash of the query text — this "
                "endpoint keys its persisted-operation store on a small "
                "integer ID, so the entire registered operation set is "
                "discoverable by walking the ID space."
            ),
            "reproduction": (
                "For each integer N in a bounded range, POST "
                '`{"extensions":{"persistedQuery":{"version":1,"id":"N"}}}` '
                "with no `query` field and observe which IDs return a `data` "
                "response. Each `data` response is a registered operation the "
                "server executed purely from its identifier."
            ),
            "impact": (
                "An attacker can enumerate every registered persisted "
                "operation — including admin, internal, and privileged "
                "operations whose source they never possessed — and replay "
                "them without authorization. Defeats the confidentiality "
                "benefit of persisting queries server-side and converts a "
                "supposedly opaque operation catalogue into a public, "
                "walkable index."
            ),
            "remediation": (
                "Treat persisted-query identifiers as secrets bound to an "
                "authenticated session, or key the store on the SHA-256 hash "
                "of the query text (APQ-style) so identifiers are not "
                "guessable. Enforce per-operation authorization on the "
                "resolved operation regardless of how it was referenced. If "
                "small integer IDs must be retained for client convenience, "
                "rate-limit ID-only requests aggressively and reject "
                "unauthenticated callers entirely."
            ),
        }
    )

    return findings
