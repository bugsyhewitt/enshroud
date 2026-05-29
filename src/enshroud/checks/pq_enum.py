"""Persisted-query enumeration over an ID-keyed document store (pq-enum).

This check targets a persisted-query surface that the three existing APQ checks
do **not** cover. ``apq`` (``src/enshroud/checks/apq.py``), ``apq-collision``
(``src/enshroud/checks/apq_collision.py``) and ``apq-get``
(``src/enshroud/checks/apq_get.py``) all probe Apollo **Automatic Persisted
Queries**, whose cache is keyed by the **SHA-256 hash of the query text**
(``extensions.persistedQuery.sha256Hash``). A 256-bit hash is not guessable, so
those checks are about *registration*, *hash collision* and *GET execution* — not
about *discovering* operations you were never given.

A different, widely deployed persisted-query model keys the store on a short,
client-supplied **document identifier** instead of a content hash. Relay
persisted queries, ``@apollo/persisted-query-lists`` / "trusted documents",
Hasura allow-lists and many bespoke gateways let a client replay a registered
operation by sending only an ``id`` / ``documentId`` (often a small integer or a
sequential build identifier) with **no query body**. When that identifier space
is small and guessable, an unauthenticated attacker can **enumerate the
registered operation set** — replaying admin/internal operations they never
possessed the source for — purely by walking IDs. This is a distinct attack
class from APQ hash lookup: the signal is "an operation executed from a
guessable ID, with no query text supplied".

The check is fully **read-only and differential**:

1. Probe the ID-keyed store with a handful of small, guessable identifiers
   (``"1"``, ``"2"`` …) across the three common ID transports:
     * top-level ``{"id": "<n>"}``
     * top-level ``{"documentId": "<n>"}``
     * ``{"extensions": {"persistedQuery": {"version": 1, "id": "<n>"}}}``
   None of these carries a ``query`` body, so the check never sends — let alone
   executes — an operation of its own choosing. It only asks the server to run
   something it has already registered under that ID.
2. The finding fires **only** when one of those ID-only requests returns a
   top-level ``data`` response — i.e. the server executed a registered operation
   selected purely by a guessable identifier. A server that has no ID-keyed
   store (returns an error / 400 / ``PersistedQueryNotFound`` / non-``data``
   body for every probe) produces no finding.

Because the probe never includes a SHA-256 ``sha256Hash`` registration and never
sends a query body, it is strictly differential against the three APQ checks: a
pure-APQ server (hash-keyed, no ID lookup) returns ``PersistedQueryNotFound`` or
an error to every ID probe and yields nothing here.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from enshroud.client import GraphQLClient

# Small, guessable identifiers an attacker would walk first. Kept short so the
# probe is cheap and unmistakably an *enumeration* signal rather than a fuzz run.
_PROBE_IDS = ["1", "2", "100"]

_EVIDENCE_LEN = 500


def _id_payloads(doc_id: str) -> list[dict[str, Any]]:
    """Return the three common ID-only persisted-query request shapes.

    Each shape references a registered operation by a short identifier and
    deliberately carries **no** ``query`` body, so the server can only respond
    with data if it executes an operation it already has registered under that
    ID. The shapes mirror Relay (``id``), trusted-documents / generic gateways
    (``documentId``), and the APQ-extension-with-id variant some servers accept.
    """
    return [
        {"id": doc_id},
        {"documentId": doc_id},
        {"extensions": {"persistedQuery": {"version": 1, "id": doc_id}}},
    ]


async def _post_json(client: GraphQLClient, body: dict[str, Any]) -> httpx.Response:
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

    The finding requires actual execution: a 200 response whose body has a
    non-null top-level ``data`` key and is **not** a PersistedQueryNotFound
    (that latter case is the hash-keyed APQ store telling us this ID is not a
    known *hash* — not an executed operation).
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


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Detect a guessable, ID-keyed persisted-query store (operation enumeration)."""
    findings: list[dict[str, Any]] = []

    for doc_id in _PROBE_IDS:
        for payload in _id_payloads(doc_id):
            try:
                resp = await _post_json(client, payload)
            except Exception:
                # Transport error on one shape does not close the others.
                continue

            if not _executed_from_id(resp):
                continue

            evidence = json.dumps(
                {
                    "request_body": payload,
                    "status_code": resp.status_code,
                    "response_body": resp.text[:_EVIDENCE_LEN],
                }
            )[:_EVIDENCE_LEN]

            findings.append(
                {
                    "category": "persisted_query_id_enumeration",
                    "severity": "MEDIUM",
                    "title": (
                        "Persisted Operation Executes From a Guessable Document ID"
                    ),
                    "evidence": evidence,
                    "probe_id": doc_id,
                    "description": (
                        "A registered GraphQL operation executed when referenced "
                        "by a short, guessable document identifier "
                        f"({json.dumps(payload)}) with no query body supplied. "
                        "Unlike Automatic Persisted Queries — whose cache is keyed "
                        "by the unguessable SHA-256 hash of the query text — this "
                        "endpoint keys its persisted-operation store on a small "
                        "client-supplied ID (Relay `id` / trusted-documents "
                        "`documentId` / an `extensions.persistedQuery.id`). When "
                        "that identifier space is small and sequential, an "
                        "unauthenticated client can enumerate the entire set of "
                        "registered operations — including admin or internal "
                        "operations they were never given the source for — simply "
                        "by walking IDs."
                    ),
                    "reproduction": (
                        "POST the identifier-only body "
                        f"{json.dumps(payload)} (no `query` field) and observe a "
                        "`data` response, then increment the ID to enumerate "
                        "further registered operations."
                    ),
                    "impact": (
                        "An attacker can discover and replay registered operations "
                        "by ID without ever possessing their source, defeating the "
                        "confidentiality benefit of persisting queries server-side "
                        "and exposing privileged or internal operations to "
                        "unauthenticated execution and reconnaissance."
                    ),
                    "remediation": (
                        "Treat persisted-query identifiers as secrets bound to an "
                        "authenticated session, or key the store on the SHA-256 "
                        "hash of the query text (APQ-style) so identifiers are not "
                        "guessable. Enforce per-operation authorization on the "
                        "resolved operation regardless of how it was referenced, "
                        "and reject ID-only requests for operations the caller is "
                        "not entitled to run."
                    ),
                }
            )
            # One confirmed enumeration signal is enough; do not hammer the
            # endpoint with the remaining probes.
            return findings

    return findings
