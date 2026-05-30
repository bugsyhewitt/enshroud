"""Operation-name enumeration over a name-keyed persisted-operation registry.

This check targets a persisted-operation surface that the existing APQ /
``pq-enum`` checks do **not** cover. The Apollo APQ family
(``apq``, ``apq-collision``, ``apq-get``) keys the operation store on the
**SHA-256 hash of the query text** — a 256-bit value not amenable to
enumeration. ``pq-enum`` covers the case where the store is keyed on a short,
guessable **document identifier** (``id`` / ``documentId`` /
``extensions.persistedQuery.id``). What neither family covers is the model where
the registry is keyed on a human-meaningful **operation name** string.

This model exists in the wild. Several persisted-document / "trusted documents"
implementations let a client replay a registered operation by sending only an
``operationName`` field with **no query body** — the server looks the name up in
a name-keyed registry and executes the registered operation. When the registry
is populated with conventional, semantically-named operations
(``IntrospectionQuery``, ``Login``, ``Me``, ``HealthCheck``, ``GetUser``, …) an
unauthenticated client can enumerate the registered set purely by guessing
common operation names — replaying admin or internal operations whose source
they never had.

The check is fully **read-only and differential**:

1. Probe the registry with a short list of conventional operation names an
   attacker would try first (introspection, auth, profile, admin smoke probes).
2. For each name, POST a body that contains **only** ``operationName`` (no
   ``query`` body, no ``id`` / ``documentId``, no
   ``extensions.persistedQuery``). The check never sends — let alone executes —
   an operation of its own choosing; it only asks the server to run something it
   has already registered under that name.
3. The finding fires **only** when one of those name-only requests returns a
   top-level ``data`` response. A server that has no name-keyed registry
   returns an error / 400 / ``PersistedQueryNotFound`` / a non-``data`` body for
   every probe and produces no finding.

Strictly differential against the rest of the persisted-operation family:

* No ``sha256Hash`` is ever supplied, so the APQ hash path is untouched.
* No ``id`` / ``documentId`` / ``extensions.persistedQuery.id`` is ever
  supplied, so the ``pq-enum`` ID path is untouched.
* The probe carries ``operationName`` *without* a matching query body — a
  spec-compliant executor with no name-keyed registry has nothing to resolve
  the name against and must return an error rather than ``data``.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from enshroud.client import GraphQLClient

# Conventional operation names an attacker would walk first. Drawn from the
# de-facto standard introspection client name, common auth/profile operations,
# and common smoke-probe operations. Kept short and high-signal: the goal is
# to demonstrate enumerability, not to fuzz an arbitrary namespace.
_PROBE_NAMES = [
    "IntrospectionQuery",
    "Login",
    "Me",
    "HealthCheck",
    "GetUser",
]

_EVIDENCE_LEN = 500


def _name_only_payload(op_name: str) -> dict[str, Any]:
    """A request body that carries *only* ``operationName``.

    No ``query`` body, no ``id``, no ``documentId``, no
    ``extensions.persistedQuery``. A spec-compliant executor with no
    name-keyed registry has nothing to resolve the name against; only a
    server that consults a name-keyed registered-operation store can return
    ``data`` for this payload.
    """
    return {"operationName": op_name}


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
    """True when the body carries a PersistedQueryNotFound error.

    A server that runs an APQ / persisted-query layer but does not honour
    name-only lookups will commonly respond with this code; that response
    means "no registered operation matched", which is the secure posture the
    check must read as no finding.
    """
    errors = body.get("errors") or []
    return any(
        "PersistedQueryNotFound"
        in (e.get("extensions", {}).get("code", "") or "")
        or "PersistedQueryNotFound" in (e.get("message") or "")
        for e in errors
    )


def _executed_from_name(resp: httpx.Response) -> bool:
    """True when a name-only request returned real GraphQL ``data``.

    The finding requires actual execution: a 200 response whose body has a
    non-null top-level ``data`` key and is **not** a PersistedQueryNotFound.
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
    """Detect a guessable, name-keyed persisted-operation registry."""
    findings: list[dict[str, Any]] = []

    for op_name in _PROBE_NAMES:
        payload = _name_only_payload(op_name)
        try:
            resp = await _post_json(client, payload)
        except Exception:
            # Transport error on one probe does not close the others.
            continue

        if not _executed_from_name(resp):
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
                "category": "persisted_operation_name_enumeration",
                "severity": "MEDIUM",
                "title": (
                    "Persisted Operation Executes From a Guessable Operation Name"
                ),
                "evidence": evidence,
                "probe_operation_name": op_name,
                "description": (
                    "A registered GraphQL operation executed when referenced "
                    "purely by a guessable operation name "
                    f"({json.dumps(payload)}) with no query body, no document "
                    "ID, and no APQ hash supplied. Unlike Automatic Persisted "
                    "Queries — whose cache is keyed by the unguessable SHA-256 "
                    "hash of the query text — and unlike ID-keyed persisted-"
                    "operation stores (the `pq-enum` vector), this endpoint "
                    "keys its persisted-operation registry on the human-"
                    "meaningful operation name. When that name space is "
                    "populated with conventional operations (`Login`, `Me`, "
                    "`IntrospectionQuery`, …) an unauthenticated client can "
                    "enumerate the registered set — replaying admin or "
                    "internal operations they were never given the source for "
                    "— simply by guessing common names."
                ),
                "reproduction": (
                    "POST the name-only body "
                    f"{json.dumps(payload)} (no `query` field, no `id`, no "
                    "`documentId`, no `extensions.persistedQuery`) and observe "
                    "a `data` response. Walk a wordlist of conventional "
                    "operation names to enumerate further registered "
                    "operations."
                ),
                "impact": (
                    "An attacker can discover and replay registered operations "
                    "by name without ever possessing their source, defeating "
                    "the confidentiality benefit of persisting operations "
                    "server-side and exposing privileged or internal "
                    "operations to unauthenticated execution and "
                    "reconnaissance."
                ),
                "remediation": (
                    "Do not resolve operations from a name-only request. "
                    "Require either the full query body, an unguessable "
                    "registration identifier (a SHA-256 hash of the query "
                    "text, APQ-style), or a session-bound persisted-operation "
                    "ID that is not derivable from public knowledge. Enforce "
                    "per-operation authorization on the resolved operation "
                    "regardless of how it was referenced, and reject "
                    "name-only requests for operations the caller is not "
                    "entitled to run."
                ),
            }
        )
        # One confirmed enumeration signal is enough; do not hammer the
        # endpoint with the remaining probes.
        return findings

    return findings
