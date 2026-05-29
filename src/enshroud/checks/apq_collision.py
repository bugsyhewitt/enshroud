"""Automatic Persisted Query (APQ) hash-mismatch / cache-poisoning check.

This check is distinct from the ``apq`` check. ``apq`` confirms that APQ is
enabled and probes for unauthenticated / unthrottled *registration*. This check
targets the integrity primitive that protects the APQ cache: a spec-compliant
server MUST verify that ``sha256(query) == sha256Hash`` before storing a
registration. The Apollo APQ protocol mandates a ``PersistedQueryHashMismatch``
error when the supplied query does not hash to the supplied key.

A server that skips that verification will store *attacker-controlled query
text* under an *attacker-chosen hash*. Because clients resolve a query by hash,
an attacker who can predict or learn a legitimate client's hash can pre-register
malicious query content under that same hash, so the next hash-only lookup from a
trusting client executes the attacker's query instead of the intended one. This
is the cache-poisoning primitive behind the Apollo Client cache-poisoning advisory
(GitHub issue #10784) — and it is invisible to the registration-spam probes in
the ``apq`` check.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

import httpx

from enshroud.client import GraphQLClient

# The query body we attempt to register. Harmless and side-effect-free, but its
# real sha256 will deliberately NOT match the hash we send alongside it.
_PROBE_QUERY = "{ __typename }"

# A syntactically valid, deterministic sha256 hex that is NOT sha256(_PROBE_QUERY).
# All-'b' is 64 hex chars (256 bits) and will never equal the real digest.
_WRONG_HASH = "b" * 64


def _correct_hash(query: str) -> str:
    """Return the spec-correct sha256 hex digest of a query string."""
    return hashlib.sha256(query.encode("utf-8")).hexdigest()


def _build_mismatch_probe(query: str, wrong_hash: str) -> dict[str, Any]:
    """Build an APQ registration payload whose hash does NOT match the query."""
    return {
        "query": query,
        "extensions": {
            "persistedQuery": {
                "version": 1,
                "sha256Hash": wrong_hash,
            }
        },
    }


def _build_lookup_probe(hash_hex: str) -> dict[str, Any]:
    """Build a hash-only APQ lookup (no query body)."""
    return {
        "extensions": {
            "persistedQuery": {
                "version": 1,
                "sha256Hash": hash_hex,
            }
        }
    }


async def _post_json(client: GraphQLClient, body: dict) -> httpx.Response:
    """POST a raw JSON body to the endpoint, bypassing the query() helper."""
    async with httpx.AsyncClient(timeout=client.timeout) as http:
        resp = await http.post(
            client.endpoint,
            headers=client.headers,
            content=json.dumps(body),
        )
    return resp


def _is_apq_enabled(resp: httpx.Response) -> bool:
    """True when a hash-only lookup yields PersistedQueryNotFound (APQ active)."""
    if resp.status_code != 200:
        return False
    try:
        body = resp.json()
    except Exception:
        return False
    errors = body.get("errors") or []
    return any(
        "PersistedQueryNotFound"
        in (e.get("extensions", {}).get("code", "") or "")
        or "PersistedQueryNotFound" in (e.get("message") or "")
        for e in errors
    )


def _is_hash_mismatch_rejected(resp: httpx.Response) -> bool:
    """True when the server correctly rejects a hash/query mismatch.

    A spec-compliant server returns a ``PersistedQueryHashMismatch`` error (Apollo
    uses HTTP 400; some engines use 200 with the error in the body). Either way
    the presence of the mismatch signal means the integrity check is intact.
    """
    try:
        body = resp.json()
    except Exception:
        # Non-JSON error body (e.g. a 400 HTML page) is still a rejection.
        return resp.status_code >= 400
    errors = body.get("errors") or []

    def _signals_mismatch(e: dict[str, Any]) -> bool:
        # Normalise both the code and message: Apollo uses the camelCase
        # "PersistedQueryHashMismatch"; some engines use the SCREAMING_SNAKE
        # "PERSISTED_QUERY_HASH_MISMATCH". Strip separators to match either.
        code = (e.get("extensions", {}) or {}).get("code", "") or ""
        code_norm = code.replace("_", "").lower()
        if "persistedqueryhashmismatch" in code_norm:
            return True
        msg = (e.get("message") or "").lower()
        if "does not match" in msg:
            return True
        if "hash" in msg and ("match" in msg or "mismatch" in msg):
            return True
        if "sha" in msg and "match" in msg:
            return True
        return False

    signalled = any(_signals_mismatch(e) for e in errors)
    if signalled:
        return True
    # No data and an HTTP error status with some error array → treat as rejected.
    if resp.status_code >= 400 and errors:
        return True
    return False


def _registration_accepted(resp: httpx.Response) -> bool:
    """True when the mismatched registration was accepted and executed."""
    if resp.status_code != 200:
        return False
    try:
        body = resp.json()
    except Exception:
        return False
    return bool(body.get("data")) and not body.get("errors")


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Detect APQ cache poisoning via unverified query/hash registration."""
    findings: list[dict[str, Any]] = []

    # ── Step 1: confirm APQ is enabled at all ──────────────────────────────
    try:
        probe = await _post_json(client, _build_lookup_probe(_WRONG_HASH))
    except Exception:
        return findings

    if not _is_apq_enabled(probe):
        # APQ not enabled (or not in a recognisable form) → nothing to test.
        return findings

    # ── Step 2: attempt a mismatched registration ──────────────────────────
    # Send a real query body alongside a hash that is NOT sha256(query).
    try:
        reg = await _post_json(
            client, _build_mismatch_probe(_PROBE_QUERY, _WRONG_HASH)
        )
    except Exception:
        return findings

    if _is_hash_mismatch_rejected(reg):
        # Server verifies hash integrity → not vulnerable. No finding.
        return findings

    if not _registration_accepted(reg):
        # Ambiguous (auth wall, generic error, etc.) — do not over-report.
        return findings

    # ── Step 3: confirm the poisoned entry is now served by hash lookup ────
    # If a subsequent hash-only lookup of the wrong hash returns data (no
    # PersistedQueryNotFound), the attacker-controlled query is cached under a
    # hash the attacker chose — confirmed cache poisoning.
    poison_confirmed = False
    try:
        lookup = await _post_json(client, _build_lookup_probe(_WRONG_HASH))
        if lookup.status_code == 200 and not _is_apq_enabled(lookup):
            lbody = lookup.json()
            poison_confirmed = bool(lbody.get("data"))
    except Exception:
        poison_confirmed = False

    severity = "HIGH" if poison_confirmed else "MEDIUM"
    confirm_text = (
        " A follow-up hash-only lookup of the attacker-chosen hash returned the "
        "poisoned query's data, confirming the entry is now served from cache."
        if poison_confirmed
        else ""
    )

    findings.append(
        {
            "category": "apq_hash_mismatch",
            "severity": severity,
            "title": "APQ Cache Poisoning via Unverified Query Hash",
            "evidence": reg.text[:500],
            "real_hash": _correct_hash(_PROBE_QUERY),
            "submitted_hash": _WRONG_HASH,
            "poison_confirmed": poison_confirmed,
            "description": (
                "The endpoint accepted an Automatic Persisted Query registration "
                "whose `sha256Hash` does not match the SHA-256 digest of the "
                "submitted `query`. A spec-compliant server must reject this with "
                "`PersistedQueryHashMismatch`. Skipping that integrity check lets "
                "an attacker store arbitrary query text under an arbitrary "
                "(attacker-chosen) hash. Because GraphQL clients resolve operations "
                "by hash, an attacker who predicts or observes a legitimate hash can "
                "pre-poison it so trusting clients execute attacker-controlled "
                "queries via hash-only lookup." + confirm_text
            ),
            "reproduction": (
                'POST {"query": "{ __typename }", "extensions": {"persistedQuery": '
                '{"version": 1, "sha256Hash": "' + _WRONG_HASH + '"}}} — note the '
                "hash is NOT sha256 of the query — and observe the server stores it "
                "instead of returning PersistedQueryHashMismatch."
            ),
            "impact": (
                "An attacker can poison the APQ cache with attacker-controlled query "
                "content keyed by a hash a victim client will request, causing the "
                "victim to execute the attacker's query (data exfiltration, "
                "allow-list bypass, or unsafe response rendering per Apollo Client "
                "issue #10784)."
            ),
            "remediation": (
                "Use an APQ implementation that verifies `sha256(query) == "
                "sha256Hash` on every registration and rejects mismatches with "
                "`PersistedQueryHashMismatch` (the default in Apollo Server and "
                "GraphQL Yoga). Never deploy a custom APQ layer that stores the "
                "client-supplied hash without recomputing it server-side."
            ),
        }
    )

    return findings
