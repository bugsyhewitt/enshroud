"""Automatic Persisted Query (APQ) abuse check."""
from __future__ import annotations

import json
import os
from typing import Any

import httpx

from enshroud.client import GraphQLClient

# A well-formed but random sha256 hex hash that will never be in any real cache
_RANDOM_HASH = "a" * 64  # 64 hex chars = 256 bits, all-'a' is syntactically valid

# A simple introspection query to register (keeps evidence meaningful)
_PROBE_QUERY = "{ __typename }"

# Number of rapid registration probes to test rate-limiting
_RATE_LIMIT_PROBES = 5


def _build_apq_probe(*, include_query: bool = False, hash_hex: str = _RANDOM_HASH) -> dict:
    """Build an APQ extension payload, optionally with the query body attached."""
    payload: dict[str, Any] = {
        "extensions": {
            "persistedQuery": {
                "version": 1,
                "sha256Hash": hash_hex,
            }
        }
    }
    if include_query:
        payload["query"] = _PROBE_QUERY
    return payload


async def _post_json(client: GraphQLClient, body: dict) -> httpx.Response:
    """POST raw JSON to the client endpoint, bypassing the query() helper."""
    async with httpx.AsyncClient(timeout=client.timeout) as http:
        resp = await http.post(
            client.endpoint,
            headers=client.headers,
            content=json.dumps(body),
        )
    return resp


def _is_apq_not_found(resp: httpx.Response) -> bool:
    """Return True when the server signals APQ is enabled via PersistedQueryNotFound."""
    if resp.status_code != 200:
        return False
    try:
        body = resp.json()
    except Exception:
        return False
    errors = body.get("errors") or []
    return any(
        "PersistedQueryNotFound" in (e.get("extensions", {}).get("code", "") or "")
        or "PersistedQueryNotFound" in (e.get("message") or "")
        for e in errors
    )


def _registration_succeeded(resp: httpx.Response) -> bool:
    """Return True when a registration request returned real data (not an error)."""
    if resp.status_code != 200:
        return False
    try:
        body = resp.json()
    except Exception:
        return False
    return bool(body.get("data"))


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Check for APQ abuse: unrestricted registration and missing rate-limiting."""
    findings: list[dict[str, Any]] = []

    # ── Step 1: probe for APQ support ──────────────────────────────────────
    try:
        probe_resp = await _post_json(client, _build_apq_probe(include_query=False))
    except Exception:
        return findings

    if not _is_apq_not_found(probe_resp):
        # Server does not respond with PersistedQueryNotFound → APQ not enabled
        # or not in a recognisable form; no findings.
        return findings

    findings.append(
        {
            "category": "apq_enabled",
            "severity": "LOW",
            "title": "Automatic Persisted Queries (APQ) Enabled",
            "evidence": probe_resp.text[:500],
            "description": (
                "The GraphQL endpoint responded with `PersistedQueryNotFound`, "
                "confirming that Automatic Persisted Queries (APQ) are active. "
                "APQ is not a vulnerability by itself but enables the registration "
                "probes below."
            ),
            "reproduction": (
                'POST {"extensions": {"persistedQuery": {"version": 1, '
                f'"sha256Hash": "{_RANDOM_HASH}"}}}}'
                " and observe the PersistedQueryNotFound error."
            ),
            "impact": (
                "APQ support expands the server attack surface for cache poisoning "
                "and amplification if registration is not controlled."
            ),
            "remediation": (
                "Disable APQ if not required, or restrict query registration to "
                "authenticated clients with rate limiting applied."
            ),
        }
    )

    # ── Step 2: try unauthenticated registration ────────────────────────────
    try:
        reg_resp = await _post_json(
            client, _build_apq_probe(include_query=True)
        )
    except Exception:
        return findings

    if not _registration_succeeded(reg_resp):
        # Registration failed — server may require auth or the query was rejected.
        return findings

    findings.append(
        {
            "category": "apq_unrestricted_registration",
            "severity": "MEDIUM",
            "title": "APQ Cache Allows Unauthenticated Query Registration",
            "evidence": reg_resp.text[:500],
            "description": (
                "An unauthenticated client was able to register a new query into "
                "the APQ cache. This provides a foothold for cache-poisoning attacks: "
                "a malicious client can pre-load expensive or otherwise restricted "
                "queries so that authenticated clients execute them via hash lookup."
            ),
            "reproduction": (
                'POST {"query": "{ __typename }", "extensions": {"persistedQuery": '
                '{"version": 1, "sha256Hash": "<valid-hash-of-query>"}}} '
                "without any authentication header."
            ),
            "impact": (
                "An attacker can pollute the APQ cache with arbitrary queries, "
                "potentially bypassing allow-list controls or pre-staging DoS payloads."
            ),
            "remediation": (
                "Require authentication for APQ registration requests, or use a "
                "static allow-list of approved hashes compiled at build time."
            ),
        }
    )

    # ── Step 3: rate-limit check (rapid re-registration) ───────────────────
    # Re-use a different random hash each time so each request is a fresh registration.
    successes = 0
    for i in range(_RATE_LIMIT_PROBES):
        variant_hash = format(i + 0x1000, "064x")  # distinct but valid hex hashes
        try:
            r = await _post_json(
                client,
                _build_apq_probe(include_query=True, hash_hex=variant_hash),
            )
        except Exception:
            break
        if _registration_succeeded(r):
            successes += 1

    if successes >= _RATE_LIMIT_PROBES:
        findings.append(
            {
                "category": "apq_no_rate_limit",
                "severity": "MEDIUM",
                "title": "APQ Registration Has No Rate Limiting",
                "evidence": (
                    f"All {_RATE_LIMIT_PROBES} rapid registration requests succeeded "
                    "without throttling."
                ),
                "description": (
                    f"Sent {_RATE_LIMIT_PROBES} APQ registration requests in rapid "
                    "succession; all were accepted. The endpoint imposes no visible "
                    "rate limit on query registration, allowing unbounded cache "
                    "population by any client."
                ),
                "reproduction": (
                    f"Send {_RATE_LIMIT_PROBES} APQ registration POSTs with distinct "
                    "hashes back-to-back and observe that every response returns data."
                ),
                "impact": (
                    "An attacker can flood the APQ cache to exhaust server memory or "
                    "pre-stage a large number of attack payloads cheaply."
                ),
                "remediation": (
                    "Apply per-IP and per-token rate limits to APQ registration "
                    "endpoints. Consider a maximum cache size with LRU eviction."
                ),
            }
        )

    return findings
