"""Automatic Persisted Query execution-over-GET check (apq-get).

This check is distinct from the other two APQ checks. ``apq``
(``src/enshroud/checks/apq.py``) confirms APQ is enabled and probes for
unauthenticated / unthrottled *registration* over POST. ``apq-collision``
(``src/enshroud/checks/apq_collision.py``) targets the hash-integrity primitive
that protects the cache. Both probe **POST only**. Neither tests the transport
that is the entire point of Automatic Persisted Queries: the **cacheable GET
lookup**.

APQ exists so a client can replay a registered operation by sending only its
SHA-256 hash. The hash-only form is small enough to fit in a URL, so the
canonical APQ optimisation is to issue the lookup as ``GET
/graphql?extensions={"persistedQuery":{"version":1,"sha256Hash":"…"}}`` and let a
CDN / reverse proxy cache the response. That GET path is a security boundary the
POST-only checks never see:

* **Cacheable CSRF / SSRF-via-cache.** A ``GET`` is a CORS "simple request" and
  is trivially triggerable cross-site (``<img>``, ``<script>``, link prefetch,
  a crafted URL). If a registered *mutation* — or a query that returns
  sensitive, per-user data — executes over GET, an attacker can drive it from a
  victim's browser, exactly the class the ``csrf`` check guards on the POST/JSON
  path but which APQ-over-GET reintroduces. The hash makes the payload a
  fixed, shareable URL.
* **Cache-flooding / cache-poisoning storm.** Because the response is designed
  to be cacheable and is keyed by the persisted-query hash, an attacker who can
  register (see ``apq`` / ``apq-collision``) or predict hashes can flood a
  shared cache with persisted-operation responses, or poison a hash a victim
  client will later request — the "persisted-query storm" dimension, made
  deterministic by the GET-execution signal.

The check is strictly **differential and read-only**:

1. Confirm APQ is enabled at all (a hash-only POST lookup returns
   ``PersistedQueryNotFound``). If not, no probing and no finding.
2. Register a benign, side-effect-free ``{ __typename }`` query over POST so a
   known hash exists in the cache. (If registration is blocked — e.g. auth
   required — the check still proceeds to the GET probe below using the same
   hash; it simply will not be served, producing no false positive.)
3. Issue the **hash-only GET** for that query's correct SHA-256 hash. The
   finding fires **only** when that GET returns ``data`` (the persisted
   operation executed over GET). A server that honours APQ over POST but returns
   ``PersistedQueryNotFound`` (or any non-``data`` response) over GET is the
   secure default and produces no finding.

The probe query is the universally-valid, side-effect-free ``{ __typename }``,
so the check never executes anything sensitive against the target — it only
proves that the *transport* is open.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

import httpx

from enshroud.client import GraphQLClient

# A universally-valid, side-effect-free query. `__typename` resolves on the root
# Query type of every GraphQL schema, so registering it is harmless and its hash
# is a deterministic, known value we can replay over GET.
_PROBE_QUERY = "{ __typename }"

# A syntactically valid random hash used only to probe whether APQ is enabled
# (a hash-only lookup of an unknown hash yields PersistedQueryNotFound).
_RANDOM_HASH = "a" * 64

_EVIDENCE_LEN = 500


def _sha256(query: str) -> str:
    """Return the spec-correct SHA-256 hex digest of a query string."""
    return hashlib.sha256(query.encode("utf-8")).hexdigest()


def _persisted_query_param(hash_hex: str) -> str:
    """Build the JSON value for the GET `extensions` query-string parameter."""
    return json.dumps(
        {"persistedQuery": {"version": 1, "sha256Hash": hash_hex}}
    )


async def _post_json(client: GraphQLClient, body: dict[str, Any]) -> httpx.Response:
    """POST a raw JSON body to the endpoint, bypassing the query() helper."""
    async with httpx.AsyncClient(timeout=client.timeout) as http:
        resp = await http.post(
            client.endpoint,
            headers=client.headers,
            content=json.dumps(body),
        )
    return resp


async def _get_persisted(
    client: GraphQLClient, hash_hex: str
) -> httpx.Response:
    """Issue a hash-only APQ lookup over GET (no query body in the URL)."""
    headers = dict(client.headers)
    # GET is a CORS simple request; drop the JSON content type a browser would
    # not send so the probe faithfully mirrors a cross-site GET.
    headers.pop("Content-Type", None)
    params = {"extensions": _persisted_query_param(hash_hex)}
    async with httpx.AsyncClient(timeout=client.timeout) as http:
        resp = await http.get(
            client.endpoint,
            headers=headers,
            params=params,
        )
    return resp


def _is_apq_not_found(resp: httpx.Response) -> bool:
    """True when the response signals PersistedQueryNotFound (APQ active)."""
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


def _served_data(resp: httpx.Response) -> bool:
    """True when a GET lookup returned real GraphQL `data` (operation executed)."""
    if resp.status_code != 200:
        return False
    try:
        body = resp.json()
    except Exception:
        return False
    return bool(body.get("data")) and not _is_apq_not_found(resp)


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Detect APQ persisted-query execution over a cacheable GET request."""
    findings: list[dict[str, Any]] = []

    # ── Step 1: confirm APQ is enabled (hash-only POST lookup) ──────────────
    try:
        probe = await _post_json(
            client,
            {"extensions": {"persistedQuery": {"version": 1, "sha256Hash": _RANDOM_HASH}}},
        )
    except Exception:
        return findings

    if probe.status_code != 200 or not _is_apq_not_found(probe):
        # APQ not enabled (or not in a recognisable form) → nothing to test.
        return findings

    probe_hash = _sha256(_PROBE_QUERY)

    # ── Step 2: register the benign probe query so a known hash exists ──────
    # Registration may be blocked (auth required); that is fine — we still try
    # the GET probe below. If the hash was never cached, the GET returns
    # PersistedQueryNotFound and the check correctly reports nothing.
    try:
        await _post_json(
            client,
            {
                "query": _PROBE_QUERY,
                "extensions": {
                    "persistedQuery": {"version": 1, "sha256Hash": probe_hash}
                },
            },
        )
    except Exception:
        # A registration transport error does not by itself mean the GET path is
        # closed; fall through to the GET probe.
        pass

    # ── Step 3: replay the persisted query over a hash-only GET ─────────────
    try:
        get_resp = await _get_persisted(client, probe_hash)
    except Exception:
        return findings

    if not _served_data(get_resp):
        # The GET lookup did not execute the persisted operation (it returned
        # PersistedQueryNotFound, an error, or a non-200). This is the secure
        # default — APQ honoured only over POST — so no finding.
        return findings

    evidence = json.dumps(
        {
            "get_url": str(get_resp.request.url),
            "status_code": get_resp.status_code,
            "body": get_resp.text[:_EVIDENCE_LEN],
        }
    )[:_EVIDENCE_LEN]

    findings.append(
        {
            "category": "apq_execution_over_get",
            "severity": "MEDIUM",
            "title": "APQ Persisted Query Executes Over a Cacheable GET Request",
            "evidence": evidence,
            "probe_hash": probe_hash,
            "description": (
                "A registered Automatic Persisted Query executed when replayed as "
                "a hash-only `GET` request "
                "(`GET /graphql?extensions={\"persistedQuery\":{\"version\":1,"
                "\"sha256Hash\":\"<hash>\"}}`). The GET form is APQ's cacheable "
                "transport, but a `GET` is a CORS simple request that is trivially "
                "triggerable cross-site and is routinely cached by CDNs and "
                "reverse proxies keyed on the persisted-query hash. Executing "
                "persisted operations over GET reintroduces the CSRF surface the "
                "POST/JSON content-type guard is meant to close, and turns the "
                "shared cache into a flooding / poisoning target keyed by a hash "
                "an attacker can register or predict."
            ),
            "reproduction": (
                "After confirming APQ is enabled, register `{ __typename }` over "
                "POST (or use any known hash), then issue "
                "`GET /graphql?extensions=" + _persisted_query_param(probe_hash)
                + "` and observe the response returns `data` instead of "
                "`PersistedQueryNotFound`."
            ),
            "impact": (
                "An attacker can drive a registered (or hash-predicted) operation "
                "from a victim's browser via `<img>`/`<script>`/link prefetch — a "
                "CSRF path the POST content-type defence does not cover — and can "
                "flood or poison any shared cache fronting the endpoint with "
                "persisted-operation responses keyed by hash. If a registered "
                "mutation or a sensitive query is reachable this way, it is "
                "executed or its response is served from cache without the client "
                "ever sending the operation body."
            ),
            "remediation": (
                "Serve APQ lookups only over POST, or restrict the GET transport "
                "to non-mutating, non-sensitive persisted operations and set "
                "`Cache-Control: private, no-store` on responses that depend on "
                "the authenticated session. Require a custom (non-simple) request "
                "header or CSRF token on every state-changing or per-user "
                "operation regardless of transport, and gate persisted-query "
                "registration behind authentication (see the `apq` check) so the "
                "cache cannot be populated by anonymous clients."
            ),
        }
    )

    return findings
