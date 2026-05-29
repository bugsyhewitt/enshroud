"""Read-query execution over a cacheable GET (`query-get`).

This is the *read* counterpart to two existing GET-transport checks, and it
covers a surface neither of them touches:

  * ``csrf`` probes whether a **mutation** executes over
    ``GET /graphql?query=mutation{...}`` — a HIGH state-changing CSRF. A
    CSRF-safe server *correctly* rejects mutations over GET (HTTP 405,
    "GET requests may not perform mutations") while still happily executing
    arbitrary **read queries** over GET.
  * ``apq-get`` probes whether a **persisted** query (hash-only lookup) executes
    over GET. That requires APQ to be enabled and a hash to be registered.

Neither check fires for the plain, non-persisted, non-mutation case: a normal
read query sent as ``GET /graphql?query={__typename}`` that the server executes
and returns ``data`` for. That GET execution is its own exposure, independent of
mutations and of APQ:

  1. **Cross-site readability.** A GET with a ``query`` string is a CORS *simple
     request*: a malicious page can issue it (``<img>``, ``<script>``, ``fetch``,
     link prefetch) against a victim's authenticated session with no preflight.
     Combined with a permissive CORS policy (see the ``cors`` check) the response
     body — the victim's data — becomes cross-site readable.
  2. **Cacheability / cache poisoning.** A query addressed by a stable URL is
     cacheable by any intermediary (CDN, reverse proxy, browser). An attacker who
     can influence the cache key (or a server that caches authenticated
     responses by URL) can poison or harvest cached query results. This is the
     precondition the OWASP GraphQL Cheat Sheet warns about: *"GET requests can
     be cached … only enable GET for queries you explicitly want cached, and
     never for anything that returns sensitive data."*

The probe is benign and read-only: it sends a single ``{ __typename }`` query
(no mutation, no APQ, no schema knowledge) over GET. The finding fires only when
the server *executes* it — returns 2xx with a top-level ``data`` key. A server
that reserves GET for safe/empty responses, rejects it (405 / "must use POST"),
or only answers JSON over POST produces no finding.

Severity is LOW: serving read queries over GET is a deliberate, sometimes-desired
configuration (it is how GraphQL responses are made CDN-cacheable). The check
reports it as an attack-surface fact a bug-bounty / pentest reader should weigh
*together* with the ``cors`` and ``graphql-ide`` findings, not as a standalone
vulnerability. It is strictly differential against ``csrf`` (which only fires for
the higher-severity GET *mutation* case) and never double-counts with it.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from enshroud.client import GraphQLClient

CATEGORY = "query_execution_over_get"
SEVERITY = "LOW"

# A benign, schema-agnostic read query. `__typename` resolves on the root Query
# type of every GraphQL server, requires no arguments, and is side-effect free —
# so executing it proves the GET transport runs read operations without touching
# any business resolver or mutating anything.
PROBE_QUERY = "{ __typename }"

BODY_PREFIX_LEN = 300


def _is_executed(resp: httpx.Response) -> bool:
    """True when the GET response shows the query was *executed*.

    GraphQL servers answer with HTTP 200 even for errors, so a 2xx alone is not
    enough. We require a JSON object body carrying a non-null top-level ``data``
    key. A pure ``{"errors": [...]}`` body (e.g. "must use POST", "GET not
    allowed", "Introspection is disabled"), a non-JSON body, a non-2xx status,
    or an HTML page (IDE console) all mean the read query was *not* executed over
    GET — no finding.
    """
    if not (200 <= resp.status_code < 300):
        return False
    try:
        body = resp.json()
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(body, dict):
        return False
    return body.get("data") is not None


def _evidence(resp: httpx.Response) -> str:
    body_text = resp.text or ""
    return json.dumps(
        {
            "request_method": "GET",
            "probe_query": PROBE_QUERY,
            "response_status": resp.status_code,
            "response_content_type": resp.headers.get("content-type", ""),
            "response_body_prefix": body_text[:BODY_PREFIX_LEN],
        }
    )


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Probe whether a plain read query executes over a cacheable GET."""
    findings: list[dict[str, Any]] = []

    try:
        resp = await client.get_query(PROBE_QUERY)
    except Exception:
        # Transport error / refused GET → the read query was not served. No
        # finding (a server that does not answer GET at all is the safe case).
        return findings

    if not _is_executed(resp):
        return findings

    findings.append(
        {
            "category": CATEGORY,
            "severity": SEVERITY,
            "title": "GraphQL Read Query Executable via Cacheable GET",
            "evidence": _evidence(resp),
            "description": (
                "The endpoint executed a plain, non-persisted read query sent as "
                "GET /graphql?query={ __typename } and returned a top-level "
                "`data` response. A GET carrying a `query` string is a CORS "
                "'simple request' (no preflight) and is addressable by a stable, "
                "cacheable URL. This is distinct from GET *mutation* execution "
                "(reported separately and at higher severity by the `csrf` check) "
                "and from APQ-over-GET (the `apq-get` check): it is the "
                "read-query GET transport itself, which turns any query response "
                "into cross-site-readable, intermediary-cacheable content."
            ),
            "reproduction": (
                "Send GET "
                "`/graphql?query=%7B%20__typename%20%7D` (i.e. ?query={ __typename }) "
                "with no body and no special headers. Observe an HTTP 2xx response "
                "containing a `data` key, confirming the read query executed over "
                "GET. Replace the probe with any sensitive query to demonstrate "
                "the cacheable / cross-site-readable surface."
            ),
            "impact": (
                "Because the query is served over GET, a cross-origin page can "
                "trigger it against a victim's authenticated session via "
                "`<img>`/`<script>`/`fetch`/prefetch, and any intermediary (CDN, "
                "reverse proxy, browser cache) can store the response keyed on the "
                "URL. Combined with a permissive CORS policy this makes the "
                "victim's query results cross-site readable; combined with a "
                "shared cache it enables cache poisoning or harvesting of cached "
                "authenticated responses."
            ),
            "remediation": (
                "Reserve GET for operations you explicitly want cached and that "
                "return no sensitive or per-user data; reject read queries over "
                "GET otherwise and require POST + `application/json`. If GET "
                "queries must stay enabled for CDN caching, mark authenticated "
                "responses `Cache-Control: private, no-store`, vary the cache key "
                "on the auth context, and pair them with strict CORS and an "
                "anti-CSRF custom-header requirement."
            ),
        }
    )

    return findings
