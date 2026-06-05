"""GraphQL response-cache-poisoning surface probe (`response-cache-poison`).

When a GraphQL server accepts queries over GET (see the `query-get` check), each
distinct ``?query=...`` URL is individually cacheable by CDN layers, reverse
proxies, and browser caches. This creates a **response-cache-poisoning** surface:
an attacker who can influence the query URL (or who sends crafted requests to
prime the cache) can serve stale, attacker-controlled response bodies to victims
who subsequently fetch the *same* URL through the cache.

**Two sub-checks are run:**

1. **GET-based query execution** (precondition probe).
   Sends ``GET /graphql?query={__typename}`` — the minimal benign baseline. If
   the server does not execute queries over GET, both sub-checks are silent: a
   server that forces POST is not exposed to URL-keyed caching abuse.

2. **Alias-variant caching** (differentiation probe).
   Sends ``GET /graphql?query={enshroudCachePoisonProbe:__typename}``. This query
   is semantically identical to the baseline — the alias renames the response key
   but the resolved field and its value are the same — but produces a *different*
   URL. On a caching layer that uses the full URL as the cache key (standard
   behaviour), these two requests populate two separate cache slots. An attacker
   who convinces the cache to serve the aliased-URL response at the canonical URL
   (via a cache-key normalisation bypass, a ``Vary:`` header misconfiguration, or
   a CDN forwarding quirk) can poison the cache with attacker-authored content.

A finding fires only when **both** probes succeed (both return 2xx with a
top-level ``data`` key). A server that rejects GET queries, or only one of the
two forms, never fires. The check is strictly read-only and does not modify cache
state — it reports the *surface* (the server accepts aliased GET variants) rather
than proving a cache in the path actually normalises incorrectly.

**Severity:** LOW — informational surface exposure, requires a misconfigured CDN
or proxy in the path to escalate to an exploitable finding. Upgrade to MEDIUM if
combined with a permissive CORS policy (`cors` finding): cross-site readable +
cacheable query responses are directly reportable on many bug-bounty programmes.

**Competitor gap:** graphql-cop, InQL, graphw00f, and graphql-armor each probe
GET execution but none test the alias-variant URL differentiation that is the
structural precondition of a normalisation-based cache-poisoning attack.

**References:**
- PortSwigger Web Security Academy: "GraphQL API vulnerabilities — GraphQL
  caching" (portswigger.net/web-security/graphql/graphql-caching)
- OWASP GraphQL Cheat Sheet: "GET requests can be cached … only enable GET for
  queries you explicitly want cached, and never for anything that returns
  sensitive data"
- HackerOne GraphQL cache-poisoning reports (H1/graphql-related)
- RFC 7234 §2 — HTTP caching: cache key includes the full request URI
"""
from __future__ import annotations

import json
from typing import Any

from enshroud.client import GraphQLClient

CATEGORY = "response_cache_poison_surface"
SEVERITY = "LOW"

# Baseline probe: the canonical benign query every enshroud GET check uses.
# `__typename` resolves on the root Query type of every GraphQL server.
_BASELINE_QUERY = "{ __typename }"

# Differentiation probe: semantically identical (same field, same value),
# but the URL-encoded form differs because the alias changes the selection-set
# text. Any cache keyed on the full URL stores this in a different slot.
_ALIAS_QUERY = "{ enshroudCachePoisonProbe: __typename }"

# The alias key we inject, used both in the probe and in evidence strings.
_ALIAS_KEY = "enshroudCachePoisonProbe"

# Maximum characters from the JSON response body to include as evidence.
_EVIDENCE_BODY_LEN = 300


def _is_data_response(resp_json: dict[str, Any]) -> bool:
    """True when the server executed the query and returned data (not an error)."""
    return "data" in resp_json and resp_json.get("data") is not None


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Probe for response-cache-poisoning surface via aliased GET variants.

    Returns at most one finding when:
    - the baseline GET query executes (precondition: server accepts GET), AND
    - the alias-variant GET query also executes (probe: server accepts aliased
      URL-encoded variants that map to the same logical query).
    """
    findings: list[dict[str, Any]] = []

    # --- Sub-check 1: baseline GET execution ---
    try:
        baseline_resp = await client.get_query(_BASELINE_QUERY)
    except Exception:
        return findings  # transport failure — be conservative

    if baseline_resp.status_code < 200 or baseline_resp.status_code >= 300:
        return findings  # GET not accepted
    try:
        baseline_json = baseline_resp.json()
    except Exception:
        return findings  # non-JSON body — not a GraphQL execution response
    if not _is_data_response(baseline_json):
        return findings  # query not executed (validation error, etc.)

    # --- Sub-check 2: alias-variant GET execution ---
    try:
        alias_resp = await client.get_query(_ALIAS_QUERY)
    except Exception:
        return findings
    if alias_resp.status_code < 200 or alias_resp.status_code >= 300:
        return findings
    try:
        alias_json = alias_resp.json()
    except Exception:
        return findings
    if not _is_data_response(alias_json):
        return findings

    # Both probes executed. The URL-keyed caching surface is present.
    baseline_body = json.dumps(baseline_json)[:_EVIDENCE_BODY_LEN]
    alias_body = json.dumps(alias_json)[:_EVIDENCE_BODY_LEN]

    findings.append(
        {
            "category": CATEGORY,
            "severity": SEVERITY,
            "title": "GraphQL Response-Cache-Poisoning Surface (Alias-Variant GET)",
            "baseline_query": _BASELINE_QUERY,
            "alias_query": _ALIAS_QUERY,
            "baseline_status": baseline_resp.status_code,
            "alias_status": alias_resp.status_code,
            "evidence": json.dumps(
                {
                    "baseline_query": _BASELINE_QUERY,
                    "alias_query": _ALIAS_QUERY,
                    "baseline_response_prefix": baseline_body,
                    "alias_response_prefix": alias_body,
                }
            )[:_EVIDENCE_BODY_LEN * 2],
            "description": (
                "The server executes GraphQL queries over GET, and accepts "
                "alias-variant URL forms that are semantically identical but "
                "produce different cache-key URLs. Two distinct cache slots can "
                "be populated for what a correct cache would treat as one "
                "canonical response: "
                f"`GET ?query={{{_BASELINE_QUERY}}}` (canonical) and "
                f"`GET ?query={{{_ALIAS_QUERY}}}` (aliased). "
                "A CDN or reverse proxy with a cache-key normalisation gap "
                "can serve the attacker-primed aliased-URL response at the "
                "canonical URL, poisoning cached GraphQL responses for victims."
            ),
            "reproduction": (
                f"1. GET `{client.endpoint}?query={{{_BASELINE_QUERY}}}` "
                f"→ HTTP {baseline_resp.status_code}, data returned. "
                f"2. GET `{client.endpoint}?query={{{_ALIAS_QUERY}}}` "
                f"→ HTTP {alias_resp.status_code}, data returned under the alias key. "
                "Both queries resolve the same logical field with different URL shapes. "
                "A caching layer that normalises aliases before keying would merge "
                "these; one that does not is poisonable."
            ),
            "impact": (
                "If a CDN, reverse proxy, or browser cache sits in front of this "
                "endpoint and uses the raw URL as its cache key (RFC 7234 default), "
                "an attacker can: (1) send many alias-variant requests to evict the "
                "canonical response from cache, (2) prime the cache with a crafted "
                "alias-variant query whose response body contains attacker-authored "
                "data under a legitimate response key, (3) deliver that poisoned "
                "cached response to victims. Severity escalates from LOW to MEDIUM "
                "when the `cors` check also fires: cached responses readable "
                "cross-site are directly reportable on bug-bounty programmes."
            ),
            "remediation": (
                "Options (choose one or more): "
                "(a) Disable GET-based query execution entirely — POST-only GraphQL "
                "eliminates the URL-keyed caching surface. "
                "(b) Configure the caching layer to normalise the GraphQL query "
                "before computing the cache key (e.g. parse and re-serialise the "
                "query AST, strip aliases that do not change selection semantics). "
                "(c) Add `Cache-Control: no-store` / `Vary: *` to GraphQL responses "
                "so that intermediaries do not cache authenticated query results. "
                "(d) In Apollo Router, enable query normalisation in the cache-key "
                "policy (`cache_key.query_dedup: true`)."
            ),
        }
    )

    return findings
