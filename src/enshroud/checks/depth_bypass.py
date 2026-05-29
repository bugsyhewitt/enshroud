"""Query-depth-limit bypass check (fragment-expanded nesting).

The `depth-dos` check fires only when a server enforces *no* depth limit at all.
This check covers the complementary, higher-value class: a server that *does*
enforce a depth limit but computes that depth from the literal operation body
only — without first expanding fragment spreads. Because GraphQL fragments are
inlined at execution, an attacker can hide the expensive nesting inside a named
fragment so the operation body looks shallow to the naive counter, then spread
that fragment to reach an effective depth far beyond the advertised cap.

Detection is strictly differential and read-only:

  1. Confirm the limit is *enforced*: a flat query nested ``PROBE_DEPTH`` levels
     deep is rejected with a depth / complexity error.
  2. Confirm the limit is *bypassable*: a fragment-wrapped query whose literal
     operation-body depth is shallow (a single ``...F`` spread) but whose
     fragment-expanded depth reaches ``PROBE_DEPTH`` is *accepted* (returns data,
     no depth error).

A finding fires only when step 1 rejects *and* step 2 is accepted. A server with
no depth limit (caught by `depth-dos`), or one that correctly expands fragments
before counting, produces no finding here — so this never double-counts with
`depth-dos` and never false-positives on a hardened endpoint.
"""
from __future__ import annotations

import json
from typing import Any

from enshroud.client import GraphQLClient

# Nesting depth used for both the flat probe and the fragment-expanded probe.
# Chosen well above any sane production depth limit (typically 5-15) so the flat
# probe is reliably rejected by an enforcing server.
PROBE_DEPTH = 20

# Error keywords that indicate the server rejected a query for being too deep /
# too complex. Mirrors the depth-dos keyword set.
_DEPTH_ERROR_KEYWORDS = ("depth", "complexity", "too deep", "max depth", "limit")


def _build_flat_query(depth: int) -> str:
    """Build a flat query nested ``depth`` levels deep (no fragments)."""
    inner = "__typename"
    for _ in range(depth):
        inner = f"a {{ {inner} }}"
    return "{ " + inner + " }"


def _build_fragment_query(depth: int) -> str:
    """Build a query whose nesting lives inside a fragment, not the operation body.

    The operation body is a single fragment spread (``query { ...D }``) — depth 1
    to a counter that never resolves fragments — but the fragment ``D`` carries
    the full ``depth``-level nesting that the executor inlines. A depth limiter
    that counts the operation body alone sees depth ~1 and lets it through.
    """
    inner = "__typename"
    for _ in range(depth):
        inner = f"a {{ {inner} }}"
    fragment_body = inner
    return (
        "query { ...D } "
        f"fragment D on Query {{ {fragment_body} }}"
    )


def _is_depth_rejected(resp: dict[str, Any]) -> bool:
    """Return True when the response is a depth/complexity rejection."""
    errors = resp.get("errors") or []
    if not errors:
        return False
    messages = " ".join((e.get("message") or "").lower() for e in errors)
    return any(kw in messages for kw in _DEPTH_ERROR_KEYWORDS)


def _is_accepted(resp: dict[str, Any]) -> bool:
    """Return True when the server executed the query (returned data, no errors)."""
    if resp.get("errors"):
        return False
    return resp.get("data") is not None


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Check whether an enforced query-depth limit is bypassable via fragments."""
    findings: list[dict[str, Any]] = []

    flat_query = _build_flat_query(PROBE_DEPTH)
    fragment_query = _build_fragment_query(PROBE_DEPTH)

    # ── Step 1: confirm a depth limit is actually enforced ──────────────────
    try:
        flat_resp = await client.query(flat_query)
    except Exception:
        return findings

    if not _is_depth_rejected(flat_resp):
        # No depth limit enforced (or rejected for another reason) — that's the
        # `depth-dos` check's territory, not a *bypass*. Stay silent here.
        return findings

    # ── Step 2: confirm the enforced limit is bypassable via a fragment ─────
    try:
        frag_resp = await client.query(fragment_query)
    except Exception:
        return findings

    if not _is_accepted(frag_resp):
        # Fragment-wrapped query was also rejected → the limiter expands
        # fragments before counting. Correctly hardened; no finding.
        return findings

    findings.append(
        {
            "category": "depth_limit_bypass",
            "severity": "MEDIUM",
            "title": "Query Depth Limit Bypassable via Fragment Expansion",
            "probe_depth": PROBE_DEPTH,
            "evidence": json.dumps(
                {
                    "flat_query_rejected": flat_resp,
                    "fragment_query_accepted": frag_resp,
                }
            )[:500],
            "description": (
                f"A flat query nested {PROBE_DEPTH} levels deep was rejected with "
                "a depth/complexity error, confirming the server enforces a query "
                "depth limit. However, the identical nesting wrapped inside a named "
                "fragment and reached via a single fragment spread "
                "(`query { ...D } fragment D on Query { ... }`) was accepted and "
                "executed. The depth limiter counts the literal operation body but "
                "does not expand fragment spreads before measuring depth, so an "
                "attacker can hide arbitrarily deep nesting inside a fragment and "
                "defeat the limit entirely."
            ),
            "reproduction": (
                "1. Send a flat query nested ~20 levels deep and observe a "
                "depth-limit error. "
                "2. Send `query { ...D } fragment D on Query { <same 20-level "
                "nesting> }` and observe that it executes without a depth error."
            ),
            "impact": (
                "The query-depth control — a primary GraphQL DoS mitigation — can "
                "be bypassed, restoring the full deeply-nested-query denial-of-"
                "service vector the limit was meant to prevent. An attacker can "
                "exhaust server CPU/memory with a single small request."
            ),
            "remediation": (
                "Compute query depth (and complexity/cost) on the fully expanded "
                "operation, resolving all fragment spreads before measuring, rather "
                "than on the raw operation body. Most maintained validation rules "
                "(e.g. graphql-js depth/cost analysis) already inline fragments — "
                "ensure custom or string-based limiters do the same."
            ),
        }
    )

    return findings
