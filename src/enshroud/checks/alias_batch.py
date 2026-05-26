"""Alias-based query batching check."""
from __future__ import annotations

import json
from typing import Any

from enshroud.client import GraphQLClient

ALIAS_COUNT = 100


def _build_alias_query(count: int) -> str:
    """Build a query with many aliased copies of __typename."""
    aliases = " ".join(f"q{i}: __typename" for i in range(1, count + 1))
    return "{ " + aliases + " }"


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Check if the server limits alias-based query batching."""
    findings: list[dict[str, Any]] = []
    query = _build_alias_query(ALIAS_COUNT)

    try:
        resp = await client.query(query)
    except Exception:
        return findings

    errors = resp.get("errors") or []
    error_messages = " ".join(
        (e.get("message") or "").lower() for e in errors
    )

    batch_limited = any(
        kw in error_messages
        for kw in ("alias", "batch", "limit", "too many", "complexity", "max")
    )

    data = resp.get("data") or {}
    # Count how many aliases were returned
    returned_count = len(data)

    if not batch_limited and returned_count >= ALIAS_COUNT:
        evidence = json.dumps(resp)[:500]
        findings.append(
            {
                "category": "alias_batching",
                "severity": "MEDIUM",
                "title": "Alias-Based Query Batching Not Limited",
                "queries_per_request_accepted": ALIAS_COUNT,
                "evidence": evidence,
                "description": (
                    f"The server accepted a single request with {ALIAS_COUNT} aliased field "
                    "copies without enforcing an alias or complexity limit. This allows "
                    "rate-limit bypass and resource exhaustion."
                ),
                "reproduction": (
                    f"Send a POST with {ALIAS_COUNT} aliased fields: "
                    "{ q1: __typename q2: __typename ... q100: __typename }"
                ),
                "impact": (
                    "An attacker can bypass per-request rate limits by embedding many "
                    "queries in a single request, or exhaust resolver resources."
                ),
                "remediation": (
                    "Implement query complexity limiting or alias count limits. "
                    "Consider limiting aliases to 10-20 per request."
                ),
            }
        )

    return findings
