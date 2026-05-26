"""Query depth DoS check."""
from __future__ import annotations

import json
from typing import Any

from enshroud.client import GraphQLClient

MAX_DEPTH = 15


def _build_deep_query(depth: int) -> str:
    """Build a deeply nested GraphQL query."""
    # Use __typename which is available on every type without knowing the schema
    inner = "__typename"
    for _ in range(depth):
        inner = f"a {{ {inner} }}"
    return "{ " + inner + " }"


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Check if the server enforces a query depth limit."""
    findings: list[dict[str, Any]] = []
    query = _build_deep_query(MAX_DEPTH)

    try:
        resp = await client.query(query)
    except Exception:
        return findings

    errors = resp.get("errors") or []
    error_messages = " ".join(
        (e.get("message") or "").lower() for e in errors
    )

    depth_limited = any(
        kw in error_messages
        for kw in ("depth", "complexity", "too deep", "max depth", "limit")
    )

    if not depth_limited:
        evidence = json.dumps(resp)[:500]
        findings.append(
            {
                "category": "depth_dos",
                "severity": "LOW",
                "title": "No Query Depth Limit",
                "max_depth_accepted": MAX_DEPTH,
                "evidence": evidence,
                "description": (
                    f"The server accepted a query with {MAX_DEPTH} levels of nesting without "
                    "returning a depth-limit error. This can be exploited for denial-of-service "
                    "by sending exponentially expensive nested queries."
                ),
                "reproduction": (
                    f"Send a POST with a query nested {MAX_DEPTH} levels deep: {query[:80]}..."
                ),
                "impact": (
                    "An attacker can craft deeply nested queries that exhaust server resources, "
                    "causing degraded performance or outages."
                ),
                "remediation": (
                    "Implement query depth limiting (e.g. graphql-depth-limit). "
                    "A depth of 5-10 is sufficient for most APIs."
                ),
            }
        )

    return findings
