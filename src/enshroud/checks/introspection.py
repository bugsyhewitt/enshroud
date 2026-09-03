"""Introspection enabled check."""
from __future__ import annotations

import json
from typing import Any

from enshroud.client import GraphQLClient

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
      }
    }
  }
}
""".strip()


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Check if GraphQL introspection is enabled."""
    findings: list[dict[str, Any]] = []

    try:
        resp = await client.query(INTROSPECTION_QUERY)
    except Exception:
        # Connection error or non-2xx — not considered a finding
        return findings

    data = resp.get("data") or {}
    if "__schema" in data:
        evidence = json.dumps(resp)[:500]
        findings.append(
            {
                "category": "introspection_enabled",
                "severity": "MEDIUM",
                "title": "GraphQL Introspection Enabled in Production",
                "evidence": evidence,
                "description": (
                    "The GraphQL introspection API is enabled, allowing any client to query "
                    "the full schema including all types, fields, queries, and mutations."
                ),
                "reproduction": (
                    'Send a POST request with body: {"query": "{__schema{queryType{name}}}"}'
                ),
                "impact": (
                    "An attacker can enumerate the entire API surface, discover hidden "
                    "endpoints, and craft targeted attacks."
                ),
                "remediation": (
                    "Disable introspection in production. Most GraphQL servers support this "
                    "via a configuration flag."
                ),
            }
        )

    return findings
