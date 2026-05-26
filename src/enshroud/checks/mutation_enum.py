"""Dangerous mutation enumeration check."""
from __future__ import annotations

import json
import re
from typing import Any

from enshroud.client import GraphQLClient

INTROSPECTION_MUTATIONS_QUERY = """
{
  __schema {
    mutationType {
      name
      fields {
        name
        description
        args {
          name
          type {
            name
            kind
          }
        }
      }
    }
  }
}
""".strip()

# Patterns for dangerous mutations (case-insensitive prefix match)
DANGEROUS_PATTERNS = re.compile(
    r'^(delete|remove|update|transfer|admin)',
    re.IGNORECASE,
)


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Enumerate dangerous mutations via introspection."""
    findings: list[dict[str, Any]] = []

    try:
        resp = await client.query(INTROSPECTION_MUTATIONS_QUERY)
    except Exception:
        return findings

    data = resp.get("data") or {}
    schema = data.get("__schema") or {}
    mutation_type = schema.get("mutationType")

    if not mutation_type:
        return findings

    fields = mutation_type.get("fields") or []

    for field in fields:
        name = field.get("name") or ""
        if DANGEROUS_PATTERNS.match(name):
            evidence = json.dumps({"mutation": field})[:500]
            findings.append(
                {
                    "category": "dangerous_mutation_exposed",
                    "severity": "HIGH",
                    "title": f"Dangerous Mutation Exposed: {name}",
                    "mutation_name": name,
                    "evidence": evidence,
                    "description": (
                        f"The mutation `{name}` matches a dangerous operation pattern "
                        f"(delete/remove/update/transfer/admin) and is publicly visible "
                        "in the GraphQL schema."
                    ),
                    "reproduction": (
                        "Query the schema via introspection: "
                        '{"query": "{__schema{mutationType{fields{name}}}}"}'
                        f' — observe `{name}` in results.'
                    ),
                    "impact": (
                        f"Exposure of `{name}` reveals sensitive business logic. "
                        "Combined with authorization flaws, this mutation may allow "
                        "data destruction, privilege escalation, or unauthorized transfers."
                    ),
                    "remediation": (
                        "Audit authorization controls on this mutation. "
                        "Consider disabling introspection in production to reduce "
                        "schema enumeration risk."
                    ),
                }
            )

    return findings
