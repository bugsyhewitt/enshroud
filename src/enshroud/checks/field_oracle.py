"""Field suggestion oracle check."""
from __future__ import annotations

import json
import re
from typing import Any

from enshroud.client import GraphQLClient

NONEXISTENT_FIELD = "nonExistentFieldXyzzy"

# Patterns that indicate field name suggestions in error messages
SUGGESTION_PATTERNS = [
    re.compile(r'Did you mean\s+"?([^"?]+)"?', re.IGNORECASE),
    re.compile(r'did you mean\s+([^\s?]+)', re.IGNORECASE),
    re.compile(r'suggestion[s]?:\s*(.+)', re.IGNORECASE),
    re.compile(r'similar field[s]?:\s*(.+)', re.IGNORECASE),
    re.compile(r'"([a-zA-Z_][a-zA-Z0-9_]*)"', re.IGNORECASE),
]


def _extract_suggestions(error_message: str) -> list[str]:
    """Extract suggested field names from a GraphQL error message."""
    suggestions: list[str] = []

    # Try "Did you mean" pattern first (most common)
    dm_pattern = re.compile(r'[Dd]id you mean\s+["\']?([^"\'?]+)["\']?', re.IGNORECASE)
    for match in dm_pattern.finditer(error_message):
        raw = match.group(1).strip().rstrip("?")
        # May contain multiple quoted names: `"foo"` or `"foo", "bar"`
        names = re.findall(r'"([^"]+)"', raw) or re.findall(r"'([^']+)'", raw)
        if names:
            suggestions.extend(names)
        else:
            suggestions.append(raw)

    return list(set(s.strip() for s in suggestions if s.strip()))


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Check if the server leaks field names via error suggestions."""
    findings: list[dict[str, Any]] = []
    query = f"{{ {NONEXISTENT_FIELD} }}"

    try:
        resp = await client.query(query)
    except Exception:
        return findings

    errors = resp.get("errors") or []
    extracted_fields: list[str] = []

    for error in errors:
        msg = error.get("message") or ""
        suggestions = _extract_suggestions(msg)
        extracted_fields.extend(suggestions)

    extracted_fields = list(set(extracted_fields))

    if extracted_fields:
        evidence = json.dumps(resp)[:500]
        findings.append(
            {
                "category": "field_suggestion_oracle",
                "severity": "LOW",
                "title": "Field Suggestion Oracle (Introspection Bypass)",
                "extracted_fields": extracted_fields,
                "evidence": evidence,
                "description": (
                    "The server returns field name suggestions in error messages when a "
                    "non-existent field is queried. This allows schema enumeration even "
                    "when introspection is disabled."
                ),
                "reproduction": (
                    f'Send a POST with body: {{"query": "{{ {NONEXISTENT_FIELD} }}"}} '
                    "and observe the error message for field name suggestions."
                ),
                "impact": (
                    "An attacker can enumerate field names by iterating through "
                    "non-existent field queries, bypassing introspection controls."
                ),
                "remediation": (
                    "Disable field suggestions in your GraphQL server configuration. "
                    "In Apollo Server, set `formatError` to strip suggestion text. "
                    "In graphql-js, use a custom error formatter."
                ),
            }
        )

    return findings
