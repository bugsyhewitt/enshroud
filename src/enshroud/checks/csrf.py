"""CSRF via content-type bypass check.

Detects GraphQL endpoints that execute mutations when the request is sent in a
way browsers can issue cross-origin without a CORS preflight:

  * `application/x-www-form-urlencoded` POST with body `query=mutation{...}`
  * a plain `GET /graphql?query=mutation{...}`

Both are "simple requests" under the CORS spec, so a malicious page can trigger
them against a victim's authenticated session — classic CSRF, even when the API
requires `application/json` for its normal clients.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from enshroud.client import GraphQLClient

# Introspection query to discover the first mutation field name.
MUTATION_DISCOVERY_QUERY = """
{
  __schema {
    mutationType {
      name
      fields { name }
    }
  }
}
""".strip()

# Used when no mutation can be discovered (introspection disabled). A mutation
# selecting only `__typename` is side-effect free but still proves the endpoint
# parses and executes a `mutation` operation via the bypass transport. We label
# the operation so a human can see exactly what was sent.
SYNTHETIC_MUTATION = "mutation enshroudCsrfProbe { __typename }"

BODY_PREFIX_LEN = 300


def _build_mutation(field_name: str | None) -> str:
    """Build a minimal mutation document for the given field, or a probe."""
    if field_name:
        # Select __typename so we don't need to know the field's return shape
        # or supply required args; many servers still execute the resolver.
        return f"mutation {{ {field_name} }}"
    return SYNTHETIC_MUTATION


def _is_accepted(resp: httpx.Response) -> bool:
    """A request is 'accepted' if it returns 2xx with a top-level `data` key.

    GraphQL servers return HTTP 200 even for errors, so we additionally require
    a non-null `data` key and the absence of a fatal `errors`-only body. A
    response that is purely `{"errors": [...]}` (e.g. "must use POST",
    "unsupported content type", "GET not allowed for mutation") is a rejection.
    """
    if not (200 <= resp.status_code < 300):
        return False
    try:
        body = resp.json()
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(body, dict):
        return False
    if "data" not in body or body.get("data") is None:
        return False
    # If the server returned data but ALSO a populated errors array, treat the
    # presence of data as execution having occurred (partial execution still
    # means the mutation transport was accepted).
    return True


def _evidence(method: str, content_type: str, resp: httpx.Response) -> str:
    body_text = resp.text or ""
    return json.dumps(
        {
            "request_method": method,
            "request_content_type": content_type,
            "response_status": resp.status_code,
            "response_body_prefix": body_text[:BODY_PREFIX_LEN],
        }
    )


def _finding(vector: str, evidence: str, mutation: str, synthetic: bool) -> dict[str, Any]:
    probe_note = (
        " (a synthetic `__typename` probe mutation was used because no mutation "
        "was discoverable via introspection)"
        if synthetic
        else ""
    )
    return {
        "category": "csrf_via_content_type",
        "severity": "HIGH",
        "title": f"GraphQL Mutation Executable via {vector} (CSRF)",
        "vector": vector,
        "evidence": evidence,
        "description": (
            f"The GraphQL endpoint executed a mutation sent via {vector}. "
            "Browsers issue this request type as a CORS 'simple request', "
            "without a preflight, so a cross-origin page can trigger it against "
            "a victim's authenticated session. This is a Cross-Site Request "
            f"Forgery (CSRF) exposure{probe_note}."
        ),
        "reproduction": (
            f"Send the mutation `{mutation}` to the endpoint via {vector}. "
            "Observe an HTTP 2xx response containing a `data` key, confirming "
            "the mutation was accepted and executed."
        ),
        "impact": (
            "An attacker can host a page that, when visited by an authenticated "
            "victim, silently executes state-changing GraphQL mutations "
            "(password reset, account deletion, fund transfer) using the "
            "victim's cookies — with no same-origin or token defense in play."
        ),
        "remediation": (
            "Require `application/json` and reject "
            "`application/x-www-form-urlencoded`, `multipart/form-data`, and "
            "`text/plain` for mutating operations. Disallow mutations over GET. "
            "Adopt a CSRF prevention scheme such as a custom-header requirement "
            "(e.g. Apollo's CSRF prevention) or anti-CSRF tokens."
        ),
    }


async def _discover_mutation_field(client: GraphQLClient) -> str | None:
    """Return the first mutation field name via introspection, or None."""
    try:
        resp = await client.query(MUTATION_DISCOVERY_QUERY)
    except Exception:
        return None
    data = resp.get("data") or {}
    schema = data.get("__schema") or {}
    mutation_type = schema.get("mutationType")
    if not mutation_type:
        return None
    fields = mutation_type.get("fields") or []
    for field in fields:
        name = field.get("name")
        if name:
            return name
    return None


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Check whether mutations are executable via CSRF-amenable transports."""
    findings: list[dict[str, Any]] = []

    field_name = await _discover_mutation_field(client)
    synthetic = field_name is None
    mutation = _build_mutation(field_name)

    # Vector 1: application/x-www-form-urlencoded POST
    try:
        form_resp = await client.post_form(mutation)
    except Exception:
        form_resp = None
    if form_resp is not None and _is_accepted(form_resp):
        findings.append(
            _finding(
                vector="application/x-www-form-urlencoded POST",
                evidence=_evidence(
                    "POST", "application/x-www-form-urlencoded", form_resp
                ),
                mutation=mutation,
                synthetic=synthetic,
            )
        )

    # Vector 2: GET with query in the URL
    try:
        get_resp = await client.get_query(mutation)
    except Exception:
        get_resp = None
    if get_resp is not None and _is_accepted(get_resp):
        findings.append(
            _finding(
                vector="GET request",
                evidence=_evidence("GET", "n/a", get_resp),
                mutation=mutation,
                synthetic=synthetic,
            )
        )

    return findings
