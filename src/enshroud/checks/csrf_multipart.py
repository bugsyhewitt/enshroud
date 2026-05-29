"""CSRF via alternate simple-request transports (``multipart/form-data`` / ``text/plain``).

The existing ``csrf`` check (``src/enshroud/checks/csrf.py``) probes exactly two
CSRF-amenable transports: an ``application/x-www-form-urlencoded`` POST and a
plain ``GET``. It does **not** probe the other two content types a browser can
send cross-origin *without* a CORS preflight:

  * ``multipart/form-data`` — a ``<form enctype="multipart/form-data">`` submit, or
    a cross-origin ``fetch`` with a ``FormData`` body.
  * ``text/plain`` — a cross-origin ``fetch`` with a JSON-shaped string body and
    ``Content-Type: text/plain``.

All three (urlencoded, multipart, text/plain) are CORS "simple requests": the
browser issues them with the victim's cookies and *no* preflight. This is a
genuinely distinct gap from the existing ``csrf`` check, not a duplicate:
a server very commonly validates the JSON and the ``x-www-form-urlencoded``
parsing paths but routes a ``multipart/form-data`` body through a *different*
parser that never runs the CSRF / content-type check — exactly the
"fixed CSRF vulnerability still allowed a bypass via multipart" class disclosed
across 2024–2026 (the validation was tied to request *parsing*, not to the
operation *execution* layer, so an alternate transport slipped past it).
``text/plain`` is the same story for servers that body-sniff JSON regardless of
the declared content type.

The probe is read-only by default: it discovers the first mutation field via
introspection and selects only ``__typename`` on it (no arguments, no resolver
side effects beyond what the server does for a bare field selection), and falls
back to a synthetic ``mutation enshroudCsrfMultipartProbe { __typename }`` when
introspection is disabled. A finding fires only when the server returns HTTP 2xx
with a top-level ``data`` key for one of these transports — i.e. it actually
executed the operation. A server that rejects the alternate content type
(``{"errors": [...]}`` / non-2xx) produces no finding.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from enshroud.client import GraphQLClient

# Introspection query to discover the first mutation field name. Mirrors the
# csrf check so behaviour is consistent across the two CSRF probes.
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
# parses and executes a `mutation` operation via the bypass transport.
SYNTHETIC_MUTATION = "mutation enshroudCsrfMultipartProbe { __typename }"

BODY_PREFIX_LEN = 300


def _build_mutation(field_name: str | None) -> str:
    """Build a minimal mutation document for the given field, or a probe."""
    if field_name:
        # Select __typename so we don't need to know the field's return shape
        # or supply required args; many servers still execute the resolver.
        return f"mutation {{ {field_name} }}"
    return SYNTHETIC_MUTATION


def _is_accepted(resp: httpx.Response) -> bool:
    """A request is 'accepted' if it returns 2xx with a non-null `data` key.

    GraphQL servers return HTTP 200 even for errors, so a response that is purely
    ``{"errors": [...]}`` (e.g. "unsupported content type", "must be
    application/json") is a rejection, not an acceptance. Presence of a non-null
    ``data`` key means the operation was actually executed via this transport.
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
            "This content type is a CORS 'simple request': a browser issues it "
            "cross-origin with the victim's cookies and without a preflight. "
            "Servers frequently validate the JSON and "
            "application/x-www-form-urlencoded paths but route this transport "
            "through a different parser that skips the CSRF / content-type check "
            "— the documented bypass class where a 'fixed' CSRF mitigation still "
            f"lets a mutation through via an alternate transport{probe_note}."
        ),
        "reproduction": (
            f"Send the mutation `{mutation}` to the endpoint via {vector}. "
            "Observe an HTTP 2xx response containing a `data` key, confirming "
            "the mutation was accepted and executed over this transport even if "
            "application/json is otherwise required."
        ),
        "impact": (
            "An attacker can host a page that, when visited by an authenticated "
            "victim, silently executes state-changing GraphQL mutations "
            "(password reset, account deletion, fund transfer) using the "
            "victim's cookies — bypassing a CSRF defense that only guards the "
            "JSON / form-urlencoded transports."
        ),
        "remediation": (
            "Enforce the CSRF / content-type check at the operation *execution* "
            "layer, not the request *parsing* layer, so it applies uniformly "
            "across every transport. Reject `multipart/form-data`, `text/plain`, "
            "and `application/x-www-form-urlencoded` for operations; require "
            "`application/json`. Adopt a CSRF prevention scheme such as a "
            "custom-header requirement (e.g. Apollo's CSRF prevention, which "
            "demands a non-simple Content-Type or a preflight) or anti-CSRF "
            "tokens."
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
    """Check whether mutations execute via multipart/form-data or text/plain.

    Complements the `csrf` check (which probes x-www-form-urlencoded + GET) by
    covering the remaining two CORS simple-request content types. Read-only:
    selects only `__typename` on the discovered mutation field, or a synthetic
    `__typename` probe mutation when introspection is disabled.
    """
    findings: list[dict[str, Any]] = []

    field_name = await _discover_mutation_field(client)
    synthetic = field_name is None
    mutation = _build_mutation(field_name)

    # Vector 1: multipart/form-data POST
    try:
        mp_resp = await client.post_multipart(mutation)
    except Exception:
        mp_resp = None
    if mp_resp is not None and _is_accepted(mp_resp):
        findings.append(
            _finding(
                vector="multipart/form-data POST",
                evidence=_evidence("POST", "multipart/form-data", mp_resp),
                mutation=mutation,
                synthetic=synthetic,
            )
        )

    # Vector 2: text/plain POST with a JSON body
    try:
        tp_resp = await client.post_text_plain(mutation)
    except Exception:
        tp_resp = None
    if tp_resp is not None and _is_accepted(tp_resp):
        findings.append(
            _finding(
                vector="text/plain POST",
                evidence=_evidence("POST", "text/plain", tp_resp),
                mutation=mutation,
                synthetic=synthetic,
            )
        )

    return findings
