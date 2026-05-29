"""Authorization-bypass-via-field-aliasing check.

Some GraphQL servers enforce authorization (or rate-limiting / WAF deny-lists)
by matching the *literal field name* or the *response key* of a selection
against a deny-list, instead of evaluating the field's own authorization
metadata during execution. On such a server, requesting a forbidden field under
a different **alias** changes the response key the control matches on — so the
field resolves and its data is returned, bypassing the check entirely.

This is a real, repeatedly-reported GraphQL bug class (alias-based authorization
/ WAF bypass). It is distinct from `alias-batch`, which abuses the *number* of
aliases to defeat rate-limiting via resource exhaustion: here a *single* alias
defeats a *field-name-keyed* security control, and the impact is unauthorized
data access rather than denial of service.

Detection is read-only and differential. For each candidate field the check
sends two queries:

  1. direct:  ``{ <field> { __typename } }``
  2. aliased: ``{ enshroudAliasProbe: <field> { __typename } }``

A finding fires only when the direct form is **denied** (an authorization /
forbidden error) and the aliased form **succeeds** (returns data under the alias
key). Equal outcomes — both denied, both allowed, both errored — never fire, so
a correctly-implemented server (authorization evaluated on the resolved field,
not its response key) produces no findings.
"""
from __future__ import annotations

import json
from typing import Any

from enshroud.client import GraphQLClient

# Response key used for the aliased probe. Deliberately distinctive so a
# name-keyed deny-list will not coincidentally match it.
ALIAS_KEY = "enshroudAliasProbe"

# Error-message / extensions-code substrings that indicate an authorization
# denial (as opposed to a "field does not exist" or other validation error).
_AUTH_DENIAL_MARKERS = (
    "not authorized",
    "unauthorized",
    "not authenticated",
    "permission",
    "forbidden",
    "access denied",
    "must be logged in",
    "requires authentication",
)

# Candidate field names to probe when introspection does not yield a field list.
# These are field names that are commonly access-controlled in real schemas.
_DEFAULT_CANDIDATES = [
    "user",
    "users",
    "me",
    "admin",
    "adminUser",
    "adminUsers",
    "account",
    "accounts",
    "secret",
    "secrets",
    "apiKey",
    "apiKeys",
    "token",
    "tokens",
    "internalUser",
    "auditLog",
    "billing",
    "payment",
    "payments",
    "ssn",
    "creditCard",
]

# Cap on how many candidate fields we probe, to bound request volume.
_MAX_CANDIDATES = 25

_INTROSPECTION_FIELDS_QUERY = (
    "{ __schema { queryType { fields { name } } } }"
)


def _is_auth_denial(resp: dict[str, Any]) -> bool:
    """Return True when the response is an authorization denial.

    A denial is an error whose message or extensions.code matches a known
    authorization-failure marker. A plain "cannot query field" / "field does
    not exist" validation error is NOT a denial and must not count.
    """
    errors = resp.get("errors") or []
    if not errors:
        return False
    for err in errors:
        msg = (err.get("message") or "").lower()
        code = ""
        ext = err.get("extensions") or {}
        if isinstance(ext, dict):
            code = str(ext.get("code") or "").lower()
        haystack = f"{msg} {code}"
        if any(marker in haystack for marker in _AUTH_DENIAL_MARKERS):
            return True
    return False


def _returned_key(resp: dict[str, Any], key: str) -> bool:
    """Return True when the response carries non-null data under ``key``."""
    data = resp.get("data")
    if not isinstance(data, dict):
        return False
    return key in data and data[key] is not None


async def _discover_candidates(client: GraphQLClient) -> list[str]:
    """Build the candidate-field list, preferring real query-type fields.

    When introspection is enabled we probe the actual top-level query fields
    (skipping meta-fields), which makes the check precise. Otherwise we fall
    back to a bundled list of commonly-protected field names.
    """
    try:
        resp = await client.query(_INTROSPECTION_FIELDS_QUERY)
    except Exception:
        return list(_DEFAULT_CANDIDATES[:_MAX_CANDIDATES])

    fields: list[str] = []
    schema = (resp.get("data") or {}).get("__schema") or {}
    query_type = schema.get("queryType") or {}
    for f in query_type.get("fields") or []:
        name = f.get("name") or ""
        if name and not name.startswith("__"):
            fields.append(name)

    if fields:
        return fields[:_MAX_CANDIDATES]
    return list(_DEFAULT_CANDIDATES[:_MAX_CANDIDATES])


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Probe for authorization bypass via field aliasing."""
    findings: list[dict[str, Any]] = []

    candidates = await _discover_candidates(client)

    for field in candidates:
        direct_query = f"{{ {field} {{ __typename }} }}"
        aliased_query = f"{{ {ALIAS_KEY}: {field} {{ __typename }} }}"

        try:
            direct_resp = await client.query(direct_query)
            aliased_resp = await client.query(aliased_query)
        except Exception:
            # Transport/HTTP error on this candidate — skip it, keep probing.
            continue

        # The bypass signal: the field is denied when named directly, but the
        # very same field resolves when aliased to a different response key.
        if _is_auth_denial(direct_resp) and not _is_auth_denial(aliased_resp):
            if _returned_key(aliased_resp, ALIAS_KEY):
                evidence = json.dumps(
                    {"direct": direct_resp, "aliased": aliased_resp}
                )[:600]
                findings.append(
                    {
                        "category": "authz_bypass_via_alias",
                        "severity": "HIGH",
                        "title": "Authorization Bypass via Field Aliasing",
                        "field": field,
                        "evidence": evidence,
                        "description": (
                            f"The field `{field}` is denied when requested "
                            "directly but resolves and returns data when "
                            "aliased to a different response key. The server's "
                            "authorization (or WAF/deny-list) control is keyed "
                            "on the literal field name / response key rather "
                            "than on the field's authorization metadata, so "
                            "renaming the field via an alias bypasses it."
                        ),
                        "reproduction": (
                            f'Denied: POST {{"query": "{{ {field} '
                            '{ __typename } }"}} → authorization error. '
                            f'Bypass: POST {{"query": "{{ {ALIAS_KEY}: '
                            f'{field} {{ __typename }} }}"}} → data returned '
                            "under the alias."
                        ),
                        "impact": (
                            "An attacker can read fields that should be "
                            "access-controlled by aliasing them, defeating "
                            "field-name-based authorization or WAF rules and "
                            "exposing restricted data."
                        ),
                        "remediation": (
                            "Enforce authorization inside field resolvers (or "
                            "via schema directives that the executor evaluates "
                            "on the resolved field), never by matching the "
                            "query text, field name, or response key. Any "
                            "deny-list or WAF that inspects GraphQL field "
                            "names must canonicalise aliases back to their "
                            "underlying field before deciding."
                        ),
                    }
                )
                # One representative finding is enough to prove the bug class;
                # stop probing to keep the check fast and quiet.
                break

    return findings
