"""Field-level authorization gap (sensitive-field over-fetch) confirmation.

The object-level sibling of this check (``bola``) proves a caller can read the
*wrong object*. This one proves a caller can read the *wrong fields of an object
they are otherwise allowed to see*: GraphQL authorization is frequently enforced
only at the query/object level, leaving individual sensitive fields (SSN, credit
card, password hash, internal flags) ungated. Requesting them returns their
values — Broken Object Property Level Authorization / Excessive Data Exposure,
OWASP API Security Top 10 **API3:2023**, CWE-200 / CWE-639.

The confirmation is a **single benign request** (the packet's D3 / §10 line):
it selects the operator-named sensitive fields on a single object and fires only
when those fields come back **non-null**. A server that gates them (returning
null, or an authorization error) yields **no finding** — and the sensitive
*values* are **redacted** in the stored evidence (we prove the field was
*returned*, we do not exfiltrate its contents).

Because it actively requests fields the caller may not be entitled to, the check
is **active** (gated behind ``--active``, off by default) and is never part of
``--checks all``. The operator supplies the field and the sensitive sub-fields,
e.g.::

    enshroud --target … --checks field-authz --active \\
        --auth-header "Authorization: Bearer <low-priv-session>" \\
        --authz-field me --authz-sensitive ssn,creditCard,passwordHash

References:
  * OWASP API Security Top 10 — API3:2023 Broken Object Property Level
    Authorization (formerly Excessive Data Exposure + Mass Assignment)
  * CWE-200 — Exposure of Sensitive Information; CWE-639 — Authorization Bypass
  * *Black Hat GraphQL* — Authorization Bypasses (field-level)
"""
from __future__ import annotations

import json
import re
from typing import Any

from enshroud.client import GraphQLClient

EVIDENCE_MAX_LEN = 500

# Sensitive field-name shapes used to (a) raise severity and (b) decide
# redaction of values in the evidence blob. Substring match, case-insensitive.
_SENSITIVE_HINT = re.compile(
    r"(ssn|social|creditcard|credit_card|card|cvv|password|passwd|secret|"
    r"token|apikey|api_key|private|salary|dob|birth|passport|taxid|tax_id|"
    r"bank|account_?number|routing)",
    re.IGNORECASE,
)


def build_overfetch_query(query_field: str, sensitive_fields: list[str]) -> str:
    """Build a single query selecting ``id`` plus the sensitive fields."""
    selection = " ".join(dict.fromkeys(["id", *sensitive_fields])) or "id"
    return f"{{ {query_field} {{ {selection} }} }}"


def _redact_value(field: str, value: Any) -> Any:
    """Mask a sensitive value for evidence while preserving the non-sensitive."""
    if _SENSITIVE_HINT.search(field) and value not in (None, ""):
        return "<redacted>"
    return value


def _leaked_sensitive(obj: dict[str, Any], sensitive_fields: list[str]) -> list[str]:
    """Return the requested sensitive fields the server returned non-null."""
    return [f for f in sensitive_fields if obj.get(f) not in (None, "")]


async def check(
    client: GraphQLClient,
    *,
    active: bool = False,
    query_field: str | None = None,
    sensitive_fields: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Confirm a field-level authorization gap with one benign over-fetch.

    No-op unless explicitly enabled and configured:

      * ``active`` must be True (the ``--active`` flag).
      * ``query_field`` and a non-empty ``sensitive_fields`` list must be given
        — there is no safe default sensitive field to request.

    Fires a single finding listing the sensitive fields the server returned
    without field-level authorization. A server that nulls/blocks them yields no
    finding. Sensitive *values* are redacted in the evidence.
    """
    findings: list[dict[str, Any]] = []

    if not active or not query_field or not sensitive_fields:
        return findings

    # De-duplicate while preserving order; drop empties.
    sensitive = list(dict.fromkeys(f for f in sensitive_fields if f))
    if not sensitive:
        return findings

    query = build_overfetch_query(query_field, sensitive)
    try:
        resp = await client.query(query)
    except Exception:
        return findings

    data = resp.get("data")
    if not isinstance(data, dict):
        return findings
    obj = data.get(query_field)
    if not isinstance(obj, dict):
        return findings

    leaked = _leaked_sensitive(obj, sensitive)
    if not leaked:
        # Every sensitive field was gated (null) or absent — authz enforced.
        return findings

    # Build redacted evidence: prove the fields were *returned* without leaking
    # their contents off-host.
    redacted_obj = {k: _redact_value(k, v) for k, v in obj.items()}
    evidence = json.dumps({"data": {query_field: redacted_obj}})[:EVIDENCE_MAX_LEN]

    # Severity: HIGH when any leaked field looks genuinely sensitive (PII /
    # credential shaped), MEDIUM for a plain property-level authz gap.
    high = any(_SENSITIVE_HINT.search(f) for f in leaked)
    severity = "HIGH" if high else "MEDIUM"

    findings.append(
        {
            "category": "field_level_authz_missing",
            "severity": severity,
            "title": (
                f"Field-Level Authorization Missing (Excessive Data Exposure) "
                f"on `{query_field}`"
            ),
            "owasp": ["API3:2023"],
            "cwe": ["CWE-200", "CWE-639"],
            "query_field": query_field,
            "leaked_fields": leaked,
            "confirmation": {
                "method": "benign_poc",
                "evidence": (
                    f"sensitive fields returned without field-level "
                    f"authorization: {leaked} (values redacted)"
                ),
                "blast_radius": (
                    f"excessive data exposure of {', '.join(leaked)} for every "
                    f"object reachable via `{query_field}` (NOT enumerated here)"
                ),
                "reproduction": (
                    f"request {build_overfetch_query(query_field, leaked)} with a "
                    "session that should not see these fields"
                ),
            },
            "evidence": evidence,
            "description": (
                f"Selecting the field(s) {leaked} on `{query_field}` returned "
                "their values to a caller that should not be able to read them. "
                "GraphQL authorization is commonly enforced only at the "
                "query/object level, so individual sensitive fields are left "
                "ungated and any client that knows the field name can request "
                "them — Broken Object Property Level Authorization (excessive "
                "data exposure). enshroud confirmed the gap with a single benign "
                "request; the returned values are redacted in this evidence."
            ),
            "reproduction": (
                f"POST {{\"query\": \"{build_overfetch_query(query_field, leaked)}\"}} "
                "with a low-privilege session and observe the sensitive field "
                "values in the response."
            ),
            "impact": (
                "Sensitive data (PII, credentials, internal state) is exposed to "
                "callers who pass query/object-level authorization but should not "
                "see these specific fields. Because the leak is per-field, it is "
                "easily missed by object-level access reviews and maps to OWASP "
                "API3:2023 (CWE-200 / CWE-639)."
            ),
            "remediation": (
                "Apply authorization at the field/property level, not only at the "
                "query or object level: gate sensitive fields with a schema "
                "directive (`@auth`) or per-resolver check so they are nulled or "
                "rejected for unauthorized callers. Audit every resolver that "
                "exposes PII or credential-shaped fields and ensure the field-"
                "level check runs even when the parent object is accessible."
            ),
        }
    )

    return findings
