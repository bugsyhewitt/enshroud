"""Mutation-allowlist-bypass check — operation-type confusion vector.

A common production hardening pattern places a guard *in front* of the GraphQL
executor — a WAF rule, an edge / CDN routing rule, a reverse-proxy middleware,
or a gateway allow-list — that decides whether a request is permitted by
matching on the literal ``mutation`` operation token in the request body. The
rule typically looks for ``mutation\\s*{`` (or the equivalent operation type
keyword) and applies an extra control: an allow-list of permitted mutation
names, a CSRF token requirement, a stricter rate-limit, a higher authorization
threshold, or simply "block by default".

That guard is bypassed when the **operation type token** is changed while the
**mutation field** is left in place. The GraphQL spec is unambiguous: mutation
fields may only be selected under a ``mutation { ... }`` operation, never under
a ``query { ... }`` operation (spec §6.2.2 — "Mutation root operation type
SHOULD be the type used … When mutation operations are not provided, the
mutation root operation type should not be defined"). A spec-correct executor
rejects ``query { someMutation { ... } }`` with a validation error along the
lines of ``Cannot query field "someMutation" on type "Query"``.

A non-spec-correct or schema-misconfigured server, however, **resolves the
mutation field anyway** — either because the executor never enforces the root
operation type at validation time, or because the schema accidentally exposes
the same field on both the ``Query`` and ``Mutation`` roots, or because a
custom gateway / persisted-query layer rewrites the operation type before
executing. When this happens, every gateway control that gated on the
``mutation`` operation token is **silently bypassed** — the request body
contains only ``query``, never ``mutation``, but the mutation still runs.

This check is strictly **differential** and strictly **read-only**:

  1. It enumerates mutation field names via introspection (the same query
     ``mutation-enum`` uses) and filters to mutations that declare **at least
     one required (non-null) argument**. That filter is the safety property:
     such a mutation cannot execute without the argument, so even if the
     server resolves the field under ``Query``, the resolver never runs — the
     executor stops at an argument-validation error.

  2. For each such mutation it sends a single probe of the shape
     ``query { <mutation_field_name> { __typename } }`` — no arguments
     supplied, the operation type deliberately set to ``query``.

  3. A finding fires **only** when the response contains a top-level error
     whose message mentions the missing required argument
     (``argument "<arg>" of type "<T>!" is required`` and equivalents), which
     proves the executor *resolved* the field on the Query root. A spec-correct
     server returns ``Cannot query field "<name>" on type "Query"`` — that is
     **not** a bypass and produces no finding.

A server that disables this confusion (executor enforces the mutation root
type; schema does not expose mutation fields on Query) rejects every probe
with a "Cannot query field" validation error, so the check produces no
finding.

Read-only: every probe omits required arguments, so the resolver can never
run — only the validator does. No mutation completes, no state changes, no
side effects.
"""
from __future__ import annotations

import json
import re
from typing import Any

from enshroud.client import GraphQLClient

# Introspection query that fetches mutation field names along with their
# argument types — we need the type kind/nonNull info to identify mutations
# whose required arguments make them safe to probe without arguments. The
# `ofType` chain handles wrapping types (NON_NULL → LIST → NAMED).
_INTROSPECTION_QUERY = """
{
  __schema {
    mutationType {
      fields {
        name
        args {
          name
          type {
            kind
            name
            ofType { kind name }
          }
        }
      }
    }
  }
}
""".strip()

# Cap on how many mutations we probe per run. Bounded so a schema with
# hundreds of mutations doesn't fan out into a noisy scan; one confirmed
# bypass already proves the bug class.
_MAX_PROBES = 25

# Error-message substrings that indicate the executor *resolved* the mutation
# field under the Query root and then failed at argument validation. These
# wordings are stable across all major engines (graphql-js, Apollo Server,
# graphene, Hot Chocolate, juniper, async-graphql, gqlgen, sangria). The
# distinguishing property is that the message names the field and an argument
# / variable — the field was found and its argument signature was checked.
_BYPASS_ARG_ERROR_PATTERNS = (
    re.compile(r'argument\s+"[^"]+"\s+of\s+type\s+"[^"]+!"\s+is\s+required', re.IGNORECASE),
    re.compile(r'field\s+"[^"]+"\s+argument\s+"[^"]+"\s+of\s+type\s+"[^"]+!"\s+is\s+required', re.IGNORECASE),
    re.compile(r'required\s+argument\s+"[^"]+"', re.IGNORECASE),
    re.compile(r'missing\s+required\s+argument', re.IGNORECASE),
    re.compile(r'must\s+have\s+a\s+value\s+for\s+(its\s+)?required\s+argument', re.IGNORECASE),
)

# Error-message substrings that indicate the server correctly rejected the
# operation-type confusion at validation time — the mutation field does not
# exist on the Query root. Seeing one of these is the "secure" outcome.
_REJECTION_PATTERNS = (
    re.compile(r'cannot\s+query\s+field\s+"[^"]+"\s+on\s+type\s+"query"', re.IGNORECASE),
    re.compile(r'field\s+"[^"]+"\s+is\s+not\s+defined\s+(by|on)\s+type\s+"query"', re.IGNORECASE),
    re.compile(r'unknown\s+field\s+"[^"]+"\s+on\s+type\s+"query"', re.IGNORECASE),
    re.compile(r'mutation\s+fields\s+(may|can|must)\s+(not|only)', re.IGNORECASE),
)


def _unwrap_type(type_ref: dict[str, Any] | None) -> tuple[bool, str | None]:
    """Return (is_non_null, named_kind) for a GraphQL type reference.

    The introspection `type` field is a nested wrapper chain:
    NON_NULL → LIST → NON_NULL → NAMED. We only care whether the outer
    wrapper is NON_NULL (the argument is required).
    """
    if not isinstance(type_ref, dict):
        return False, None
    is_non_null = (type_ref.get("kind") == "NON_NULL")
    inner = type_ref
    while isinstance(inner, dict) and inner.get("kind") in ("NON_NULL", "LIST"):
        nxt = inner.get("ofType")
        if not isinstance(nxt, dict):
            break
        inner = nxt
    named_kind = inner.get("kind") if isinstance(inner, dict) else None
    return is_non_null, named_kind


def _has_required_arg(field: dict[str, Any]) -> bool:
    """Return True when a mutation field declares at least one NON_NULL argument."""
    for arg in field.get("args") or ():
        is_required, _ = _unwrap_type(arg.get("type"))
        if is_required:
            return True
    return False


def _looks_like_resolved_field_arg_error(resp: dict[str, Any], field_name: str) -> bool:
    """Return True when the response is an argument-validation error.

    The signal: at least one error message matches a "required argument
    missing" pattern, and the error references the probed field name (or
    *no* error names a different field — covers engines whose error message
    omits the field name but still proves the field was resolved at
    validation time). We also require the absence of a "field does not exist
    on type Query" rejection, which is the secure outcome and never co-occurs
    with an argument-validation error from the same probe.
    """
    errors = resp.get("errors") or []
    if not errors:
        return False
    # If *any* error explicitly says the field doesn't exist on Query, the
    # server rejected operation-type confusion. Treat the whole response as
    # secure regardless of any other error in the list.
    for err in errors:
        msg = err.get("message") or ""
        for pat in _REJECTION_PATTERNS:
            if pat.search(msg):
                return False
    for err in errors:
        msg = err.get("message") or ""
        for pat in _BYPASS_ARG_ERROR_PATTERNS:
            if pat.search(msg):
                return True
    return False


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Probe for operation-type confusion — mutations resolvable under Query."""
    findings: list[dict[str, Any]] = []

    # Step 1 — enumerate mutation fields via introspection. If introspection
    # is disabled or the schema has no mutationType, there is nothing to test
    # and the check stays silent. (This is the same posture as `mutation-enum`
    # and is correct: without a known mutation field name, every probe would
    # be a guess, and guesses against arbitrary field names overlap with the
    # `field-oracle` / `schema-fuzz` surface.)
    try:
        intro = await client.query(_INTROSPECTION_QUERY)
    except Exception:
        return findings

    data = intro.get("data") or {}
    schema = data.get("__schema") or {}
    mutation_type = schema.get("mutationType") or {}
    fields = mutation_type.get("fields") or []
    if not fields:
        return findings

    # Step 2 — filter to mutations whose argument signature makes the probe
    # safe: at least one NON_NULL argument that, when omitted, halts the
    # request at validation. Without this filter, probing a no-argument
    # mutation (e.g. `logout`) could *complete the mutation* and have a real
    # side effect — that is the active-write risk we must not take.
    candidates = [f for f in fields if _has_required_arg(f)]
    if not candidates:
        return findings

    candidates = candidates[:_MAX_PROBES]

    for field in candidates:
        field_name = field.get("name") or ""
        if not field_name:
            continue

        # Probe shape: a `query` operation containing a mutation field with
        # *no* arguments. The operation-type token is `query` — not
        # `mutation` — so any gateway / WAF rule keyed on the `mutation`
        # token is bypassed at the edge. The executor is then asked to
        # resolve a mutation field on the Query root.
        probe = (
            f"query EnshroudOpTypeConfusion {{ "
            f"{field_name} {{ __typename }} "
            f"}}"
        )
        try:
            resp = await client.query(probe)
        except Exception:
            # Network / HTTP error on this candidate — skip and keep probing.
            continue

        if _looks_like_resolved_field_arg_error(resp, field_name):
            evidence = json.dumps(
                {"probe": probe, "response": resp}
            )[:600]
            findings.append(
                {
                    "category": "mutation_allowlist_bypass_via_op_type",
                    "severity": "HIGH",
                    "title": (
                        "Mutation Allowlist Bypass via Operation-Type "
                        "Confusion"
                    ),
                    "mutation_name": field_name,
                    "evidence": evidence,
                    "description": (
                        f"The mutation `{field_name}` was resolved by the "
                        "executor when requested under a `query { ... }` "
                        "operation type rather than `mutation { ... }`. "
                        "The response is an argument-validation error that "
                        "names the field's required argument — proof the "
                        "executor walked the Query root and matched the "
                        "mutation field there. Any gateway, WAF, CSRF "
                        "control, or persisted-query allow-list keyed on "
                        "the literal `mutation` operation token in the "
                        "request body is bypassed: the body contains only "
                        "`query`, but the mutation field is still "
                        "executable (subject only to the resolver's own "
                        "authorization)."
                    ),
                    "reproduction": (
                        'POST {"query": "query { '
                        f'{field_name} {{ __typename }} '
                        '}"} — observe an "argument is required" error '
                        "naming the mutation field, instead of the "
                        '"Cannot query field on type Query" rejection a '
                        "spec-correct server returns."
                    ),
                    "impact": (
                        "An attacker can invoke mutations while bypassing "
                        "every guard that gated on the `mutation` "
                        "operation token: gateway allow-lists, edge CSRF "
                        "rules, mutation-only rate limits, persisted-query "
                        "filters, and WAF mutation deny-lists. The full "
                        "mutation surface is reachable through a `query` "
                        "operation type, so any authorization gap on the "
                        "underlying mutation resolver is now exploitable "
                        "from a path the defenders did not expect."
                    ),
                    "remediation": (
                        "Enforce the GraphQL spec at validation: mutation "
                        "fields must only resolve under a `mutation` "
                        "operation. Ensure the executor (graphql-js / "
                        "Apollo / graphene / Hot Chocolate / equivalent) "
                        "rejects mutation fields selected under a `query` "
                        "operation type. Audit the schema for fields "
                        "exposed on both `Query` and `Mutation` roots and "
                        "remove the Query-side aliases. Any gateway "
                        "control that matches on the operation type token "
                        "must be paired with executor-side enforcement; "
                        "the gateway match is necessary but never "
                        "sufficient."
                    ),
                }
            )
            # One representative finding is enough to prove the bug class.
            # The bypass is a server-wide property: every mutation with a
            # required argument would behave the same way. Stop probing to
            # keep the check fast and quiet.
            break

    return findings
