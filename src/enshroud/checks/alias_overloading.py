"""Alias-overloading: per-real-field alias-dedupe / rate-limit bypass.

This check targets the canonical "brute-force via aliases" GraphQL bug class:
an attacker packs many aliased copies of the *same* real query / mutation
field into a single request, so a server that throttles or rate-limits by
literal field name (or by an alias-unaware cost-analysis pass) executes every
copy under its own response key without ever tripping the per-field counter.
This is the documented vector behind GraphQL login / OTP / coupon brute-force
write-ups, where one HTTP request executes hundreds of `login` attempts in
parallel.

The existing v0.1 ``alias-batch`` check (`alias_batching`, MEDIUM) probes
**alias breadth using the meta-field ``__typename``**. ``__typename`` is a
schema-introspection meta-field — it is never the target of a per-field rate
limit, brute-force protection, or resolver cost weighting, because it does
not resolve to a backend operation. As a result ``alias-batch`` only answers
"does this server enforce *any* alias / complexity cap?" — it can never
demonstrate that a cap that *is* enforced on real fields is bypassable by
aliasing those real fields.

``alias-overloading`` answers the distinct question: when a real, resolved
query field is the alias target, does the server still execute every aliased
copy? It is strictly differential against ``alias-batch``:

* The probe uses a **non-meta, resolvable top-level query field** discovered
  via introspection. ``__typename`` is explicitly excluded.
* The check is **silent** when no real top-level query fields are
  introspectable (no false positives on schema-less / introspection-disabled
  endpoints — that surface is owned by ``introspection`` /
  ``introspection-bypass`` / ``schema-fuzz``).
* The finding requires that the server return **every** aliased response key
  with a non-null payload — proving that each aliased copy independently
  resolved. A server that enforces a per-real-field alias cap returns a
  complexity / rate-limit error and produces no finding; a server that omits
  aliases or returns nulls for them also produces no finding.

Because the probe selects only ``__typename`` under each aliased field, the
check is **read-only by construction**: no real resolver arguments are
supplied (the discovered candidates are filtered to argless fields), so no
side-effecting mutation can ever execute, even if the discovered field
happens to be a mutation-shaped query field.
"""
from __future__ import annotations

import json
from typing import Any

from enshroud.client import GraphQLClient

# How many aliased copies of the real field to pack into one request. Mirrors
# the order of magnitude of `alias-batch` (100 __typename aliases) so the two
# checks probe the same alias-breadth regime — what differs is the alias
# target (real field vs meta-field), which is the whole point of the check.
ALIAS_COUNT = 50

# Alias-key prefix. Deliberately distinctive so a parser/grep that strips
# aliases by name pattern cannot coincidentally collide with a real schema
# identifier.
_ALIAS_PREFIX = "enshroudOverloadAlias"

_INTROSPECTION_QUERY = (
    "{ __schema { queryType { fields { name args { name } } } } }"
)

_EVIDENCE_LEN = 600


def _discover_argless_real_field(resp: dict[str, Any]) -> str | None:
    """Pick a top-level query field that has no arguments and is non-meta.

    Required: argless (so we can probe without supplying real args, keeping
    the check strictly read-only) and non-meta (so we are not just re-probing
    ``__typename`` / ``__schema`` / ``__type``, which is the `alias-batch`
    surface, not this check's).
    """
    schema = (resp.get("data") or {}).get("__schema") or {}
    query_type = schema.get("queryType") or {}
    for f in query_type.get("fields") or []:
        name = f.get("name") or ""
        if not name or name.startswith("__"):
            continue
        args = f.get("args") or []
        if len(args) > 0:
            continue
        return name
    return None


def _build_overload_query(field: str, count: int) -> str:
    """Build a single query with ``count`` aliased copies of ``field``.

    Each aliased copy selects only ``__typename`` under the field, which is
    the safest universally-valid sub-selection for an OBJECT-returning field
    and is a syntactic no-op for SCALAR-returning fields under any executor
    that tolerates the redundant selection. The probe is read-only: the
    discovered field has no args (filtered by `_discover_argless_real_field`),
    so no resolver argument can carry attacker-controlled input.
    """
    parts = [
        f"{_ALIAS_PREFIX}{i}: {field} {{ __typename }}"
        for i in range(1, count + 1)
    ]
    return "{ " + " ".join(parts) + " }"


def _count_executed_aliases(resp: dict[str, Any], count: int) -> int:
    """Count how many aliased response keys carry a non-null payload.

    The bypass signal is *every* aliased copy resolving independently — i.e.
    all `count` alias keys present in the top-level `data` map with non-null
    values. A spec-correct cost-analysis cap returns an error (no `data` or
    `data` is null) and yields zero; a partial result (some aliases dropped /
    nulled) likewise stays below the threshold.
    """
    data = resp.get("data")
    if not isinstance(data, dict):
        return 0
    executed = 0
    for i in range(1, count + 1):
        key = f"{_ALIAS_PREFIX}{i}"
        if key in data and data[key] is not None:
            executed += 1
    return executed


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Probe for alias-overloading per-real-field rate-limit / cost-cap bypass."""
    findings: list[dict[str, Any]] = []

    try:
        intro = await client.query(_INTROSPECTION_QUERY)
    except Exception:
        # No introspection → no candidate → no finding. That surface is owned
        # by `introspection` / `introspection-bypass` / `schema-fuzz`.
        return findings

    field = _discover_argless_real_field(intro)
    if field is None:
        # Either introspection was rejected or every top-level field is a
        # meta-field or requires args. Either way this check has nothing to
        # probe and must stay silent — a deliberate no-false-positive design.
        return findings

    overload_query = _build_overload_query(field, ALIAS_COUNT)

    try:
        resp = await client.query(overload_query)
    except Exception:
        return findings

    # If the server rejected the probe with a cost / complexity / rate-limit
    # error, the cap is enforced on real fields and there is no finding.
    errors = resp.get("errors") or []
    error_messages = " ".join(
        (e.get("message") or "").lower() for e in errors
    )
    cap_enforced_markers = (
        "alias", "complexity", "cost", "limit", "rate", "too many", "max",
        "throttle", "quota",
    )
    if any(marker in error_messages for marker in cap_enforced_markers):
        return findings

    executed = _count_executed_aliases(resp, ALIAS_COUNT)
    if executed < ALIAS_COUNT:
        # Partial / no execution means the server is not running every
        # aliased copy independently — no bypass demonstrated.
        return findings

    evidence = json.dumps(
        {"probe_field": field, "alias_count": ALIAS_COUNT, "response": resp}
    )[:_EVIDENCE_LEN]
    findings.append(
        {
            "category": "alias_overloading",
            "severity": "MEDIUM",
            "title": "Real-Field Alias Overloading (Per-Field Rate-Limit Bypass)",
            "probe_field": field,
            "aliased_copies_executed": ALIAS_COUNT,
            "evidence": evidence,
            "description": (
                f"The server executed {ALIAS_COUNT} aliased copies of the "
                f"real query field `{field}` in a single request, returning "
                "every aliased response key with non-null data. Unlike the "
                "`alias-batch` check, which probes breadth using the "
                "introspection meta-field `__typename` (never the target of "
                "real-world rate limits), this finding uses a non-meta, "
                "resolvable schema field as the alias target — the actual "
                "surface a brute-force attack against a `login` / OTP / "
                "coupon-redemption / password-reset resolver would exploit. "
                "A server that throttles or rate-limits by literal field "
                "name (or that runs an alias-unaware cost-analysis pass) "
                "executes every aliased copy under its own response key "
                "without ever incrementing the per-field counter."
            ),
            "reproduction": (
                f'POST {{"query": "{{ {_ALIAS_PREFIX}1: {field} '
                f"{{ __typename }} {_ALIAS_PREFIX}2: {field} {{ __typename }} "
                f"... {_ALIAS_PREFIX}{ALIAS_COUNT}: {field} "
                f'{{ __typename }} }}"}} and observe every alias key in the '
                "`data` map. Weaponise by replacing `__typename` with the "
                "real sub-selection (and, for fields that take args, by "
                "varying per-alias arguments) to pack many independent "
                "login / OTP / coupon attempts into one HTTP request."
            ),
            "impact": (
                "An attacker can bypass per-field rate-limits and brute-force "
                "protections by aliasing the protected field many times in a "
                "single request. The canonical impact is credential / OTP "
                "brute-force against a `login`-style mutation, but the same "
                "primitive enables coupon stuffing, password-reset enumeration, "
                "and any other per-field throttle that counts by field name "
                "rather than by resolved invocation."
            ),
            "remediation": (
                "Implement query cost analysis that counts every selection "
                "(aliased or not) toward the per-field budget, *and* enforce "
                "rate limits inside the resolver on the resolved invocation "
                "rather than on the literal field name in the operation text. "
                "If the engine offers an alias-aware complexity rule "
                "(graphql-cost-analysis, graphql-validation-complexity, "
                "Apollo Router's `max_aliases` / `max_root_fields`, Hot "
                "Chocolate cost analysis), enable it; otherwise add a "
                "validation pass that caps the number of aliased copies of "
                "any single underlying field per operation."
            ),
        }
    )

    return findings
