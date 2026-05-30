"""Argument-name and type-name suggestion-oracle leak check.

The v0.1 ``field-oracle`` check (``src/enshroud/checks/field_oracle.py``) probes
a single suggestion axis: the **selection-set field-name** oracle. It sends one
probe (``{ nonExistentFieldXyzzy }``) and looks for graphql-js's
``getSuggestedFieldNames`` "Did you mean" hint in the resulting
``Cannot query field`` error. That is exactly one of the three distinct
``didYouMean`` suggestion oracles graphql-js (and every executor that mirrors
its validation rules — Apollo Server, graphene, Hot Chocolate, juniper,
async-graphql, gqlgen, sangria, …) emits at validation time:

1. **Selection-set field-name** — owned by ``field-oracle`` /
   ``schema-fuzz`` (opt-in).
2. **Argument-name** — emitted by ``KnownArgumentNamesRule`` when an unknown
   argument is supplied to a known field. Leaks **input argument names** on
   real fields, e.g. ``Unknown argument "naem" on field "Query.__type".
   Did you mean "name"?``
3. **Type-name** (fragment condition) — emitted by ``KnownTypeNamesRule`` when a
   fragment's type condition references an undefined type. Leaks **type
   names**, e.g. ``Unknown type "Queryy". Did you mean "Query"?``

Axes 2 and 3 are uncovered by every existing check in the suite. They probe
**distinct schema metadata** — input argument names and type names live in
different parts of the schema from output field names — and they are emitted by
distinct validation rules. The documented partial-hardening misconfiguration is
common: an operator strips the ``Did you mean`` text from
``Cannot query field`` errors via a ``formatError`` regex (the most-cited
remediation snippet on Stack Overflow / blog posts for "field suggestion
oracle") and assumes the suggestion oracle is closed. But the regex never
matches an ``Unknown argument`` or ``Unknown type`` error, so axes 2 and 3
continue to leak schema structure on every request — ``field-oracle`` will
return no finding while the oracle is still wide open.

Both probes target universal introspection metadata that exists on every
GraphQL server, regardless of whether application introspection is enabled —
the validation rules run at parse / validate time, before the introspection
authorisation gate. The probes are strictly read-only by construction (a
typo'd argument or fragment condition halts at validation; no resolver is
invoked) and single-request per axis.

The check is strictly differential: a finding fires only when the server's
error message carries a ``Did you mean`` suggestion containing a recognisable
real identifier (``name`` for argument-name, ``Query`` for type-name). A
server that suppresses suggestions on every axis (``NoSuggestionsRule`` or
``noDeprecatedCustomRule`` equivalent applied to the validator), or rejects
the probes at the transport layer, produces no finding.
"""
from __future__ import annotations

import json
import re
from typing import Any

from enshroud.client import GraphQLClient

# Argument-name probe: `__type(naem: "Query")` — `__type` is a spec-mandated
# meta-field on every GraphQL server (§4.5); `naem` is a one-edit-distance
# typo of `name`, the field's lone required argument. graphql-js validates the
# argument *names* at parse / validate time via `KnownArgumentNamesRule`,
# independently of whether the resolver would have executed, so the
# suggestion fires even on servers that block introspection at execution.
ARG_PROBE = "{ __type(naem: \"Query\") { name } }"

# The real argument name we expect to see surfaced in a "Did you mean" hint.
# Used only as a confirmation substring — we never echo it as a finding token.
ARG_REAL_NAME = "name"

# Type-name probe: a fragment condition naming an undefined type that is one
# edit distance from the universal `Query` root type. graphql-js validates
# fragment type conditions via `KnownTypeNamesRule`. The probe contains no
# field-name selections that could trip `field-oracle`'s `nonExistentFieldXyzzy`
# heuristic, and uses only the universal `__typename` meta-field inside the
# fragment so no schema knowledge is required.
TYPE_PROBE = "{ ... on Queryy { __typename } }"

# The real type name we expect to see surfaced in the type-name suggestion.
TYPE_REAL_NAME = "Query"

# Bound for the response evidence payload included in a finding. Mirrors the
# 500-byte ceiling field_oracle uses for the same purpose.
EVIDENCE_MAX_LEN = 500

# Regex for the documented graphql-js phrasing across both axes. We accept
# either a bare hint (`Did you mean name?`) or a quoted hint
# (`Did you mean "name"?`), matching the same accommodation field-oracle makes
# for executors that quote differently.
_DID_YOU_MEAN = re.compile(
    r"[Dd]id you mean\s+[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?",
)


def _extract_suggested_identifiers(error_message: str) -> list[str]:
    """Pull every identifier the server hinted at in `Did you mean ...`.

    graphql-js emits one or more identifiers separated by commas / "or";
    we capture the first-token form here (``Did you mean "id"``) — additional
    tokens after the first are typically more of the same axis and the leading
    one is sufficient to prove the oracle is open. Returns deduplicated
    identifiers in arrival order, which keeps the evidence small and stable.
    """
    seen: dict[str, None] = {}
    for match in _DID_YOU_MEAN.finditer(error_message):
        token = match.group(1)
        if token and token not in seen:
            seen[token] = None
    return list(seen.keys())


def _suggestion_signal(resp: dict[str, Any], expected_real: str) -> tuple[bool, list[str]]:
    """Return ``(fired, extracted)`` for a single suggestion probe response.

    A probe is judged to have leaked the oracle when the server returned at
    least one ``errors`` entry whose message contains a ``Did you mean`` hint
    that surfaces ``expected_real`` (the real identifier we know corresponds
    to our deliberately-typo'd probe). Requiring the *known* real identifier
    avoids false positives from generic ``Did you mean ...`` text that
    references something unrelated (e.g. a custom suggestion enum entirely
    decoupled from our probe shape).
    """
    errors = resp.get("errors") or []
    extracted: list[str] = []
    for error in errors:
        msg = error.get("message") or ""
        if not isinstance(msg, str):
            continue
        for ident in _extract_suggested_identifiers(msg):
            if ident not in extracted:
                extracted.append(ident)
    fired = expected_real in extracted
    return fired, extracted


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Probe the argument-name and type-name suggestion-oracle axes.

    Returns at most one finding listing every axis that leaked. No finding is
    emitted when both axes are silent (suggestions suppressed across the
    validator) or when both probes fail at the transport layer.
    """
    findings: list[dict[str, Any]] = []

    probe_defs: list[tuple[str, str, str, str]] = [
        # (axis_id, human_label, query, expected_real_identifier)
        (
            "argument_name",
            "argument-name oracle (KnownArgumentNamesRule)",
            ARG_PROBE,
            ARG_REAL_NAME,
        ),
        (
            "type_name",
            "type-name oracle (KnownTypeNamesRule)",
            TYPE_PROBE,
            TYPE_REAL_NAME,
        ),
    ]

    leaked_axes: list[str] = []
    leaked_labels: list[str] = []
    extracted_by_axis: dict[str, list[str]] = {}
    response_by_axis: dict[str, dict[str, Any]] = {}

    for axis_id, label, query, expected in probe_defs:
        try:
            resp = await client.query(query)
        except Exception:
            # Transport-level failure — be conservative and skip this axis.
            continue
        fired, extracted = _suggestion_signal(resp, expected)
        response_by_axis[axis_id] = resp
        extracted_by_axis[axis_id] = extracted
        if fired:
            leaked_axes.append(axis_id)
            leaked_labels.append(label)

    if not leaked_axes:
        return findings

    evidence = json.dumps(
        {
            "leaked_axes": leaked_axes,
            "extracted_identifiers": {
                axis: extracted_by_axis.get(axis, []) for axis in leaked_axes
            },
            "sample_responses": {
                axis: response_by_axis[axis] for axis in leaked_axes
            },
        }
    )[:EVIDENCE_MAX_LEN]

    findings.append(
        {
            "category": "suggestion_oracle_leak",
            "severity": "LOW",
            "title": "Schema Suggestion Oracle Leak (Argument / Type axes)",
            "leaked_axes": leaked_axes,
            "leaked_axis_labels": leaked_labels,
            "evidence": evidence,
            "description": (
                "The server returns `Did you mean` suggestions in validation "
                "error messages on schema axes that the `field-oracle` check "
                "does not cover: "
                f"{', '.join(leaked_labels)}. graphql-js (and every executor "
                "that mirrors its validation rules) emits three distinct "
                "didYouMean oracles — selection-set field-name (owned by "
                "`field-oracle`), argument-name (`KnownArgumentNamesRule`), "
                "and type-name in fragment conditions (`KnownTypeNamesRule`) "
                "— and a common partial-hardening misconfiguration strips "
                "only the first via a `Cannot query field` regex in "
                "`formatError`, leaving the other two wide open. An attacker "
                "can enumerate input argument names and type names without "
                "introspection."
            ),
            "reproduction": (
                "Argument-name axis: POST "
                f'`{{"query": "{ARG_PROBE}"}}` and observe '
                "`Unknown argument \"naem\" on field \"Query.__type\". "
                "Did you mean \"name\"?` in the errors. "
                "Type-name axis: POST "
                f'`{{"query": "{TYPE_PROBE}"}}` and observe '
                "`Unknown type \"Queryy\". Did you mean \"Query\"?`. Both "
                "probes are read-only and halt at validation."
            ),
            "impact": (
                "Schema enumeration over the argument and type axes proceeds "
                "with one request per guessed identifier, even when "
                "introspection is disabled and `field-oracle`'s selection-set "
                "axis is suppressed. Recovered argument names reveal input "
                "shapes for sensitive resolvers (admin-only filters, "
                "permission-keyed mutations); recovered type names support "
                "follow-on fragment-based recovery (`__schema`-keyword "
                "deny-list bypass via fragment spreads, see "
                "`introspection-bypass`)."
            ),
            "remediation": (
                "Suppress suggestions across the entire validator, not just "
                "on field-name errors. In graphql-js, configure the "
                "validation rules to omit `getSuggestionsForArguments` and "
                "`getSuggestionsForTypes` (a common pattern is to install a "
                "`NoSuggestionsRule` that overrides every `Did you mean` "
                "code path). In Apollo Server, use `formatError` to strip "
                "`Did you mean` text on `Unknown argument` and `Unknown "
                "type` messages in addition to `Cannot query field`."
            ),
        }
    )

    return findings
