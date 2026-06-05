"""Enum-value suggestion-oracle leak check.

This is the **third** distinct ``didYouMean`` suggestion-oracle axis in
graphql-js, complementing the two axes already covered by ``suggestion-leak``
(argument-name and type-name):

1. **Selection-set field-name** — ``FieldsInSetCanMerge`` /
   ``FieldsOnCorrectTypeRule`` — owned by ``field-oracle`` / ``schema-fuzz``.
2. **Argument-name** — ``KnownArgumentNamesRule`` — owned by
   ``suggestion-leak``.
3. **Type-name in fragment condition** — ``KnownTypeNamesRule`` — owned by
   ``suggestion-leak``.
4. **Enum value** — ``ValuesOfCorrectTypeRule`` — **this check.**

The ``ValuesOfCorrectTypeRule`` validator fires when a literal value is
supplied to an enum-typed argument but the literal is not a valid enum member.
If suggestions are enabled, graphql-js emits::

    Expected type "StatusEnum", found ACTIV. Did you mean the enum value
    "ACTIVE" or "INACTIVE"?

An attacker who knows (or can guess) *one enum-typed argument name* on *any
query field* (discoverable via the argument-name oracle from ``suggestion-leak``,
schema fuzzing, or introspection) can submit a phonetically-close probe and
enumerate the entire enum value set from the suggestion list — even when
introspection is completely disabled.

**How this check works:**

1. Attempt introspection to discover enum-typed arguments on ``queryType``
   fields.  If introspection is disabled, fall back to a universal meta-field
   probe: ``__type(kind: FAKE_ENUM_VALUE)`` — the ``kind`` argument of
   ``__type`` is ``String``-typed and will not yield an enum suggestion, but
   ``__schema.queryType.fields[N].args[M].type.kind`` is an enum
   (``__TypeKind``).  Since we cannot guarantee introspection access, we use
   a distinct, introspection-independent probe path described below.

2. **Universal probe (introspection-independent):** graphql-js validates
   inline enum literals against the schema-defined enum type. The
   ``__Schema.queryType`` field takes no arguments, so there is no enum
   argument on the meta-fields accessible without introspection. However,
   when introspection IS available, any discovered enum-typed argument on a
   query field becomes a probe surface.

3. **Introspection-dependent flow (primary):**
   a. Fetch ``queryType.fields[*].args[*].type`` to find an enum-typed arg.
   b. Take its first declared enum value ``V`` from
      ``__type(name: "<EnumTypeName>") { enumValues { name } }``.
   c. Construct a near-miss probe by truncating ``V`` to ``V[:-1]``
      (one deletion from the end) — a one-edit-distance typo that triggers
      ``getSuggestionsForEnumValues`` in graphql-js.
   d. Send the probe. If the response contains "Did you mean" referencing
      ``V``, the enum oracle is open.

The check emits at most one finding per invocation.  It is included in
``--checks all`` because it requires only introspection (which is itself
already a reportable finding when enabled, ``introspection`` check) and
produces no side effects — strictly read-only, validation-halting.

**Severity:** LOW — same as ``field-oracle`` / ``suggestion-leak`` axes.
Recon-multiplier: the leaked enum values expose internal domain vocabulary
(user status strings, permission levels, feature flags) that accelerates
targeted injection and authorisation-bypass attempts.

**Competitor gap:** graphql-cop / InQL / graphw00f / Clairvoyance do not
probe the ``ValuesOfCorrectTypeRule`` enum-suggestion axis.

References:
  * graphql-js ``src/validation/rules/ValuesOfCorrectTypeRule.ts``
  * OWASP GraphQL Cheat Sheet — "Information Exposure Through Suggestions"
  * HackerOne report corpus: suggestion oracles as recon primitives
"""
from __future__ import annotations

import json
import re
from typing import Any

from enshroud.client import GraphQLClient

# Introspection query: enumerate query-type fields and their arguments,
# capturing the type name and kind (and the ofType chain for non-null / list
# wrappers). We walk up to two layers of wrapping to handle ``NonNull(Enum)``
# and ``NonNull(List(NonNull(Enum)))`` argument shapes.
_ARG_INTROSPECTION = """{
  __schema {
    queryType {
      fields(includeDeprecated: true) {
        name
        args {
          name
          type {
            kind name
            ofType {
              kind name
              ofType { kind name }
            }
          }
        }
      }
    }
  }
}"""

# Fetch the declared values of a named enum type.  Used to construct a
# near-miss probe value (one deletion from the first declared value).
_ENUM_VALUES_QUERY = """{
  __type(name: "%s") {
    enumValues(includeDeprecated: true) { name }
  }
}"""

# Maximum length of the evidence payload included in a finding (bytes).
EVIDENCE_MAX_LEN = 500

# Minimum enum value length to produce a non-empty truncated probe.
# A single-char value like ``A`` would truncate to the empty string, which is
# not a valid GraphQL enum literal.
_MIN_ENUM_VALUE_LEN = 2

# Regex matching the graphql-js ``ValuesOfCorrectTypeRule`` suggestion clause.
# Captures the entire "Did you mean ..." phrase so we can then scan it for
# all enum-value identifiers (graphql-js may list two: "ACTIVE" or "INACTIVE").
_DID_YOU_MEAN_CLAUSE = re.compile(
    r"[Dd]id you mean\s+(?:the enum value\s+)?(.+?)(?:\?|$)",
)
# All UPPER_CASE identifiers inside a suggestion clause.
_ENUM_IDENT = re.compile(r"[A-Z_][A-Z0-9_]+")


def _unwrap_type(type_obj: dict[str, Any]) -> dict[str, Any]:
    """Unwrap NON_NULL / LIST wrappers to reach the named type."""
    while type_obj and type_obj.get("kind") in ("NON_NULL", "LIST"):
        inner = type_obj.get("ofType")
        if inner is None:
            break
        type_obj = inner
    return type_obj


def _find_enum_arg(
    schema: dict[str, Any],
) -> tuple[str, str, str] | None:
    """Return ``(field_name, arg_name, enum_type_name)`` for the first found
    enum-typed argument on any query-type field.

    Returns ``None`` if introspection is disabled or no enum argument exists.
    """
    try:
        qt = schema["data"]["__schema"]["queryType"]
        fields = qt.get("fields") or []
    except (KeyError, TypeError):
        return None

    for field in fields:
        field_name = field.get("name") or ""
        for arg in field.get("args") or []:
            arg_name = arg.get("name") or ""
            type_obj = _unwrap_type(arg.get("type") or {})
            if type_obj.get("kind") == "ENUM" and type_obj.get("name"):
                return field_name, arg_name, type_obj["name"]
    return None


def _extract_suggestions(error_message: str) -> list[str]:
    """Pull every enum-value identifier surfaced by a ``Did you mean`` hint.

    Handles both single-value ("Did you mean the enum value "ACTIVE"?") and
    multi-value ("Did you mean "ACTIVE" or "INACTIVE"?") formats emitted by
    graphql-js's getSuggestionsForEnumValues helper.
    """
    seen: dict[str, None] = {}
    for clause_m in _DID_YOU_MEAN_CLAUSE.finditer(error_message):
        clause = clause_m.group(1)
        for tok in _ENUM_IDENT.findall(clause):
            if tok not in seen:
                seen[tok] = None
    return list(seen.keys())


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Probe the enum-value suggestion-oracle axis (``ValuesOfCorrectTypeRule``).

    Returns at most one finding when the server leaks enum values via
    ``Did you mean`` suggestions in response to a probe carrying a
    deliberately-wrong enum literal.  No finding is emitted when introspection
    is unavailable, no enum-typed argument is found, or the server suppresses
    suggestions.
    """
    # Step 1: introspect for an enum-typed argument.
    try:
        schema_resp = await client.query(_ARG_INTROSPECTION)
    except Exception:
        return []

    found = _find_enum_arg(schema_resp)
    if found is None:
        return []

    field_name, arg_name, enum_type_name = found

    # Step 2: fetch the enum's declared values.
    try:
        ev_resp = await client.query(_ENUM_VALUES_QUERY % enum_type_name)
    except Exception:
        return []

    try:
        enum_values: list[str] = [
            v["name"]
            for v in (ev_resp["data"]["__type"]["enumValues"] or [])
            if isinstance(v.get("name"), str)
        ]
    except (KeyError, TypeError):
        return []

    # Pick the first value that is long enough to produce a non-empty probe.
    target_value: str | None = next(
        (v for v in enum_values if len(v) >= _MIN_ENUM_VALUE_LEN), None
    )
    if target_value is None:
        return []

    # Step 3: construct a one-deletion near-miss and probe.
    probe_value = target_value[:-1]          # one-edit-distance truncation
    # Build a query that passes the near-miss literal to the discovered arg.
    # Use __typename as the sole selection so the probe is read-only and
    # resolver-halting regardless of the field's return type.
    probe_query = (
        f"{{ {field_name}({arg_name}: {probe_value}) {{ __typename }} }}"
    )

    try:
        probe_resp = await client.query(probe_query)
    except Exception:
        return []

    # Step 4: detect a suggestion containing the real value.
    errors = probe_resp.get("errors") or []
    all_suggestions: list[str] = []
    for error in errors:
        msg = error.get("message") or ""
        if isinstance(msg, str):
            for sug in _extract_suggestions(msg):
                if sug not in all_suggestions:
                    all_suggestions.append(sug)

    if target_value not in all_suggestions:
        return []

    evidence = json.dumps(
        {
            "field": field_name,
            "argument": arg_name,
            "enum_type": enum_type_name,
            "probe_value": probe_value,
            "target_value": target_value,
            "suggested_values": all_suggestions,
            "sample_error": (errors[0].get("message") or "")[:200] if errors else "",
        }
    )[:EVIDENCE_MAX_LEN]

    return [
        {
            "category": "enum_value_oracle_leak",
            "severity": "LOW",
            "title": "Schema Enum-Value Suggestion Oracle Leak (ValuesOfCorrectTypeRule)",
            "enum_type": enum_type_name,
            "field": field_name,
            "argument": arg_name,
            "leaked_values": all_suggestions,
            "evidence": evidence,
            "description": (
                "The server returns ``Did you mean <EnumValue>`` suggestions "
                "in validation error messages when an invalid literal is "
                "supplied to an enum-typed argument. graphql-js's "
                "``ValuesOfCorrectTypeRule`` emits the ``getSuggestionsForEnumValues`` "
                "hint by default; if suggestions are not suppressed globally, "
                "an attacker can enumerate the full enum value set one probe "
                f"at a time. Enum type affected: ``{enum_type_name}`` "
                f"(argument ``{arg_name}`` on field ``{field_name}``)."
            ),
            "reproduction": (
                f"POST `{{\"query\": \"{probe_query}\"}}` and observe a "
                "``Did you mean\" hint in the errors array naming one or more "
                f"``{enum_type_name}`` values. Repeat with each returned "
                "suggestion truncated by one character to walk the full value set."
            ),
            "impact": (
                "Leaked enum values expose internal domain vocabulary — status "
                "strings, permission levels, feature flags, role identifiers — "
                "that accelerates targeted injection, IDOR, and "
                "authorisation-bypass attempts. The oracle is independent of "
                "the field-name (``field-oracle``) and argument-name / "
                "type-name (``suggestion-leak``) axes: an operator who has "
                "suppressed those axes may still leave enum-value suggestions "
                "enabled."
            ),
            "remediation": (
                "Suppress suggestions across the entire validator. In "
                "graphql-js, disable ``getSuggestionsForEnumValues`` or "
                "apply a ``NoSuggestionsRule`` / equivalent. In Apollo Server "
                "/ Yoga, set ``validationRules: [NoSuggestionsRule]`` or use "
                "``formatError`` to strip ``Did you mean`` text from "
                "``ValuesOfCorrectTypeRule`` messages in addition to the "
                "``Cannot query field`` pattern."
            ),
        }
    ]
