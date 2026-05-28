"""Directive-overloading / `@skip`/`@include` abuse check (POST_V01 #9).

A fourth probe axis that complements the three denial-of-service checks
(`depth-dos` = nesting, `alias-batch` = breadth, `field-dup` = repetition) with
a recon-and-DoS dimension that targets the *directive* layer specifically.

Two read-only probes, both anchored on the `__typename` meta-field so no schema
knowledge is required and nothing is ever mutated:

1. **Directive overloading** — `{ __typename @skip(if: false) @skip(if: false)
   ... }` with the built-in `@skip` directive repeated N times on a single
   field. The GraphQL spec forbids repeating a non-repeatable directive on one
   location, so a *validating* executor rejects this with a "directive ...may
   not be used more than once" error. A server that accepts the overloaded
   selection has weak (or skipped) directive validation, and must still parse
   and process every directive occurrence — a cheap super-linear amplification
   vector (the directive-layer analogue of field duplication). Custom
   middleware that evaluates directives before validation pays O(N) work.

2. **Unknown-directive recon** — `{ __typename @enshroudUnknownDirective }`. A
   spec-compliant server rejects an undefined directive with "Unknown directive
   ...". A server that *accepts* it (returns `data` with no directive error) has
   directive validation disabled or runs a permissive custom executor — a recon
   signal that the directive layer is unguarded. The error text is also mined
   for a "Did you mean" suggestion, which can leak the names of internal/custom
   directives (e.g. `@auth`, `@cacheControl`, `@cost`, `@stream`, `@defer`) that
   hint at the server's tooling and policy enforcement.

The finding fires per accepted vector and is MEDIUM (low false-positive risk:
the overloading probe is invalid per the spec, so any server that returns data
for it is genuinely not validating; the unknown-directive probe only fires on a
clear accept). When the recon probe leaks a custom-directive suggestion, that
leaked name is surfaced in the evidence even if no finding fires for that vector.
"""
from __future__ import annotations

import json
import re
from typing import Any

from enshroud.client import GraphQLClient

# Number of repeated `@skip` directives in the overloading probe. Large enough
# that an unvalidated executor's per-directive cost is obvious, small enough to
# remain a single cheap request.
DIRECTIVE_COUNT = 500

# A directive name that no real schema defines, used for the unknown-directive
# recon probe. Deliberately namespaced to avoid colliding with a real directive.
_UNKNOWN_DIRECTIVE = "enshroudUnknownDirective"

# Error keywords that indicate the server *did* validate the directive layer and
# rejected the probe (non-repeatable-directive enforcement, unknown-directive
# rejection, or a generic complexity / limit guard). When any of these appear the
# server is protected for that vector and no finding fires.
_LIMIT_KEYWORDS = (
    "directive",        # "may not be used more than once", "unknown directive"
    "more than once",
    "not be used",
    "unknown",
    "undefined",
    "may not",
    "complexity",
    "too many",
    "exceeds",
    "limit",
    "max ",
    "maximum",
    "cost",
    "rejected",
)

# A "Did you mean @X" suggestion in an unknown-directive error leaks the names of
# directives the server actually defines — useful recon (e.g. @auth, @cost).
_SUGGESTION_RE = re.compile(r'did you mean\s+(.+?)[\?\.]', re.IGNORECASE)


def _build_directive_overload_query(count: int) -> str:
    """`{ __typename @skip(if: false) @skip(if: false) ... }` (count copies)."""
    directives = " ".join(["@skip(if: false)"] * count)
    return "{ __typename " + directives + " }"


def _build_unknown_directive_query() -> str:
    """`{ __typename @enshroudUnknownDirective }`."""
    return "{ __typename @" + _UNKNOWN_DIRECTIVE + " }"


def _error_messages(resp: dict[str, Any]) -> str:
    """Concatenate all error messages from a response, lower-cased."""
    errors = resp.get("errors") or []
    return " ".join((e.get("message") or "").lower() for e in errors)


def _is_limited(resp: dict[str, Any]) -> bool:
    """True when the response carries a directive / complexity / limit error."""
    messages = _error_messages(resp)
    if not messages:
        return False
    return any(kw in messages for kw in _LIMIT_KEYWORDS)


def _extract_directive_suggestion(resp: dict[str, Any]) -> str | None:
    """Pull a leaked custom-directive name from a 'Did you mean' suggestion."""
    errors = resp.get("errors") or []
    for e in errors:
        message = e.get("message") or ""
        m = _SUGGESTION_RE.search(message)
        if m:
            # Keep only directive-looking tokens (e.g. @auth, @cost, "@auth").
            tokens = re.findall(r"@?[A-Za-z_][A-Za-z0-9_]*", m.group(1))
            directives = [t if t.startswith("@") else f"@{t}" for t in tokens]
            if directives:
                return ", ".join(directives)
    return None


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Probe whether the server validates / caps directive overloading."""
    findings: list[dict[str, Any]] = []

    vectors: list[tuple[str, str]] = [
        ("directive_overloading", _build_directive_overload_query(DIRECTIVE_COUNT)),
        ("unknown_directive_accepted", _build_unknown_directive_query()),
    ]

    accepted: list[str] = []
    leaked_directives: str | None = None
    last_resp: dict[str, Any] | None = None

    for vector, query in vectors:
        try:
            resp = await client.query(query)
        except Exception:
            # A transport error / non-2xx (the server rejected the request
            # outright) counts as the server NOT silently accepting the abuse.
            continue
        last_resp = resp

        # Recon: even when the unknown-directive probe is rejected, the error may
        # leak the names of real custom directives via a "Did you mean" hint.
        if vector == "unknown_directive_accepted":
            suggestion = _extract_directive_suggestion(resp)
            if suggestion:
                leaked_directives = suggestion

        if _is_limited(resp):
            # The server explicitly validated / capped this vector — protected.
            continue
        # No directive/limit error: the server accepted the abusive directive.
        accepted.append(vector)

    if not accepted and not leaked_directives:
        return findings

    evidence = json.dumps(
        {
            "accepted_vectors": accepted,
            "directive_count": DIRECTIVE_COUNT,
            "leaked_directives": leaked_directives,
            "sample_response": (json.dumps(last_resp)[:300] if last_resp else None),
        }
    )

    # Build a description that reflects which signals actually fired.
    parts: list[str] = []
    if "directive_overloading" in accepted:
        parts.append(
            f"accepted a single field carrying the non-repeatable @skip "
            f"directive {DIRECTIVE_COUNT} times without a validation or "
            "complexity error"
        )
    if "unknown_directive_accepted" in accepted:
        parts.append(
            f"accepted the undefined directive @{_UNKNOWN_DIRECTIVE} without "
            "an 'Unknown directive' validation error"
        )
    if leaked_directives:
        parts.append(
            f"leaked the names of custom directives via a field-suggestion "
            f"hint ({leaked_directives})"
        )
    description = (
        "The server " + "; it also ".join(parts) + ". "
        "This indicates the directive layer is weakly validated: the "
        "directive axis (distinct from query depth, alias breadth, and field "
        "repetition) can be abused both to amplify parse/validation cost from "
        "a single request and to enumerate the server's internal directive "
        "tooling."
    )

    findings.append(
        {
            "category": "directive_abuse",
            "severity": "MEDIUM",
            "title": "Directive Overloading / Unknown-Directive Validation Weakness",
            "accepted_vectors": accepted,
            "directive_count": DIRECTIVE_COUNT,
            "leaked_directives": leaked_directives,
            "evidence": evidence,
            "description": description,
            "reproduction": (
                "Send a POST repeating a non-repeatable built-in directive on "
                "one field, e.g. { __typename @skip(if: false) @skip(if: false) "
                "... } (" + str(DIRECTIVE_COUNT) + " copies), and a POST with an "
                "undefined directive: { __typename @" + _UNKNOWN_DIRECTIVE + " }. "
                "A validating server rejects both; an accepting server is "
                "vulnerable."
            ),
            "impact": (
                "An attacker can amplify directive parsing/validation cost with "
                "a single small request by stacking hundreds of directive "
                "occurrences on one field, contributing to denial of service. "
                "A server that accepts unknown directives (or leaks real "
                "directive names via suggestions) also hands an attacker recon "
                "about internal directive-based tooling such as auth, caching, "
                "or cost-limiting directives."
            ),
            "remediation": (
                "Enable strict query validation so non-repeatable directives "
                "are rejected when repeated and unknown directives are rejected "
                "outright, and ensure directive processing happens after (not "
                "before) validation. Disable field/directive suggestion hints in "
                "production so error messages do not enumerate the schema's "
                "directives. Count directive occurrences toward the query "
                "complexity budget."
            ),
        }
    )

    return findings
