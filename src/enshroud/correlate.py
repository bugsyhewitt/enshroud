"""Fingerprint-informed correlation of findings.

POST_V01 direction #2 promised that, once the GraphQL engine is fingerprinted,
"other checks can optionally consume the fingerprint result to weight their
confidence levels." The ``fingerprint`` check identifies the engine and ships a
catalogue of that engine's ``known_default_insecure_behaviors``; this module is
the consumer side of that promise.

When a scan runs ``fingerprint`` alongside the vulnerability checks, this layer
correlates each vulnerability finding against the identified engine's catalogued
default-insecure behaviours. If a finding's category lines up with a documented
default for that engine, the finding is annotated with an ``engine_context``
block that:

* names the engine and the specific catalogued behaviour,
* sets a machine-readable ``confidence`` of ``expected-default`` (this is the
  engine's documented out-of-the-box posture, so the detection is high
  confidence and unlikely to be a false positive), and
* appends a short human-readable note to the finding's ``impact`` so the
  H1-markdown report explains *why* the issue is present on this stack.

This is purely additive: it never changes a finding's category or severity and
never removes findings. If no engine was identified (no ``fingerprint`` finding,
or an unrecognised engine), correlation is a no-op and findings pass through
unchanged.
"""
from __future__ import annotations

import copy
from typing import Any

# Map each vulnerability finding category to the set of lower-cased keywords
# that, when present in an engine behaviour string, indicate the finding is an
# expected out-of-the-box default for that engine. A finding correlates to a
# behaviour when *any* keyword group for its category is fully matched, i.e.
# every keyword in that group appears somewhere in the behaviour text.
#
# Keyword groups are intentionally specific to avoid spurious correlation
# (e.g. "introspection enabled" should not correlate to a behaviour that merely
# mentions "introspection ... disabled in production").
_CATEGORY_KEYWORDS: dict[str, list[list[str]]] = {
    "introspection_enabled": [["introspection", "enabled"]],
    "field_suggestion_oracle": [
        ["field", "suggestion"],
        ["did you mean"],
        ["suggestions", "enabled"],
    ],
    "schema_reconstructed": [
        ["field", "suggestion"],
        ["did you mean"],
        ["suggestions", "enabled"],
    ],
    "apq_enabled": [["apq"], ["persisted quer"]],
    "apq_no_rate_limit": [["apq"], ["persisted quer"]],
    "apq_unrestricted_registration": [
        ["apq", "unauthenticated"],
        ["apq", "cache population"],
        ["persisted quer", "unauthenticated"],
    ],
    "csrf_via_content_type": [["csrf"]],
    "depth_dos": [["depth"], ["complexity"]],
    "dangerous_mutation_exposed": [["schema"], ["users connection"]],
}


def _behavior_matches_category(behavior: str, category: str) -> bool:
    """Return True if ``behavior`` documents the default behind ``category``."""
    haystack = behavior.lower()
    for group in _CATEGORY_KEYWORDS.get(category, []):
        if all(keyword in haystack for keyword in group):
            return True
    return False


def _engine_from_fingerprint(findings: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Extract engine context from the first ``engine_identified`` finding."""
    for finding in findings:
        if finding.get("category") == "engine_identified":
            return {
                "engine_name": finding.get("engine_name"),
                "engine_display_name": finding.get(
                    "engine_display_name", finding.get("engine_name")
                ),
                "behaviors": list(
                    finding.get("known_default_insecure_behaviors") or []
                ),
            }
    return None


def _matching_behaviors(engine: dict[str, Any], category: str) -> list[str]:
    return [
        behavior
        for behavior in engine.get("behaviors") or []
        if _behavior_matches_category(behavior, category)
    ]


def _annotate(
    finding: dict[str, Any], engine: dict[str, Any], behaviors: list[str]
) -> dict[str, Any]:
    """Return a copy of ``finding`` annotated with engine correlation context."""
    annotated = copy.deepcopy(finding)
    display = (
        engine.get("engine_display_name") or engine.get("engine_name") or "the identified engine"
    )
    annotated["engine_context"] = {
        "engine_name": engine.get("engine_name"),
        "engine_display_name": display,
        "confidence": "expected-default",
        "matched_behaviors": behaviors,
        "note": (
            f"This finding matches a documented default-insecure behaviour of "
            f"{display}, so it reflects the engine's out-of-the-box posture "
            f"rather than a one-off misconfiguration."
        ),
    }

    behavior_lines = "\n".join(f"- {b}" for b in behaviors)
    addendum = (
        f"\n\nEngine correlation ({display}): this is an expected default for "
        f"the identified server, increasing detection confidence. Relevant "
        f"catalogued defaults:\n{behavior_lines}"
    )
    existing_impact = annotated.get("impact")
    if isinstance(existing_impact, str):
        annotated["impact"] = existing_impact + addendum
    else:
        annotated["impact"] = addendum.lstrip()
    return annotated


def correlate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Annotate findings with engine context derived from the fingerprint.

    Returns a new list. The original findings are not mutated. When no engine
    was identified, the input findings are returned unchanged (still a new
    list, preserving the no-mutation contract).
    """
    engine = _engine_from_fingerprint(findings)
    if engine is None or not engine.get("engine_name"):
        return list(findings)

    correlated: list[dict[str, Any]] = []
    for finding in findings:
        category = finding.get("category")
        if category == "engine_identified" or not category:
            correlated.append(finding)
            continue
        behaviors = _matching_behaviors(engine, category)
        if behaviors:
            correlated.append(_annotate(finding, engine, behaviors))
        else:
            correlated.append(finding)
    return correlated
