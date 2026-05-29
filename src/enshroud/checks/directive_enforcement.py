"""`@skip` / `@include` directive-enforcement bypass check.

GraphQL spec §3.13 mandates that a server **must not** include a field in the
response when ``@skip(if: true)`` or ``@include(if: false)`` is applied to that
field's selection — the directive is the spec's contract that the client can ask
for a field to be excluded from the result on a per-request basis. A server that
*returns* such a field is violating the spec at the executor layer: its
directive-evaluation logic is broken (a custom executor skipping the directive
pass, a middleware that drops directives before resolution, a string-based
"strip-directives" pre-processor, or a schema layer that ignores the built-in
directives entirely).

This is a *distinct* class from every other directive check in the suite:

* ``directive-abuse`` (POST_V01 #9) probes whether the server *validates* the
  directive layer — it stacks the *non-repeatable* ``@skip`` directive 500× on
  one field and sends an *undefined* directive, looking for a validation /
  complexity rejection. It never asks whether a single, legal, spec-defined
  directive is *honoured*.
* ``defer-abuse`` (POST_V01 #14) probes the *incremental-delivery* directives
  (``@defer`` / ``@stream``) for exposure of a connection-holding feature.

This check is the first to probe **enforcement** of the two universally-supported
built-in directives. Detection is read-only, single-request-per-probe, and
strictly differential — anchored entirely on the ``__typename`` meta-field so no
schema knowledge is required and nothing is ever mutated.

Two probes, both packing an unconditional ``__typename`` with a directive-gated
``__typename`` under a distinct alias:

1. ``@skip(if: true)``  — ``{ keep: __typename drop: __typename @skip(if: true) }``
2. ``@include(if: false)`` — ``{ keep: __typename drop: __typename @include(if: false) }``

A spec-compliant executor returns only the ``keep`` key. A finding fires per
probe when the server returns the ``drop`` key (the directive was ignored), and
only then. A server that fails the request, omits ``drop``, or returns no data
at all produces no finding — no false positives on a hardened endpoint.
"""
from __future__ import annotations

import json
from typing import Any

from enshroud.client import GraphQLClient

# Aliases used for the two response keys. ``KEEP_KEY`` is unconditional and must
# always be present (sanity anchor — its absence means the server returned a
# completely different shape and we should not infer enforcement either way).
# ``DROP_KEY`` carries the directive: a spec-compliant server omits it; a server
# that returns it ignored the directive.
KEEP_KEY = "enshroudKeep"
DROP_KEY = "enshroudDrop"

# The two probes. Each is a single-request, single-field-shape query whose only
# selections are aliased ``__typename`` meta-fields — read-only by construction.
_PROBES: list[tuple[str, str, str]] = [
    (
        "skip_if_true",
        "@skip(if: true)",
        (
            "{ "
            f"{KEEP_KEY}: __typename "
            f"{DROP_KEY}: __typename @skip(if: true) "
            "}"
        ),
    ),
    (
        "include_if_false",
        "@include(if: false)",
        (
            "{ "
            f"{KEEP_KEY}: __typename "
            f"{DROP_KEY}: __typename @include(if: false) "
            "}"
        ),
    ),
]


def _drop_key_returned(resp: dict[str, Any]) -> bool:
    """Return True when the server returned the directive-gated alias.

    The signal is strictly: the response carries a ``data`` object whose
    ``DROP_KEY`` is present and non-null. ``KEEP_KEY`` must also be present so
    we know the executor actually ran the operation (otherwise an empty / null
    ``data`` would falsely look like a "no drop returned" success). Any error
    response, missing data, or absent keep-key is conservative no-signal.
    """
    if resp.get("errors"):
        return False
    data = resp.get("data")
    if not isinstance(data, dict):
        return False
    if KEEP_KEY not in data or data.get(KEEP_KEY) is None:
        # The executor did not produce the unconditional anchor — we cannot
        # safely infer anything about directive enforcement from this shape.
        return False
    return DROP_KEY in data and data[DROP_KEY] is not None


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Probe whether the server honours `@skip(if: true)` / `@include(if: false)`."""
    findings: list[dict[str, Any]] = []

    accepted: list[str] = []
    probe_evidence: dict[str, dict[str, Any]] = {}

    for vector, directive_label, query in _PROBES:
        try:
            resp = await client.query(query)
        except Exception:
            # Transport-level failure — be conservative and skip this vector.
            continue
        probe_evidence[vector] = {
            "directive": directive_label,
            "response": resp,
        }
        if _drop_key_returned(resp):
            accepted.append(vector)

    if not accepted:
        return findings

    # Build one consolidated finding listing every vector the server failed on.
    directives_failed = [
        next(d for v, d, _ in _PROBES if v == vec) for vec in accepted
    ]
    evidence = json.dumps(
        {
            "accepted_vectors": accepted,
            "directives_failed": directives_failed,
            "keep_alias": KEEP_KEY,
            "drop_alias": DROP_KEY,
            "sample_responses": {
                v: probe_evidence[v]["response"] for v in accepted
            },
        }
    )[:800]

    findings.append(
        {
            "category": "directive_enforcement_bypass",
            "severity": "MEDIUM",
            "title": "Built-in Directive Enforcement Bypass (@skip / @include)",
            "accepted_vectors": accepted,
            "directives_failed": directives_failed,
            "evidence": evidence,
            "description": (
                "The server returned a field whose selection carried "
                f"{' and '.join(directives_failed)}. Per GraphQL spec §3.13 the "
                "executor must omit a field from the response when "
                "`@skip(if: true)` or `@include(if: false)` is applied to its "
                "selection — these are the two universally-supported built-in "
                "directives that let a client control per-request inclusion. "
                "Returning the gated field proves the directive-evaluation "
                "stage was not run (or was bypassed) before resolution. This "
                "is distinct from `directive-abuse` (which probes the "
                "*validation* of the directive layer, not its *enforcement*) "
                "and from `defer-abuse` (which probes the incremental-delivery "
                "directives)."
            ),
            "reproduction": (
                "POST `{ "
                f"{KEEP_KEY}: __typename {DROP_KEY}: __typename @skip(if: true)"
                " }`. A spec-compliant server returns "
                f"`{{\"data\": {{\"{KEEP_KEY}\": \"Query\"}}}}` (no "
                f"`{DROP_KEY}` key). A vulnerable server also returns "
                f"`{DROP_KEY}`. The same applies to "
                "`@include(if: false)`."
            ),
            "impact": (
                "Built-in directive enforcement is broken at the executor "
                "layer. Any *custom* schema directive layered on top of the "
                "same evaluation pass — `@auth`, `@requireRole`, `@cost`, "
                "`@cacheControl`, `@rateLimit`, vendor authorization "
                "directives — is at risk of being silently skipped the same "
                "way, because schema-directive enforcement reuses the same "
                "directive-resolution hook the built-ins do. The immediate, "
                "concrete impact is that clients cannot rely on `@skip` / "
                "`@include` to exclude sensitive fields they explicitly opted "
                "out of."
            ),
            "remediation": (
                "Restore standard directive evaluation in the executor: every "
                "selection must run the directive-evaluation step (resolving "
                "`@skip` / `@include` against the supplied arguments) before "
                "the resolver is invoked. If you are running a custom or "
                "string-rewriting middleware that strips directives, route "
                "them through the spec-defined evaluation path instead. "
                "Audit every custom schema directive (`@auth`, `@cost`, …) — "
                "if `@skip` / `@include` are not honoured, those directives "
                "are almost certainly not honoured either."
            ),
        }
    )

    return findings
