"""Circular-fragment validation check — fragment-cycle DoS / spec-bypass.

The GraphQL specification (§5.5.2.2, "Fragment spreads must not form cycles")
requires every executor to *statically reject* an operation whose fragment
definitions reference each other in a cycle, **before** execution begins:

    { ...A }
    fragment A on Query { __typename ...B }
    fragment B on Query { __typename ...A }

A spec-compliant validator detects the A → B → A cycle and returns a validation
error such as *"Cannot spread fragment 'A' within itself via 'B'."* — and never
executes the operation. A server that instead **accepts** the document (returns
``data`` with no error) or attempts to expand it (recursing until it exhausts the
stack / times out) has skipped this mandatory validation rule. That is a genuine
denial-of-service primitive: a single tiny request forces unbounded fragment
expansion, and it is the canonical "fragment cycle" crash documented for
non-validating and custom GraphQL middleware.

This is a **distinct axis** from the existing ``field-dup`` check. ``field-dup``
probes *repetition* — the same non-recursive fragment spread N times, which is
linear amplification. This check probes a *cycle* — mutually recursive fragments,
which the spec forbids outright and which a vulnerable server expands without
bound. ``field-dup`` deliberately uses a non-recursive fragment so it stays
benign on validating servers; the cyclic document here is the dangerous variant
that ``field-dup`` never sends.

Two probes, both anchored on ``__typename`` so no schema knowledge is needed and
nothing is ever mutated:

1. **Two-fragment cycle** — the A ⇄ B pair above. The common, textbook case.
2. **Self-referential fragment** — a single fragment that spreads itself:
   ``{ ...S } fragment S on Query { __typename ...S }``. The minimal cycle; some
   executors special-case the two-fragment form but miss direct self-reference.

The check fires when the server does **not** return a cycle/validation error for
a probe — either because it executed the document (returned ``data``) or because
the request failed at the transport layer in a way consistent with an expansion
crash (timeout / read error). It stays silent on a spec-compliant server that
rejects the cycle with a validation error, which is the safe behaviour.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from enshroud.client import GraphQLClient

CATEGORY = "fragment_cycle_dos"
SEVERITY = "MEDIUM"

# A mutually-recursive fragment pair (A -> B -> A). Every selection is the
# meta-field __typename, so the document is read-only; the only abusive property
# is the cycle, which a spec-compliant server must reject before execution.
_TWO_FRAGMENT_CYCLE = (
    "{ ...A } "
    "fragment A on Query { __typename ...B } "
    "fragment B on Query { __typename ...A }"
)

# The minimal cycle: a fragment that spreads itself directly.
_SELF_REFERENTIAL = (
    "{ ...S } "
    "fragment S on Query { __typename ...S }"
)

# Error keywords that indicate the server correctly applied the
# "fragment spreads must not form cycles" validation rule (or some
# complexity/limit guard) and rejected the cyclic document. When any of these
# appear in an error message the server is protected and no finding fires.
_CYCLE_REJECTION_KEYWORDS = (
    "cycle",
    "cyclic",
    "within itself",
    "recursive",
    "recursion",
    "spread fragment",
    "circular",
    "infinite",
    "complexity",
    "exceeds",
    "limit",
    "too deep",
    "depth",
    "max ",
    "maximum",
)


def _rejected_cycle(resp: dict[str, Any]) -> bool:
    """True when the response carries a cycle / validation / limit error."""
    errors = resp.get("errors") or []
    messages = " ".join((e.get("message") or "").lower() for e in errors)
    if not messages:
        return False
    return any(kw in messages for kw in _CYCLE_REJECTION_KEYWORDS)


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Probe whether the server rejects cyclic fragment definitions.

    Read-only: both probes select only ``__typename``. The finding fires when a
    probe is *not* rejected with a cycle/validation error — either the server
    executed the cyclic document (returned ``data``) or the request failed at the
    transport layer in a way consistent with an unbounded-expansion crash
    (timeout / read error), both of which indicate the mandatory cycle-validation
    rule was skipped.
    """
    findings: list[dict[str, Any]] = []

    probes: list[tuple[str, str]] = [
        ("two_fragment_cycle", _TWO_FRAGMENT_CYCLE),
        ("self_referential_fragment", _SELF_REFERENTIAL),
    ]

    accepted: list[str] = []
    crashed: list[str] = []
    last_resp: dict[str, Any] | None = None

    for vector, query in probes:
        try:
            resp = await client.query(query)
        except (httpx.TimeoutException, httpx.ReadError, httpx.RemoteProtocolError):
            # A timeout / dropped connection on a tiny cyclic document is a
            # strong signal the server tried to expand the cycle and choked —
            # i.e. it did NOT statically reject it. Treat as an accepted cycle.
            crashed.append(vector)
            continue
        except Exception:
            # Any other transport/HTTP error (e.g. 400 Bad Request, refused) is
            # the server rejecting the request — protected, no finding.
            continue
        last_resp = resp
        if _rejected_cycle(resp):
            # Spec-compliant: the cycle was caught by validation. Protected.
            continue
        # No cycle/validation error: the server accepted (and likely executed)
        # the cyclic document.
        accepted.append(vector)

    if not accepted and not crashed:
        return findings

    evidence = json.dumps(
        {
            "accepted_vectors": accepted,
            "crashed_vectors": crashed,
            "sample_response": (
                json.dumps(last_resp)[:300] if last_resp else None
            ),
        }
    )

    crashed_note = (
        " One or more probes also caused a transport timeout / dropped "
        "connection, consistent with the server attempting unbounded fragment "
        "expansion."
        if crashed
        else ""
    )

    findings.append(
        {
            "category": CATEGORY,
            "severity": SEVERITY,
            "title": "Cyclic Fragment Definitions Not Rejected",
            "accepted_vectors": accepted,
            "crashed_vectors": crashed,
            "evidence": evidence,
            "description": (
                "The server did not reject a GraphQL document containing "
                "mutually recursive (cyclic) fragment definitions. The GraphQL "
                "specification (§5.5.2.2, “Fragment spreads must not "
                "form cycles”) requires executors to statically reject such "
                "documents during validation, before execution. A server that "
                "accepts or attempts to expand them has skipped this mandatory "
                "rule. This is a distinct denial-of-service axis from repeated "
                "fragment spreads (field-dup): a cycle expands without bound "
                "rather than linearly." + crashed_note
            ),
            "reproduction": (
                "Send a POST with a cyclic fragment pair, e.g. "
                "{ ...A } fragment A on Query { __typename ...B } "
                "fragment B on Query { __typename ...A } "
                "and observe that the server does not return a "
                "“cannot spread fragment within itself” / cycle "
                "validation error."
            ),
            "impact": (
                "A single small request with cyclic fragments can force a "
                "non-validating executor into unbounded recursive expansion, "
                "exhausting CPU/stack and crashing the worker — a reliable "
                "denial-of-service primitive that bypasses depth and complexity "
                "limits because the abuse is in the fragment graph, not the "
                "query shape."
            ),
            "remediation": (
                "Use a spec-compliant GraphQL validator that enforces the "
                "“fragment spreads must not form cycles” rule "
                "(rule 5.5.2.2) and reject any operation whose fragment "
                "definitions reference each other in a cycle before execution. "
                "Do not disable or bypass standard validation in custom "
                "middleware."
            ),
        }
    )

    return findings
