"""Field-duplication DoS check (POST_V01 #8).

The third denial-of-service axis. `depth-dos` probes nesting depth and
`alias-batch` probes breadth via distinct aliases; this check probes *repetition*
— whether the server collapses repeated identical fields / repeated fragment
spreads or expands the work super-linearly.

Two probes, both built only from `__typename`, so no schema knowledge is needed:

1. **Raw field duplication** — `{ __typename __typename ... }` (N identical
   selections). A spec-compliant executor *merges* identical sibling fields, so a
   well-behaved server still does O(1) work; but many servers (and any custom
   middleware that counts "selections" before merging) pay O(N) cost, and a
   server that returns N results or accepts the request without any
   complexity/limit error has no protection against repetition amplification.

2. **Repeated fragment spread** — one fragment defined on `Query` containing a
   single `__typename`, spread N times into the operation:
   `{ ...F ...F ... } fragment F on Query { __typename }`. This is the classic
   fragment-amplification vector (each spread re-expands the fragment body), and
   it is the building block of the circular-fragment attacks that crash
   non-validating executors.

Read-only and benign: every selection is `__typename`, so nothing is mutated and
no resolver beyond the meta-field is invoked. The finding fires only when the
server accepts the duplication *without* a complexity / limit / depth / fragment
error, which is the signal that repetition is uncapped.
"""
from __future__ import annotations

import json
from typing import Any

from enshroud.client import GraphQLClient

# Number of repeated fields / fragment spreads per probe. Large enough to make a
# missing cap obvious, small enough to stay a single cheap request.
DUP_COUNT = 500

# Error keywords that indicate the server *did* cap the repetition (de-dup,
# complexity scoring, fragment limits, or a generic max/limit guard). When any of
# these appear the server is protected and no finding fires.
_LIMIT_KEYWORDS = (
    "complexity",
    "too many",
    "exceeds",
    "limit",
    "max ",
    "maximum",
    "depth",
    "fragment",
    "duplicate",
    "cost",
    "rejected",
)


def _build_duplicate_field_query(count: int) -> str:
    """`{ __typename __typename ... }` with `count` identical selections."""
    body = " ".join(["__typename"] * count)
    return "{ " + body + " }"


def _build_repeated_fragment_query(count: int) -> str:
    """`{ ...F ...F ... } fragment F on Query { __typename }`."""
    spreads = " ".join(["...F"] * count)
    return "{ " + spreads + " } fragment F on Query { __typename }"


def _is_limited(resp: dict[str, Any]) -> bool:
    """True when the response carries a complexity/limit/fragment error."""
    errors = resp.get("errors") or []
    messages = " ".join((e.get("message") or "").lower() for e in errors)
    if not messages:
        return False
    return any(kw in messages for kw in _LIMIT_KEYWORDS)


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Probe whether the server caps repeated fields / fragment spreads."""
    findings: list[dict[str, Any]] = []

    field_query = _build_duplicate_field_query(DUP_COUNT)
    fragment_query = _build_repeated_fragment_query(DUP_COUNT)

    vectors: list[tuple[str, str]] = [
        ("repeated_fields", field_query),
        ("repeated_fragment_spread", fragment_query),
    ]

    accepted: list[str] = []
    last_resp: dict[str, Any] | None = None

    for vector, query in vectors:
        try:
            resp = await client.query(query)
        except Exception:
            # A transport error / non-2xx (e.g. the server rejected the request
            # outright) counts as the server NOT silently accepting the abuse.
            continue
        last_resp = resp
        if _is_limited(resp):
            # The server explicitly capped this vector — protected.
            continue
        # No limit error: the server accepted the duplicated work.
        accepted.append(vector)

    if not accepted:
        return findings

    evidence = json.dumps(
        {
            "accepted_vectors": accepted,
            "duplication_count": DUP_COUNT,
            "sample_response": (json.dumps(last_resp)[:300] if last_resp else None),
        }
    )

    findings.append(
        {
            "category": "field_duplication_dos",
            "severity": "MEDIUM",
            "title": "Field / Fragment Duplication Not Limited",
            "accepted_vectors": accepted,
            "duplication_count": DUP_COUNT,
            "evidence": evidence,
            "description": (
                f"The server accepted a request that repeated the same field "
                f"or fragment {DUP_COUNT} times without returning a complexity, "
                "fragment, or limit error. This is the repetition axis of "
                "GraphQL denial-of-service, distinct from query depth "
                "(depth-dos) and alias breadth (alias-batch): a server that "
                "does not de-duplicate or cost-cap repeated selections can be "
                "forced to perform super-linear work from a single request."
            ),
            "reproduction": (
                "Send a POST with a repeated selection set, e.g. "
                "{ __typename __typename ... } or a fragment spread repeated "
                f"{DUP_COUNT} times: "
                "{ ...F ...F ... } fragment F on Query { __typename }"
            ),
            "impact": (
                "An attacker can amplify resolver and validation cost with a "
                "single small request by repeating fields or fragment spreads, "
                "degrading service or causing an outage. Repeated/circular "
                "fragment spreads can crash executors that do not enforce a "
                "fragment-expansion limit."
            ),
            "remediation": (
                "Enforce a query-complexity / cost limit that counts repeated "
                "selections and fragment spreads, and cap the number of "
                "fragment spreads per operation. Reject operations whose "
                "computed cost exceeds a fixed budget before execution."
            ),
        }
    )

    return findings
