"""JSON-array batching check (transport-level operation batching).

Many GraphQL servers accept a top-level JSON array as the request body —
``[{"query": "..."}, {"query": "..."}, ...]`` — and execute every operation in
the array, returning a parallel array of results. This is distinct from alias
batching (which packs many fields into a single operation): array batching packs
many *independent* operations, including repeated mutations, into one HTTP
request.

That makes it the canonical vector for bypassing per-request rate limits: an
attacker can send hundreds of `login` / `verifyOtp` / `redeemCoupon` mutations
in one request, defeating defenses that throttle requests rather than
operations. This class is behind multiple disclosed 2FA-bypass and
credential-stuffing reports (e.g. the HackerOne/Wallarm GraphQL batching
writeups). enshroud reports it as a HIGH finding because the downstream impact is
authentication brute-force, not mere resource consumption.

Detection is read-only and side-effect free: the probe batches a benign
`__typename` query repeatedly. A server that returns a parallel array of N
results for an N-element batch has array batching enabled.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from enshroud.client import GraphQLClient

# Number of operations to pack into the probe batch. Large enough to be
# unambiguous (a server that genuinely executes the whole array returns this
# many results) without being abusive.
BATCH_SIZE = 50

# Each element is a side-effect-free introspection-free query.
PROBE_QUERY = "{ __typename }"

BODY_PREFIX_LEN = 300


def _evidence(sent: int, returned: int, resp: httpx.Response) -> str:
    body_text = resp.text or ""
    return json.dumps(
        {
            "operations_sent": sent,
            "results_returned": returned,
            "response_status": resp.status_code,
            "response_body_prefix": body_text[:BODY_PREFIX_LEN],
        }
    )


def _count_array_results(resp: httpx.Response) -> int | None:
    """Return the number of results in a JSON-array batch response, or None.

    A server with array batching enabled answers a list request with a list of
    per-operation results. Anything else (a single object, an error object, a
    non-JSON body, or an HTTP error) means the batch was not executed as a
    batch — return None so the caller produces no finding.
    """
    if not (200 <= resp.status_code < 300):
        return None
    try:
        body = resp.json()
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(body, list):
        return None
    # Each element should look like a GraphQL result (a dict, typically with a
    # `data` or `errors` key). Count elements that executed (have `data`).
    executed = 0
    for item in body:
        if isinstance(item, dict) and item.get("data") is not None:
            executed += 1
    return executed


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Check whether the endpoint executes JSON-array operation batches."""
    findings: list[dict[str, Any]] = []

    queries = [PROBE_QUERY] * BATCH_SIZE
    try:
        resp = await client.post_batch(queries)
    except Exception:
        return findings

    returned = _count_array_results(resp)
    if returned is None or returned < BATCH_SIZE:
        return findings

    findings.append(
        {
            "category": "array_batching",
            "severity": "HIGH",
            "title": "JSON-Array Operation Batching Enabled (Rate-Limit Bypass)",
            "operations_per_request_accepted": BATCH_SIZE,
            "evidence": _evidence(BATCH_SIZE, returned, resp),
            "description": (
                f"The endpoint accepted a single HTTP request containing a JSON "
                f"array of {BATCH_SIZE} independent operations and executed all "
                "of them, returning a parallel array of results. Unlike alias "
                "batching, array batching packs separate operations — including "
                "repeated mutations — into one request, so any defense that "
                "rate-limits by request rather than by operation is bypassed."
            ),
            "reproduction": (
                "POST a JSON array body such as "
                '`[{"query":"{ __typename }"}, {"query":"{ __typename }"}, ...]` '
                f"with {BATCH_SIZE} elements. Observe a response that is a JSON "
                f"array of {BATCH_SIZE} results, confirming every operation ran. "
                "To weaponise, replace the probe with a sensitive mutation "
                "(e.g. `login`, `verifyOtp`, `redeemCoupon`)."
            ),
            "impact": (
                "An attacker can pack hundreds of authentication or "
                "state-changing mutations into a single request to brute-force "
                "credentials or one-time-passcodes, stuff coupon/voucher codes, "
                "or otherwise defeat per-request rate limiting and WAF counters."
            ),
            "remediation": (
                "Disable transport-level array batching unless it is required "
                "(Apollo Server: set `allowBatchedHttpRequests: false`; other "
                "servers offer equivalent toggles). If batching must stay on, "
                "cap the batch size and apply rate limiting per operation, not "
                "per HTTP request, and never expose authentication mutations to "
                "batched execution."
            ),
        }
    )

    return findings
