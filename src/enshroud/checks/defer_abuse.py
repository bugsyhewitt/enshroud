"""Incremental-delivery (`@defer` / `@stream`) abuse check.

GraphQL's incremental-delivery directives `@defer` (on fragments) and `@stream`
(on list fields) let a server return a query's results in *multiple* payloads
over a single long-lived response: the initial payload first, then each deferred
fragment / streamed list item as it resolves. This is a genuinely distinct attack
surface from every existing enshroud check:

* It is **not** the directive-overloading probe in `directive-abuse`, which
  stacks the built-in `@skip` directive and sends an *undefined* directive to
  test validation. `@defer` / `@stream` are *real, executable* directives whose
  acceptance means a functional incremental-delivery pipeline is enabled.
* It is **not** any of the DoS axes (`depth-dos` = nesting, `alias-batch` =
  breadth, `field-dup` = repetition, `fragment-cycle` = recursion): the cost here
  is *connection-holding* — each `@defer` fragment forces the server to keep a
  streaming response open and emit an additional `multipart/mixed` part, so a
  single small request ties up a worker/connection for the life of the slowest
  deferred resolver.

Why it matters (read-only, deterministic):

1. **DoS via connection exhaustion / amplification.** When incremental delivery
   is enabled, an attacker stacks many `@defer` fragments (or `@stream`s a large
   list) in one request to hold connections open and multiply the number of
   response parts the server must frame and flush. The Apollo Router and
   graphql-js incremental-delivery implementations have shipped fixes for exactly
   this resource-amplification class. A server that has no business serving
   deferred responses but accepts `@defer` is exposing the pipeline needlessly.
2. **Authorization-context staleness.** Deferred payloads resolve *after* the
   initial response. Servers that evaluate authorization once at operation start
   (rather than per deferred fragment) can leak data whose authorization context
   changed between the initial and the deferred payload — the incremental-delivery
   analogue of the WebSocket per-event re-authorization gap.

Detection is read-only and anchored entirely on the `__typename` meta-field, so
no schema knowledge is required and nothing is ever mutated. Two probes:

  1. `@defer`:  ``{ ... @defer { __typename } }``  (inline fragment, the only
     place `@defer` is legal).
  2. `@stream`: ``{ __typename @stream }`` — `@stream` is only legal on a list
     field, so a *correct* server rejects this with a directive-location error;
     a server that does **not** reject it (returns data or an unrelated response)
     has weak directive-location validation around its streaming layer.

A finding fires only when the server **accepts** an incremental-delivery probe —
i.e. it does **not** return an "unknown directive" / directive-validation /
"cannot be used"-location error. A server with incremental delivery disabled
rejects `@defer` as an unknown directive and is reported clean, so a server that
has simply never enabled the feature produces no false positive.
"""
from __future__ import annotations

import json
from typing import Any

from enshroud.client import GraphQLClient

# The two incremental-delivery probes. `@defer` is only valid on a fragment
# (inline or named), so we wrap `__typename` in an inline fragment. `@stream` is
# only valid on a list field — applying it to `__typename` is deliberately a
# location violation, so a validating server rejects it and a lax one does not.
_DEFER_QUERY = "{ ... @defer { __typename } }"
_STREAM_QUERY = "{ __typename @stream }"

# Error keywords that mean the server *rejected* the incremental-delivery
# directive: it does not know the directive, it is disabled, or the directive was
# used in an illegal location. Any of these => the feature is not exposed for that
# vector and no finding fires for it.
_REJECTION_KEYWORDS = (
    "unknown directive",
    "unknown argument",
    "is not defined",
    "not defined",
    "undefined",
    "cannot be used",
    "may not be used",
    "not be used",
    "may not be located",
    "is misplaced",
    "directive",  # generic directive-validation wording
    "disabled",
    "not supported",
    "not enabled",
    "not allowed",
    "no such directive",
)


def _error_messages(resp: dict[str, Any]) -> str:
    """Concatenate all error messages from a response, lower-cased."""
    errors = resp.get("errors") or []
    return " ".join((e.get("message") or "").lower() for e in errors)


def _is_rejected(resp: dict[str, Any]) -> bool:
    """True when the response is a directive-validation rejection of the probe.

    A rejection is an error whose message indicates the incremental-delivery
    directive is unknown, disabled, or used in an illegal location. A clean
    `data` response (no such error) means the server *accepted* the probe.
    """
    messages = _error_messages(resp)
    if not messages:
        return False
    return any(kw in messages for kw in _REJECTION_KEYWORDS)


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Probe whether the server exposes `@defer` / `@stream` incremental delivery."""
    findings: list[dict[str, Any]] = []

    vectors: list[tuple[str, str]] = [
        ("defer", _DEFER_QUERY),
        ("stream", _STREAM_QUERY),
    ]

    accepted: list[str] = []
    last_resp: dict[str, Any] | None = None

    for vector, query in vectors:
        try:
            resp = await client.query(query)
        except Exception:
            # A transport error / non-2xx (the server rejected the request
            # outright) counts as the server NOT exposing the directive.
            continue
        last_resp = resp
        if _is_rejected(resp):
            # The server validated the directive away — feature not exposed.
            continue
        # No directive-rejection error: the server accepted incremental delivery.
        accepted.append(vector)

    if not accepted:
        return findings

    evidence = json.dumps(
        {
            "accepted_vectors": accepted,
            "sample_response": (json.dumps(last_resp)[:300] if last_resp else None),
        }
    )

    # Tailor the description to which vectors actually fired.
    parts: list[str] = []
    if "defer" in accepted:
        parts.append(
            "accepted an inline fragment carrying @defer "
            "({ ... @defer { __typename } }) without a directive-validation error"
        )
    if "stream" in accepted:
        parts.append(
            "accepted @stream on a non-list meta-field "
            "({ __typename @stream }) without a directive-location error"
        )
    description = (
        "The server " + "; it also ".join(parts) + ". "
        "This means GraphQL incremental delivery (@defer / @stream) is exposed. "
        "Incremental delivery is a distinct attack surface from query depth, "
        "alias breadth, field repetition, and fragment recursion: each deferred "
        "fragment or streamed list element forces the server to hold a streaming "
        "response open and frame an additional multipart payload, so a single "
        "small request can hold connections/workers open and amplify response "
        "framing cost. Servers that authorize once at operation start (rather "
        "than per deferred payload) can also leak data whose authorization "
        "context changed before the deferred part resolved."
    )

    findings.append(
        {
            "category": "incremental_delivery_dos",
            "severity": "MEDIUM",
            "title": "Incremental Delivery (@defer / @stream) Exposed",
            "accepted_vectors": accepted,
            "evidence": evidence,
            "description": description,
            "reproduction": (
                "Send a POST with an inline fragment carrying @defer: "
                "{ ... @defer { __typename } }, and a POST applying @stream to a "
                "non-list field: { __typename @stream }. A server with "
                "incremental delivery disabled rejects @defer as an unknown "
                "directive and rejects @stream as a location violation; an "
                "exposed server accepts one or both. Weaponise by stacking many "
                "@defer fragments (or @stream-ing a large list) in one request "
                "to hold connections open and multiply response parts."
            ),
            "impact": (
                "An attacker can hold server connections/workers open and "
                "amplify the number of response payloads the server must frame "
                "and flush from a single small request, contributing to denial "
                "of service. If authorization is evaluated once at operation "
                "start instead of per deferred payload, deferred fragments can "
                "also leak data whose access context changed after the initial "
                "response was sent."
            ),
            "remediation": (
                "Disable @defer / @stream if the API does not need incremental "
                "delivery. If it does, enforce strict directive-location "
                "validation (reject @stream on non-list fields), cap the number "
                "of deferred fragments / streamed items per operation in the "
                "query-complexity budget, bound the total time a streaming "
                "response may stay open, and re-evaluate authorization for each "
                "deferred payload rather than only at operation start."
            ),
        }
    )

    return findings
