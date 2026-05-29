"""Apollo Tracing / performance-extension exposure check (trace-exposure).

This check is distinct from every other check in the suite. ``verbose-errors``
(``debug_errors``) inspects the *error* path: it looks for stack traces and
exception detail attached to ``errors[].extensions`` when a query *fails*. This
check inspects the *success* path: it sends a single benign, valid query and
looks at the top-level ``extensions`` block of a 200/``data`` response for
performance-tracing metadata that a production server should never emit.

Two tracing formats are detected, both well documented:

* **Apollo Tracing** (``extensions.tracing``) — the legacy apollo-tracing
  format. It carries the full ``execution.resolvers`` list: for *every* field
  resolved it leaks the response path, the parent/field GraphQL type names, the
  resolver's wall-clock start offset and duration in nanoseconds, plus
  ``startTime`` / ``endTime`` / ``parsing`` / ``validation`` timestamps. This is
  a schema-shape leak (type and field names, even with introspection disabled)
  *and* a timing side-channel (per-resolver latency enables enumeration / timing
  attacks against authz and lookup paths).

* **Apollo Federation FTV1** (``extensions.ftv1``) — the federated-trace format
  emitted by Apollo Server / the Apollo Router when ``apollo-federation-include-trace:
  ftv1`` is honoured for arbitrary clients. The base64 ``ftv1`` blob is a
  protobuf trace with the same per-resolver timing and type information. A
  production gateway should only emit it for the trusted router, never for an
  unauthenticated client request.

The signal is unambiguous and requires no schema knowledge: a single
``{ __typename }`` query is valid against every GraphQL endpoint, so a tracing
block in the response is purely the server's choice to expose it. The check
fires only when that block is present, so a server with tracing disabled (the
production default) produces no finding.
"""
from __future__ import annotations

import json
from typing import Any

from enshroud.client import GraphQLClient

# A universally-valid, side-effect-free query. `__typename` resolves on the root
# Query type of every GraphQL schema, so the response is a 200 with `data` on any
# endpoint — the success path we need to inspect for a tracing block.
_PROBE_QUERY = "{ __typename }"

# Top-level extensions keys that carry resolver-level performance traces.
_APOLLO_TRACING_KEY = "tracing"
_FTV1_KEY = "ftv1"

_EVIDENCE_LEN = 600


def _extract_resolver_sample(tracing: dict[str, Any]) -> list[str]:
    """Pull a few leaked field/type names from an Apollo Tracing block.

    The apollo-tracing ``execution.resolvers`` array names every resolved field
    and its parent/field GraphQL type. Returning a small sample makes the finding
    concretely demonstrate the schema-shape leak without dumping the whole trace.
    """
    names: list[str] = []
    execution = tracing.get("execution")
    if not isinstance(execution, dict):
        return names
    resolvers = execution.get("resolvers")
    if not isinstance(resolvers, list):
        return names
    for entry in resolvers:
        if not isinstance(entry, dict):
            continue
        parent = entry.get("parentType")
        field = entry.get("fieldName")
        ret = entry.get("returnType")
        if field and parent:
            names.append(f"{parent}.{field}" + (f": {ret}" if ret else ""))
        elif field:
            names.append(str(field))
        if len(names) >= 10:
            break
    return names


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Detect Apollo Tracing / FTV1 performance metadata on the success path."""
    findings: list[dict[str, Any]] = []

    try:
        resp = await client.query(_PROBE_QUERY)
    except Exception:
        return findings

    if not isinstance(resp, dict):
        return findings

    extensions = resp.get("extensions")
    if not isinstance(extensions, dict):
        # No top-level extensions block → nothing leaked. (A correctly
        # configured production server omits it entirely.)
        return findings

    tracing = extensions.get(_APOLLO_TRACING_KEY)
    ftv1 = extensions.get(_FTV1_KEY)

    if not isinstance(tracing, dict) and not ftv1:
        # Extensions present but no recognised tracing format → no finding. We
        # deliberately do not flag arbitrary unknown extension keys to avoid
        # false positives on benign server metadata (e.g. cost hints).
        return findings

    leaked_fields: list[str] = []
    formats: list[str] = []

    if isinstance(tracing, dict):
        formats.append("apollo-tracing (extensions.tracing)")
        leaked_fields = _extract_resolver_sample(tracing)

    if ftv1:
        formats.append("federation FTV1 (extensions.ftv1)")

    evidence = json.dumps({"extensions": extensions})[:_EVIDENCE_LEN]
    formats_text = " and ".join(formats)

    leak_note = ""
    if leaked_fields:
        leak_note = (
            " The trace's resolver list leaked these field/type names: "
            + ", ".join(leaked_fields)
            + " — schema shape recoverable even with introspection disabled."
        )

    findings.append(
        {
            "category": "trace_exposure",
            "severity": "LOW",
            "title": "GraphQL Performance Tracing Exposed in Response Extensions",
            "tracing_formats": formats,
            "leaked_fields": leaked_fields,
            "evidence": evidence,
            "description": (
                "A single benign `{ __typename }` query returned performance "
                f"tracing metadata in the response's top-level `extensions` "
                f"block ({formats_text}). Apollo Tracing / FTV1 traces carry "
                "per-resolver wall-clock timings and the GraphQL type and field "
                "names touched by the operation. This data is meant for "
                "development tooling or the trusted Apollo Router, not for "
                "arbitrary clients in production." + leak_note
            ),
            "reproduction": (
                'POST {"query": "{ __typename }"} and inspect the response\'s '
                "top-level `extensions` object for a `tracing` block (Apollo "
                "Tracing) or an `ftv1` base64 string (Apollo Federation trace)."
            ),
            "impact": (
                "Per-resolver latency is a timing side-channel: an attacker can "
                "distinguish authorized-but-empty from forbidden lookups, "
                "enumerate valid identifiers by resolver duration, and map the "
                "schema's type/field structure even when introspection is "
                "disabled — all from an unauthenticated query."
            ),
            "remediation": (
                "Disable performance tracing in production. In Apollo Server, "
                "remove the legacy `tracing: true` option and do not install "
                "`apollo-tracing`. For Apollo Federation, ensure the subgraph "
                "only emits FTV1 traces for the trusted gateway "
                "(`apollo-federation-include-trace: ftv1`) and never honours that "
                "header from arbitrary clients. Strip `extensions.tracing` / "
                "`extensions.ftv1` at the edge if a dependency adds them."
            ),
        }
    )

    return findings
