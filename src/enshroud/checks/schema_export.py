"""Export a reconstructed schema as an InQL / Voyager-compatible JSON artifact.

The ``schema-fuzz`` check reconstructs schema *field names* from the
field-suggestion oracle and reports them as a flat list inside a finding. This
check turns that same introspection-disabled reconstruction into a **reusable,
structured artifact**: a standard GraphQL introspection-result JSON document
(``{"data": {"__schema": {...}}}``) — the exact shape Clairvoyance emits and the
shape InQL, GraphQL Voyager, and graphql-path-enum consume — so a reconstructed
schema becomes a first-class operator deliverable, not just prose in a report
(the packet's D8).

It also performs **argument inference** (packet Appendix D): graphql-js leaks
*argument* names through the same "Did you mean" oracle
(``Unknown argument "x" on field "Query.user". Did you mean "id"?``). Recovering
those argument names is what makes the reconstructed schema actionable for
follow-on resolver-BOLA testing — the ``bola`` check needs to know the ID-shaped
argument name, and this is where it comes from.

The whole pass is **read-only and safe**: it sends invalid field/argument names
and reads validation errors. No resolver executes, no state changes — so it runs
as a normal (passive) check, throttled by ``--fuzz-rate`` like ``schema-fuzz``.
When ``--schema-out PATH`` is given the artifact is also written to disk.

References:
  * Clairvoyance (nikitastupin) — introspection-disabled inference; the JSON it
    emits is a standard introspection result.
  * InQL / GraphQL Voyager / graphql-path-enum — consume that JSON.
  * Packet 08 §5 (inference), §D8 (artifact), Appendix D (argument inference).
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any, Iterable

from enshroud.checks.schema_fuzz import (
    DEFAULT_FUZZ_RATE,
    _classify,
    load_wordlist,
)
from enshroud.client import GraphQLClient

# Bound on total probes so a misconfigured run can't hammer a target. Covers the
# field-discovery sweep plus the bounded argument-inference probes per field.
MAX_FIELD_PROBES = 2000

# Argument-name probes: short near-miss tokens that tend to be one edit-distance
# from real GraphQL argument names (id, ids, filter, first, after, name, slug,
# input, where, by, page, limit, offset, query, key, uuid, …). graphql-js
# replies "Unknown argument "<probe>" on field "…". Did you mean "<real>"?".
_ARG_PROBE_TOKENS: tuple[str, ...] = (
    "idd",
    "ids",
    "iid",
    "usr",
    "namee",
    "slugg",
    "filterr",
    "firstt",
    "afterr",
    "inputt",
    "wheree",
    "keyy",
    "uuidd",
    "pagee",
    "limitt",
    "offsett",
    "queryy",
    "byy",
)

# Cap on argument probes per field, so argument inference stays bounded.
_MAX_ARG_PROBES_PER_FIELD = len(_ARG_PROBE_TOKENS)

# graphql-js argument-suggestion wording. Captured separately from the
# field-suggestion regex (schema_fuzz) because it targets a different oracle
# (KnownArgumentNamesRule), per packet Appendix L (engine-specific parsers).
_ARG_SUGGEST = re.compile(
    r'Unknown argument\b.*?[Dd]id you mean\s+(.+?)\s*\??$',
    re.MULTILINE | re.DOTALL,
)
_QUOTED = re.compile(r'["\']([A-Za-z_][A-Za-z0-9_]*)["\']')
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _extract_arg_suggestions(message: str) -> list[str]:
    """Pull argument names out of an 'Unknown argument … Did you mean …' message."""
    names: list[str] = []
    for m in _ARG_SUGGEST.finditer(message):
        chunk = m.group(1)
        quoted = _QUOTED.findall(chunk)
        if quoted:
            names.extend(quoted)
        else:
            for tok in re.split(r"[,\s]+|\bor\b", chunk):
                tok = tok.strip().strip("\"'?")
                if _IDENT.fullmatch(tok):
                    names.append(tok)
    return names


async def _probe_field(client: GraphQLClient, field: str) -> dict[str, Any] | None:
    """Send ``{ <field> { __typename } }``; None on transport error."""
    try:
        return await client.query(f"{{ {field} {{ __typename }} }}")
    except Exception:
        return None


async def infer_arguments(
    client: GraphQLClient,
    field: str,
    *,
    delay: float = 0.0,
) -> list[str]:
    """Recover argument names for ``field`` via the argument-suggestion oracle.

    Sends a bounded set of near-miss argument probes
    (``{ <field>(<wrongArg>: "x") { __typename } }``) and harvests every real
    argument name the server suggests back. Read-only — the probes halt at
    validation (an unknown argument is rejected before the resolver runs).
    """
    found: dict[str, None] = {}
    for token in _ARG_PROBE_TOKENS:
        query = f'{{ {field}({token}: "x") {{ __typename }} }}'
        try:
            resp = await client.query(query)
        except Exception:
            continue
        for err in resp.get("errors") or []:
            msg = err.get("message") or ""
            for name in _extract_arg_suggestions(msg):
                found.setdefault(name, None)
        if delay:
            await asyncio.sleep(delay)
    return list(found.keys())


def build_introspection_artifact(
    query_fields: list[str],
    field_args: dict[str, list[str]],
) -> dict[str, Any]:
    """Render reconstructed fields/args as a standard introspection-result JSON.

    The output is the canonical ``{"data": {"__schema": {...}}}`` document
    Clairvoyance emits and InQL / Voyager consume. Reconstructed-but-unresolved
    return types are rendered as a placeholder ``OBJECT`` named ``Unknown`` (the
    oracle confirms a field exists without always revealing its concrete return
    type); arguments are rendered as nullable ``String`` scalars (the oracle
    leaks argument *names*, not their types). This is a faithful "partial
    schema" — exactly what an introspection-disabled reconstruction can know.
    """
    fields_json: list[dict[str, Any]] = []
    for name in query_fields:
        args_json = [
            {
                "name": arg,
                "description": None,
                "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                "defaultValue": None,
            }
            for arg in field_args.get(name, [])
        ]
        fields_json.append(
            {
                "name": name,
                "description": None,
                "args": args_json,
                "type": {"kind": "OBJECT", "name": "Unknown", "ofType": None},
                "isDeprecated": False,
                "deprecationReason": None,
            }
        )

    query_type = {
        "kind": "OBJECT",
        "name": "Query",
        "description": "Reconstructed via field-suggestion inference (introspection disabled).",
        "fields": fields_json,
        "inputFields": None,
        "interfaces": [],
        "enumValues": None,
        "possibleTypes": None,
    }

    return {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": None,
                "subscriptionType": None,
                "types": [query_type],
                "directives": [],
            },
            "_enshroud": {
                "reconstructed": True,
                "method": "field_suggestion_inference",
                "note": (
                    "Partial schema reconstructed without introspection. Field "
                    "return types and argument types are placeholders; field and "
                    "argument NAMES are oracle-confirmed."
                ),
            },
        }
    }


async def check(
    client: GraphQLClient,
    *,
    fuzz_rate: float = DEFAULT_FUZZ_RATE,
    wordlist: Iterable[str] | None = None,
    schema_out: str | None = None,
    infer_args: bool = True,
) -> list[dict[str, Any]]:
    """Reconstruct the schema and emit an InQL/Voyager-compatible JSON artifact.

    Args:
        client: GraphQL client (scope already validated by the CLI).
        fuzz_rate: max probes/second; <= 0 disables throttling.
        wordlist: override the bundled field wordlist (used by tests).
        schema_out: if given, write the artifact JSON to this path.
        infer_args: also recover argument names for each discovered field
            (Appendix D). On by default; the result drives ``bola``.

    Read-only / safe. Returns one finding carrying the reconstructed artifact, or
    no finding when the oracle yields nothing.
    """
    findings: list[dict[str, Any]] = []

    words = list(wordlist) if wordlist is not None else load_wordlist()
    if not words:
        return findings

    delay = (1.0 / fuzz_rate) if fuzz_rate and fuzz_rate > 0 else 0.0

    # ── 1) field discovery (BFS over the suggestion oracle) ────────────────
    confirmed: set[str] = set()
    suggested: set[str] = set()
    queue: list[str] = list(words)
    tried: set[str] = set()
    probes = 0
    sample_evidence = ""

    while queue and probes < MAX_FIELD_PROBES:
        field = queue.pop(0)
        if field in tried:
            continue
        tried.add(field)

        resp = await _probe_field(client, field)
        probes += 1
        if delay and queue:
            await asyncio.sleep(delay)
        if resp is None:
            continue

        is_confirmed, new_suggestions = _classify(resp, field)
        if is_confirmed:
            confirmed.add(field)
            if not sample_evidence:
                sample_evidence = json.dumps(resp)[:500]
        for s in new_suggestions:
            suggested.add(s)
            if not sample_evidence:
                sample_evidence = json.dumps(resp)[:500]
            if s not in tried and s not in queue and probes < MAX_FIELD_PROBES:
                queue.append(s)

    all_fields = sorted(confirmed | suggested)
    if not all_fields:
        return findings

    # ── 2) argument inference per discovered field (Appendix D) ────────────
    field_args: dict[str, list[str]] = {}
    if infer_args:
        for field in all_fields:
            if probes >= MAX_FIELD_PROBES:
                break
            args = await infer_arguments(client, field, delay=delay)
            probes += _MAX_ARG_PROBES_PER_FIELD
            if args:
                field_args[field] = args

    # ── 3) render the artifact ─────────────────────────────────────────────
    artifact = build_introspection_artifact(all_fields, field_args)

    written_to: str | None = None
    if schema_out:
        try:
            with open(schema_out, "w", encoding="utf-8") as fh:
                json.dump(artifact, fh, indent=2)
            written_to = schema_out
        except OSError:
            # Non-fatal: the artifact still ships inside the finding.
            written_to = None

    total_args = sum(len(v) for v in field_args.values())
    findings.append(
        {
            "category": "schema_artifact_reconstructed",
            "severity": "MEDIUM",
            "title": (
                "GraphQL Schema Artifact Reconstructed (introspection disabled)"
            ),
            "owasp": ["API3:2023"],
            "cwe": ["CWE-200"],
            "reconstructed_fields": all_fields,
            "field_arguments": field_args,
            "probes_sent": probes,
            "schema_out": written_to,
            "schema_artifact": artifact,
            "confirmation": {
                "method": "benign_poc",
                "evidence": (
                    f"reconstructed {len(all_fields)} query field(s) and "
                    f"{total_args} argument name(s) from suggestions; emitted "
                    "InQL/Voyager-compatible introspection JSON"
                    + (f" → {written_to}" if written_to else "")
                ),
                "blast_radius": (
                    "full schema disclosure despite disabled introspection "
                    "enables targeted query/mutation/BOLA/injection testing"
                ),
                "reproduction": (
                    "probe invalid field and argument names; parse 'Did you "
                    "mean' suggestions; assemble a standard introspection JSON"
                ),
            },
            "evidence": sample_evidence,
            "description": (
                f"By probing candidate field and argument names against the "
                "endpoint's suggestion oracle, "
                f"{len(all_fields)} field name(s)"
                + (f" and {total_args} argument name(s)" if total_args else "")
                + " were reconstructed without introspection and assembled into "
                "a standard GraphQL introspection-result JSON document (the shape "
                "InQL, GraphQL Voyager, and graphql-path-enum consume). A "
                "reconstructed schema is itself a reusable attack artifact: it "
                "maps the API surface a disabled-introspection control was meant "
                "to hide. Argument names additionally drive resolver-BOLA testing "
                "by revealing the ID-shaped arguments to manipulate."
            ),
            "reproduction": (
                "For each candidate name F, POST {\"query\": \"{ F { __typename "
                "} }\"} and read suggestions; for each discovered field, POST a "
                "near-miss argument probe and read 'Unknown argument … Did you "
                "mean …'. Assemble the confirmed names into an introspection JSON "
                "and load it in InQL / Voyager."
            ),
            "impact": (
                "An attacker rebuilds the schema — fields and their argument "
                "names — despite introspection being disabled, defeating that "
                "control and gaining a precise map for follow-on IDOR/BOLA, "
                "injection, and mutation abuse. The exported JSON makes the "
                "recovered schema trivially reusable across tooling."
            ),
            "remediation": (
                "Disable field and argument suggestions in the GraphQL server's "
                "error formatter (graphql-js: strip 'Did you mean' on every "
                "validation rule, not just field-name errors; Apollo v4+: disable "
                "suggestions). Treat the schema as confidential, enforce field- "
                "and object-level authorization, and do not rely on disabled "
                "introspection alone to hide the API surface."
            ),
        }
    )

    return findings
