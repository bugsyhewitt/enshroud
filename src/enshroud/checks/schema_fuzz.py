"""Clairvoyance-style schema reconstruction via the field-suggestion oracle.

Even when introspection is disabled, many GraphQL servers still leak schema
structure through "Did you mean ..." hints in their validation errors (the
v0.1 ``field-oracle`` check confirms the *presence* of this oracle). This check
turns that oracle into an enumeration primitive: it probes the endpoint with a
bundled wordlist of common field names and records every name the server
confirms — either by accepting the field or by suggesting it back in an error.

The technique is the one popularised by Clairvoyance (nikitastupin). enshroud
ships it as an opt-in, rate-limited check so a hunter gets one tool instead of
two and H1-markdown output directly.

The wordlist lives in ``enshroud/data/gql_fields.txt``.
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any, Iterable

from enshroud.client import GraphQLClient

try:  # Python 3.9+ stdlib resource access
    from importlib.resources import files as _resource_files
except ImportError:  # pragma: no cover - we target 3.13+
    _resource_files = None  # type: ignore[assignment]

# Default probe rate (requests/second). Conservative so routine scans against a
# live target don't trip rate limits or WAFs. Override via --fuzz-rate.
DEFAULT_FUZZ_RATE = 5.0

# Cap on total probes so a misconfigured run can't hammer a target forever.
# (wordlist size + a bounded amount of sub-field expansion)
MAX_PROBES = 2000

# Field names that, if confirmed, materially raise the severity of the finding
# because they hint at sensitive/administrative surface.
_SENSITIVE_FIELD_HINTS = re.compile(
    r"(admin|secret|token|credential|password|apikey|internal|debug|audit|"
    r"webhook|config|payment|invoice|ssn|private)",
    re.IGNORECASE,
)

# "Did you mean" extraction — mirrors field_oracle so behaviour stays consistent.
_DID_YOU_MEAN = re.compile(r"[Dd]id you mean\s+(.+?)\s*\??$", re.MULTILINE)
_QUOTED = re.compile(r'["\']([A-Za-z_][A-Za-z0-9_]*)["\']')

# A field is "confirmed present" when the server returns data for it OR returns
# an error that is NOT the generic "cannot query field" rejection.
_CANNOT_QUERY = re.compile(r"[Cc]annot query field", re.IGNORECASE)


def load_wordlist() -> list[str]:
    """Load and de-duplicate the bundled field-name wordlist.

    Degrades gracefully to an empty list if the data file is missing so the
    check never crashes a scan.
    """
    text = ""
    try:
        if _resource_files is not None:
            text = (
                _resource_files("enshroud.data")
                .joinpath("gql_fields.txt")
                .read_text(encoding="utf-8")
            )
        else:  # pragma: no cover
            import os

            here = os.path.dirname(os.path.dirname(__file__))
            with open(os.path.join(here, "data", "gql_fields.txt"), encoding="utf-8") as fh:
                text = fh.read()
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return []

    seen: dict[str, None] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Only accept syntactically valid GraphQL field names.
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", line):
            seen.setdefault(line, None)
    return list(seen.keys())


def _extract_suggestions(message: str) -> list[str]:
    """Pull suggested field names out of a 'Did you mean' error message."""
    names: list[str] = []
    for m in _DID_YOU_MEAN.finditer(message):
        chunk = m.group(1)
        quoted = _QUOTED.findall(chunk)
        if quoted:
            names.extend(quoted)
        else:
            # Bare token fallback: "Did you mean user" → user
            for tok in re.split(r"[,\s]+|\bor\b", chunk):
                tok = tok.strip().strip("\"'?")
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tok):
                    names.append(tok)
    return names


def _classify(resp: dict[str, Any], field: str) -> tuple[bool, list[str]]:
    """Inspect a probe response.

    Returns ``(field_confirmed, suggested_fields)``:
      * ``field_confirmed`` — True if ``field`` itself exists on the target type
        (data returned, or an error that isn't a plain "cannot query field").
      * ``suggested_fields`` — any field names the oracle leaked via suggestions.
    """
    suggestions: list[str] = []
    if resp.get("data"):
        return True, suggestions

    errors = resp.get("errors") or []
    confirmed = False
    for err in errors:
        msg = err.get("message") or ""
        suggestions.extend(_extract_suggestions(msg))
        if msg and not _CANNOT_QUERY.search(msg):
            # e.g. "Field 'x' of type 'T' must have a selection of subfields"
            # means the field DOES exist but we queried it wrong.
            confirmed = True
    return confirmed, suggestions


async def _probe(client: GraphQLClient, field: str) -> dict[str, Any] | None:
    """Send a single ``{ <field> { __typename } }`` probe. None on transport error."""
    query = f"{{ {field} {{ __typename }} }}"
    try:
        return await client.query(query)
    except Exception:
        return None


async def check(
    client: GraphQLClient,
    *,
    fuzz_rate: float = DEFAULT_FUZZ_RATE,
    wordlist: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Reconstruct schema field names through the field-suggestion oracle.

    Args:
        client: the GraphQL client (scope already validated by the CLI).
        fuzz_rate: max probes per second; <= 0 disables throttling.
        wordlist: override the bundled wordlist (used by tests).
    """
    findings: list[dict[str, Any]] = []

    words = list(wordlist) if wordlist is not None else load_wordlist()
    if not words:
        return findings

    delay = (1.0 / fuzz_rate) if fuzz_rate and fuzz_rate > 0 else 0.0

    confirmed: set[str] = set()
    suggested: set[str] = set()
    probes_sent = 0
    sample_evidence = ""

    # BFS queue: start with the wordlist; enqueue oracle-suggested names we
    # haven't tried yet (bounded by MAX_PROBES).
    queue: list[str] = list(words)
    tried: set[str] = set()

    while queue and probes_sent < MAX_PROBES:
        field = queue.pop(0)
        if field in tried:
            continue
        tried.add(field)

        resp = await _probe(client, field)
        probes_sent += 1
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
            if s not in tried and s not in queue and probes_sent < MAX_PROBES:
                queue.append(s)

    all_fields = sorted(confirmed | suggested)
    if not all_fields:
        # Oracle yielded nothing — no schema leakage detected. No finding.
        return findings

    sensitive = sorted(f for f in all_fields if _SENSITIVE_FIELD_HINTS.search(f))
    severity = "MEDIUM" if sensitive else "LOW"

    findings.append(
        {
            "category": "schema_reconstructed",
            "severity": severity,
            "title": "GraphQL Schema Reconstructed via Field-Suggestion Oracle",
            "reconstructed_fields": all_fields,
            "sensitive_fields": sensitive,
            "probes_sent": probes_sent,
            "evidence": sample_evidence,
            "description": (
                f"By probing {probes_sent} candidate field names against the "
                "endpoint's field-suggestion oracle, "
                f"{len(all_fields)} real schema field name(s) were reconstructed "
                "without using introspection. This confirms that the field "
                "suggestion oracle leaks enough signal to enumerate the actual "
                "schema even when introspection is disabled — the technique behind "
                "Clairvoyance."
                + (
                    " Sensitive/administrative field names were among those "
                    "recovered, raising the impact."
                    if sensitive
                    else ""
                )
            ),
            "reproduction": (
                "For each candidate field name F, send "
                '{"query": "{ F { __typename } }"} and read the error message. '
                'A "Did you mean ..." hint or a "must have a selection of '
                'subfields" error confirms F (or the suggested name) exists.'
            ),
            "impact": (
                "An attacker can rebuild a partial schema and target specific "
                "queries, mutations, and fields despite introspection being "
                "disabled, defeating that control. Recovered field names guide "
                "follow-on IDOR, BOLA, and injection testing."
            ),
            "remediation": (
                "Disable field suggestions in the GraphQL server's error formatter "
                "(graphql-js: strip 'Did you mean' hints in a custom formatError; "
                "Apollo: set formatError to remove suggestion text). Treat the "
                "schema as confidential and enforce field-level authorization."
            ),
        }
    )

    return findings
