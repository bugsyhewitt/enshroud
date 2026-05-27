"""GraphQL engine fingerprinting check.

Identifies the GraphQL server implementation (Apollo, Graphene, Strawberry,
WPGraphQL, Hasura, Yoga, Mercurius, graphql-ruby, graphql-js, ...) by probing
the endpoint with malformed and edge-case queries and matching the resulting
error messages, response shape, and headers against a bundled signature set.

This is a recon multiplier: knowing the engine tells a hunter which of that
engine's default-insecure behaviours (e.g. introspection-on-by-default,
field-suggestion leakage, unprotected APQ) are likely to apply, so they can go
straight to engine-specific misconfigurations and CVEs.

Signatures live in ``enshroud/data/signatures.json`` and are derived from
graphw00f (dolevf) and the GraphQL Threat Matrix (nicholasess).
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from typing import Any

import httpx

from enshroud.client import GraphQLClient

try:  # Python 3.9+ stdlib resource access
    from importlib.resources import files as _resource_files
except ImportError:  # pragma: no cover - we target 3.13+
    _resource_files = None  # type: ignore[assignment]

# Probe queries. Each is intentionally crafted to coax a distinctive error or
# response out of the server. We keep them side-effect free (no mutations).
PROBES: list[str] = [
    # 1. Empty selection set — engines differ in their parse-error wording.
    "query { }",
    # 2. Reference to a field that cannot exist — triggers "Cannot query field"
    #    style validation errors and, on some engines, "Did you mean" hints.
    "query { enshroudFingerprintProbe___ }",
    # 3. An unsupported / unknown directive — directive validation wording
    #    varies sharply between implementations.
    "query @enshroudProbe { __typename }",
    # 4. A bare reserved-name reference — some engines special-case this.
    "query { __typename @skip }",
]

# How much response body to keep as evidence, per probe.
EVIDENCE_BODY_LEN = 400


@lru_cache(maxsize=1)
def load_signatures() -> dict[str, Any]:
    """Load and cache the bundled signature set.

    Returns an empty (but well-formed) structure if the data file is missing or
    unreadable, so the check degrades gracefully rather than crashing a scan.
    """
    try:
        if _resource_files is not None:
            data_text = (
                _resource_files("enshroud.data")
                .joinpath("signatures.json")
                .read_text(encoding="utf-8")
            )
        else:  # pragma: no cover
            import os

            here = os.path.dirname(os.path.dirname(__file__))
            with open(os.path.join(here, "data", "signatures.json"), encoding="utf-8") as fh:
                data_text = fh.read()
        return json.loads(data_text)
    except (FileNotFoundError, ModuleNotFoundError, ValueError, OSError):
        return {"schema_version": "0", "engines": []}


def _response_corpus(probe: str, resp: httpx.Response) -> str:
    """Build the searchable text corpus for one probe response.

    Includes the HTTP status, the header block, and the body, so that
    header-based signatures (e.g. ``x-hasura-``) and body-based signatures match
    against the same haystack.
    """
    header_block = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    body = resp.text or ""
    return f"HTTP {resp.status_code}\n{header_block}\n{body}"


def _engine_matches(corpus: str, engine: dict[str, Any]) -> bool:
    """Return True if the engine's signature matches the corpus.

    Match semantics:
      * every pattern in ``match.all`` must be found (regex, case-insensitive),
      * at least one pattern in ``match.any`` must be found (if ``any`` is
        non-empty).
    An engine with neither ``all`` nor ``any`` populated never matches.
    """
    match = engine.get("match") or {}
    all_patterns: list[str] = match.get("all") or []
    any_patterns: list[str] = match.get("any") or []

    if not all_patterns and not any_patterns:
        return False

    for pat in all_patterns:
        if not re.search(pat, corpus, re.IGNORECASE | re.DOTALL):
            return False

    if any_patterns:
        if not any(
            re.search(pat, corpus, re.IGNORECASE | re.DOTALL) for pat in any_patterns
        ):
            return False

    return True


def identify_engine(corpus: str, signatures: dict[str, Any]) -> dict[str, Any] | None:
    """Return the first matching engine signature, or None.

    Engines are evaluated in declaration order; the data file lists the most
    specific engines first so that, e.g., Hasura wins over a generic graphql-js
    body pattern.
    """
    for engine in signatures.get("engines") or []:
        if _engine_matches(corpus, engine):
            return engine
    return None


def _finding(engine: dict[str, Any], evidence: str) -> dict[str, Any]:
    behaviors: list[str] = engine.get("known_default_insecure_behaviors") or []
    display = engine.get("display_name") or engine.get("name") or "unknown"
    behavior_md = (
        "\n".join(f"- {b}" for b in behaviors)
        if behaviors
        else "- (no default-insecure behaviours catalogued)"
    )
    return {
        "category": "engine_identified",
        "severity": "INFO",
        "title": f"GraphQL Engine Identified: {display}",
        "engine_name": engine.get("name"),
        "engine_display_name": display,
        "known_default_insecure_behaviors": behaviors,
        "evidence": evidence,
        "description": (
            f"The GraphQL endpoint was fingerprinted as **{display}** based on "
            "its error-message wording, response shape, and headers. Knowing the "
            "engine reveals which default-insecure behaviours are likely to "
            "apply, focusing further testing on engine-specific "
            "misconfigurations and CVEs."
        ),
        "reproduction": (
            "Send the enshroud fingerprint probe queries (malformed selection "
            "set, non-existent field, unknown directive) and compare the "
            "returned error messages and headers against the engine signature "
            "set. The matched signature identifies the server implementation."
        ),
        "impact": (
            "Engine identification is reconnaissance, not a vulnerability by "
            "itself. It is a force multiplier: an attacker can skip generic "
            "probing and go directly to this engine's known weak defaults:\n"
            f"{behavior_md}"
        ),
        "remediation": (
            "Suppress or normalise GraphQL error messages so they do not reveal "
            "the underlying implementation. Disable verbose parse/validation "
            "errors, strip framework-identifying headers, and review each of the "
            "engine's default-insecure behaviours listed above."
        ),
    }


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Fingerprint the GraphQL engine. Emits at most one INFO finding."""
    signatures = load_signatures()
    if not (signatures.get("engines") or []):
        return []

    corpus_parts: list[str] = []
    evidence_probes: list[dict[str, Any]] = []

    for probe in PROBES:
        try:
            resp = await client.post_raw(probe)
        except Exception:
            continue
        corpus_parts.append(_response_corpus(probe, resp))
        body = resp.text or ""
        evidence_probes.append(
            {
                "probe": probe,
                "status": resp.status_code,
                "body_prefix": body[:EVIDENCE_BODY_LEN],
            }
        )

    if not corpus_parts:
        return []

    corpus = "\n\n".join(corpus_parts)
    engine = identify_engine(corpus, signatures)
    if engine is None:
        return []

    evidence = json.dumps({"matched_engine": engine.get("name"), "probes": evidence_probes})
    return [_finding(engine, evidence)]
