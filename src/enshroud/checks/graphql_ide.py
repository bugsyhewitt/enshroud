"""In-browser GraphQL IDE exposure check (`graphql-ide`).

Most GraphQL servers can serve an interactive, in-browser query console at the
same URL as the API itself when the endpoint is requested with a browser
``Accept: text/html`` header (i.e. navigated to directly). The canonical
consoles are **GraphiQL**, **GraphQL Playground**, and Apollo's
**Sandbox / Explorer**. These tools are intended for local development and are
routinely left enabled in production.

Why this is a genuinely distinct attack surface from every existing check:

* It is **not** the ``introspection`` check. That check sends an
  ``application/json`` POST carrying a ``{ __schema }`` query and inspects the
  JSON ``data``. This check sends a browser-style **GET** with
  ``Accept: text/html`` and inspects the returned **HTML document** for IDE
  markers. A server can ship the IDE (which then enables introspection in the
  victim's browser) while the bare JSON ``__schema`` probe is blocked, and vice
  versa — they are independent controls.
* It is **not** ``fingerprint``. Fingerprinting matches engine-specific *error
  wording* on the JSON API to name the engine. This check looks for an HTML
  document that is itself an exploitation console.
* It is **not** ``csrf``. CSRF probes whether *mutations* execute over GET /
  form-encoded POST. This probes whether a GET serves an HTML *IDE page*.

Why it matters (read-only, deterministic, single GET):

An exposed GraphQL IDE in production is a directly reportable information- and
attack-surface-disclosure finding on every major bug-bounty platform. The IDE:

1. Ships with introspection / schema exploration enabled, handing an attacker
   the full schema in a point-and-click UI even when the documented control
   ("introspection disabled") only blocks the raw JSON probe.
2. Provides a hosted, pre-wired query runner against the production endpoint —
   lowering the bar for every follow-on attack (enumeration, IDOR hunting,
   dangerous-mutation discovery) to "type and click".
3. Often loads third-party assets (CDN-hosted GraphiQL/Playground bundles),
   widening the supply-chain surface of the production origin.

Detection is a single GET per path-candidate carrying a realistic browser
``Accept`` header. A finding fires only when the response is an HTML document
(``Content-Type: text/html`` *or* an ``<html`` body) that contains a known IDE
marker string. A JSON API response, a 404, or any non-HTML reply produces no
finding, so a server that correctly serves only the JSON API is reported clean
with no false positive. Nothing is ever mutated.
"""
from __future__ import annotations

import json
from typing import Any

from enshroud.client import GraphQLClient

# A realistic browser Accept header. Servers commonly content-negotiate the IDE
# vs. the JSON API on exactly this header: a browser navigating to /graphql gets
# the HTML console, while an `application/json` client gets the API.
_BROWSER_ACCEPT = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,"
    "image/avif,image/webp,*/*;q=0.8"
)

# Marker substrings that identify a served in-browser GraphQL IDE. Each maps a
# lower-cased needle (matched against the HTML body) to a human-readable IDE
# name for the finding. Markers are chosen to be specific to the IDE bundles and
# unlikely to appear in an ordinary application page.
_IDE_MARKERS: tuple[tuple[str, str], ...] = (
    ("graphql-playground", "GraphQL Playground"),
    ("graphqlplayground", "GraphQL Playground"),
    ("graphiql", "GraphiQL"),
    ("embeddable-sandbox", "Apollo Sandbox"),
    ("apollographql/sandbox", "Apollo Sandbox"),
    ("apollo-server-landing-page", "Apollo Sandbox"),
    ("apollo sandbox", "Apollo Sandbox"),
    ("__apollo_devtools_global_hook__", "Apollo Sandbox"),
)


def _looks_like_html(content_type: str, body: str) -> bool:
    """True when the response is an HTML document (by header or body shape)."""
    if "text/html" in content_type.lower():
        return True
    head = body[:512].lower()
    return "<!doctype html" in head or "<html" in head


def _identify_ide(body: str) -> str | None:
    """Return the IDE name if the HTML body contains a known IDE marker."""
    haystack = body.lower()
    for needle, name in _IDE_MARKERS:
        if needle in haystack:
            return name
    return None


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Probe whether the endpoint serves an in-browser GraphQL IDE over GET."""
    findings: list[dict[str, Any]] = []

    try:
        resp = await client.get_html(accept=_BROWSER_ACCEPT)
    except Exception:
        # Transport error / refused request → not a finding.
        return findings

    # Only consider 2xx responses; an error/redirect page is not a served IDE.
    if not (200 <= resp.status_code < 300):
        return findings

    content_type = resp.headers.get("content-type", "")
    body = resp.text or ""

    if not _looks_like_html(content_type, body):
        # A JSON API reply (or anything non-HTML) is the safe, expected case.
        return findings

    ide_name = _identify_ide(body)
    if ide_name is None:
        # HTML that is not a recognised GraphQL IDE → no finding (avoids firing
        # on an unrelated landing page that merely returns HTML).
        return findings

    # Trim a representative HTML prefix for the evidence (keep it small).
    body_excerpt = body[:300]
    evidence = json.dumps(
        {
            "method": "GET",
            "accept": _BROWSER_ACCEPT,
            "status": resp.status_code,
            "content_type": content_type,
            "ide": ide_name,
            "body_prefix": body_excerpt,
        }
    )

    findings.append(
        {
            "category": "graphql_ide_exposed",
            "severity": "MEDIUM",
            "title": f"In-Browser GraphQL IDE Exposed ({ide_name})",
            "ide": ide_name,
            "evidence": evidence,
            "description": (
                f"The endpoint serves the {ide_name} in-browser GraphQL IDE when "
                "requested with a browser Accept: text/html header. These consoles "
                "are development tools that ship with schema exploration / "
                "introspection enabled and a query runner wired directly to the "
                "production endpoint. This is a distinct exposure from the JSON "
                "introspection API: a server can serve the IDE (which then runs "
                "introspection inside the victim's browser) even when the raw "
                "JSON __schema probe is blocked, so disabling introspection alone "
                "does not close it."
            ),
            "reproduction": (
                "Send a GET request to the endpoint with a browser Accept header: "
                "`GET <endpoint> Accept: text/html`. The server returns an HTML "
                f"document containing the {ide_name} bundle (marker string present "
                "in the body). Open the same URL in a browser to get an "
                "interactive query console against the production API."
            ),
            "impact": (
                "An attacker is handed a hosted, point-and-click console against "
                "the production GraphQL endpoint: full schema exploration, query "
                "and mutation execution, and a force-multiplier for enumerating "
                "hidden fields, IDOR candidates, and dangerous mutations — all "
                "without writing a request by hand. The IDE also typically loads "
                "third-party (CDN) assets onto the production origin."
            ),
            "remediation": (
                f"Disable the {ide_name} IDE in production (most GraphQL servers "
                "expose a flag, e.g. Apollo Server `introspection: false` plus "
                "disabling the landing page / `graphiql: false`, or serving the "
                "IDE only in development). Do not rely on disabling introspection "
                "alone — the served console is a separate control. If an internal "
                "IDE is required, restrict it by network / authentication rather "
                "than serving it from the public endpoint."
            ),
        }
    )

    return findings
