"""Federation SDL exposure check — Apollo Federation `_service { sdl }` leak.

This is an introspection-*bypass* recon check. The v0.1 ``introspection`` check
probes the standard ``{ __schema { ... } }`` meta-field; a target that has
disabled introspection rejects that query and the ``introspection`` finding
stays silent. But Apollo Federation subgraphs implement the Federation
subgraph spec, which mandates an enhanced introspection field:

    query { _service { sdl } }

``_service.sdl`` returns the subgraph's **entire schema as an SDL string** —
every type, field, argument, directive, and federation key. It is served
regardless of whether ``__schema`` introspection is enabled, because it is a
distinct spec-mandated field rather than the introspection system. A server
operator who "disabled introspection" to hide the schema is therefore still
leaking the full schema through ``_service.sdl`` if the endpoint is a
federation subgraph (very common behind Apollo Gateway / Router deployments).

The companion federation field ``query { _entities(representations: [...]) }``
is the entity-resolution entry point. Probing it (with a deliberately empty /
malformed representation) confirms the subgraph exposes the entity resolver to
unauthenticated clients — the surface behind several documented federation
authorization-bypass chains, where an attacker fetches arbitrary entities by
``__typename`` + key directly from a subgraph, skipping the gateway's auth layer.

This check is read-only: it sends two benign query probes (``_service { sdl }``
and an ``_entities`` probe with an empty representation list) and never mutates.
It fires:

* HIGH (``federation_sdl_exposed``) when ``_service.sdl`` returns the schema SDL.
  This is the impactful finding — a full schema dump that bypasses a disabled
  introspection control.
* MEDIUM (``federation_entities_exposed``) when the ``_entities`` resolver is
  reachable (the field exists / is invoked) without authentication, flagging the
  direct-subgraph entity-access surface.

It stays silent on non-federation endpoints (the fields do not exist, so the
server returns a "Cannot query field" error and no finding fires).
"""
from __future__ import annotations

import json
from typing import Any

from enshroud.client import GraphQLClient

SDL_CATEGORY = "federation_sdl_exposed"
SDL_SEVERITY = "HIGH"
ENTITIES_CATEGORY = "federation_entities_exposed"
ENTITIES_SEVERITY = "MEDIUM"

# The spec-mandated federation introspection field. `_service.sdl` returns the
# subgraph's full schema as an SDL string.
_SDL_QUERY = "{ _service { sdl } }"

# The federation entity-resolution entry point. An empty representations list is
# a benign, read-only probe: a federation subgraph recognises the field (and
# returns an empty/zero-length list or a representations validation error),
# while a non-federation server reports the field as unknown.
_ENTITIES_QUERY = "{ _entities(representations: []) { __typename } }"


def _looks_like_sdl(value: Any) -> bool:
    """Heuristic: does this string look like a GraphQL SDL document?

    A real ``_service.sdl`` payload is a schema document. We require it to be a
    non-trivial string that contains at least one SDL type-system keyword so an
    empty string or a stray scalar does not trip the finding.
    """
    if not isinstance(value, str) or len(value.strip()) < 8:
        return False
    lowered = value.lower()
    keywords = ("type ", "type\n", "schema", "interface ", "enum ", "input ", "scalar ")
    return any(kw in lowered for kw in keywords)


def _field_is_unknown(resp: dict[str, Any], field: str) -> bool:
    """True if the response is a 'Cannot query field <field>' style rejection.

    Non-federation servers reject the federation probe fields. We treat any
    error mentioning the probed field name alongside a 'cannot query'/'unknown
    field' wording as a clean negative so those endpoints stay silent.
    """
    errors = resp.get("errors") or []
    for err in errors:
        msg = str(err.get("message", "")).lower()
        if field.lower() in msg and (
            "cannot query field" in msg
            or "unknown field" in msg
            or "doesn't exist" in msg
            or "does not exist" in msg
        ):
            return True
    return False


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Probe for Apollo Federation SDL and entity-resolver exposure.

    Read-only: sends two benign query probes and inspects the responses. Never
    mutates and never sends payloads beyond the two fixed federation queries.
    """
    findings: list[dict[str, Any]] = []

    # ── Probe 1: _service { sdl } — full schema dump ────────────────────────
    try:
        resp = await client.query(_SDL_QUERY)
    except Exception:
        resp = None

    if isinstance(resp, dict):
        data = resp.get("data") or {}
        service = data.get("_service") if isinstance(data, dict) else None
        sdl = service.get("sdl") if isinstance(service, dict) else None
        if _looks_like_sdl(sdl):
            sdl_str = str(sdl)
            evidence = json.dumps(
                {
                    "probe": _SDL_QUERY,
                    "sdl_length": len(sdl_str),
                    "sdl_prefix": sdl_str[:500],
                }
            )
            findings.append(
                {
                    "category": SDL_CATEGORY,
                    "severity": SDL_SEVERITY,
                    "title": "Apollo Federation Schema Disclosure via _service.sdl",
                    "evidence": evidence,
                    "description": (
                        "The GraphQL endpoint is an Apollo Federation subgraph and "
                        "returns its complete schema as an SDL string via the "
                        "federation `_service { sdl }` field. This exposes every "
                        "type, field, argument, and directive even when standard "
                        "`__schema` introspection is disabled."
                    ),
                    "reproduction": (
                        'Send a POST request with body: '
                        '{"query": "{ _service { sdl } }"} and observe that the '
                        "response `data._service.sdl` contains the full schema "
                        "definition language document."
                    ),
                    "impact": (
                        "`_service.sdl` is a complete bypass of a disabled "
                        "introspection control: an attacker recovers the entire "
                        "schema — including hidden admin types, mutations, and "
                        "federation `@key` directives — and uses it to craft "
                        "targeted queries and entity-resolution attacks, exactly "
                        "as if introspection were enabled."
                    ),
                    "remediation": (
                        "Federation subgraphs must not be directly reachable by "
                        "untrusted clients; place them behind the gateway/router "
                        "on a private network and restrict `_service` access to "
                        "the gateway. If a subgraph must be public, enforce "
                        "authentication on the `_service` field or strip it at an "
                        "edge proxy."
                    ),
                }
            )

    # ── Probe 2: _entities resolver reachability ────────────────────────────
    try:
        ent_resp = await client.query(_ENTITIES_QUERY)
    except Exception:
        ent_resp = None

    if isinstance(ent_resp, dict) and not _field_is_unknown(ent_resp, "_entities"):
        data = ent_resp.get("data") or {}
        has_entities_data = isinstance(data, dict) and "_entities" in data
        # A representations-validation error (field exists but the empty/invalid
        # representation was rejected) also confirms the resolver is reachable.
        errors = ent_resp.get("errors") or []
        representations_error = any(
            "representation" in str(e.get("message", "")).lower() for e in errors
        )
        if has_entities_data or representations_error:
            evidence = json.dumps(
                {
                    "probe": _ENTITIES_QUERY,
                    "response_prefix": json.dumps(ent_resp)[:400],
                }
            )
            findings.append(
                {
                    "category": ENTITIES_CATEGORY,
                    "severity": ENTITIES_SEVERITY,
                    "title": "Apollo Federation _entities Resolver Reachable",
                    "evidence": evidence,
                    "description": (
                        "The GraphQL endpoint exposes the Apollo Federation "
                        "`_entities(representations: [...])` resolver to direct "
                        "clients. This is the entity-resolution entry point "
                        "normally invoked only by the federation gateway."
                    ),
                    "reproduction": (
                        'Send a POST request with body: '
                        '{"query": "{ _entities(representations: []) { __typename } }"} '
                        "and observe that the `_entities` field is recognised "
                        "(returns data or a representations-validation error "
                        "rather than an unknown-field error)."
                    ),
                    "impact": (
                        "A reachable `_entities` resolver lets an attacker fetch "
                        "arbitrary entities by `__typename` and `@key` value "
                        "directly from the subgraph, bypassing authorization "
                        "enforced only at the gateway layer (a documented "
                        "federation BOLA/authz-bypass surface)."
                    ),
                    "remediation": (
                        "Keep federation subgraphs on a private network behind "
                        "the gateway. If a subgraph is exposed, enforce the same "
                        "authorization on the `_entities` resolver that the "
                        "gateway applies, and validate that entity references "
                        "belong to the requesting principal."
                    ),
                }
            )

    return findings
