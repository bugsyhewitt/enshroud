"""Object-level authorization (BOLA / IDOR) confirmation via ID-argument swap.

GraphQL has no built-in authorization: every resolver is responsible for
checking that the caller may see the object it returns. When a resolver fetches
an object by an ID argument and forgets that check, any authenticated (even
low-privilege) caller can read another user's object simply by changing the ID
— Broken Object Level Authorization, OWASP API Security Top 10 **API1:2023**,
CWE-639. It is the single most common and highest-impact GraphQL authorization
bug.

This check *confirms* the missing control with a **bounded, benign** proof: it
sends **one** request that asks for a specific other object by ID, using the
caller's own session, and fires only when the server returns **that other
object's data**. That is the bright line between a confirmation and an attack
(the packet's D3 / §10 discipline):

  * It reads **one** object the operator names on the command line — it never
    enumerates an ID range or sweeps a user base (that is the attack the
    ``blast_radius`` *describes*, not what enshroud runs — anti-pattern A8).
  * Merely observing that ``user(id: …)`` *exists and takes an ID* is
    **detection**, not confirmation. The finding fires only when the response
    carries the *other* object's identifier — returning the caller's *own*
    object is explicitly **not** BOLA (anti-pattern A5).

Because it actively requests another principal's object, the check is **active**
and gated behind the ``--active`` flag (off by default), and is never part of
``--checks all``. The operator must supply the field, the ID argument name, and
the two object IDs (ideally both test accounts they control), e.g.::

    enshroud --target … --checks bola --active \\
        --auth-header "Authorization: Bearer <low-priv-session>" \\
        --bola-field user --bola-id-arg id --bola-my-id 1 --bola-other-id 2

References:
  * OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization
  * CWE-639 — Authorization Bypass Through User-Controlled Key
  * *Black Hat GraphQL* — Authorization Bypasses (object-level)
"""
from __future__ import annotations

import json
from typing import Any

from enshroud.client import GraphQLClient

# Maximum length of the response evidence payload embedded in a finding.
# Mirrors the 500-byte ceiling the other checks use; the evidence is also
# redacted (see ``_redact``) so sensitive field *values* never leave the host.
EVIDENCE_MAX_LEN = 500

# Field names whose *values* must be redacted from the evidence blob. We prove
# BOLA by the returned object's *identifier*, never by exfiltrating its
# sensitive contents — so personal/credential-shaped fields are masked in the
# stored evidence while still demonstrating the object was readable.
_REDACT_FIELDS = frozenset(
    {
        "ssn",
        "creditcard",
        "credit_card",
        "password",
        "passwordhash",
        "token",
        "apikey",
        "api_key",
        "secret",
        "email",
        "phone",
        "address",
    }
)


def build_bola_query(query_field: str, id_arg: str, object_id: str, fields: list[str]) -> str:
    """Build a single benign object-fetch query swapping in ``object_id``.

    The selection always includes ``id`` (the identifier we prove BOLA with);
    any extra ``fields`` are requested too so the operator can see *what* was
    exposed, but the confirmation decision rests on the ``id`` alone.
    """
    selection = " ".join(dict.fromkeys(["id", *fields])) or "id"
    # The ID is rendered as a quoted string literal. GraphQL coerces a string
    # literal to ID/Int server-side, so this works for both ID and numeric keys
    # without the check needing to know the scalar type.
    escaped = object_id.replace("\\", "\\\\").replace('"', '\\"')
    return f'{{ {query_field}({id_arg}: "{escaped}") {{ {selection} }} }}'


def _redact(obj: dict[str, Any]) -> dict[str, Any]:
    """Mask sensitive field *values* in an object before storing it as evidence."""
    redacted: dict[str, Any] = {}
    for key, value in obj.items():
        if key.lower() in _REDACT_FIELDS and value not in (None, ""):
            redacted[key] = "<redacted>"
        else:
            redacted[key] = value
    return redacted


def _extract_object(resp: dict[str, Any], query_field: str) -> dict[str, Any] | None:
    """Return the object the server returned under ``query_field`` (or None).

    None is returned both when the field is absent/null and when the response
    is an error — in either case no object was disclosed and the check must not
    fire.
    """
    data = resp.get("data")
    if not isinstance(data, dict):
        return None
    obj = data.get(query_field)
    if not isinstance(obj, dict):
        return None
    return obj


async def check(
    client: GraphQLClient,
    *,
    active: bool = False,
    query_field: str | None = None,
    id_arg: str = "id",
    my_id: str | None = None,
    other_id: str | None = None,
    extra_fields: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Confirm object-level BOLA with one benign ID-swap request.

    The check is a no-op unless it is explicitly enabled and fully configured:

      * ``active`` must be True (the ``--active`` flag) — it requests another
        principal's object, so it never runs in a default/passive scan.
      * ``query_field`` and ``other_id`` must be supplied — there is no safe
        default object to fetch.

    It fires a single finding when the server returns the *other* object
    (identified by ``other_id``) for the caller's own session. Returning the
    caller's own object, an error, or null yields no finding.
    """
    findings: list[dict[str, Any]] = []

    # Fail-closed: only run when explicitly enabled and fully targeted.
    if not active or not query_field or other_id is None:
        return findings
    # Confirming BOLA requires reading *another* principal's object; if the two
    # IDs are identical there is no cross-object access to prove (A5).
    if my_id is not None and str(my_id) == str(other_id):
        return findings

    fields = extra_fields or []
    query = build_bola_query(query_field, id_arg, str(other_id), fields)

    try:
        resp = await client.query(query)
    except Exception:
        # Transport-level failure — be conservative and report nothing.
        return findings

    obj = _extract_object(resp, query_field)
    if obj is None:
        return findings

    returned_id = obj.get("id")
    # Confirmation invariant (A5): the object returned must be the *other*
    # principal's object. If the server echoed our own id (or some unrelated
    # id), object-level authorization was *not* proven bypassed.
    if returned_id is None or str(returned_id) != str(other_id):
        return findings

    redacted = _redact(obj)
    evidence = json.dumps({"data": {query_field: redacted}})[:EVIDENCE_MAX_LEN]
    leaked_fields = sorted(k for k in obj if k != "id" and obj.get(k) not in (None, ""))

    findings.append(
        {
            "category": "bola_object_authz_missing",
            "severity": "HIGH",
            "title": (
                f"Object-Level Authorization Missing (BOLA) on `{query_field}`"
            ),
            "owasp": ["API1:2023"],
            "cwe": ["CWE-639"],
            "query_field": query_field,
            "id_arg": id_arg,
            "other_id": str(other_id),
            "leaked_fields": leaked_fields,
            "confirmation": {
                "method": "benign_poc",
                "evidence": (
                    f"retrieved {query_field} id={other_id} using the caller's "
                    "own session (object-level authorization missing)"
                ),
                "blast_radius": (
                    f"any user's {query_field} is readable by enumerating the "
                    f"`{id_arg}` argument — account takeover precursors, mass "
                    "data exfiltration (NOT executed here)"
                ),
                "reproduction": (
                    f"with a low-privilege session, send "
                    f"{build_bola_query(query_field, id_arg, str(other_id), fields)} "
                    "and observe another principal's object returned"
                ),
            },
            "evidence": evidence,
            "description": (
                f"The `{query_field}` resolver returned the object identified by "
                f"`{id_arg}: \"{other_id}\"` to a caller whose session does not "
                "own it. GraphQL performs no authorization of its own, so a "
                "resolver that fetches an object by a client-supplied identifier "
                "must check that the caller is allowed to see it. This one does "
                "not — Broken Object Level Authorization. enshroud confirmed the "
                "missing control with a single benign request reading one object "
                "the operator named; it did not enumerate the ID space."
            ),
            "reproduction": (
                f"Authenticate as a low-privilege principal, then POST "
                f'{{"query": "{build_bola_query(query_field, id_arg, str(other_id), fields)}"}} '
                "and observe that the other principal's object is returned."
            ),
            "impact": (
                "An attacker can read (and, where the same gap exists on "
                "mutations, modify) arbitrary objects belonging to other users "
                f"by changing the `{id_arg}` argument of `{query_field}`. Object "
                "IDs are frequently sequential or guessable, turning this into "
                "mass data exposure and account-takeover groundwork. This is the "
                "highest-frequency GraphQL authorization bug (OWASP API1:2023, "
                "CWE-639)."
            ),
            "remediation": (
                "Enforce object-level authorization inside the resolver (or a "
                "shared data-loader / policy layer): after loading the object by "
                "ID, verify the authenticated principal is permitted to access "
                "*that specific object* before returning it. Do not rely on the "
                "object ID being unguessable. Centralise the check so every "
                "ID-keyed field is covered uniformly."
            ),
        }
    )

    return findings
