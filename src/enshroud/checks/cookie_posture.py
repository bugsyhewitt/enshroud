"""Cookie posture check — Set-Cookie attribute hygiene (POST_V01 #10).

This is the response-header companion to the active ``csrf`` and ``batch-array``
checks. Those checks prove that a server *accepts* cross-origin / batched
state-changing requests; this check inspects whether the session cookies the
server hands out can actually be *replayed* by a browser from an attacker's page.

A GraphQL endpoint is only exploitable via CSRF, Cross-Site WebSocket Hijacking,
or batched auth brute-force from a victim's browser if the victim's session
cookie rides along on the cross-site request. The ``SameSite`` cookie attribute
is the modern browser-side control that decides this:

* ``SameSite=None`` (or any cookie that also lacks ``Secure``) is sent on
  cross-site requests — the precondition that turns the ``csrf`` finding into a
  working attack.
* a missing ``SameSite`` attribute leaves the cookie at the browser default,
  which is inconsistent across browsers and versions and is treated here as a
  weak posture worth flagging.
* a missing ``Secure`` attribute lets the cookie travel over plaintext HTTP
  (MITM / sidejacking), and ``SameSite=None`` without ``Secure`` is rejected by
  modern browsers entirely.
* a missing ``HttpOnly`` attribute exposes the cookie to XSS-driven theft.

This check is pure response-header analysis: it sends no payloads, mutates
nothing, and never probes actively. It fires at MEDIUM when a Set-Cookie value
is missing a hardening attribute, and stays silent when the endpoint sets no
cookies or sets only well-hardened ones.
"""
from __future__ import annotations

from typing import Any

from enshroud.client import GraphQLClient

CATEGORY = "insecure_cookie_posture"
SEVERITY = "MEDIUM"


def _parse_attributes(set_cookie: str) -> tuple[str, dict[str, str]]:
    """Split a single Set-Cookie header into (cookie_name, lowercased attrs).

    Attribute values are kept as-is (lowercased) for matching; flag attributes
    (Secure, HttpOnly) map to an empty string. The cookie name is the token
    before the first ``=`` in the first ``name=value`` pair.
    """
    parts = [p.strip() for p in set_cookie.split(";")]
    name = ""
    attrs: dict[str, str] = {}
    if parts:
        first = parts[0]
        name = first.split("=", 1)[0].strip()
    for segment in parts[1:]:
        if not segment:
            continue
        if "=" in segment:
            key, _, value = segment.partition("=")
            attrs[key.strip().lower()] = value.strip().lower()
        else:
            attrs[segment.strip().lower()] = ""
    return name, attrs


def _evaluate_cookie(set_cookie: str) -> dict[str, Any] | None:
    """Return a weakness record for one Set-Cookie, or None if well-hardened."""
    name, attrs = _parse_attributes(set_cookie)

    has_secure = "secure" in attrs
    has_httponly = "httponly" in attrs
    samesite = attrs.get("samesite")  # None == attribute absent

    issues: list[str] = []

    # SameSite is the control that decides cross-site cookie replay.
    if samesite is None:
        issues.append(
            "missing SameSite attribute (browser default is inconsistent; the "
            "cookie may be sent on cross-site requests, enabling CSRF/CSWSH)"
        )
    elif samesite == "none":
        issues.append(
            "SameSite=None — the cookie is sent on cross-site requests, the "
            "precondition that makes CSRF and batched auth brute-force "
            "exploitable from a browser"
        )

    if not has_secure:
        issues.append(
            "missing Secure attribute (cookie can travel over plaintext HTTP; "
            "SameSite=None without Secure is rejected by modern browsers)"
        )

    if not has_httponly:
        issues.append(
            "missing HttpOnly attribute (cookie is readable by JavaScript, "
            "exposing it to theft via XSS)"
        )

    if not issues:
        return None

    return {"name": name, "raw": set_cookie, "issues": issues}


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Inspect Set-Cookie attributes on the GraphQL endpoint response.

    Read-only: sends a single benign ``{ __typename }`` request and analyses
    the response's Set-Cookie headers. No payloads, no mutations.
    """
    findings: list[dict[str, Any]] = []

    try:
        resp = await client.post_raw("{ __typename }")
    except Exception:
        return findings

    # httpx merges duplicate headers for .get(); get_list preserves each
    # Set-Cookie header so multi-cookie responses are evaluated individually.
    try:
        set_cookies = resp.headers.get_list("set-cookie")
    except AttributeError:  # pragma: no cover - non-httpx header containers
        single = resp.headers.get("set-cookie")
        set_cookies = [single] if single else []

    weaknesses = [
        record
        for record in (_evaluate_cookie(sc) for sc in set_cookies if sc)
        if record is not None
    ]

    if not weaknesses:
        return findings

    import json

    cookie_summaries: list[str] = []
    for w in weaknesses:
        label = w["name"] or "(unnamed cookie)"
        cookie_summaries.append(f"`{label}`: " + "; ".join(w["issues"]))

    evidence = json.dumps(
        {
            "set_cookie_headers": [w["raw"] for w in weaknesses],
            "weaknesses": {
                (w["name"] or "(unnamed cookie)"): w["issues"] for w in weaknesses
            },
            "status_code": resp.status_code,
        }
    )

    findings.append(
        {
            "category": CATEGORY,
            "severity": SEVERITY,
            "title": "Insecure Session Cookie Posture on GraphQL Endpoint",
            "evidence": evidence,
            "description": (
                "The GraphQL endpoint sets one or more cookies that are missing "
                "hardening attributes. Detected: " + " | ".join(cookie_summaries) + "."
            ),
            "reproduction": (
                "Send a request to the endpoint and inspect the `Set-Cookie` "
                "response headers. Observe the missing or weak `SameSite`, "
                "`Secure`, or `HttpOnly` attributes listed in the evidence."
            ),
            "impact": (
                "Weak cookie attributes are the browser-side precondition that "
                "turns enshroud's `csrf`, `array_batching`, and "
                "`websocket_cswsh` findings into working real-world attacks. A "
                "cookie without `SameSite=Lax/Strict` is replayed on cross-site "
                "requests, so a victim's session rides along on an attacker's "
                "forged GraphQL request; a cookie without `Secure` can be "
                "captured over plaintext HTTP; a cookie without `HttpOnly` can "
                "be stolen via XSS."
            ),
            "remediation": (
                "Set session cookies with `SameSite=Lax` (or `Strict` where the "
                "UX allows), `Secure`, and `HttpOnly`. Only use `SameSite=None` "
                "for cookies that genuinely require cross-site delivery, and "
                "always pair it with `Secure`. This complements — but does not "
                "replace — server-side CSRF token validation."
            ),
        }
    )

    return findings
