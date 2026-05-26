"""CORS misconfiguration check."""
from __future__ import annotations

import json
from typing import Any

from enshroud.client import GraphQLClient

EVIL_ORIGIN = "https://evil.example.com"


async def check(client: GraphQLClient) -> list[dict[str, Any]]:
    """Check for CORS misconfiguration: wildcard origin + credentials."""
    findings: list[dict[str, Any]] = []

    try:
        resp = await client.post_raw(
            "{ __typename }",
            extra_headers={"Origin": EVIL_ORIGIN},
        )
    except Exception:
        return findings

    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "")

    wildcard = acao == "*"
    credentials_true = acac.lower() == "true"

    if wildcard and credentials_true:
        evidence = json.dumps(
            {
                "Access-Control-Allow-Origin": acao,
                "Access-Control-Allow-Credentials": acac,
                "status_code": resp.status_code,
            }
        )
        findings.append(
            {
                "category": "cors_misconfiguration",
                "severity": "HIGH",
                "title": "CORS Misconfiguration on GraphQL Endpoint",
                "evidence": evidence,
                "description": (
                    "The GraphQL endpoint responds with both "
                    "`Access-Control-Allow-Origin: *` and "
                    "`Access-Control-Allow-Credentials: true`. "
                    "This combination is prohibited by the CORS spec but some servers "
                    "misconfigure it, enabling cross-origin credential theft."
                ),
                "reproduction": (
                    f"Send a POST to the endpoint with header `Origin: {EVIL_ORIGIN}`. "
                    "Observe the response headers for "
                    "`Access-Control-Allow-Origin: *` and "
                    "`Access-Control-Allow-Credentials: true`."
                ),
                "impact": (
                    "A malicious website can make authenticated GraphQL requests on "
                    "behalf of a victim user, exfiltrating data or performing actions "
                    "using their credentials."
                ),
                "remediation": (
                    "Never combine a wildcard `Access-Control-Allow-Origin` with "
                    "`Access-Control-Allow-Credentials: true`. "
                    "Use an explicit allowlist of trusted origins instead."
                ),
            }
        )

    return findings
