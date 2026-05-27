"""FastAPI mock GraphQL server for testing."""
from __future__ import annotations

import re
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


def create_app(
    introspection_enabled: bool = True,
    depth_limit: int | None = None,
    batch_limit: int | None = None,
    suggestions_enabled: bool = True,
    dangerous_mutations: list[str] | None = None,
    cors_misconfigured: bool = True,
    accept_form_post: bool = False,
    accept_get_query: bool = False,
    engine: str | None = None,
    apq_enabled: bool = False,
    apq_require_auth: bool = False,
    apq_rate_limit: int | None = None,
) -> FastAPI:
    app = FastAPI()
    cfg = {
        "introspection_enabled": introspection_enabled,
        "depth_limit": depth_limit,
        "batch_limit": batch_limit,
        "suggestions_enabled": suggestions_enabled,
        "dangerous_mutations": dangerous_mutations or [],
        "cors_misconfigured": cors_misconfigured,
        "accept_form_post": accept_form_post,
        "accept_get_query": accept_get_query,
        "engine": engine,
        "apq_enabled": apq_enabled,
        "apq_require_auth": apq_require_auth,
        "apq_rate_limit": apq_rate_limit,
    }
    # APQ state: hash → query string
    apq_cache: dict[str, str] = {}
    # Per-IP registration counts (keyed by client host)
    apq_reg_counts: dict[str, int] = {}

    # Engine-specific error wording / headers used by the fingerprint probes.
    # Keyed by the engine name from src/enshroud/data/signatures.json.
    engine_profiles: dict[str, dict[str, Any]] = {
        "apollo": {
            "headers": {},
            "error": 'Syntax Error: Expected Name, found "}".',
            "extensions": {"code": "GRAPHQL_PARSE_FAILED"},
        },
        "hasura": {
            "headers": {"x-hasura-role": "anonymous"},
            "error": "not a valid graphql query",
            "extensions": {},
        },
        "graphene": {
            "headers": {},
            "error": "Syntax Error GraphQL request (1:9) Expected Name, found }",
            "extensions": {},
        },
        "wpgraphql": {
            "headers": {"x-graphql-keys": "skipped"},
            "error": "Internal server error processing the WPGraphQL request",
            "extensions": {"category": "graphql_error"},
        },
    }

    def _engine_headers(response: JSONResponse) -> JSONResponse:
        profile = engine_profiles.get(cfg["engine"] or "")
        if profile:
            for k, v in profile.get("headers", {}).items():
                response.headers[k] = v
        return response

    def _add_cors(response: JSONResponse) -> JSONResponse:
        if cfg["cors_misconfigured"]:
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Credentials"] = "true"
        return response

    def _query_depth(query: str) -> int:
        """Count the maximum nesting depth of a GraphQL query string."""
        depth = 0
        max_depth = 0
        for ch in query:
            if ch == "{":
                depth += 1
                max_depth = max(max_depth, depth)
            elif ch == "}":
                depth -= 1
        return max_depth

    def _count_aliases(query: str) -> int:
        """Count aliased fields (pattern: word: word)."""
        return len(re.findall(r'\b\w+\s*:\s*\w+', query))

    def _build_introspection_response(dangerous_mutations: list[str]) -> dict:
        mutation_fields = [
            {"name": name, "description": None, "args": []}
            for name in dangerous_mutations
        ]
        return {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"} if mutation_fields else None,
                    "types": [
                        {
                            "name": "Query",
                            "kind": "OBJECT",
                            "fields": [{"name": "__typename"}],
                        },
                        {
                            "name": "Mutation",
                            "kind": "OBJECT",
                            "fields": mutation_fields,
                        },
                    ],
                }
            }
        }

    def _build_mutation_introspection_response(dangerous_mutations: list[str]) -> dict:
        """Build introspection response specifically for mutationType fields query."""
        mutation_fields = [
            {"name": name, "description": None, "args": []}
            for name in dangerous_mutations
        ]
        return {
            "data": {
                "__schema": {
                    "mutationType": {
                        "name": "Mutation",
                        "fields": mutation_fields,
                    }
                }
            }
        }

    @app.options("/graphql")
    async def graphql_options(request: Request) -> JSONResponse:
        response = JSONResponse(content={})
        if cfg["cors_misconfigured"]:
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return response

    @app.get("/graphql")
    async def graphql_get(request: Request) -> JSONResponse:
        query = request.query_params.get("query", "")
        is_mutation = query.lstrip().startswith("mutation")
        if is_mutation and not cfg["accept_get_query"]:
            # Reject mutations over GET (CSRF-safe behavior).
            response = JSONResponse(
                status_code=405,
                content={
                    "errors": [
                        {"message": "GET requests may not perform mutations."}
                    ]
                },
            )
            _add_cors(response)
            return response
        response = JSONResponse(content={"data": {"__typename": "Query"}})
        _add_cors(response)
        return response

    @app.post("/graphql")
    async def graphql_post(request: Request) -> JSONResponse:
        content_type = request.headers.get("content-type", "")
        is_form = "application/x-www-form-urlencoded" in content_type

        if is_form:
            if not cfg["accept_form_post"]:
                # Reject non-JSON content types (CSRF-safe behavior).
                response = JSONResponse(
                    status_code=400,
                    content={
                        "errors": [
                            {
                                "message": (
                                    "This operation requires "
                                    "Content-Type: application/json."
                                )
                            }
                        ]
                    },
                )
                _add_cors(response)
                return response
            form = await request.form()
            query = form.get("query", "")
            response = JSONResponse(content={"data": {"__typename": "Mutation"}})
            _add_cors(response)
            return response

        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                status_code=400,
                content={"errors": [{"message": "Invalid JSON"}]},
            )

        # ── APQ handling ────────────────────────────────────────────────────
        extensions = body.get("extensions") or {}
        pq = extensions.get("persistedQuery")
        if pq is not None and cfg["apq_enabled"]:
            client_hash: str = pq.get("sha256Hash", "")
            incoming_query: str | None = body.get("query")

            if incoming_query is None:
                # Hash-only lookup
                if client_hash in apq_cache:
                    # Serve from cache
                    response = JSONResponse(content={"data": {"__typename": "Query"}})
                    _add_cors(response)
                    return response
                else:
                    response = JSONResponse(
                        content={
                            "errors": [
                                {
                                    "message": "PersistedQueryNotFound",
                                    "extensions": {"code": "PersistedQueryNotFound"},
                                }
                            ]
                        }
                    )
                    _add_cors(response)
                    return response
            else:
                # Registration request
                if cfg["apq_require_auth"]:
                    auth = request.headers.get("authorization", "")
                    if not auth:
                        response = JSONResponse(
                            status_code=401,
                            content={"errors": [{"message": "Unauthorized"}]},
                        )
                        return response

                client_ip = request.client.host if request.client else "unknown"
                if cfg["apq_rate_limit"] is not None:
                    count = apq_reg_counts.get(client_ip, 0)
                    if count >= cfg["apq_rate_limit"]:
                        response = JSONResponse(
                            status_code=429,
                            content={"errors": [{"message": "Too Many Requests"}]},
                        )
                        return response
                    apq_reg_counts[client_ip] = count + 1

                apq_cache[client_hash] = incoming_query
                response = JSONResponse(content={"data": {"__typename": "Query"}})
                _add_cors(response)
                return response

        query: str = body.get("query", "")

        # Check depth limit
        if cfg["depth_limit"] is not None:
            depth = _query_depth(query)
            if depth > cfg["depth_limit"]:
                response = JSONResponse(
                    content={
                        "errors": [
                            {
                                "message": (
                                    f"Query depth {depth} exceeds max depth {cfg['depth_limit']}"
                                )
                            }
                        ]
                    }
                )
                _add_cors(response)
                return response

        # Check batch/alias limit
        if cfg["batch_limit"] is not None:
            alias_count = _count_aliases(query)
            if alias_count > cfg["batch_limit"]:
                response = JSONResponse(
                    content={
                        "errors": [
                            {
                                "message": (
                                    f"Alias count {alias_count} exceeds batch limit "
                                    f"{cfg['batch_limit']}"
                                )
                            }
                        ]
                    }
                )
                _add_cors(response)
                return response

        # Handle introspection queries
        # Use word-boundary checks to avoid matching __typename as __type
        import re as _re
        is_introspection = (
            "__schema" in query
            or bool(_re.search(r'__type\b(?!name)', query))
        )

        if is_introspection:
            if not cfg["introspection_enabled"]:
                response = JSONResponse(
                    content={
                        "errors": [{"message": "Introspection is disabled"}]
                    }
                )
                _add_cors(response)
                return response

            # Detect what kind of introspection query
            if "mutationType" in query and "fields" in query and "args" in query:
                # mutation-enum style query
                resp_data = _build_mutation_introspection_response(cfg["dangerous_mutations"])
            else:
                resp_data = _build_introspection_response(cfg["dangerous_mutations"])

            response = JSONResponse(content=resp_data)
            _add_cors(response)
            return response

        # Handle field suggestion oracle
        if "nonExistentFieldXyzzy" in query:
            errors: list[dict] = [
                {"message": "Cannot query field 'nonExistentFieldXyzzy' on type 'Query'."}
            ]
            if cfg["suggestions_enabled"]:
                errors[0]["message"] += ' Did you mean "user" or "users"?'
            response = JSONResponse(content={"errors": errors})
            _add_cors(response)
            return response

        # If the query has aliases (e.g. q1: __typename q2: __typename ...),
        # return all of them so alias-batch detection works correctly.
        alias_matches = re.findall(r'(\w+)\s*:\s*__typename', query)
        if alias_matches:
            data = {alias: "Query" for alias in alias_matches}
            response = JSONResponse(content={"data": data})
            _add_cors(response)
            return response

        # Fingerprint probes: malformed selection sets / non-existent fields /
        # unknown directives. When an engine profile is configured, return that
        # engine's distinctive error wording so the fingerprint check can match.
        profile = engine_profiles.get(cfg["engine"] or "")
        looks_malformed = (
            "enshroudFingerprintProbe" in query
            or "@enshroudProbe" in query
            or bool(re.match(r"\s*query\s*\{\s*\}\s*$", query))
            or "@skip" in query
        )
        if profile is not None and looks_malformed:
            err: dict[str, Any] = {"message": profile["error"]}
            if profile.get("extensions"):
                err["extensions"] = profile["extensions"]
            response = JSONResponse(status_code=200, content={"errors": [err]})
            _add_cors(response)
            _engine_headers(response)
            return response

        # Default response
        response = JSONResponse(content={"data": {"__typename": "Query"}})
        _add_cors(response)
        return response

    return app
