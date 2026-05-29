"""FastAPI mock GraphQL server for testing."""
from __future__ import annotations

import hashlib
import re
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

# Minimal HTML pages carrying each IDE's distinctive marker string, matching the
# needles in src/enshroud/checks/graphql_ide.py. Real consoles ship large
# bundles; for detection purposes the marker substring is what matters.
_IDE_HTML: dict[str, str] = {
    "graphiql": (
        "<!DOCTYPE html><html><head><title>GraphiQL</title></head>"
        '<body><div id="graphiql">Loading GraphiQL...</div>'
        '<script src="//cdn.jsdelivr.net/npm/graphiql/graphiql.min.js">'
        "</script></body></html>"
    ),
    "playground": (
        "<!DOCTYPE html><html><head><title>GraphQL Playground</title></head>"
        '<body><div id="root"></div>'
        '<script src="//cdn.jsdelivr.net/npm/graphql-playground-react/build/'
        'static/js/middleware.js"></script></body></html>'
    ),
    "sandbox": (
        "<!DOCTYPE html><html><head><title>Apollo Sandbox</title></head>"
        '<body><div id="embeddable-sandbox"></div>'
        '<script src="https://embeddable-sandbox.cdn.apollographql.com/'
        '_latest/embeddable-sandbox.umd.production.min.js"></script>'
        "</body></html>"
    ),
}


def create_app(
    introspection_enabled: bool = True,
    depth_limit: int | None = None,
    depth_limit_expands_fragments: bool = True,
    batch_limit: int | None = None,
    suggestions_enabled: bool = True,
    dangerous_mutations: list[str] | None = None,
    cors_misconfigured: bool = True,
    accept_form_post: bool = False,
    accept_multipart_post: bool = False,
    accept_text_plain_post: bool = False,
    accept_get_query: bool = False,
    accept_get_read_query: bool = True,
    array_batch_enabled: bool = False,
    engine: str | None = None,
    apq_enabled: bool = False,
    apq_require_auth: bool = False,
    apq_rate_limit: int | None = None,
    apq_verify_hash: bool = False,
    apq_serve_over_get: bool = False,
    pq_id_store: bool = False,
    schema_fields: list[str] | None = None,
    injectable_arg: dict[str, Any] | None = None,
    set_cookies: list[str] | None = None,
    field_dup_limit: int | None = None,
    directive_validation: bool = False,
    custom_directives: list[str] | None = None,
    federation_sdl: str | None = None,
    federation_entities: bool = False,
    fragment_cycle_validation: bool = False,
    alias_auth_bypass: dict[str, Any] | None = None,
    incremental_delivery: bool = False,
    graphql_ide: str | None = None,
    introspection_filter: str | None = None,
    tracing: str | None = None,
    mutation_arg_signature: dict[str, list[dict[str, Any]]] | None = None,
    op_type_confusion: bool = False,
    directive_enforcement_bypass: bool = False,
) -> FastAPI:
    app = FastAPI()
    cfg = {
        "introspection_enabled": introspection_enabled,
        "depth_limit": depth_limit,
        # Whether the depth limiter expands fragment spreads before measuring
        # depth, used by the depth-bypass check. When True (default, spec-correct)
        # the server inlines fragment definitions into the operation before
        # counting nesting, so a fragment-wrapped deep query is rejected just like
        # a flat one. When False it models the documented buggy limiter that
        # counts only the literal operation body: a flat deep query is rejected,
        # but the same nesting hidden inside a named fragment (reached via a single
        # `...Spread` at the operation top level) slips past the cap and executes.
        "depth_limit_expands_fragments": depth_limit_expands_fragments,
        "batch_limit": batch_limit,
        "suggestions_enabled": suggestions_enabled,
        "dangerous_mutations": dangerous_mutations or [],
        "cors_misconfigured": cors_misconfigured,
        "accept_form_post": accept_form_post,
        # Whether mutations are executable via multipart/form-data and text/plain
        # POSTs — the two CORS simple-request content types the csrf-multipart
        # check probes (distinct from the x-www-form-urlencoded path above). A
        # server that validates JSON / urlencoded but routes these alternate
        # transports through a parser that skips the CSRF check executes them.
        "accept_multipart_post": accept_multipart_post,
        "accept_text_plain_post": accept_text_plain_post,
        "accept_get_query": accept_get_query,
        # Whether a plain, non-persisted, non-mutation *read* query executes over
        # GET (`GET /graphql?query={ __typename }`), used by the query-get check.
        # `accept_get_query` above gates GET *mutations* (the csrf check); this
        # flag gates GET *read queries*. When True (default) the GET route runs
        # the read query and returns a `data` response — the cacheable /
        # cross-site-readable surface the query-get check reports. When False the
        # GET route rejects a read query with HTTP 405 ("GET requests are not
        # supported"), modelling a server that reserves GET for safe/empty
        # responses only. Default True keeps the mock's permissive-by-default
        # posture (mirroring cors_misconfigured=True etc.) and preserves the
        # pre-existing behaviour the csrf / introspection-bypass GET probes rely
        # on.
        "accept_get_read_query": accept_get_read_query,
        "array_batch_enabled": array_batch_enabled,
        "engine": engine,
        "apq_enabled": apq_enabled,
        "apq_require_auth": apq_require_auth,
        "apq_rate_limit": apq_rate_limit,
        # Whether the APQ layer verifies sha256(query) == sha256Hash before
        # storing a registration (the spec-compliant behaviour). When False
        # (default) the server trusts the client-supplied hash, modelling the
        # cache-poisoning vulnerability the apq-collision check detects.
        "apq_verify_hash": apq_verify_hash,
        # Whether a registered persisted query can be *executed over GET* via a
        # hash-only lookup (`GET /graphql?extensions={persistedQuery:{...}}`),
        # used by the apq-get check. APQ's defining feature is serving a query
        # by hash over a cacheable GET request. When True (the documented
        # misconfiguration) the GET route resolves the hash from the same APQ
        # cache the POST route populates and returns the operation's data — a
        # cacheable cross-site (CSRF / cache-flooding) execution path. When
        # False (default, safe) a persisted-query GET returns
        # PersistedQueryNotFound regardless of cache state, mirroring a server
        # that only honours APQ over POST.
        "apq_serve_over_get": apq_serve_over_get,
        # ID-keyed persisted-query store, used by the pq-enum check. This is a
        # *different* persisted-query model from APQ (above): instead of keying
        # the cache on the SHA-256 hash of the query text, the server resolves a
        # registered operation from a short, client-supplied document identifier
        # (Relay `id`, trusted-documents `documentId`, or
        # `extensions.persistedQuery.id`) sent with *no* query body. When True
        # (the misconfiguration the pq-enum check detects) the POST route treats
        # any such ID-only request as a hit and returns a `data` response,
        # modelling a small/sequential ID space an attacker can enumerate to
        # replay registered operations. When False (default, safe) an ID-only
        # request is not recognised and falls through to the normal handlers
        # (yielding an error / non-`data` response), so the check stays silent.
        "pq_id_store": pq_id_store,
        # Real top-level fields, used by the schema-fuzz oracle simulation.
        "schema_fields": schema_fields,
        # Injectable argument simulation, used by the injection check.
        # Shape: {"field": str, "arg": str, "dbms_error": str | None,
        #         "time_based": bool}. When set, the server exposes a query
        #         field with a String arg and reflects a DBMS error / sleeps
        #         when an injection payload hits that arg.
        "injectable_arg": injectable_arg,
        # Raw Set-Cookie header values emitted on every response, used by the
        # cookie-posture check. Each entry is a full Set-Cookie value, e.g.
        # "sid=abc; Path=/; SameSite=None".
        "set_cookies": set_cookies,
        # Field-duplication / fragment-spread cap, used by the field-dup check.
        # When set, the server rejects a query whose repeated __typename count
        # or fragment-spread count exceeds this limit with a complexity error.
        "field_dup_limit": field_dup_limit,
        # Directive validation, used by the directive-abuse check. When True the
        # server behaves like a spec-compliant validating executor: it rejects a
        # repeated non-repeatable directive ("may not be used more than once")
        # and an unknown directive ("Unknown directive ..."). When False it
        # silently accepts both.
        "directive_validation": directive_validation,
        # Real custom directive names (without the @). When set and an unknown
        # directive probe is lexically close to one of these, the server emits a
        # "Did you mean @X" suggestion that leaks the real directive name —
        # exercising the directive-abuse recon path.
        "custom_directives": custom_directives,
        # Apollo Federation simulation, used by the federation check. When
        # `federation_sdl` is a non-empty string the server answers
        # `{ _service { sdl } }` with that SDL document (the introspection-bypass
        # schema leak). When `federation_entities` is True the server recognises
        # the `{ _entities(representations: []) { __typename } }` probe and
        # returns an empty entity list. When neither is set, both federation
        # fields are reported as unknown (non-federation endpoint).
        "federation_sdl": federation_sdl,
        "federation_entities": federation_entities,
        # Cyclic-fragment validation, used by the fragment-cycle check. When True
        # the server behaves like a spec-compliant validator: it rejects a
        # document whose fragment definitions form a cycle (A -> B -> A) or a
        # self-referential fragment (S -> S) with a "Cannot spread fragment
        # within itself" cycle error. When False (default) it silently accepts
        # the cyclic document and executes it (returns data), simulating a
        # non-validating / buggy executor.
        "fragment_cycle_validation": fragment_cycle_validation,
        # Field-aliasing authorization-bypass simulation, used by the
        # `auth-alias` check. When set, models a server whose authorization is
        # keyed on the *response key* (alias or field name) rather than on the
        # field's own authorization metadata — the real-world bug class. Shape:
        #   {"field": str,                 # the protected field name
        #    "denied_key": str | None}     # the response key the deny-list
        #                                   # matches on (defaults to `field`).
        # The server returns a "not authorized" error when the protected field
        # is selected under its denied key, but returns data when the same
        # field is requested under a *different* alias — the bypass. When None
        # (default) no field is protected and the check stays silent.
        "alias_auth_bypass": alias_auth_bypass,
        # Incremental-delivery (@defer / @stream) exposure, used by the
        # defer-abuse check. When True the server behaves like an engine with
        # incremental delivery *enabled*: it accepts an inline fragment carrying
        # @defer ({ ... @defer { __typename } }) and accepts @stream, returning
        # data with no directive error. When False (default) it behaves like a
        # spec-compliant / feature-disabled server: it rejects @defer as an
        # "Unknown directive" and rejects @stream as a directive-location
        # violation ("@stream may not be used on this field").
        "incremental_delivery": incremental_delivery,
        # In-browser GraphQL IDE exposure, used by the graphql-ide check. When
        # set to an IDE name ("graphiql", "playground", or "sandbox") the server
        # serves an HTML console page (containing that IDE's marker string) in
        # response to a GET carrying a browser `Accept: text/html` header — the
        # production-IDE-left-enabled misconfiguration. When None (default) the
        # GET endpoint only ever returns the JSON API, so the check stays silent.
        "graphql_ide": graphql_ide,
        # Naive introspection-filter modelling, used by the introspection-bypass
        # check. `introspection_enabled` is the spec-correct switch (when False
        # *all* introspection is blocked uniformly). `introspection_filter`
        # instead models a *broken* block that leaks via an alternate technique:
        #   * "schema_keyword" — the server string-matches the literal
        #     "__schema" token and rejects it, but never inspects `__type`, so a
        #     `__type(name: "Query")` POST query still returns schema data. The
        #     classic deny-list-by-substring bug.
        #   * "post_only" — the server blocks introspection on the POST/JSON
        #     transport but the same `__schema` query succeeds over GET (the
        #     control was wired into one route handler only).
        #   * "top_level_only" — the server inspects only the operation's
        #     top-level selection field names and rejects a literal top-level
        #     `__schema` / `__type` selection, but never resolves fragment
        #     spreads. A `__schema` query reached through a named fragment
        #     (`query { ...F } fragment F on Query { __schema {...} }`) has a
        #     top-level selection of `...F` (a spread, not a meta-field), so it
        #     slips past the naive guard and returns schema data.
        # When set, `introspection_enabled` is treated as False for the standard
        # POST `__schema` probe (so the existing `introspection` check stays
        # silent) while the modelled alternate technique leaks. When None
        # (default) introspection behaves per `introspection_enabled`.
        "introspection_filter": introspection_filter,
        # Performance-tracing exposure, used by the trace-exposure check.
        # `introspection_filter` and friends shape the *error* / introspection
        # paths; this flag shapes the *success* path's top-level `extensions`
        # block — the metadata a production server should never emit to an
        # arbitrary client. Values:
        #   * "apollo"     — attach an Apollo Tracing block
        #     (`extensions.tracing`) with an `execution.resolvers` list that
        #     leaks parent/field type names and per-resolver nanosecond timings.
        #   * "ftv1"       — attach a base64 `extensions.ftv1` Apollo Federation
        #     trace string (opaque protobuf blob).
        #   * "both"       — attach both formats.
        # When None (default) the success path returns no `extensions` block, so
        # the trace-exposure check stays silent (production-correct behaviour).
        "tracing": tracing,
        # Optional per-mutation argument signature, used by the
        # mutation-allowlist-bypass check. When provided, the introspection
        # response advertises each named mutation with the listed args
        # (each entry shaped {"name": str, "type": str, "required": bool}).
        # Independent of `dangerous_mutations`, which only carries names.
        "mutation_arg_signature": mutation_arg_signature or {},
        # When True, the POST handler models operation-type confusion: a
        # `query { <mut> { ... } }` request resolves the mutation field on
        # the Query root and stops at argument-validation, returning the
        # "argument is required" error the bypass probe looks for. When
        # False, the same request is rejected with a "Cannot query field on
        # type Query" validation error — the spec-correct outcome.
        "op_type_confusion": op_type_confusion,
        # Built-in directive enforcement, used by the directive-enforcement check.
        # When False (default, spec-correct) the server honours
        # `@skip(if: true)` / `@include(if: false)` on a field's selection by
        # omitting that field from the response. When True the server ignores
        # the directives and returns the gated field anyway, modelling a broken
        # executor whose directive-evaluation stage is skipped before resolution.
        "directive_enforcement_bypass": directive_enforcement_bypass,
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

    @app.middleware("http")
    async def _emit_cookies(request: Request, call_next):
        """Append configured Set-Cookie headers to every response."""
        response = await call_next(request)
        for cookie in cfg["set_cookies"] or []:
            response.headers.append("set-cookie", cookie)
        return response

    def _tracing_extensions() -> dict[str, Any] | None:
        """Build the success-path `extensions` block for the configured tracing.

        Models what apollo-tracing / Apollo Federation FTV1 attach to a normal
        200/`data` response. Returns None when tracing is disabled so the
        success path stays free of any `extensions` key.
        """
        mode = cfg["tracing"]
        if not mode:
            return None
        ext: dict[str, Any] = {}
        if mode in ("apollo", "both"):
            ext["tracing"] = {
                "version": 1,
                "startTime": "2026-01-01T00:00:00.000Z",
                "endTime": "2026-01-01T00:00:00.002Z",
                "duration": 2_000_000,
                "parsing": {"startOffset": 1000, "duration": 5000},
                "validation": {"startOffset": 7000, "duration": 3000},
                "execution": {
                    "resolvers": [
                        {
                            "path": ["__typename"],
                            "parentType": "Query",
                            "fieldName": "__typename",
                            "returnType": "String!",
                            "startOffset": 11000,
                            "duration": 1500,
                        }
                    ]
                },
            }
        if mode in ("ftv1", "both"):
            # An opaque base64 protobuf blob in real servers; for detection
            # purposes any non-empty string under `ftv1` is the signal.
            ext["ftv1"] = "GhEKD0Fwb2xsb1RyYWNlRlRWMQ=="
        return ext

    def _success(data: dict[str, Any]) -> JSONResponse:
        """Build a 200 data response, attaching tracing extensions if enabled."""
        body: dict[str, Any] = {"data": data}
        ext = _tracing_extensions()
        if ext is not None:
            body["extensions"] = ext
        return JSONResponse(content=body)

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

    def _closest_field(candidate: str, fields: list[str]) -> str | None:
        """Return a real field name the oracle would suggest for `candidate`.

        Mirrors how graphql-js emits "Did you mean": a suggestion fires only when
        the candidate is lexically close to a real field (shared prefix or one
        being a substring of the other), so unrelated probes get no hint.
        """
        cand = candidate.lower()
        best: str | None = None
        best_score = 0
        for f in fields:
            fl = f.lower()
            score = 0
            if fl == cand:
                continue
            if fl.startswith(cand) or cand.startswith(fl):
                score = min(len(fl), len(cand))
            elif cand in fl or fl in cand:
                score = min(len(fl), len(cand)) - 1
            # Require a meaningful overlap (>=3 chars) to avoid noise.
            if score >= 3 and score > best_score:
                best_score = score
                best = f
        return best

    def _count_aliases(query: str) -> int:
        """Count aliased fields (pattern: word: word)."""
        return len(re.findall(r'\b\w+\s*:\s*\w+', query))

    def _query_fields_for_introspection() -> list[dict]:
        """Query-type fields, including an injectable field+arg when configured."""
        fields: list[dict] = [{"name": "__typename", "args": []}]
        inj = cfg["injectable_arg"]
        if inj:
            fields.append(
                {
                    "name": inj["field"],
                    "args": [
                        {
                            "name": inj["arg"],
                            "type": {
                                "kind": "SCALAR",
                                "name": "String",
                                "ofType": None,
                            },
                        }
                    ],
                }
            )
        return fields

    def _build_arg_introspection(arg_spec: dict[str, Any]) -> dict[str, Any]:
        """Render one arg entry in introspection shape (with NON_NULL wrapper)."""
        named = {"kind": "SCALAR", "name": arg_spec.get("type") or "String", "ofType": None}
        if arg_spec.get("required"):
            return {
                "name": arg_spec.get("name"),
                "type": {"kind": "NON_NULL", "name": None, "ofType": named},
            }
        return {"name": arg_spec.get("name"), "type": named}

    def _args_for(name: str) -> list[dict[str, Any]]:
        spec = cfg["mutation_arg_signature"].get(name) or []
        return [_build_arg_introspection(a) for a in spec]

    def _build_introspection_response(dangerous_mutations: list[str]) -> dict:
        mutation_fields = [
            {"name": name, "description": None, "args": _args_for(name)}
            for name in dangerous_mutations
        ]
        return {
            "data": {
                "__schema": {
                    "queryType": {
                        "name": "Query",
                        "fields": _query_fields_for_introspection(),
                    },
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
            {"name": name, "description": None, "args": _args_for(name)}
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
    async def graphql_get(request: Request):
        # ── In-browser GraphQL IDE exposure ─────────────────────────────────
        # When an IDE is configured and the request carries a browser HTML
        # Accept header with no query string, serve the IDE console page (the
        # production-IDE-left-enabled misconfiguration). A GET carrying a query
        # string, or any non-HTML Accept, falls through to the JSON API below.
        accept = request.headers.get("accept", "")
        ide = cfg["graphql_ide"]
        if (
            ide
            and "text/html" in accept.lower()
            and "query" not in request.query_params
        ):
            html = _IDE_HTML.get(ide, _IDE_HTML["graphiql"])
            response = HTMLResponse(content=html)
            for cookie in cfg["set_cookies"] or []:
                response.headers.append("set-cookie", cookie)
            return response

        # ── APQ execution over GET (apq-get vector) ─────────────────────────
        # A persisted-query lookup over GET carries the hash in an `extensions`
        # query-string parameter and no `query` body. When APQ is enabled the
        # server recognises it; whether it *executes* the cached operation over
        # GET (the cacheable CSRF / cache-flooding misconfiguration) is gated on
        # `apq_serve_over_get`. The GET route never registers — it only resolves
        # the hash against the cache the POST route populates.
        ext_param = request.query_params.get("extensions")
        if ext_param is not None and cfg["apq_enabled"]:
            import json as _json

            try:
                ext_obj = _json.loads(ext_param)
            except Exception:
                ext_obj = {}
            pq_get = (ext_obj or {}).get("persistedQuery")
            if isinstance(pq_get, dict):
                get_hash = pq_get.get("sha256Hash", "")
                served = cfg["apq_serve_over_get"] and get_hash in apq_cache
                if served:
                    response = JSONResponse(
                        content={"data": {"__typename": "Query"}}
                    )
                    _add_cors(response)
                    return response
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

        query = request.query_params.get("query", "")

        # ── Introspection over GET (introspection-bypass vector: post_only) ──
        # Some servers wire the introspection block into the POST route handler
        # only, leaving the GET transport able to answer the same `__schema`
        # query. Model that here: when the filter is "post_only", a `__schema`
        # GET succeeds even though the POST equivalent is blocked below.
        get_is_introspection = (
            "__schema" in query or bool(re.search(r"__type\b(?!name)", query))
        )
        if get_is_introspection and cfg["introspection_filter"] == "post_only":
            resp_data = _build_introspection_response(cfg["dangerous_mutations"])
            response = JSONResponse(content=resp_data)
            _add_cors(response)
            return response

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
        # ── Read query over GET (query-get vector) ──────────────────────────
        # A plain non-mutation read query carried in the URL. When the server
        # reserves GET for safe/empty responses only, reject it (the secure
        # posture the query-get check expects to find no finding for). When
        # `accept_get_read_query` is True (default) the read query executes and
        # returns data — the cacheable / cross-site-readable surface.
        if query and not is_mutation and not cfg["accept_get_read_query"]:
            response = JSONResponse(
                status_code=405,
                content={
                    "errors": [
                        {"message": "GET requests are not supported; use POST."}
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
        is_multipart = "multipart/form-data" in content_type
        is_text_plain = "text/plain" in content_type

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

        # ── multipart/form-data transport (csrf-multipart vector 1) ─────────
        # A CORS simple-request content type. A CSRF-safe server rejects it; a
        # vulnerable one parses the multipart body and executes the operation.
        if is_multipart:
            if not cfg["accept_multipart_post"]:
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
            _ = form.get("query", "")
            response = JSONResponse(content={"data": {"__typename": "Mutation"}})
            _add_cors(response)
            return response

        # ── text/plain transport (csrf-multipart vector 2) ─────────────────
        # The body is JSON but labelled text/plain (a CORS simple request). A
        # CSRF-safe server rejects the content type; a vulnerable one sniffs the
        # JSON body and executes it regardless of the declared content type.
        if is_text_plain:
            if not cfg["accept_text_plain_post"]:
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

        # ── JSON-array batching ─────────────────────────────────────────────
        # A top-level JSON array is a transport-level operation batch. A server
        # with array batching enabled executes every element and returns a
        # parallel array of results; one with it disabled rejects the request.
        if isinstance(body, list):
            if cfg["array_batch_enabled"]:
                results = [
                    {"data": {"__typename": "Query"}} for _ in body
                ]
                response = JSONResponse(content=results)
                _add_cors(response)
                return response
            response = JSONResponse(
                status_code=400,
                content={
                    "errors": [
                        {"message": "Batched requests are not supported."}
                    ]
                },
            )
            _add_cors(response)
            return response

        query_for_cycle: str = body.get("query", "") or ""

        # ── Cyclic-fragment validation ──────────────────────────────────────
        # The fragment-cycle check sends documents whose fragment definitions
        # form a cycle: a two-fragment cycle (fragment A spreads B and B spreads
        # A) or a self-referential fragment (fragment S spreads S). Detect that a
        # fragment spreads itself directly or indirectly by building the spread
        # graph from the query text and looking for a back-edge.
        frag_defs = re.findall(
            r"fragment\s+(\w+)\s+on\s+\w+\s*\{([^}]*)\}", query_for_cycle
        )
        if frag_defs:
            graph: dict[str, set[str]] = {}
            for name, body_text in frag_defs:
                spreads = set(re.findall(r"\.\.\.\s*(\w+)", body_text))
                graph[name] = spreads

            def _has_cycle() -> bool:
                visiting: set[str] = set()
                done: set[str] = set()

                def dfs(node: str) -> bool:
                    visiting.add(node)
                    for nxt in graph.get(node, ()):  # type: ignore[arg-type]
                        if nxt in visiting:
                            return True
                        if nxt not in done and nxt in graph and dfs(nxt):
                            return True
                    visiting.discard(node)
                    done.add(node)
                    return False

                return any(dfs(n) for n in graph if n not in done)

            if _has_cycle():
                if cfg["fragment_cycle_validation"]:
                    response = JSONResponse(
                        content={
                            "errors": [
                                {
                                    "message": (
                                        "Cannot spread fragment within itself "
                                        "via a fragment cycle."
                                    )
                                }
                            ]
                        }
                    )
                    _add_cors(response)
                    return response
                # Non-validating executor: accept and "execute" the cyclic doc.
                response = JSONResponse(content={"data": {"__typename": "Query"}})
                _add_cors(response)
                return response

        # ── ID-keyed persisted-query store (pq-enum vector) ─────────────────
        # An operation referenced by a short, guessable document identifier with
        # NO query body. Distinct from APQ below, which keys on a SHA-256 hash.
        # The pq-enum check probes three identifier transports: top-level
        # `{"id": ...}`, top-level `{"documentId": ...}`, and an
        # `extensions.persistedQuery.id` (no `sha256Hash`). When `pq_id_store`
        # is enabled and one of these arrives without a query body, model a hit
        # by returning data — the enumerable surface the check reports. When the
        # store is off, fall through so the request hits the normal handlers.
        if body.get("query") is None:
            _ext = body.get("extensions") or {}
            _pq_ext = _ext.get("persistedQuery") if isinstance(_ext, dict) else None
            _has_id = (
                body.get("id") is not None
                or body.get("documentId") is not None
                or (
                    isinstance(_pq_ext, dict)
                    and _pq_ext.get("id") is not None
                    and "sha256Hash" not in _pq_ext
                )
            )
            if _has_id:
                if cfg["pq_id_store"]:
                    response = JSONResponse(
                        content={"data": {"__typename": "Query"}}
                    )
                    _add_cors(response)
                    return response
                # No ID-keyed store: an operation referenced by an unknown ID
                # (with no query body) cannot be resolved. A server without this
                # feature rejects it rather than executing something — the secure
                # posture the pq-enum check must read as "no finding".
                response = JSONResponse(
                    status_code=400,
                    content={
                        "errors": [
                            {
                                "message": (
                                    "PersistedQueryNotFound: no operation is "
                                    "registered for the supplied identifier."
                                ),
                                "extensions": {"code": "PersistedQueryNotFound"},
                            }
                        ]
                    },
                )
                _add_cors(response)
                return response

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
                # Registration request.
                # Spec-compliant servers verify sha256(query) == sha256Hash
                # before storing, rejecting mismatches with
                # PersistedQueryHashMismatch. The default (verify off) models
                # the cache-poisoning bug the apq-collision check detects.
                if cfg["apq_verify_hash"]:
                    real_hash = hashlib.sha256(
                        incoming_query.encode("utf-8")
                    ).hexdigest()
                    if real_hash != client_hash:
                        response = JSONResponse(
                            status_code=400,
                            content={
                                "errors": [
                                    {
                                        "message": (
                                            "provided sha does not match query"
                                        ),
                                        "extensions": {
                                            "code": "PERSISTED_QUERY_HASH_MISMATCH"
                                        },
                                    }
                                ]
                            },
                        )
                        _add_cors(response)
                        return response

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

        # ── Apollo Federation probes ────────────────────────────────────────
        # `_service { sdl }` leaks the full schema even when introspection is
        # disabled; `_entities(...)` is the entity-resolution entry point.
        if "_service" in query and "sdl" in query:
            if cfg["federation_sdl"]:
                response = JSONResponse(
                    content={"data": {"_service": {"sdl": cfg["federation_sdl"]}}}
                )
                _add_cors(response)
                return response
            response = JSONResponse(
                content={
                    "errors": [
                        {
                            "message": (
                                'Cannot query field "_service" on type "Query".'
                            )
                        }
                    ]
                }
            )
            _add_cors(response)
            return response

        if "_entities" in query:
            if cfg["federation_entities"]:
                response = JSONResponse(content={"data": {"_entities": []}})
                _add_cors(response)
                return response
            response = JSONResponse(
                content={
                    "errors": [
                        {
                            "message": (
                                'Cannot query field "_entities" on type "Query".'
                            )
                        }
                    ]
                }
            )
            _add_cors(response)
            return response

        # ── Field-aliasing authorization bypass ─────────────────────────────
        # Model a server whose authorization is enforced by matching the
        # *response key* (the alias, or the field name when no alias is given)
        # against a deny-list, instead of on the field's authorization metadata.
        # The auth-alias check sends the protected field twice: once directly
        # (`{ <field> { __typename } }`) and once aliased to a benign key
        # (`{ <alias>: <field> { __typename } }`). A vulnerable server denies
        # the first and serves data for the second.
        aab = cfg["alias_auth_bypass"]
        if aab and aab.get("field") and aab["field"] in query:
            protected = aab["field"]
            denied_key = aab.get("denied_key") or protected
            # Find how the protected field is selected: `<key>: <field>` (alias)
            # or bare `<field>`. The response key is the alias when present,
            # else the field name itself.
            alias_m = re.search(
                rf"(\w+)\s*:\s*{re.escape(protected)}\b", query
            )
            if alias_m:
                response_key = alias_m.group(1)
            else:
                response_key = protected
            if response_key == denied_key:
                # Authorization is keyed on this response key → deny.
                response = JSONResponse(
                    content={
                        "errors": [
                            {
                                "message": (
                                    f"Not authorized to access field "
                                    f"\"{protected}\"."
                                ),
                                "extensions": {"code": "FORBIDDEN"},
                            }
                        ]
                    }
                )
                _add_cors(response)
                return response
            # Different response key → control missed it → serve data (bypass).
            response = JSONResponse(
                content={"data": {response_key: {"__typename": "Object"}}}
            )
            _add_cors(response)
            return response

        # ── Incremental-delivery (@defer / @stream) probes ──────────────────
        # The defer-abuse check sends two probes:
        #   1. @defer on an inline fragment: { ... @defer { __typename } }
        #   2. @stream on a non-list field:  { __typename @stream }
        # A server with incremental delivery enabled accepts both (returns
        # data); a spec-compliant / feature-disabled server rejects @defer as an
        # unknown directive and @stream as a directive-location violation.
        has_defer = "@defer" in query
        has_stream = "@stream" in query
        if has_defer or has_stream:
            if cfg["incremental_delivery"]:
                # Feature enabled — accept the probe and return data. (Real
                # servers stream a multipart response; for detection purposes a
                # non-error data response is the accept signal.)
                response = JSONResponse(content={"data": {"__typename": "Query"}})
                _add_cors(response)
                return response
            # Feature disabled / spec-compliant validator — reject the probe.
            if has_defer:
                msg = 'Unknown directive "@defer".'
            else:
                msg = (
                    'Directive "@stream" may not be used on a non-list field.'
                )
            response = JSONResponse(content={"errors": [{"message": msg}]})
            _add_cors(response)
            return response

        # Check depth limit
        if cfg["depth_limit"] is not None:
            if cfg["depth_limit_expands_fragments"]:
                # Spec-correct limiter: inline fragment definitions into the
                # operation body before measuring depth, so fragment-hidden
                # nesting counts the same as inline nesting. We approximate
                # inlining by measuring depth over the *whole* document text
                # (operation body + every fragment definition), which is what
                # `_query_depth` already does — a fragment-wrapped deep query has
                # its full nesting present in the fragment body and is counted.
                depth = _query_depth(query)
            else:
                # Buggy limiter: count depth on the literal operation body only,
                # never resolving fragment spreads. Strip out fragment
                # *definitions* (`fragment X on T { ... }`) so the deep nesting
                # they carry is invisible to the counter — the depth-bypass class.
                operation_body = re.sub(
                    r"fragment\s+\w+\s+on\s+\w+\s*\{.*\}", "", query, flags=re.DOTALL
                )
                depth = _query_depth(operation_body)
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

        # Check field-duplication / fragment-spread limit. A protected server
        # caps repeated identical selections and repeated fragment spreads.
        if cfg["field_dup_limit"] is not None:
            typename_dups = len(re.findall(r"\b__typename\b", query))
            spread_dups = len(re.findall(r"\.\.\.\s*\w+", query))
            repetition = max(typename_dups, spread_dups)
            if repetition > cfg["field_dup_limit"]:
                response = JSONResponse(
                    content={
                        "errors": [
                            {
                                "message": (
                                    f"Query complexity {repetition} exceeds the "
                                    f"maximum allowed {cfg['field_dup_limit']}"
                                )
                            }
                        ]
                    }
                )
                _add_cors(response)
                return response

        # ── Directive-abuse probes ──────────────────────────────────────────
        # The directive-abuse check sends two probes against __typename:
        #   1. overloading: { __typename @skip(if: false) @skip(if: false) ... }
        #   2. unknown:     { __typename @enshroudUnknownDirective }
        # A validating server rejects both; a permissive one accepts them.
        skip_count = query.count("@skip")
        unknown_match = re.search(r"@(enshroudUnknownDirective|[A-Za-z_]\w*)\b", query)
        has_unknown_directive = (
            "@enshroudUnknownDirective" in query
        )
        # Only treat as a directive probe when it is a bare __typename selection
        # carrying directives (avoids colliding with the fingerprint @skip probe,
        # which is matched later and uses a query{} wrapper / different shape).
        is_directive_overload_probe = skip_count >= 2 and "__typename" in query
        if is_directive_overload_probe:
            if cfg["directive_validation"]:
                response = JSONResponse(
                    content={
                        "errors": [
                            {
                                "message": (
                                    'The directive "@skip" may not be used more '
                                    "than once at this location."
                                )
                            }
                        ]
                    }
                )
                _add_cors(response)
                return response
            response = JSONResponse(content={"data": {"__typename": "Query"}})
            _add_cors(response)
            return response

        if has_unknown_directive:
            if cfg["directive_validation"]:
                msg = 'Unknown directive "@enshroudUnknownDirective".'
                # Leak a real custom directive via a suggestion when close.
                customs = cfg["custom_directives"] or []
                suggestion = _closest_field("enshroudUnknownDirective", customs)
                # _closest_field needs lexical overlap; for recon tests we make
                # the probe explicitly suggestible by matching any configured
                # directive when the probe shares a prefix, else first custom.
                if customs and cfg["suggestions_enabled"]:
                    hint = suggestion or customs[0]
                    msg += f' Did you mean "@{hint}"?'
                response = JSONResponse(content={"errors": [{"message": msg}]})
                _add_cors(response)
                return response
            response = JSONResponse(content={"data": {"__typename": "Query"}})
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
            # ── Naive-filter modelling (introspection-bypass) ───────────────
            # A broken introspection block that leaks via an alternate probe.
            filt = cfg["introspection_filter"]
            if filt == "schema_keyword":
                # Server string-matches the literal "__schema" token only. A
                # `__schema` query is rejected; a `__type(name: ...)` query —
                # which never contains "__schema" — slips through and returns
                # schema data.
                if "__schema" in query:
                    response = JSONResponse(
                        content={
                            "errors": [{"message": "Introspection is disabled"}]
                        }
                    )
                    _add_cors(response)
                    return response
                # __type probe — leak a minimal type result.
                response = JSONResponse(
                    content={
                        "data": {
                            "__type": {
                                "name": "Query",
                                "kind": "OBJECT",
                                "fields": [{"name": "__typename"}],
                            }
                        }
                    }
                )
                _add_cors(response)
                return response
            if filt == "post_only":
                # Introspection is blocked on the POST transport (it succeeds
                # over GET, handled in the GET route above).
                response = JSONResponse(
                    content={
                        "errors": [{"message": "Introspection is disabled"}]
                    }
                )
                _add_cors(response)
                return response
            if filt == "top_level_only":
                # The guard inspects only the operation's *top-level* selection
                # field names and never resolves fragment spreads. Strip out
                # fragment *definitions* (`fragment X on T { ... }`) and look for
                # a literal `__schema` / `__type` meta-field in what remains: the
                # operation body. A fragment-wrapped introspection query has only
                # a `...Spread` at top level, so the guard misses it and the
                # schema leaks.
                operation_body = re.sub(
                    r"fragment\s+\w+\s+on\s+\w+\s*\{[^}]*\}", "", query
                )
                top_level_meta = (
                    "__schema" in operation_body
                    or bool(re.search(r"__type\b(?!name)", operation_body))
                )
                if top_level_meta:
                    response = JSONResponse(
                        content={
                            "errors": [{"message": "Introspection is disabled"}]
                        }
                    )
                    _add_cors(response)
                    return response
                # Fragment-wrapped introspection slipped past the guard → leak.
                resp_data = _build_introspection_response(
                    cfg["dangerous_mutations"]
                )
                response = JSONResponse(content=resp_data)
                _add_cors(response)
                return response

            if not cfg["introspection_enabled"]:
                response = JSONResponse(
                    content={
                        "errors": [{"message": "Introspection is disabled"}]
                    }
                )
                _add_cors(response)
                return response

            # Detect what kind of introspection query. The mutation-enum check
            # asks for mutationType fields only; the injection check asks for
            # both queryType and mutationType with args. Route the latter to the
            # full-schema response so query-type args are returned.
            if (
                "mutationType" in query
                and "fields" in query
                and "args" in query
                and "queryType" not in query
            ):
                # mutation-enum style query
                resp_data = _build_mutation_introspection_response(cfg["dangerous_mutations"])
            else:
                resp_data = _build_introspection_response(cfg["dangerous_mutations"])

            response = JSONResponse(content=resp_data)
            _add_cors(response)
            return response

        # ── Mutation allow-list bypass via operation-type confusion ─────────
        # The mutation-allowlist-bypass check sends a probe shaped
        # `query EnshroudOpTypeConfusion { <mutationField> { __typename } }`
        # — a `query` operation containing a mutation field with no args.
        # Two configurable behaviours model the two posture cases:
        #   * op_type_confusion=False (spec-correct): the server rejects the
        #     mutation field on the Query root with a validation error. The
        #     check must read this as "no finding".
        #   * op_type_confusion=True (vulnerable): the server resolves the
        #     field on Query, then halts at argument validation because the
        #     probe omitted the required arg. The check reads the
        #     "argument is required" error as the bypass signal.
        # The match is gated on the probe operation name so the handler
        # never trips on unrelated `query` requests in other checks.
        if (
            "EnshroudOpTypeConfusion" in query
            and cfg["mutation_arg_signature"]
        ):
            probe_match = re.search(
                r"\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\{\s*__typename\s*\}\s*\}",
                query,
            )
            probed_name = probe_match.group(1) if probe_match else ""
            if probed_name in cfg["mutation_arg_signature"]:
                if cfg["op_type_confusion"]:
                    # Vulnerable: executor resolved the mutation on Query,
                    # then argument validation fails because the probe sent
                    # no arguments. Pick the first required arg for the
                    # canonical "argument is required" wording.
                    args = cfg["mutation_arg_signature"][probed_name]
                    required = next(
                        (a for a in args if a.get("required")), None
                    )
                    if required:
                        arg_name = required.get("name") or "input"
                        arg_type = required.get("type") or "String"
                        msg = (
                            f'Field "{probed_name}" argument "{arg_name}" '
                            f'of type "{arg_type}!" is required, but it '
                            "was not provided."
                        )
                        response = JSONResponse(content={"errors": [{"message": msg}]})
                        _add_cors(response)
                        return response
                # Spec-correct: the mutation field does not exist on Query.
                msg = (
                    f'Cannot query field "{probed_name}" on type "Query".'
                )
                response = JSONResponse(content={"errors": [{"message": msg}]})
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

        # Schema-fuzz oracle simulation: when a known field set is configured,
        # answer `{ <field> { __typename } }` probes the way a real server with
        # introspection disabled but field suggestions enabled would.
        if cfg["schema_fields"] is not None:
            probe = re.match(
                r"\s*\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\{\s*__typename\s*\}\s*\}\s*$",
                query,
            )
            if probe:
                field = probe.group(1)
                real_fields: list[str] = cfg["schema_fields"]
                if field in real_fields:
                    # Real field, queried with a selection → return data.
                    response = JSONResponse(
                        content={"data": {field: {"__typename": "Object"}}}
                    )
                    _add_cors(response)
                    return response
                # Unknown field → "cannot query field", with a "Did you mean"
                # hint if a close-enough real field exists and suggestions are on.
                msg = f"Cannot query field \"{field}\" on type \"Query\"."
                if cfg["suggestions_enabled"]:
                    suggestion = _closest_field(field, real_fields)
                    if suggestion:
                        msg += f' Did you mean "{suggestion}"?'
                response = JSONResponse(content={"errors": [{"message": msg}]})
                _add_cors(response)
                return response

        # ── Directive-enforcement probes (directive-enforcement check) ──────
        # The check sends two probes of shape:
        #   { enshroudKeep: __typename enshroudDrop: __typename @skip(if: true) }
        #   { enshroudKeep: __typename enshroudDrop: __typename @include(if: false) }
        # A spec-compliant executor (the default) returns only `enshroudKeep`;
        # a server whose directive-evaluation pass is broken / skipped returns
        # both keys. Handled before the generic alias matcher below, which
        # would otherwise blindly echo both aliases regardless of the
        # directive-enforcement flag and trip the check on every server.
        if "enshroudKeep" in query and "enshroudDrop" in query:
            has_skip_true = bool(
                re.search(r"@skip\s*\(\s*if\s*:\s*true\s*\)", query)
            )
            has_include_false = bool(
                re.search(r"@include\s*\(\s*if\s*:\s*false\s*\)", query)
            )
            if has_skip_true or has_include_false:
                data: dict[str, str] = {"enshroudKeep": "Query"}
                if cfg["directive_enforcement_bypass"]:
                    # Broken executor: returns the gated field anyway.
                    data["enshroudDrop"] = "Query"
                response = JSONResponse(content={"data": data})
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

        # Injection probes: when an injectable arg is configured, detect probe
        # queries against that field+arg and respond as a vulnerable backend
        # would (reflect a DBMS error and/or sleep for time-based payloads).
        inj = cfg["injectable_arg"]
        if inj and inj["field"] in query and f"{inj['arg']}:" in query:
            # Extract the literal value passed to the injectable argument.
            m = re.search(
                rf"{re.escape(inj['arg'])}\s*:\s*(\"(?:[^\"\\]|\\.)*\"|[^)\s]+)",
                query,
            )
            raw_val = m.group(1) if m else ""
            # Strip surrounding quotes / unescape for matching.
            val = raw_val
            if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
                val = val[1:-1].replace('\\"', '"').replace("\\\\", "\\")

            injection_payload_markers = ("'", '"', "OR 1=1", "$gt", "\\", "SELECT", "sleep", "pg_sleep")
            is_attack = any(marker in val for marker in injection_payload_markers)

            # Time-based simulation. A genuinely injectable backend sleeps for
            # the *requested* duration: pg_sleep(3) is slow, pg_sleep(0) is fast.
            # The zero-delay control payload must therefore return quickly so the
            # check's differential (slow payload vs. zero-delay control) confirms
            # the delay is attacker-controlled.
            if inj.get("time_based"):
                import re as _re
                import time as _time

                sleep_match = _re.search(r"pg_sleep\((\d+)\)", val, _re.IGNORECASE)
                if sleep_match:
                    requested = int(sleep_match.group(1))
                    # Honour the requested sleep (capped so tests stay fast).
                    _time.sleep(min(requested, 3) + (0.2 if requested else 0.0))
                    response = JSONResponse(
                        content={"data": {inj["field"]: {"__typename": "Object"}}}
                    )
                    _add_cors(response)
                    return response

            # Uniformly-slow simulation: the endpoint is slow for *every* request
            # regardless of payload (busy backend / tarpit / WAF delay). This is
            # the classic time-based false positive — the slow payload and the
            # zero-delay control both take ~uniform_delay seconds, so a correct
            # check must NOT fire on it.
            if inj.get("uniform_delay"):
                import time as _time

                _time.sleep(float(inj["uniform_delay"]))
                # Fall through to the normal benign-response path below.

            if is_attack and inj.get("dbms_error"):
                response = JSONResponse(
                    content={"errors": [{"message": inj["dbms_error"]}]}
                )
                _add_cors(response)
                return response

            # Benign value (e.g. baseline "1") → normal data.
            response = JSONResponse(content={"data": {inj["field"]: {"__typename": "Object"}}})
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

        # Default response. Uses _success so that, when tracing is configured,
        # the benign `{ __typename }` probe carries the performance-tracing
        # `extensions` block the trace-exposure check inspects.
        response = _success({"__typename": "Query"})
        _add_cors(response)
        return response

    return app
