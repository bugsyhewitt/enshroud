# enshroud

Modern GraphQL attack-surface scanner for bug bounty and penetration testing.

enshroud replaces the abandoned [GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) and expands coverage to the full modern GraphQL attack surface: introspection leakage, naive-filter introspection bypass, depth-based DoS, alias batching, JSON-array operation batching, field suggestion oracles, authorization bypass via field aliasing, dangerous mutation enumeration, CORS misconfiguration, CSRF via content-type bypass, insecure session-cookie posture, in-browser GraphQL IDE exposure, GraphQL engine fingerprinting, Automatic Persisted Query (APQ) abuse, APQ cache poisoning via unverified query hashes, APQ execution over cacheable GET requests, Clairvoyance-style schema reconstruction, SQL/NoSQL injection probing, Apollo Federation schema/entity-resolver exposure, and GraphQL-over-WebSocket subscription security.

## Ethical Use

You are responsible for ensuring you have authorization to test any target.
Only scan systems you own or have explicit written permission to test.
Use of this tool against unauthorized targets may violate computer fraud laws.
The authors accept no liability for misuse.

## Install

```bash
pip install enshroud
```

Or from source:

```bash
git clone https://github.com/bugsyhewitt/enshroud
cd enshroud
pip install -e .
```

The opt-in `websocket` check requires the optional `websockets` dependency:

```bash
pip install "enshroud[ws]"
```

All HTTP-based checks work without it; if `websockets` is absent, the
`websocket` check simply reports no findings.

## Scope file format

A plain-text file, one entry per line. Entries can be:
- Hostnames: `api.example.com`
- IP addresses: `10.0.0.1`
- CIDR blocks: `192.168.1.0/24`

Lines starting with `#` are ignored.

Example `scope.txt`:
```
# Production targets
api.example.com
10.20.30.0/24

# Staging
staging.example.com
```

## Usage

```bash
enshroud --target https://api.example.com/graphql --scope-file scope.txt
```

### Options

```
--target URL            GraphQL endpoint URL (required)
--scope-file FILE       Path to scope file (required)
--checks CHECK          Comma-separated checks to run (default: all)
                        Choices: introspection, introspection-bypass,
                                 depth-dos, depth-bypass, alias-batch,
                                 batch-array, field-dup, fragment-cycle,
                                 directive-abuse, directive-enforcement,
                                 defer-abuse, field-oracle,
                                 suggestion-leak, auth-alias,
                                 verbose-errors, mutation-enum,
                                 mutation-allowlist-bypass, cors, csrf,
                                 csrf-multipart, query-get, cookie-posture,
                                 graphql-ide,
                                 fingerprint, apq, apq-collision,
                                 apq-get, pq-enum, trace-exposure,
                                 federation, all
                        Opt-in (not in 'all'): schema-fuzz, injection,
                                 websocket
--format {json,h1md}    Output format (default: json)
--auth-header HEADER    Auth header, e.g. "Authorization: Bearer TOKEN"
--timeout SECONDS       Request timeout in seconds (default: 10)
--fuzz-rate RPS         schema-fuzz probe rate, req/s (default: 5; <=0 = no limit)
--active                Enable active/blind probing for the injection check
                        (time-based SQLi). Off by default.
--fail-on SEVERITY      Exit with code 3 if any finding is at or above this
                        severity (for CI/CD gating). One of CRITICAL, HIGH,
                        MEDIUM, LOW, INFO (case-insensitive). Output is still
                        printed. Off by default.
```

### Exit codes

enshroud uses distinct exit codes so it can gate automation pipelines:

| Code | Meaning |
|---|---|
| `0` | Scan completed; no finding met the `--fail-on` threshold (also the default when `--fail-on` is not supplied, regardless of findings) |
| `1` | Tool/usage error (scope file missing, no valid checks, invalid `--fail-on` value) |
| `2` | Target is out of scope |
| `3` | Scan completed and at least one finding met or exceeded the `--fail-on` threshold |

The report (JSON or H1-markdown) is always written to stdout before the
exit-code policy is applied, so `--fail-on` never suppresses output.

### CI/CD gating with `--fail-on`

By default enshroud exits `0` on any successful scan, so its output can be
collected without failing a job. Pass `--fail-on` to turn a finding at or above
a chosen severity into a non-zero exit, failing the pipeline:

```bash
# Fail the build if any HIGH or CRITICAL finding is present
enshroud --target https://api.example.com/graphql --scope-file scope.txt \
  --fail-on high
```

Severities are ranked `CRITICAL > HIGH > MEDIUM > LOW > INFO`; `--fail-on medium`
trips on MEDIUM, HIGH, and CRITICAL findings. The threshold is case-insensitive.
An unrecognised value is rejected before the scan runs (exit `1`). Findings with
a missing or unknown severity are treated as `INFO` so they never accidentally
trip a higher gate.

### Examples

Run all checks, JSON output:
```bash
enshroud --target https://api.example.com/graphql --scope-file scope.txt
```

Run specific checks:
```bash
enshroud --target https://api.example.com/graphql --scope-file scope.txt \
  --checks introspection,cors
```

H1-markdown output (for HackerOne reports):
```bash
enshroud --target https://api.example.com/graphql --scope-file scope.txt \
  --format h1md
```

With authentication:
```bash
enshroud --target https://api.example.com/graphql --scope-file scope.txt \
  --auth-header "Authorization: Bearer eyJ..."
```

## Example output

### JSON

```json
[
  {
    "category": "introspection_enabled",
    "severity": "MEDIUM",
    "title": "GraphQL Introspection Enabled in Production",
    "evidence": "{\"data\": {\"__schema\": {\"queryType\": {\"name\": \"Query\"}}}}",
    "description": "The GraphQL introspection API is enabled, allowing any client to query the full schema including all types, fields, queries, and mutations.",
    "reproduction": "Send a POST request with body: {\"query\": \"{__schema{queryType{name}}}\"}",
    "impact": "An attacker can enumerate the entire API surface, discover hidden endpoints, and craft targeted attacks.",
    "remediation": "Disable introspection in production. Most GraphQL servers support this via a configuration flag."
  }
]
```

### H1-markdown

```markdown
# [MEDIUM] GraphQL Introspection Enabled in Production

## Summary
The GraphQL introspection API is enabled, allowing any client to query the full schema including all types, fields, queries, and mutations.

## Steps to Reproduce
Send a POST request with body: {"query": "{__schema{queryType{name}}}"}

## Impact
An attacker can enumerate the entire API surface, discover hidden endpoints, and craft targeted attacks.

## Proof of Concept
{"data": {"__schema": {"queryType": {"name": "Query"}}}}

## Recommended Mitigation
Disable introspection in production. Most GraphQL servers support this via a configuration flag.
```

## Checks

| Check | Category | Severity | Description |
|---|---|---|---|
| `introspection` | `introspection_enabled` | MEDIUM | Schema enumeration via introspection |
| `introspection-bypass` | `introspection_filter_bypass` | MEDIUM | Standard `__schema` introspection denied, but the schema still leaks via the `__type` root field, the GET transport, or a named fragment spread — a naive `__schema`-keyword / POST-only / top-level-selection block bypass |
| `depth-dos` | `depth_dos` | LOW | Missing query depth limit |
| `depth-bypass` | `depth_limit_bypass` | MEDIUM | Query depth limit is enforced on flat queries but bypassed by hiding the deep nesting inside a named fragment — the limiter counts the operation body without expanding fragment spreads |
| `alias-batch` | `alias_batching` | MEDIUM | Unbounded alias-based query batching |
| `batch-array` | `array_batching` | HIGH | JSON-array operation batching (rate-limit / brute-force bypass) |
| `field-dup` | `field_duplication_dos` | MEDIUM | Repeated fields / fragment spreads not capped (repetition-axis DoS) |
| `fragment-cycle` | `fragment_cycle_dos` | MEDIUM | Cyclic / self-referential fragment definitions not rejected by validation (spec §5.5.2.2 bypass; unbounded-expansion DoS) |
| `directive-abuse` | `directive_abuse` | MEDIUM | Overloaded `@skip`/`@include` or unknown directives accepted without validation (directive-axis DoS + recon) |
| `directive-enforcement` | `directive_enforcement_bypass` | MEDIUM | Server returns a field whose selection carried `@skip(if: true)` or `@include(if: false)` — built-in directive enforcement is broken at the executor layer (spec §3.13), so custom schema directives (`@auth` / `@cost` / `@cacheControl`) layered on the same evaluation pass are likely silently skipped too |
| `defer-abuse` | `incremental_delivery_dos` | MEDIUM | Incremental delivery (`@defer`/`@stream`) exposed — connection-holding DoS amplification and deferred-payload authorization staleness |
| `field-oracle` | `field_suggestion_oracle` | LOW | Field name leakage via error suggestions |
| `suggestion-leak` | `suggestion_oracle_leak` | LOW | `Did you mean` suggestions leak on the **argument-name** axis (`KnownArgumentNamesRule`, via `__type(naem: …)`) and the **type-name** axis (`KnownTypeNamesRule`, via `... on Queryy`) — the two graphql-js validation suggestion oracles `field-oracle` does not cover. Catches the common partial-hardening misconfiguration where a `formatError` regex strips `Did you mean` from `Cannot query field` errors but leaves `Unknown argument` / `Unknown type` suggestions untouched, leaking input argument names and type names without introspection. |
| `auth-alias` | `authz_bypass_via_alias` | HIGH | Field denied by name resolves when aliased — authorization keyed on field name / response key instead of the resolved field |
| `verbose-errors` | `verbose_error_disclosure` | LOW–MEDIUM | Development/debug error mode leaking stack traces, source paths, exception classes, SQL, internal hosts, or framework versions |
| `mutation-enum` | `dangerous_mutation_exposed` | HIGH | Dangerous mutations in public schema |
| `mutation-allowlist-bypass` | `mutation_allowlist_bypass_via_op_type` | HIGH | A mutation field resolves under a `query { … }` operation type — operation-type confusion bypasses any gateway / WAF / CSRF / persisted-query / mutation-rate-limit control keyed on the literal `mutation` operation token. Read-only by design: probes only mutations with a required argument and reads the argument-validation error, so the resolver never runs. |
| `cors` | `cors_misconfiguration` | HIGH | CORS wildcard + credentials |
| `csrf` | `csrf_via_content_type` | HIGH | Mutations executable via form-encoded POST or GET (CSRF) |
| `csrf-multipart` | `csrf_via_content_type` | HIGH | Mutations executable via `multipart/form-data` or `text/plain` POST — the two remaining CORS simple-request transports (alternate-parser CSRF-mitigation bypass) |
| `query-get` | `query_execution_over_get` | LOW | Plain non-persisted **read** query executes over a cacheable `GET` (`?query={ __typename }`) — a CORS simple-request, stable-URL transport that makes query responses cross-site readable and intermediary-cacheable (distinct from the `csrf` GET-*mutation* and `apq-get` persisted-query cases) |
| `cookie-posture` | `insecure_cookie_posture` | MEDIUM | Session cookies missing `SameSite`/`Secure`/`HttpOnly` (browser-side precondition for CSRF/CSWSH) |
| `graphql-ide` | `graphql_ide_exposed` | MEDIUM | In-browser GraphQL IDE (GraphiQL / GraphQL Playground / Apollo Sandbox) served over a browser GET — interactive query console + schema exploration left enabled in production |
| `fingerprint` | `engine_identified` | INFO | Identifies the GraphQL engine (Apollo, Graphene, Strawberry, Hasura, WPGraphQL, Yoga, Mercurius, graphql-ruby, graphql-js) and surfaces its known default-insecure behaviours |
| `apq` | `apq_enabled`, `apq_unrestricted_registration`, `apq_no_rate_limit` | LOW–MEDIUM | Automatic Persisted Query exposure and unrestricted/unthrottled registration |
| `apq-collision` | `apq_hash_mismatch` | MEDIUM–HIGH | APQ cache poisoning: server stores a registration whose `query` does not hash to the supplied `sha256Hash` (missing `PersistedQueryHashMismatch` integrity check) |
| `apq-get` | `apq_execution_over_get` | MEDIUM | APQ persisted query executes over a cacheable `GET` (`?extensions={persistedQuery:…}`) — a cross-site / cache-flooding transport the POST-only CSRF guard never covers |
| `pq-enum` | `persisted_query_id_enumeration` | MEDIUM | A registered operation executes from a short, guessable document **ID** sent with no query body (Relay `id` / trusted-documents `documentId` / `extensions.persistedQuery.id`) — an enumerable, **ID-keyed** persisted-query store distinct from APQ's unguessable SHA-256 hash cache |
| `trace-exposure` | `trace_exposure` | LOW | Apollo Tracing (`extensions.tracing`) or Federation FTV1 (`extensions.ftv1`) performance metadata exposed on the success path — leaks per-resolver timings and schema type/field names to arbitrary clients |
| `federation` | `federation_sdl_exposed`, `federation_entities_exposed` | HIGH / MEDIUM | Apollo Federation `_service { sdl }` schema dump (introspection bypass) and a directly reachable `_entities` resolver |
| `schema-fuzz` _(opt-in)_ | `schema_reconstructed` | LOW–MEDIUM | Reconstructs schema field names via the suggestion oracle when introspection is disabled |
| `injection` _(opt-in)_ | `sql_injection_signal`, `nosql_injection_signal` | CRITICAL | Probes scalar arguments for SQL/NoSQL injection via error-based (and, with `--active`, time-based) fuzzing |
| `websocket` _(opt-in)_ | `websocket_unauth_subscription`, `websocket_introspection`, `websocket_no_tls`, `websocket_cswsh` | HIGH | Tests the GraphQL-over-WebSocket subscription transport for unauthenticated handshakes, schema reachability, plaintext `ws://`, and Cross-Site WebSocket Hijacking |

### JSON-array operation batching

The `batch-array` check tests a vector distinct from the `alias-batch` check.
Where alias batching packs many fields into a *single* operation, **array
batching** is a transport-level feature: the server accepts a top-level JSON
array body — `[{"query": "..."}, {"query": "..."}, ...]` — and executes every
operation in it, returning a parallel array of results.

This matters because array batching lets an attacker pack many *independent*
operations, including repeated mutations, into one HTTP request. Any defense
that rate-limits by request rather than by operation is bypassed, which is the
canonical vector for authentication brute-force and OTP/2FA bypass (pack
hundreds of `login` or `verifyOtp` mutations into one request) and for
coupon/voucher stuffing. enshroud reports it as **HIGH** because the downstream
impact is credential compromise, not mere resource consumption.

Detection is read-only: enshroud batches a benign `{ __typename }` query 50
times and fires only when the server returns a parallel array of 50 executed
results. It never sends mutations. The check is part of the default `--checks
all`.

```bash
enshroud --target https://api.example.com/graphql --scope-file scope.txt \
  --checks batch-array
```

To remediate, disable transport-level batching unless required (Apollo Server:
`allowBatchedHttpRequests: false`), or cap the batch size and rate-limit per
operation rather than per request — and never expose authentication mutations to
batched execution.

### Field / fragment duplication

The `field-dup` check probes the third denial-of-service axis. Where `depth-dos`
tests query *nesting* and `alias-batch` tests *breadth* via distinct aliases,
`field-dup` tests **repetition** — whether the server collapses repeated
identical fields and repeated fragment spreads, or expands the work
super-linearly.

It sends two read-only probes, both built only from `__typename` (no schema
knowledge required):

1. **Repeated fields** — `{ __typename __typename ... }` with the same selection
   repeated 500 times.
2. **Repeated fragment spread** — one fragment containing a single `__typename`,
   spread 500 times: `{ ...F ...F ... } fragment F on Query { __typename }`. This
   is the building block of the circular-fragment attacks that crash executors
   that do not enforce a fragment-expansion limit.

A finding fires (**MEDIUM**) only when the server accepts a probe *without*
returning a complexity / fragment / limit error, which is the signal that
repetition is uncapped. Nothing is mutated — every selection is the `__typename`
meta-field — so the check is part of the default `--checks all`. The `evidence`
field lists which vectors (`repeated_fields`, `repeated_fragment_spread`) the
server accepted.

```bash
enshroud --target https://api.example.com/graphql --scope-file scope.txt \
  --checks field-dup
```

To remediate, enforce a query-complexity / cost limit that counts repeated
selections and fragment spreads, and cap the number of fragment spreads per
operation, rejecting operations whose computed cost exceeds a fixed budget before
execution.

### Query depth-limit bypass via fragments

The `depth-bypass` check is the companion to `depth-dos`. Where `depth-dos`
fires only when a server enforces **no** depth limit at all, `depth-bypass`
covers the complementary, higher-value class: a server that *does* enforce a
depth limit but computes that depth from the literal operation body without first
expanding fragment spreads. Because GraphQL fragments are inlined at execution,
an attacker can hide the expensive nesting inside a named fragment so the
operation body looks shallow to the naive counter, then spread that fragment to
reach an effective depth far beyond the advertised cap — the documented
depth-limiter bypass.

Detection is strictly differential and read-only (both probes are built only
from `__typename`, no schema knowledge required):

1. **Confirm the limit is enforced** — a flat query nested ~20 levels deep is
   rejected with a depth / complexity error.
2. **Confirm the limit is bypassable** — the identical nesting wrapped inside a
   named fragment, reached via a single spread
   (`query { ...D } fragment D on Query { … }`), is accepted and executed.

A finding fires (**MEDIUM**) only when step 1 rejects *and* step 2 is accepted.
A server with no depth limit (already covered by `depth-dos`), or one that
correctly expands fragments before counting, produces no finding — so
`depth-bypass` never double-counts with `depth-dos` and never false-positives on
a hardened endpoint. It is part of the default `--checks all`.

```bash
enshroud --target https://api.example.com/graphql --scope-file scope.txt \
  --checks depth-bypass
```

To remediate, compute query depth (and complexity / cost) on the fully expanded
operation — resolving all fragment spreads before measuring — rather than on the
raw operation body. Most maintained validation rules (e.g. graphql-js depth /
cost analysis) already inline fragments; ensure custom or string-based limiters
do the same.

### Cyclic fragments

The `fragment-cycle` check tests a vector distinct from `field-dup`. Where
`field-dup` repeats a *non-recursive* fragment N times (linear amplification),
this check sends **mutually recursive (cyclic)** fragment definitions, which the
GraphQL specification (§5.5.2.2, *"Fragment spreads must not form cycles"*)
requires every executor to statically reject during validation, **before**
execution:

```graphql
{ ...A }
fragment A on Query { __typename ...B }
fragment B on Query { __typename ...A }
```

A spec-compliant validator detects the `A → B → A` cycle and returns a
*"cannot spread fragment within itself"* error without executing the document. A
server that instead **accepts** the document (returns `data` with no error) or
**chokes** on it (recursing until it exhausts the stack / times out) has skipped
this mandatory rule, exposing an unbounded-expansion denial-of-service primitive
that a single tiny request can trigger.

It sends two read-only probes, both anchored on `__typename`:

1. **Two-fragment cycle** — the `A ⇄ B` pair above (the textbook case).
2. **Self-referential fragment** — a fragment that spreads itself directly:
   `{ ...S } fragment S on Query { __typename ...S }` (the minimal cycle).

A finding fires (**MEDIUM**) when the server does *not* return a cycle/validation
error for a probe — either it executed the cyclic document, or the request failed
at the transport layer (timeout / dropped connection) in a way consistent with an
expansion crash (reported in `crashed_vectors`). Nothing is mutated, so the check
is part of the default `--checks all`.

```bash
enshroud --target https://api.example.com/graphql --scope-file scope.txt \
  --checks fragment-cycle
```

To remediate, use a spec-compliant GraphQL validator that enforces the
"fragment spreads must not form cycles" rule and reject any operation whose
fragment definitions reference each other in a cycle before execution; do not
disable or bypass standard validation in custom middleware.

### Directive overloading / unknown directives

The `directive-abuse` check probes the *directive* layer — a fourth axis beyond
the three denial-of-service checks (`depth-dos` = nesting, `alias-batch` =
breadth, `field-dup` = repetition). It is both a DoS amplifier and a recon probe.

It sends two read-only probes, both anchored on `__typename` (no schema
knowledge required):

1. **Directive overloading** — the built-in, non-repeatable `@skip` directive
   stacked 500 times on a single field:
   `{ __typename @skip(if: false) @skip(if: false) ... }`. The GraphQL spec
   forbids repeating a non-repeatable directive at one location, so a validating
   executor rejects this. A server that accepts it has weak or skipped directive
   validation and must parse/process every occurrence — a cheap super-linear
   amplification vector.
2. **Unknown-directive recon** — `{ __typename @enshroudUnknownDirective }`. A
   spec-compliant server rejects an undefined directive with "Unknown
   directive ..."; a permissive one accepts it. The rejection error is also
   mined for a "Did you mean `@X`" hint, which can **leak the names of internal
   custom directives** (e.g. `@auth`, `@cost`, `@cacheControl`, `@stream`) that
   reveal the server's auth/caching/cost tooling.

A finding fires (**MEDIUM**) when the server accepts either probe *without* a
directive / complexity / validation error, **or** when a rejection leaks a real
custom-directive name. The `accepted_vectors` field lists which vectors
(`directive_overloading`, `unknown_directive_accepted`) the server accepted, and
`leaked_directives` carries any directive names recovered via suggestions.
Nothing is mutated — every selection is the `__typename` meta-field — so the
check is part of the default `--checks all`.

```bash
enshroud --target https://api.example.com/graphql --scope-file scope.txt \
  --checks directive-abuse
```

To remediate, enable strict query validation so non-repeatable directives are
rejected when repeated and unknown directives are rejected outright, ensure
directive processing happens after validation, disable directive/field
suggestion hints in production, and count directive occurrences toward the query
complexity budget.

### Incremental delivery abuse (`@defer` / `@stream`)

The `defer-abuse` check probes GraphQL's incremental-delivery directives —
`@defer` (on fragments) and `@stream` (on list fields) — which let a server
return a single query's results across **multiple** payloads over one long-lived
`multipart/mixed` response. This is a distinct attack surface from every other
check: where the DoS axes amplify *compute* (depth, alias breadth, field
repetition, fragment recursion), incremental delivery amplifies *connection
holding* — each deferred fragment or streamed item forces the server to keep a
streaming response open and frame an additional payload.

It sends two read-only probes, both anchored on `__typename` (no schema
knowledge required):

1. **`@defer`** — an inline fragment carrying the directive:
   `{ ... @defer { __typename } }` (a fragment is the only legal `@defer`
   location). A server with incremental delivery disabled rejects this as an
   unknown directive.
2. **`@stream`** — applied to a non-list field: `{ __typename @stream }`.
   `@stream` is only valid on a list field, so a spec-compliant validator
   rejects this as a directive-location violation; a server that accepts it has
   weak validation around its streaming layer.

A finding fires (**MEDIUM**) when the server **accepts** either probe — i.e. it
does not return an unknown-directive / directive-location / disabled error. The
`accepted_vectors` field lists which vectors (`defer`, `stream`) were accepted. A
server that has simply never enabled incremental delivery rejects both probes and
produces **no** finding, so there is no false positive on feature-disabled
servers. Nothing is mutated — every selection is the `__typename` meta-field — so
the check is part of the default `--checks all`.

```bash
enshroud --target https://api.example.com/graphql --scope-file scope.txt \
  --checks defer-abuse
```

Real-world impact: an attacker stacks many `@defer` fragments (or `@stream`s a
large list) in one small request to hold connections/workers open and multiply
the number of response parts the server must frame and flush — a documented
incremental-delivery resource-amplification class (fixed in Apollo Router and
graphql-js incremental-delivery implementations). Servers that authorize once at
operation start, rather than per deferred payload, can additionally leak data
whose authorization context changed before the deferred part resolved. To
remediate, disable `@defer`/`@stream` if unused; otherwise enforce strict
directive-location validation, cap the number of deferred fragments / streamed
items per operation in the complexity budget, bound how long a streaming response
may stay open, and re-evaluate authorization for each deferred payload.

### Authorization bypass via field aliasing

The `auth-alias` check tests an *authorization* flaw, not a denial-of-service
one — and it is distinct from `alias-batch`. Where `alias-batch` abuses the
*number* of aliases to exhaust resources / defeat rate limits, `auth-alias` uses
a **single** alias to defeat a *field-name-keyed* security control and read data
that should be forbidden.

The bug class: some servers (and WAFs / API gateways) enforce authorization by
matching the **literal field name or response key** of a selection against a
deny-list, instead of evaluating the field's own authorization metadata while
resolving it. On such a server, requesting a forbidden field under a different
alias changes the response key the control inspects — so the field resolves and
returns its data, bypassing the check entirely. This has been reported
repeatedly against real GraphQL deployments (alias-based authorization / WAF
bypass).

Detection is read-only and **differential**. For each candidate field (the real
top-level query fields when introspection is available, otherwise a bundled list
of commonly-protected names like `me`, `users`, `secrets`, `apiKeys`,
`billing`), the check sends two queries:

1. **direct** — `{ <field> { __typename } }`
2. **aliased** — `{ enshroudAliasProbe: <field> { __typename } }`

A **HIGH** `authz_bypass_via_alias` finding fires *only* when the direct form is
**denied** (an authorization / forbidden error) and the aliased form
**succeeds** (returns data under the alias key). Equal outcomes — both denied,
both allowed, both plain validation errors — never fire, so a correctly
implemented server (authorization evaluated on the resolved field, not its
response key) produces no findings. A "cannot query field" validation error is
explicitly *not* treated as an authorization denial, so unknown candidate names
cause no false positives. The check is part of the default `--checks all`.

```bash
enshroud --target https://api.example.com/graphql --scope-file scope.txt \
  --checks auth-alias
```

Because the check compares a *denied* response against an *allowed* one, it is
most powerful when run with an `--auth-header` whose token can reach the
endpoint but should not be authorized for the probed field — but it also catches
servers that deny anonymously by field name yet leak the same field under an
alias.

To remediate, enforce authorization inside field resolvers (or via schema
directives the executor evaluates on the resolved field), never by matching the
query text, field name, or response key. Any deny-list or WAF that inspects
GraphQL field names must canonicalise aliases back to their underlying field
before deciding.

### Introspection recovered via a naive-filter bypass

The `introspection-bypass` check is the companion to `introspection`. The
`introspection` check sends one probe — a standard `{ __schema { ... } }` query
over the default POST/`application/json` transport — and, if that single probe
is rejected, concludes the schema is protected. A very common production
misconfiguration **blocks exactly that one probe while leaking the schema
through an equivalent technique**, because the block is a naive guard rather than
a proper executor-level "disable introspection" option:

- **`__schema`-keyword deny-list.** The guard string-matches the literal
  `__schema` token, but never inspects `__type`. A
  `{ __type(name: "Query") { name kind fields { name } } }` query is a full
  introspection root field in its own right, contains no `__schema` token, slips
  past the filter, and leaks the type graph field-by-field.
- **POST-only block.** The guard is wired into the POST/JSON route handler only.
  The *same* `{ __schema { ... } }` query issued over `GET` (document in the
  `query` URL parameter) is served by a different code path that never runs the
  guard.
- **Top-level-selection block (fragment-spread bypass).** The guard inspects
  only the operation's *top-level selection field names* and rejects a literal
  top-level `__schema` / `__type`, but never resolves fragment spreads. Moving
  the meta-field into a named fragment —
  `query { ...F } fragment F on Query { __schema { ... } }` — leaves only a
  `...F` spread at the operation's top level, so the guard sees no meta-field,
  the executor resolves the fragment normally, and the full schema is returned.

The check is strictly **differential**, so it never overlaps with
`introspection` and never false-positives on a hardened server. It first
confirms the standard POST `__schema` probe is **denied** (if standard
introspection works, the check stays silent and defers to `introspection`), then
tries the three alternate techniques (`__type` over POST, `__schema` over GET,
and `__schema` via a named fragment spread over POST). A **MEDIUM**
`introspection_filter_bypass` finding fires only when the standard probe was
denied *and* an alternate technique returns a non-null `__schema` / `__type`. A
server that disables introspection *properly* (every transport, every root
meta-field, fragments resolved) denies all four probes and produces no finding.
Every probe is read-only.

```bash
enshroud --target https://api.example.com/graphql --scope-file scope.txt \
  --checks introspection,introspection-bypass
```

Remediate by disabling introspection at the executor/validation layer — a single
rule that rejects every `__schema` *and* `__type` meta-field on *every* transport
— rather than string-matching `__schema` or guarding only the POST handler. Most
GraphQL servers expose a single configuration flag for this.

### CSRF via alternate simple-request transports

The `csrf-multipart` check is the companion to `csrf`. The `csrf` check probes
the two most common CSRF-amenable transports — an
`application/x-www-form-urlencoded` POST and a plain `GET`. `csrf-multipart`
covers the **other two CORS "simple request" content types** a browser can send
cross-origin *without* a preflight:

- **`multipart/form-data`** — a `<form enctype="multipart/form-data">` submit, or
  a cross-origin `fetch` with a `FormData` body;
- **`text/plain`** — a cross-origin `fetch` with a JSON-shaped string body
  labelled `Content-Type: text/plain`.

This is a genuinely distinct exposure, not a duplicate of `csrf`. Servers very
commonly validate the JSON and the form-urlencoded parsing paths but route a
`multipart/form-data` body through a **different parser that never re-runs the
CSRF / content-type check** — exactly the "the CSRF bug was *fixed* but a
multipart request still slips past it" class disclosed across 2024–2026, where
the validation was bound to request *parsing* instead of to the operation
*execution* layer. `text/plain` is the same story for servers that body-sniff
JSON regardless of the declared content type.

The probe is read-only: it discovers the first mutation field via introspection
and selects only `__typename` on it (no arguments, no resolver side effects
beyond a bare field selection), falling back to a synthetic
`mutation enshroudCsrfMultipartProbe { __typename }` when introspection is
disabled. A **HIGH** `csrf_via_content_type` finding fires per transport only
when the server returns HTTP 2xx with a top-level `data` key — i.e. it actually
executed the operation over that transport. A server that rejects the alternate
content type (`{"errors": [...]}` or a non-2xx status) produces no finding, so a
correctly hardened endpoint stays silent. The check is part of the default
`--checks all`.

```bash
enshroud --target https://api.example.com/graphql --scope-file scope.txt \
  --checks csrf,csrf-multipart
```

Remediate by enforcing the CSRF / content-type check at the operation
*execution* layer (not the request *parsing* layer) so it applies uniformly
across every transport: reject `multipart/form-data`, `text/plain`, and
`application/x-www-form-urlencoded` for operations, require `application/json`,
and adopt a CSRF prevention scheme such as a custom-header requirement (e.g.
Apollo's CSRF prevention, which demands a non-simple `Content-Type` or a
preflight) or anti-CSRF tokens.

### Read query over a cacheable GET

The `query-get` check is the **read** counterpart to two existing GET-transport
checks and covers a surface neither of them touches:

- `csrf` probes whether a **mutation** executes over
  `GET /graphql?query=mutation{...}` — a HIGH state-changing CSRF. A CSRF-safe
  server *correctly* rejects mutations over GET (HTTP 405) while still happily
  executing **read** queries over GET.
- `apq-get` probes whether a **persisted** query (hash-only lookup) executes over
  GET. That requires APQ to be enabled and a hash to be registered.

`query-get` fills the remaining gap: a plain, non-persisted, non-mutation read
query sent as `GET /graphql?query={ __typename }` that the server executes and
returns `data` for. Serving read queries over GET is its own attack surface,
independent of mutations and of APQ:

- **Cross-site readability.** A GET carrying a `query` string is a CORS *simple
  request* — a cross-origin page can issue it (`<img>`, `<script>`, `fetch`, link
  prefetch) against a victim's authenticated session with no preflight. Paired
  with a permissive CORS policy (see the `cors` check) the response body becomes
  cross-site readable.
- **Cacheability / cache poisoning.** A query addressed by a stable URL is
  cacheable by any intermediary (CDN, reverse proxy, browser). A server that
  caches authenticated responses by URL — or an attacker who can influence the
  cache key — can poison or harvest cached query results. This is the
  precondition the OWASP GraphQL Cheat Sheet warns about: enable GET only for
  queries you explicitly want cached, and never for anything returning sensitive
  data.

The probe is benign and read-only: a single `{ __typename }` query (no mutation,
no APQ, no schema knowledge) sent over GET. A **LOW** `query_execution_over_get`
finding fires only when the server *executes* it — HTTP 2xx with a top-level
`data` key. A server that reserves GET for safe/empty responses, rejects the read
query (405 / "use POST"), serves an HTML IDE page, or only answers JSON over POST
produces no finding. The severity is LOW because serving queries over GET is a
deliberate, sometimes-desired configuration (it is how GraphQL responses are made
CDN-cacheable); the finding is an attack-surface fact to weigh *alongside* the
`cors` and `graphql-ide` findings, not a standalone vulnerability. It is strictly
differential against `csrf` (which owns the higher-severity GET *mutation* case)
and never double-counts with it. The check is part of the default `--checks all`.

```bash
enshroud --target https://api.example.com/graphql --scope-file scope.txt \
  --checks query-get
```

Remediate by reserving GET for operations you explicitly want cached and that
return no sensitive or per-user data; reject read queries over GET otherwise and
require POST + `application/json`. If GET queries must stay enabled for CDN
caching, mark authenticated responses `Cache-Control: private, no-store`, vary
the cache key on the auth context, and pair them with strict CORS and an
anti-CSRF custom-header requirement.

### Cookie posture

The `cookie-posture` check is the response-header companion to the active `csrf`,
`batch-array`, and `websocket` checks. Those checks prove a server *accepts*
cross-origin or batched state-changing requests; this check inspects whether the
session cookies the server hands out can actually be *replayed* by a victim's
browser from an attacker's page — the missing link that turns those findings into
working real-world attacks.

It sends a single benign `{ __typename }` request and inspects every `Set-Cookie`
response header, flagging a **MEDIUM** `insecure_cookie_posture` finding for any
cookie that is:

- `SameSite=None`, or missing the `SameSite` attribute entirely — the cookie is
  (or may be) sent on cross-site requests, the precondition for CSRF and
  Cross-Site WebSocket Hijacking;
- missing `Secure` — the cookie can travel over plaintext HTTP (MITM /
  sidejacking), and `SameSite=None` without `Secure` is rejected by modern
  browsers anyway;
- missing `HttpOnly` — the cookie is readable by JavaScript and stealable via XSS.

Detection is pure response-header analysis: enshroud sends no payloads, mutates
nothing, and never probes actively, so it carries effectively zero
false-positive risk and is part of the default `--checks all`. Each weak cookie
is reported individually; well-hardened cookies (`SameSite=Lax/Strict` + `Secure`
+ `HttpOnly`) produce no finding, and an endpoint that sets no cookies is silent.

```bash
enshroud --target https://api.example.com/graphql --scope-file scope.txt \
  --checks cookie-posture
```

Remediate by setting session cookies with `SameSite=Lax` (or `Strict` where the
UX allows), `Secure`, and `HttpOnly`; reserve `SameSite=None` for cookies that
genuinely require cross-site delivery and always pair it with `Secure`. This
complements — but does not replace — server-side CSRF token validation.

### In-browser GraphQL IDE exposure

The `graphql-ide` check probes whether the endpoint serves an interactive,
in-browser GraphQL console — **GraphiQL**, **GraphQL Playground**, or Apollo
**Sandbox / Explorer** — when navigated to like a browser. These tools are
development conveniences that are routinely left enabled in production.

This is a distinct surface from the `introspection` check. That check sends an
`application/json` **POST** carrying a `{ __schema }` query and inspects the JSON
`data`; `graphql-ide` sends a browser-style **GET** with an
`Accept: text/html` header and inspects the returned **HTML document** for a
known IDE marker. The two are independent controls: a server can serve the IDE
(which then enables introspection *inside the victim's browser*) even when the
raw JSON `__schema` probe is blocked — so disabling introspection alone does not
close this hole.

A **MEDIUM** `graphql_ide_exposed` finding fires only when the GET returns an
HTML response (`Content-Type: text/html` or an `<html` body) containing an IDE
marker. A JSON API reply, a 404, or any non-IDE HTML page produces no finding,
so a server that correctly serves only the JSON API is reported clean. The probe
is a single read-only GET — nothing is ever mutated — and is part of the default
`--checks all`.

```bash
enshroud --target https://api.example.com/graphql --scope-file scope.txt \
  --checks graphql-ide
```

An exposed IDE hands an attacker a hosted, point-and-click query/mutation runner
against the production endpoint plus full schema exploration — a force-multiplier
for enumerating hidden fields, IDOR candidates, and dangerous mutations.
Remediate by disabling the console in production (e.g. Apollo Server
`introspection: false` and disabling the landing page / `graphiql: false`, or
gating the IDE behind authentication / an internal network) rather than relying
on disabling introspection alone.

### Engine fingerprinting

The `fingerprint` check sends a small set of malformed and edge-case probe
queries and matches the resulting error messages, response shape, and headers
against a bundled signature set (`src/enshroud/data/signatures.json`, derived
from [graphw00f](https://github.com/dolevf/graphw00f) and the
[GraphQL Threat Matrix](https://github.com/nicholasess/graphql-threat-matrix)).

When an engine is identified, the INFO finding lists that engine's known
default-insecure behaviours — for example, Hasura exposing the full Postgres
schema via introspection unless restricted, WPGraphQL exposing the WordPress
`users` connection, or Apollo's opt-in CSRF prevention — so you can skip generic
probing and go straight to engine-specific misconfigurations and CVEs. The probe
queries are side-effect free (no mutations are sent).

#### Engine-correlated findings

When the `fingerprint` check runs in the same invocation as the vulnerability
checks (e.g. the default `--checks all`), enshroud correlates each finding
against the identified engine's catalogued defaults. If a finding reflects a
documented out-of-the-box behaviour of that engine — for example an
`introspection_enabled` finding on Graphene, where introspection is on by
default — the finding gains an `engine_context` block:

```json
{
  "category": "introspection_enabled",
  "severity": "MEDIUM",
  "engine_context": {
    "engine_name": "graphene",
    "engine_display_name": "Graphene (Python)",
    "confidence": "expected-default",
    "matched_behaviors": [
      "Introspection enabled by default, not gated on environment"
    ],
    "note": "This finding matches a documented default-insecure behaviour of Graphene (Python), so it reflects the engine's out-of-the-box posture rather than a one-off misconfiguration."
  }
}
```

The `confidence: "expected-default"` marker tells you the detection lines up
with the engine's known posture (high confidence, low false-positive risk), and
the H1-markdown report adds an **Engine Correlation** section explaining the
root cause. Correlation is purely additive: it never changes a finding's
category or severity, and it is a no-op when `fingerprint` is not run or the
engine is unrecognised.

### Verbose / development-mode error disclosure

The `verbose-errors` check detects a GraphQL engine that is running in a
development/debug error mode in production. It sends a single deliberately
malformed query (an unbalanced selection set) to force the server down its
error-formatting path, then scans the structured error objects — both
`errors[].message` and `errors[].extensions` — for leaked internals:

- **stack traces** (Node `at fn (file:line:col)`, Python tracebacks, Ruby/Go frames),
- **absolute source file paths** (`/srv/app/resolvers/user.js`, Windows paths),
- **exception / error class names** (`KeyError`, `java.lang.NullPointerException`),
- **raw SQL** surfacing through an ORM (`SELECT ... FROM ...`, `SQLSTATE[...]`),
- **internal hosts / private IPs / DB connection strings** (`postgres://...@10.0.4.12`),
- **framework version strings** (`graphql-core 3.2.3`),
- a populated `extensions.stacktrace` / `extensions.exception` object (Apollo /
  graphql-js debug mode).

This is distinct from `fingerprint` (which matches error *wording* to identify
the engine) and `field-oracle` (which extracts "Did you mean" field-name
suggestions). `verbose-errors` flags the leakage of *implementation detail*
itself — library versions to pivot to known CVEs, file paths for
source-disclosure / traversal targets, SQL confirming injection, and internal
hostnames for lateral movement. Severity is **MEDIUM** when a stack trace,
source path, SQL, internal host, or debug extension is present, and **LOW** when
only a framework version leaks. The check is part of `--checks all` (it is
read-only and side-effect free) and stays silent against servers that return
clean, normalised errors.

```bash
enshroud \
  --target https://api.example.com/graphql \
  --scope-file scope.txt \
  --checks verbose-errors
```

### Apollo Federation exposure

The `federation` check probes two Apollo Federation surfaces that a normal
introspection check misses. Both probes are read-only single queries, so the
check is part of the default `--checks all`.

`_service { sdl }` is a **subgraph-spec-mandated** field that returns the
endpoint's entire schema as an SDL string. Crucially it is served even when
standard `__schema` introspection is disabled — so an operator who "turned off
introspection" to hide the schema is still leaking all of it if the endpoint is
a federation subgraph (common behind Apollo Gateway / Router). When `_service.sdl`
returns a schema document, enshroud fires a **HIGH** `federation_sdl_exposed`
finding with the SDL length and a prefix of the leaked document in the evidence.

`_entities(representations: [...])` is the federation entity-resolution entry
point, normally invoked only by the gateway. enshroud sends a benign empty-list
probe; if the resolver is reachable (returns data or a representations-validation
error rather than an unknown-field error) it fires a **MEDIUM**
`federation_entities_exposed` finding — flagging the direct-subgraph entity
access surface behind documented federation authorization-bypass chains.

The check stays silent on non-federation endpoints, where both fields are
rejected as unknown.

```bash
enshroud --target https://api.example.com/graphql \
  --scope-file scope.txt \
  --checks federation
```

### APQ cache poisoning (hash mismatch)

The `apq-collision` check targets the integrity primitive that protects the
Automatic Persisted Query cache, and is distinct from the `apq` check. Where
`apq` confirms APQ is enabled and probes for unauthenticated / unthrottled
*registration*, `apq-collision` tests whether the server actually verifies that
the supplied query hashes to the supplied key.

The APQ protocol requires the server to compute `sha256(query)` and compare it to
the client-supplied `sha256Hash` before storing a registration, rejecting any
mismatch with a `PersistedQueryHashMismatch` error. A server that trusts the
client's hash instead will store **attacker-controlled query text** under an
**attacker-chosen hash**. Because GraphQL clients resolve operations by hash, an
attacker who predicts or observes a legitimate client's hash can pre-poison it so
the next hash-only lookup executes the attacker's query — the cache-poisoning
primitive behind the Apollo Client advisory (GitHub issue #10784).

enshroud first confirms APQ is enabled (a hash-only lookup returns
`PersistedQueryNotFound`), then submits a registration whose `query` is
`{ __typename }` paired with a hash that is deliberately *not* its SHA-256. If the
server rejects the mismatch it is not flagged. If the server accepts and executes
the registration it fires a **MEDIUM** `apq_hash_mismatch` finding; if a follow-up
hash-only lookup of the attacker-chosen hash then serves the poisoned query's
data, the severity escalates to **HIGH** (poisoning confirmed). The finding
records both the real digest and the submitted hash so the asymmetry is
auditable. The check stays silent on endpoints without APQ and on endpoints that
gate registration behind authentication.

```bash
enshroud --target https://api.example.com/graphql \
  --scope-file scope.txt \
  --checks apq-collision
```

### APQ execution over a cacheable GET

The `apq-get` check tests the transport that is the entire point of Automatic
Persisted Queries — the **cacheable hash-only GET** — which neither `apq` nor
`apq-collision` probes (both are POST-only). APQ lets a client replay a
registered operation by sending only its SHA-256 hash, and because the hash fits
in a URL the canonical optimisation is `GET
/graphql?extensions={"persistedQuery":{"version":1,"sha256Hash":"…"}}` with a
CDN-cacheable response. That GET path is a security boundary the POST checks
never see:

- **Cacheable CSRF.** A `GET` is a CORS simple request, trivially triggerable
  cross-site (`<img>`/`<script>`/link prefetch). If a registered mutation — or a
  query returning per-user data — executes over GET, an attacker drives it from a
  victim's browser, reintroducing the surface the `csrf` check guards on the
  POST/JSON path. The hash makes the payload a fixed, shareable URL.
- **Cache-flooding / poisoning storm.** Because the response is designed to be
  cacheable and keyed by the persisted-query hash, an attacker who can register
  (see `apq` / `apq-collision`) or predict hashes can flood or poison a shared
  cache with persisted-operation responses.

enshroud first confirms APQ is enabled (a hash-only POST lookup returns
`PersistedQueryNotFound`), registers a benign `{ __typename }` so a known hash
exists, then replays that hash over a GET. It fires a **MEDIUM**
`apq_execution_over_get` finding **only** when the GET returns `data` (the
persisted operation executed over GET). A server that honours APQ over POST but
returns `PersistedQueryNotFound` over GET is the secure default and produces no
finding. The probe query is side-effect-free, so the check proves the *transport*
is open without executing anything sensitive.

```bash
enshroud --target https://api.example.com/graphql \
  --scope-file scope.txt \
  --checks apq-get
```

### Persisted-query enumeration over an ID-keyed store

The `pq-enum` check targets a persisted-query model the three APQ checks (`apq`,
`apq-collision`, `apq-get`) never touch. All three probe Apollo **Automatic
Persisted Queries**, whose cache is keyed by the **SHA-256 hash of the query
text** — a 256-bit identifier that is not guessable, so those checks are about
*registration*, *hash collision* and *GET execution*, never about *discovering*
operations you were not given.

A separate, widely deployed model keys the store on a short, client-supplied
**document identifier** instead of a content hash. Relay persisted queries,
`@apollo/persisted-query-lists` / "trusted documents", Hasura allow-lists and
many bespoke gateways let a client replay a registered operation by sending only
an `id` / `documentId` (often a small integer or a sequential build identifier)
with **no query body**. When that identifier space is small and guessable, an
unauthenticated attacker can **enumerate the entire registered operation set** —
replaying admin or internal operations they never possessed the source for —
simply by walking IDs.

enshroud probes the ID-keyed store with a handful of small identifiers across the
three common transports — top-level `{"id": …}`, top-level `{"documentId": …}`,
and an `extensions.persistedQuery.id` (no `sha256Hash`) — each carrying **no
`query` body**, so the check only ever asks the server to run an
*already-registered* operation, never one of its own. It fires a **MEDIUM**
`persisted_query_id_enumeration` finding **only** when one of those ID-only
requests returns a top-level `data` response (a registered operation executed
from a guessable ID), and stops at the first confirmed signal. A pure-APQ server
(hash-keyed, no ID lookup) returns `PersistedQueryNotFound` / a non-`data`
response to every ID probe and produces no finding — keeping `pq-enum` strictly
differential against the APQ checks.

```bash
enshroud --target https://api.example.com/graphql \
  --scope-file scope.txt \
  --checks pq-enum
```

### Performance-tracing exposure (Apollo Tracing / FTV1)

The `trace-exposure` check looks at the **success** path rather than the error
path, which makes it distinct from `verbose-errors`. Where `verbose-errors`
hunts for stack traces attached to `errors[].extensions` when a query *fails*,
`trace-exposure` sends a single benign `{ __typename }` query and inspects the
top-level `extensions` block of the normal 200/`data` response for performance
metadata a production server should never emit.

Two formats are detected. **Apollo Tracing** (`extensions.tracing`) carries an
`execution.resolvers` list that names every resolved field together with its
parent and field GraphQL types, plus per-resolver wall-clock timings in
nanoseconds — a schema-shape leak that survives introspection being disabled,
and a timing side-channel that helps distinguish authorized-empty from forbidden
lookups and enumerate valid identifiers. **Apollo Federation FTV1**
(`extensions.ftv1`) is the federated-trace protobuf blob a subgraph should emit
only for the trusted Apollo Router, never for an arbitrary client.

The signal is unambiguous: `{ __typename }` is valid against every GraphQL
endpoint, so a tracing block is purely the server's choice to expose it. The
check fires a **LOW** `trace_exposure` finding only when such a block is present
(naming the formats found and a sample of leaked resolver field/type names), and
stays silent on a production-correct server that omits `extensions` entirely. It
is part of the default `--checks all`.

```bash
enshroud --target https://api.example.com/graphql \
  --scope-file scope.txt \
  --checks trace-exposure
```

### Schema fuzzing (Clairvoyance-style)

The opt-in `schema-fuzz` check reconstructs a GraphQL schema even when
introspection is disabled, using the same field-suggestion oracle that the v0.1
`field-oracle` check detects. It probes the endpoint with a bundled wordlist of
common GraphQL field names (`src/enshroud/data/gql_fields.txt`), sending
`{ <field> { __typename } }` for each. A field is confirmed when the server
returns data for it, returns a "must have a selection of subfields" error
(the field exists but was queried wrong), or echoes a real name back in a
"Did you mean ..." hint. Confirmed suggestions are themselves re-queued, so the
check follows the oracle outward from the wordlist.

Because it is slow and noisy, `schema-fuzz` is **not** included in `--checks all`
and must be requested explicitly. Probing is rate-limited (default 5 req/s,
tunable via `--fuzz-rate`) and every request flows through the same scope
validator as the rest of enshroud. The finding rises from LOW to MEDIUM when a
sensitive/administrative field name (e.g. `adminUsers`, `secretTokens`) is among
those recovered.

```bash
enshroud --target https://api.example.com/graphql --scope-file scope.txt \
  --checks schema-fuzz --fuzz-rate 3
```

This is the technique behind
[Clairvoyance](https://github.com/nikitastupin/clairvoyance); enshroud bundles it
so you get one tool with H1-markdown output instead of two.

### Injection probing (SQL / NoSQL)

The opt-in `injection` check resurrects the original niche of
[GraphQLmap](https://github.com/swisskyrepo/GraphQLmap): fuzzing GraphQL
arguments for injection. It enumerates query and mutation arguments via
introspection, then injects a small list of classic payloads (`'`, `"`,
`1 OR 1=1`, `1' OR '1'='1`, `\`, and the NoSQL operator `{"$gt": ""}`) into each
scalar `String`/`ID`/`Int` argument. If the response surfaces a known DBMS error
fingerprint (MySQL, PostgreSQL, MSSQL, SQLite, Oracle, MongoDB), enshroud reports
a CRITICAL `sql_injection_signal` (or `nosql_injection_signal`) finding naming the
exact field, argument, and triggering payload.

Because it actively sends crafted payloads, `injection` is **not** part of
`--checks all` and must be requested explicitly. enshroud performs **detection
only** — it never attempts exploitation or data extraction. Always confirm and
demonstrate impact manually before reporting.

```bash
enshroud --target https://api.example.com/graphql --scope-file scope.txt \
  --checks injection
```

Time-based (blind) probing — which deliberately tries to make the backend sleep —
is gated behind the `--active` flag and is off by default:

```bash
enshroud --target https://api.example.com/graphql --scope-file scope.txt \
  --checks injection --active
```

To avoid the classic time-based false positive (a busy backend, a tarpit, or
network jitter that makes *every* request slow), the blind probe confirms the
delay is attacker-controlled rather than endpoint-wide. For each argument it
measures three requests: a clean baseline, a **zero-delay control** payload
(`pg_sleep(0)` — structurally identical but asking for a 0-second sleep), and the
delay payload (`pg_sleep(3)`). enshroud only reports a finding when the delay
payload is slower than **both** the baseline *and* the zero-delay control by the
margin. The recorded evidence includes all three timings and both deltas so you
can verify the differential before reporting.

The check requires introspection to enumerate arguments; if introspection is
disabled it produces no findings. Every request flows through the same scope
validator as the rest of enshroud.

### WebSocket subscription security

GraphQL subscriptions are typically served over WebSocket using one of two
protocols — `graphql-transport-ws` (the modern graphql-ws library) or the legacy
`graphql-ws` token (subscriptions-transport-ws). That transport has a security
model distinct from the HTTP endpoint, and no other open-source CLI scanner
tests it. The opt-in `websocket` check derives the `ws://`/`wss://` URL from the
target endpoint, negotiates either protocol, and runs four sub-checks:

| Category | Severity | What it means |
|---|---|---|
| `websocket_unauth_subscription` | HIGH | The server returned `connection_ack` to a `connection_init` carrying no credentials — anonymous clients can open subscription channels (BFLA/BOLA exposure). |
| `websocket_introspection` | MEDIUM | An operation sent over the socket returned data, confirming the subscription transport executes queries and exposes the schema even if the HTTP endpoint locks introspection down. |
| `websocket_no_tls` | MEDIUM | A plaintext `ws://` handshake succeeded; subscription data and any handshake token travel unencrypted (MITM — cf. CVE-2024-54147). |
| `websocket_cswsh` | HIGH | The handshake completed with a cross-origin `Origin` header, so the endpoint is open to Cross-Site WebSocket Hijacking — a two-way compromise more powerful than CSRF. |

```bash
pip install "enshroud[ws]"
enshroud --target https://api.example.com/graphql --scope-file scope.txt \
  --checks websocket
```

The check is **not** included in `--checks all` (it requires a WebSocket
round-trip and many endpoints serve no subscriptions). It sends a deliberately
unauthenticated `connection_init` to test the handshake gate; if the server
requires auth to ack — the secure behaviour — the check produces no findings.
When the optional `websockets` dependency is not installed, the check reports no
findings rather than failing.

## Attribution

Inspired by [GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) by Swissky. See NOTICE for details.
