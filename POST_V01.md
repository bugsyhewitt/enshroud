# enshroud — Post-v0.1 Directions

Ranked improvement backlog for Phase 2 implement laps.

## Ranking methodology

Rankings weight three factors equally:

1. **Bug bounty yield** — does this check produce H1-reportable findings at HIGH/CRITICAL severity, or only LOW/INFORMATIONAL? Higher severity = higher rank.
2. **Competitor gap** — is this attack surface meaningfully under-served by existing open-source tooling that a bug hunter would already run?
3. **Implementation cost vs. signal ratio** — can we ship accurate detection without a false-positive storm that trains hunters to ignore enshroud output?

Research base: portswigger.net/web-security/graphql, HackerOne disclosure corpus, GitHub security advisories (2024-2026), InQL/graphw00f/graphql-cop source analysis, YesWeHack and Intigriti GraphQL writeups.

---

## What's already in v0.1

| Check | Category | Severity |
|---|---|---|
| `introspection` | `introspection_enabled` | MEDIUM |
| `depth-dos` | `depth_dos` | LOW |
| `alias-batch` | `alias_batching` | MEDIUM |
| `field-oracle` | `field_suggestion_oracle` | LOW |
| `mutation-enum` | `dangerous_mutation_exposed` | HIGH |
| `cors` | `cors_misconfiguration` | HIGH |

---

## Post-v0.1 Directions

---

### 1. CSRF via content-type bypass ✅ IMPLEMENTED

**Status:** Shipped (Phase 2 Rotation 2). Check `csrf` (`src/enshroud/checks/csrf.py`), category `csrf_via_content_type`, included in `--checks all`. Detects mutations executable via `application/x-www-form-urlencoded` POST and via GET; falls back to a synthetic `__typename` probe mutation when introspection is disabled.

**Severity:** HIGH  
**Effort:** S (small — 1-2 days)  
**Check name:** `csrf`

**What it detects:**  
GraphQL endpoints that accept mutations via `application/x-www-form-urlencoded` or plain GET requests. Browsers send these content types without CORS preflight, allowing cross-origin mutation execution — a CSRF attack even against APIs that require `application/json` for normal clients.

**Attack value:**  
Directly reportable as a HIGH finding. Real-world impact: attacker embeds a form or `<img src>` on a malicious page; victim's browser executes state-changing mutations (password reset, account deletion, fund transfer) with their session cookies. Confirmed in multiple H1 reports. A bypass of an already-"fixed" CSRF mitigation was disclosed in 2025, demonstrating this class remains active (see: Checkmarx "What's Old Becomes New Again: CSRF Attacks on GraphQL APIs"). The `deleteStorySnaps` IDOR chain at Snapchat ($15,000 bounty) relied on a similar authorization + content-type confusion.

**Competitor gap:**  
graphql-cop v1.x checks for GET-based introspection but does NOT check whether mutations are executable via form-encoded POST. InQL (Burp) relies on the tester to manually replay. enshroud would be the first CLI tool with automated form-encoded mutation CSRF detection.

**Implementation notes:**  
1. Take the first mutation discovered via introspection (or a dummy `__typename` mutation if none available).
2. Re-send it as `application/x-www-form-urlencoded` with body `query=mutation{...}`.
3. Also attempt `GET /graphql?query=mutation{...}`.
4. Finding fires if the server returns HTTP 2xx with a `data` key (not an error).
5. Category: `csrf_via_content_type`, severity: HIGH.
6. Evidence: include the raw request method/content-type and the response status + body prefix.

**References:**  
- Checkmarx: "What's Old Becomes New Again: CSRF Attacks on GraphQL APIs"  
- Doyensec blog: "That single GraphQL issue that you keep missing" (2021, still valid)  
- Apollo CSRF prevention docs: https://www.apollographql.com/docs/graphos/routing/security/csrf  
- OWASP GraphQL Cheat Sheet

---

### 2. Engine fingerprinting

**Severity:** INFORMATIONAL (recon multiplier — enables targeted follow-on findings)  
**Effort:** M (medium — 2-3 days to build signature set)  
**Check name:** `fingerprint`

**What it detects:**  
The GraphQL server implementation (Apollo Server, Graphene, Strawberry, WPGraphQL, Hasura, Yoga, Mercurius, etc.) by probing error message patterns, response shape, and header signatures. Once the engine is known, enshroud can surface which of that engine's known default-insecure behaviors apply.

**Attack value:**  
Recon. Different engines have radically different default security postures — Apollo disables introspection in production by default (since v3), Graphene does not. WPGraphQL exposes WordPress object types including `users` by default. Hasura exposes the full database schema via introspection unless manually restricted. Knowing the engine lets a hunter skip generic checks and go straight to engine-specific CVEs and misconfigurations. graphw00f (dolevf) has documented 30+ engine signatures linked to the GraphQL Threat Matrix.

**Competitor gap:**  
graphw00f covers fingerprinting well as a standalone tool, but it is a separate Python CLI requiring its own install. InQL v5.0 added fingerprinting as a Burp-only feature. No other CLI scanner integrates fingerprinting + vuln checking in a single invocation. enshroud's advantage: a fingerprint result that immediately informs which other checks are most likely to fire, plus human-readable output in the existing JSON/H1-md format.

**Implementation notes:**  
1. Build a `signatures.json` file (ship in `src/enshroud/data/`) mapping error message patterns and response headers to engine names and their threat-matrix entries.
2. Send 3-4 probe queries: valid introspection, invalid field name, unsupported directive, schema directive.
3. Match response text against signature patterns (regex).
4. Output: `category: engine_identified`, severity: INFO, `engine_name`, `engine_version` (if detectable), `known_default_insecure_behaviors: [list]`.
5. Other checks can optionally consume the fingerprint result to weight their confidence levels.
6. Ship with signatures for at minimum: Apollo Server, Graphene, Strawberry, Hasura, WPGraphQL, Yoga/Hive, Mercurius, graphql-ruby.

**References:**  
- graphw00f GitHub: https://github.com/dolevf/graphw00f  
- GraphQL Threat Matrix: https://github.com/nicholasess/graphql-threat-matrix  
- InQL v5.0 release notes (Doyensec, 2024)

---

### 3. WebSocket subscription attack surface ✅ IMPLEMENTED

**Status:** Shipped (Phase 2 Rotation 7). Opt-in check `websocket` (`src/enshroud/checks/websocket.py`), **excluded from `--checks all`** (requires a WebSocket round-trip; many endpoints serve no subscriptions). Derives the `ws://`/`wss://` URL from the target, negotiates both `graphql-transport-ws` and legacy `graphql-ws` subprotocols, and runs four sub-checks: `websocket_unauth_subscription` (HIGH — unauthenticated `connection_init` acked), `websocket_introspection` (MEDIUM — operations execute over WS), `websocket_no_tls` (MEDIUM — plaintext `ws://` accepted), `websocket_cswsh` (HIGH — cross-origin handshake accepted). WebSocket support uses the optional `websockets` dependency (`pip install enshroud[ws]`); the check degrades to no-findings when it is absent.

**Severity:** HIGH (BFLA/BOLA via unauthenticated subscription) to LOW (info disclosure)  
**Effort:** L (large — WebSocket protocol + graphql-ws handshake)  
**Check name:** `websocket`

**What it detects:**  
GraphQL subscriptions served over WebSocket (`ws://` / `wss://`) that:  
(a) accept unauthenticated `connection_init` handshakes (no auth required to connect),  
(b) expose subscription schema via introspection over the WS connection,  
(c) serve real-time events without per-event authorization re-check (stale session issue),  
(d) accept plain `ws://` (non-TLS) — enabling MITM.

**Attack value:**  
An AI-augmented pentest engine disclosed a Broken Function-Level Authorization (BFLA) in a real-world GraphQL WebSocket endpoint in 2025 (Ostorlab blog), where any unauthenticated user could subscribe and receive sensitive event data. CVE-2023-38503 (Directus) exposed unauthorized subscription updates. CVE-2024-54147 (Altair GraphQL client) allowed MITM via missing certificate validation on WebSocket connections. Cross-site WebSocket hijacking (CSWSH) on GraphQL enables full two-way API access (query + read response) through a hijacked authenticated connection — higher impact than standard CSRF.

**Competitor gap:**  
No open-source CLI scanner currently tests GraphQL-over-WebSocket. InQL is Burp-only and requires manual WebSocket session setup. This is a genuine gap enshroud can own.

**Implementation notes:**  
1. Detect WebSocket endpoint: try common paths (`/graphql`, `/ws`, `/subscriptions`) with `Upgrade: websocket` headers; also parse endpoint URL for `ws://`/`wss://` schemes.
2. Use `websockets` library (add to optional deps) or `httpx` websocket mode.
3. Implement graphql-ws and subscriptions-transport-ws handshake protocols.
4. Sub-checks: (a) unauthenticated connection accepted, (b) introspection over WS, (c) plain `ws://` accepted (TLS check), (d) Origin header validation (CSWSH probe).
5. Mark as optional check — only runs if `--websocket` flag set or a WS endpoint is auto-detected.
6. Category: `websocket_unauth_subscription`, `websocket_no_tls`, `websocket_cswsh`.

**References:**  
- Ostorlab: "AI Pentest Engine Discovers Critical WebSocket BFLA in GraphQL Subscriptions" (2025)  
- CVE-2023-38503 (Directus) — unauthorized subscription data  
- CVE-2024-54147 (Altair GraphQL client) — MITM via missing WS cert validation  
- Include Security: "Cross-Site WebSocket Hijacking Exploitation in 2025"

---

### 4. Injection probing (SQLi / NoSQLi via argument fuzzing)

**Severity:** CRITICAL (if confirmed) / MEDIUM (error-based signal)  
**Effort:** M (medium — payload list + response analysis)  
**Check name:** `injection`

**What it detects:**  
GraphQL mutation and query arguments that reflect SQL/NoSQL error messages when injected with common payloads. This is the original niche of GraphQLmap (swisskyrepo) — enshroud's direct ancestor per the README.

**Attack value:**  
SQLi in a GraphQL resolver is a CRITICAL finding on every platform. A disclosed H1 report showed `embedded_submission_form_uuid` in a `/graphql` endpoint was SQLi-vulnerable, allowing extraction from both public and secure schema. OWASP Web Security Testing Guide (v4.2) explicitly calls out GraphQL parameter injection as a distinct test case. This class of finding regularly pays $5,000–$50,000+ in bug bounty.

**Competitor gap:**  
GraphQLmap (abandoned, Python 2/3 mix, last commit 2022) was the primary tool. graphql-cop does not probe for injection. InQL generates query templates but injection fuzzing requires Burp's scanner or manual effort. A modern, async, well-maintained injection prober built into enshroud would be unique in the current tooling landscape.

**Implementation notes:**  
1. Requires introspection to enumerate query/mutation arguments (skip if introspection disabled).
2. For each scalar String/Int argument: inject a small payload list: `'`, `"`, `1 OR 1=1`, `1' OR '1'='1`, `{"$gt": ""}` (NoSQL), `\` (escape test).
3. Detect error-based SQLi: match response errors against known DBMS error patterns (MySQL, Postgres, MongoDB, SQLite, MSSQL).
4. Detect time-based: optionally send `1; SELECT SLEEP(3)` and measure response time delta (opt-in only — `--active` flag, off by default).
5. Do NOT attempt exploitation — detection only. Flag the argument name + payload that triggered the error.
6. Category: `sql_injection_signal`, `nosql_injection_signal`, severity: CRITICAL.
7. Only runs when `--checks injection` is explicitly passed (not in `all` by default) due to active probing risk.

**References:**  
- HackerOne report #435066: SQLi in GraphQL endpoint  
- OWASP WSTG v4.2 section 4.12.1: Testing GraphQL  
- Escape.tech: "SQL Injection in GraphQL"  
- GraphQLmap original (swisskyrepo) — predecessor tool

---

### 5. Persisted query / APQ abuse

**Severity:** MEDIUM (DoS) / LOW (info disclosure)  
**Effort:** S (small — 1-2 days)  
**Check name:** `apq`

**What it detects:**  
GraphQL endpoints running Automatic Persisted Queries (APQ) that:  
(a) accept arbitrary query registration without rate limiting (DDoS registration spam),  
(b) serve queries from APQ cache that include sensitive schema details in the hash lookup error,  
(c) allow non-authenticated clients to populate the APQ cache (cache poisoning foothold).

**Attack value:**  
APQ cache poisoning allows an attacker to register a malicious query under a legitimate hash, causing cache-served clients to receive attacker-controlled responses. Apollo Client GitHub issue #10784 documents a cache poisoning vector via field aliasing that can result in code execution if response content is rendered unsafely. A spam-registration DDoS against an unprotected APQ endpoint can exhaust cache memory and degrade API performance. These are LOW-MEDIUM severity findings but reliable, easy to replicate, and common in Apollo-backed APIs.

**Competitor gap:**  
No existing open-source scanner checks for APQ exposure. graphql-cop does not cover it. This is a niche but reliable finding in Apollo-heavy targets (common in SaaS and startup bug bounty programs).

**Implementation notes:**  
1. Probe: send `{"extensions": {"persistedQuery": {"version": 1, "sha256Hash": "<random-hash>"}}}` — if server responds with `PersistedQueryNotFound` error (HTTP 200), APQ is enabled.
2. Try to register a new query: send same request with `query` field added — if it succeeds (HTTP 200, data returned), unauthenticated registration is possible.
3. Check rate limiting: send 20 registration requests in rapid succession — if all succeed, flag as unbounded APQ registration.
4. Category: `apq_enabled`, `apq_unrestricted_registration`, severity: LOW/MEDIUM.
5. Evidence: include the raw APQ error response showing the endpoint accepts the protocol.

**References:**  
- Apollo Server APQ docs: https://www.apollographql.com/docs/apollo-server/performance/apq  
- Apollo Client GitHub issue #10784: cache poisoning via field aliasing  
- Guild.dev GraphQL Yoga APQ docs  
- markaicode.com: "Why 90% of GraphQL APIs Are Vulnerable to DoS Attacks in 2025"

---

### 6. Schema fuzzing (Clairvoyance-style wordlist rebuild) ✅ IMPLEMENTED

**Status:** Shipped (Phase 2 Rotation 5). Opt-in check `schema-fuzz` (`src/enshroud/checks/schema_fuzz.py`), category `schema_reconstructed`, **excluded from `--checks all`** (slow/noisy). Bundled wordlist at `src/enshroud/data/gql_fields.txt`. Probes `{ <field> { __typename } }`, confirms via data / "selection of subfields" errors / "Did you mean" suggestions, re-queues leaked suggestions (BFS), rate-limited via `--fuzz-rate` (default 5 req/s). Severity LOW, escalates to MEDIUM when a sensitive/admin field name is recovered.

**Severity:** LOW (info disclosure — schema reconstruction when introspection disabled)  
**Effort:** L (large — async wordlist iteration, tuning for noise/signal)  
**Check name:** `schema-fuzz`

**What it detects:**  
Whether a GraphQL endpoint leaks schema structure via field suggestion errors even when introspection is disabled. By probing with a wordlist of common GraphQL field names, enshroud can reconstruct a partial schema — confirming that the field suggestion oracle (v0.1 `field-oracle` check) leaks enough signal to enumerate the real schema.

**Attack value:**  
This is the technique behind Clairvoyance (nikitastupin/clairvoyance). It's a LOW severity finding on its own but is the prerequisite for all subsequent targeted attacks when introspection is disabled. In bug bounty, schema reconstruction from an introspection-disabled endpoint is itself reportable as a bypass of a stated security control — confirming the `field-oracle` finding rises to MEDIUM when combined with proof of enumeration.

**Competitor gap:**  
Clairvoyance is the canonical tool. It is Python-based and async but requires a separate install and doesn't integrate with enshroud's output formats. Building this into enshroud as `--checks schema-fuzz` gives hunters one tool instead of two and produces H1-markdown output directly.

**Implementation notes:**  
1. Ship a bundled wordlist at `src/enshroud/data/gql_fields.txt` — ~2,000 common GraphQL field names scraped from open-source schemas (GitHub API, Shopify, HackerOne public schema, etc.).
2. Use the `__typename` anchor: probe `{ <candidate_field> { __typename } }` for each word.
3. On "Did you mean X" error: add X to confirmed field list and queue sub-field probing for X.
4. Rate-limit probing: default 5 req/s, configurable via `--fuzz-rate`.
5. Scope check: every request goes through the existing scope validator.
6. Category: `schema_reconstructed`, evidence: list of confirmed field names. Severity: LOW (bare discovery) or MEDIUM if a dangerous field name is confirmed.
7. Mark as opt-in: `--checks schema-fuzz` only — not included in `all` by default (too noisy/slow for routine scans).

**References:**  
- Clairvoyance GitHub: https://github.com/nikitastupin/clairvoyance  
- InQL v5.0: "Clairvoyance integration for introspection-disabled endpoints"  
- nikitastupin: "Clairvoyance: Uncovering GraphQL API Schemas" (blog)

---

---

## Phase 2 Rotation 10 — roadmap extension

All six original directions are shipped. The directions below were added after a
fresh gap analysis against the PortSwigger GraphQL labs, the OWASP GraphQL Cheat
Sheet, and the 2024–2026 HackerOne disclosure corpus.

---

### 7. JSON-array operation batching ✅ IMPLEMENTED

**Status:** Shipped (Phase 2 Rotation 10). Check `batch-array`
(`src/enshroud/checks/batch_array.py`), category `array_batching`, **included in
`--checks all`**. Sends a top-level JSON array of 50 benign `{ __typename }`
operations via the new `GraphQLClient.post_batch` helper and fires HIGH when the
server returns a parallel array of 50 executed results. Read-only — never sends
mutations.

**Severity:** HIGH (authentication brute-force / 2FA bypass)
**Effort:** S (small)
**Check name:** `batch-array`

**What it detects:**
Transport-level batching — the server executing a top-level JSON-array request
body `[{"query": ...}, {"query": ...}]`. This is *distinct* from the existing
`alias-batch` check, which only packs many fields into a single operation. Array
batching packs many *independent* operations, including repeated mutations, into
one HTTP request.

**Attack value:**
This is the canonical rate-limit-bypass vector. Because per-request throttling
counts the one HTTP request, an attacker can pack hundreds of `login` /
`verifyOtp` / `redeemCoupon` mutations into a single batch and brute-force
credentials, bypass 2FA, or stuff coupon codes. Multiple disclosed reports
(HackerOne / Wallarm GraphQL batching writeups) turn this into account takeover.
The `alias-batch` check did not cover the array transport at all — a genuine gap.

**Competitor gap:**
graphql-cop checks alias/array batching only as a DoS signal at MEDIUM; enshroud
frames it at HIGH because the real-world impact is auth brute-force, and ships
the explicit weaponisation guidance (swap the probe for an auth mutation) in the
finding's reproduction field.

**Implementation notes (as shipped):**
1. `GraphQLClient.post_batch(queries)` posts `[{"query": q}, ...]` as JSON.
2. Probe batches `{ __typename }` ×50; finding fires only when ≥50 array
   elements come back with `data` (full execution), avoiding false positives on
   servers that partially execute or reject batches.
3. Category `array_batching`, severity HIGH, in `--checks all`.

**References:**
- PortSwigger Web Security Academy: "Bypassing rate limiting via GraphQL batching"
- Wallarm: "GraphQL Batching Attack" writeups
- OWASP GraphQL Cheat Sheet: "Batching Attacks"

---

### 8. Field-duplication / circular-fragment DoS ✅ IMPLEMENTED

**Status:** Shipped (Phase 2 Rotation 12). Check `field-dup`
(`src/enshroud/checks/field_dup.py`), category `field_duplication_dos`,
**included in `--checks all`**. Sends two read-only probes built only from
`__typename`: `{ __typename __typename ... }` (500 repeated fields) and a
fragment spread repeated 500 times
(`{ ...F ...F ... } fragment F on Query { __typename }`). Fires MEDIUM for each
probe the server accepts without a complexity / fragment / limit error; the
`evidence` field lists the accepted vectors. Never mutates — every selection is
the `__typename` meta-field.

**Severity:** MEDIUM (DoS) — **Effort:** M — **Check name:** `field-dup`

Detects servers that do not de-duplicate repeated identical fields or that
accept circular fragment spreads, both of which amplify response cost
super-linearly. Complements `depth-dos` (depth) and `alias-batch` (breadth) with
the third DoS axis: repetition. Probe `{ a a a ... }` and a self-referential
fragment, measure whether the server caps or expands the work.

### 9. Directive-overloading / `@skip`/`@include` abuse ✅ IMPLEMENTED

**Status:** Shipped (Phase 2 Rotation 13). Check `directive-abuse`
(`src/enshroud/checks/directive_abuse.py`), category `directive_abuse`,
**included in `--checks all`**. Sends two read-only `__typename`-anchored probes:
(1) the non-repeatable `@skip` directive stacked 500 times on one field
(`{ __typename @skip(if: false) @skip(if: false) ... }`) and (2) an undefined
directive (`{ __typename @enshroudUnknownDirective }`). Fires MEDIUM when the
server accepts either probe without a directive/complexity/validation error
(`accepted_vectors`), **or** when an "Unknown directive" rejection leaks a real
custom-directive name via a "Did you mean" hint (`leaked_directives`). Never
mutates — every selection is the `__typename` meta-field. This is the fourth DoS
axis (directive) beyond `depth-dos` (nesting), `alias-batch` (breadth), and
`field-dup` (repetition), plus a low-false-positive recon signal for internal
directive tooling (`@auth`, `@cost`, `@cacheControl`, ...).

**Severity:** MEDIUM — **Effort:** M — **Check name:** `directive-abuse`

Some servers crash or leak under thousands of duplicated `@skip`/`@include`
directives on a single field, or accept unknown/custom directives that hint at
internal tooling. A reliable DoS-and-recon probe with low false-positive risk.

### 10. CSRF token / cross-site cookie posture ✅ IMPLEMENTED

**Status:** Shipped (Phase 2 Rotation 11). Standalone check `cookie-posture`
(`src/enshroud/checks/cookie_posture.py`), category `insecure_cookie_posture`,
**included in `--checks all`**. Sends a single benign `{ __typename }` request
and inspects every `Set-Cookie` response header, firing MEDIUM for each cookie
that is `SameSite=None`/missing `SameSite`, missing `Secure`, or missing
`HttpOnly`. Pure response-header analysis — zero active probing, no payloads,
no mutations. Implemented as its own check (rather than folded into `cors`/`csrf`)
so it can be selected independently and reports per-cookie weaknesses.

**Severity:** MEDIUM — **Effort:** S — **Check name:** `cookie-posture`

Inspect `Set-Cookie` attributes (`SameSite`, `Secure`, `HttpOnly`) on the
endpoint and report missing `SameSite=Lax/Strict`, which is the precondition that
makes the existing `csrf` and `array_batching` findings exploitable from a
browser. Pure response-header analysis — zero active probing.

---

## Phase 2 Rotation 15 — fresh gap analysis

All ten ranked directions above are shipped. A gap analysis against the Apollo
Federation subgraph spec, the PortSwigger GraphQL labs, and the OWASP GraphQL
Cheat Sheet surfaced one high-value vector with **zero** prior coverage in the
codebase: Apollo Federation schema/entity exposure. It was implemented this
rotation.

### 11. Apollo Federation `_service.sdl` / `_entities` exposure ✅ IMPLEMENTED

**Status:** Shipped (Phase 2 Rotation 15). Check `federation`
(`src/enshroud/checks/federation.py`), categories `federation_sdl_exposed`
(HIGH) and `federation_entities_exposed` (MEDIUM), **included in `--checks all`**.
Two read-only query probes: `{ _service { sdl } }` and
`{ _entities(representations: []) { __typename } }`. Never mutates.

**Severity:** HIGH (`_service.sdl`) / MEDIUM (`_entities`) — **Effort:** S —
**Check name:** `federation`

**What it detects:**
Apollo Federation subgraphs implement the spec-mandated `_service { sdl }`
field, which returns the subgraph's **entire schema as an SDL string regardless
of whether `__schema` introspection is disabled**. This is a complete bypass of
a disabled-introspection control — the single most impactful gap, because the
v0.1 `introspection` check goes silent on exactly the endpoints this one lights
up. The companion `_entities` resolver probe confirms the direct-subgraph
entity-access surface behind documented federation authorization-bypass chains.

**Competitor gap:**
No open-source CLI scanner probes `_service.sdl` as an introspection bypass.
graphql-cop and graphw00f do not cover federation. InQL requires manual replay.
enshroud is the first to ship automated federation SDL-leak detection in the
H1-markdown/JSON output pipeline.

**References:**
- Apollo Federation subgraph spec: `_service` / `_entities`
- PortSwigger Web Security Academy: GraphQL introspection bypasses
- OWASP GraphQL Cheat Sheet: "Introspection" and federation considerations

---

## Phase 2 Rotation 16 — fresh gap analysis

All eleven ranked directions above are shipped. A gap analysis against the
GraphQL spec validation rules (§5.5), the existing DoS-axis coverage
(`depth-dos`, `alias-batch`, `field-dup`, `directive-abuse`), and the OWASP
GraphQL Cheat Sheet surfaced one self-contained, read-only vector with **zero**
prior coverage: cyclic / self-referential fragment definitions. It was
implemented this rotation.

### 12. Cyclic fragment definitions (spec §5.5.2.2 bypass) ✅ IMPLEMENTED

**Status:** Shipped (Phase 2 Rotation 16). Check `fragment-cycle`
(`src/enshroud/checks/fragment_cycle.py`), category `fragment_cycle_dos` (MEDIUM),
**included in `--checks all`**. Sends two read-only `__typename`-anchored probes:
a two-fragment cycle (`{ ...A } fragment A on Query { __typename ...B } fragment B
on Query { __typename ...A }`) and a self-referential fragment
(`{ ...S } fragment S on Query { __typename ...S }`). Never mutates.

**Severity:** MEDIUM — **Effort:** S — **Check name:** `fragment-cycle`

**What it detects:**
The GraphQL spec (§5.5.2.2, "Fragment spreads must not form cycles") requires
executors to statically reject cyclic fragment documents during validation,
before execution. A server that **accepts** the cyclic document (returns `data`)
or **chokes** on it (timeout / dropped connection from unbounded expansion) has
skipped this mandatory rule. This is a **distinct axis** from `field-dup`, which
repeats a *non-recursive* fragment N times (linear amplification): a cycle
expands without bound. The finding fires only when no cycle/validation error is
returned; it reports accepted vs. crashed vectors in `evidence`.

**Competitor gap:**
graphql-cop and graphw00f do not probe for cyclic-fragment validation bypass;
InQL requires manual replay. enshroud ships automated detection in the
H1-markdown / JSON pipeline.

**References:**
- GraphQL spec §5.5.2.2: "Fragment spreads must not form cycles"
- OWASP GraphQL Cheat Sheet: "Query limiting / fragment limiting"
- PortSwigger Web Security Academy: GraphQL DoS via fragments

---

## Phase 2 Rotation 18 — research lap + fresh gap analysis

POST_V01.md had gone stale across several rotations: the shipped `verbose-errors`
check (commit `14d831f`, PR #15) was never recorded here, and the backlog of
"directions" was fully exhausted. This rotation began with a full codebase read
(every check, the client transport, the mock server) to rebuild an accurate
picture of what exists, then implemented the highest-value genuinely-unimplemented
vector.

### Accurate current state (as of Rotation 18)

**Default checks (`--checks all`), 17 total:**
`introspection`, `depth-dos`, `alias-batch`, `batch-array`, `field-dup`,
`fragment-cycle`, `directive-abuse`, `field-oracle`, **`auth-alias` (new this
rotation)**, `verbose-errors`, `mutation-enum`, `cors`, `csrf`, `cookie-posture`,
`fingerprint`, `apq`, `federation`.

**Opt-in checks (excluded from `all`):** `schema-fuzz`, `injection`, `websocket`.

**Previously undocumented but shipped:** `verbose-errors`
(`src/enshroud/checks/debug_errors.py`), category `verbose_error_disclosure`,
LOW–MEDIUM, in `--checks all`. Detects development/debug error mode leaking stack
traces, source paths, exception classes, raw SQL, internal hosts, or framework
versions from a single deliberately-malformed query. Now recorded here for
accuracy.

### Candidates evaluated this rotation (and why most were rejected)

- **Query batching abuse via aliases** — already covered by `alias-batch`. Not new.
- **Persisted query hash exhaustion** — `apq` already probes unauthenticated
  registration + rapid re-registration (rate-limit). Substantially covered. Not new.
- **Subscription flooding** — would be a timing-dependent sub-feature of the
  existing `websocket` check; hard to assert deterministically. Marginal.
- **`__typename` / type-name enumeration when introspection disabled** — partially
  covered by `field-oracle` (field names) and `schema-fuzz` (top-level fields).
  Incremental.
- **Authorization bypass via field aliasing** — **zero prior coverage. Selected.**

### 13. Authorization bypass via field aliasing ✅ IMPLEMENTED

**Status:** Shipped (Phase 2 Rotation 18). Check `auth-alias`
(`src/enshroud/checks/auth_alias.py`), category `authz_bypass_via_alias` (HIGH),
**included in `--checks all`**. Read-only and differential: for each candidate
field (real query-type fields when introspection is available, else a bundled
list of commonly-protected names) it sends the field directly
(`{ <field> { __typename } }`) and aliased
(`{ enshroudAliasProbe: <field> { __typename } }`). Fires **only** when the
direct form is an authorization denial and the aliased form returns data under
the alias key. Never mutates.

**Severity:** HIGH — **Effort:** S — **Check name:** `auth-alias`

**What it detects:**
Servers (and WAFs / API gateways) that enforce authorization by matching the
literal field name or response key against a deny-list, rather than evaluating
the field's own authorization metadata during resolution. On such a server,
aliasing a forbidden field to a different response key changes what the control
matches on, so the field resolves and leaks its data.

**Why it's genuinely new:**
This is an **authorization** flaw, not a DoS one, and it is conceptually distinct
from `alias-batch` (which abuses the *count* of aliases to exhaust resources /
defeat rate limits). Here a *single* alias defeats a *field-name-keyed* security
control, with impact = unauthorized data access. No existing check probes this.
The detection is strictly differential (denied-direct AND allowed-aliased), and a
plain "cannot query field" validation error is explicitly not treated as a
denial, so a correctly-implemented server (authorization on the resolved field)
produces no findings and unknown candidate names cause no false positives.

**Competitor gap:**
graphql-cop, graphw00f, and Clairvoyance do not test alias-based authorization
bypass; InQL requires manual replay. enshroud ships automated differential
detection in the H1-markdown / JSON pipeline.

**References:**
- HackerOne / PortSwigger writeups on alias-based authorization & WAF bypass
- OWASP GraphQL Cheat Sheet: "Authorization" (enforce in resolvers, not on field names)
- Apollo Client GitHub issue #10784 (field-aliasing abuse, cache context)

### Backlog after this rotation

The original ranked backlog (1–12) plus `verbose-errors` and this rotation's
`auth-alias` are all shipped. No pre-written directions remain; future rotations
should continue the research-lap pattern (read the codebase, run a fresh gap
analysis against the OWASP GraphQL Cheat Sheet / PortSwigger labs / HackerOne
corpus, implement one genuinely-new check). Open ideas not yet implemented and
worth considering next: per-event subscription re-authorization over WebSocket,
GraphQL response-cache poisoning via alias/normalisation, and batch-aware
mutation rate-limit bypass weaponisation guidance.

---

## Quick reference table

| Rank | Check name | New flag | Severity | Effort | Default in `all`? |
|---|---|---|---|---|---|
| 1 | `csrf` ✅ | `--checks csrf` | HIGH | S | Yes (shipped) |
| 2 | `fingerprint` | `--checks fingerprint` | INFO | M | Yes |
| 3 | `websocket` ✅ | `--checks websocket` | HIGH | L | No (opt-in, shipped) |
| 4 | `injection` | `--checks injection` | CRITICAL | M | No (opt-in, active) |
| 5 | `apq` | `--checks apq` | MEDIUM | S | Yes |
| 6 | `schema-fuzz` ✅ | `--checks schema-fuzz` | LOW | L | No (opt-in, slow) |
| 7 | `batch-array` ✅ | `--checks batch-array` | HIGH | S | Yes (shipped) |
| 8 | `field-dup` ✅ | `--checks field-dup` | MEDIUM | M | Yes (shipped) |
| 9 | `directive-abuse` ✅ | `--checks directive-abuse` | MEDIUM | M | Yes (shipped) |
| 10 | `cookie-posture` ✅ | `--checks cookie-posture` | MEDIUM | S | Yes (shipped) |
| 11 | `federation` ✅ | `--checks federation` | HIGH/MEDIUM | S | Yes (shipped) |
| 12 | `fragment-cycle` ✅ | `--checks fragment-cycle` | MEDIUM | S | Yes (shipped) |
| — | `verbose-errors` ✅ | `--checks verbose-errors` | LOW–MEDIUM | S | Yes (shipped) |
| 13 | `auth-alias` ✅ | `--checks auth-alias` | HIGH | S | Yes (shipped) |

Opt-in checks require explicit `--checks <name>` and are excluded from `--checks all` due to noise, speed, or active-probing concerns.
