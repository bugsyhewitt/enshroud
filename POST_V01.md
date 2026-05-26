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

### 1. CSRF via content-type bypass

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

### 3. WebSocket subscription attack surface

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

### 6. Schema fuzzing (Clairvoyance-style wordlist rebuild)

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

## Quick reference table

| Rank | Check name | New flag | Severity | Effort | Default in `all`? |
|---|---|---|---|---|---|
| 1 | `csrf` | `--checks csrf` | HIGH | S | Yes |
| 2 | `fingerprint` | `--checks fingerprint` | INFO | M | Yes |
| 3 | `websocket` | `--checks websocket` | HIGH | L | No (opt-in) |
| 4 | `injection` | `--checks injection` | CRITICAL | M | No (opt-in, active) |
| 5 | `apq` | `--checks apq` | MEDIUM | S | Yes |
| 6 | `schema-fuzz` | `--checks schema-fuzz` | LOW | L | No (opt-in, slow) |

Opt-in checks require explicit `--checks <name>` and are excluded from `--checks all` due to noise, speed, or active-probing concerns.
