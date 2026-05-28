# enshroud

Modern GraphQL attack-surface scanner for bug bounty and penetration testing.

enshroud replaces the abandoned [GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) and expands coverage to the full modern GraphQL attack surface: introspection leakage, depth-based DoS, alias batching, field suggestion oracles, dangerous mutation enumeration, CORS misconfiguration, CSRF via content-type bypass, GraphQL engine fingerprinting, Automatic Persisted Query (APQ) abuse, Clairvoyance-style schema reconstruction, SQL/NoSQL injection probing, and GraphQL-over-WebSocket subscription security.

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
                        Choices: introspection, depth-dos, alias-batch,
                                 field-oracle, mutation-enum, cors, csrf,
                                 fingerprint, apq, all
                        Opt-in (not in 'all'): schema-fuzz, injection,
                                 websocket
--format {json,h1md}    Output format (default: json)
--auth-header HEADER    Auth header, e.g. "Authorization: Bearer TOKEN"
--timeout SECONDS       Request timeout in seconds (default: 10)
--fuzz-rate RPS         schema-fuzz probe rate, req/s (default: 5; <=0 = no limit)
--active                Enable active/blind probing for the injection check
                        (time-based SQLi). Off by default.
```

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
| `depth-dos` | `depth_dos` | LOW | Missing query depth limit |
| `alias-batch` | `alias_batching` | MEDIUM | Unbounded alias-based query batching |
| `field-oracle` | `field_suggestion_oracle` | LOW | Field name leakage via error suggestions |
| `mutation-enum` | `dangerous_mutation_exposed` | HIGH | Dangerous mutations in public schema |
| `cors` | `cors_misconfiguration` | HIGH | CORS wildcard + credentials |
| `csrf` | `csrf_via_content_type` | HIGH | Mutations executable via form-encoded POST or GET (CSRF) |
| `fingerprint` | `engine_identified` | INFO | Identifies the GraphQL engine (Apollo, Graphene, Strawberry, Hasura, WPGraphQL, Yoga, Mercurius, graphql-ruby, graphql-js) and surfaces its known default-insecure behaviours |
| `apq` | `apq_enabled`, `apq_unrestricted_registration`, `apq_no_rate_limit` | LOW–MEDIUM | Automatic Persisted Query exposure and unrestricted/unthrottled registration |
| `schema-fuzz` _(opt-in)_ | `schema_reconstructed` | LOW–MEDIUM | Reconstructs schema field names via the suggestion oracle when introspection is disabled |
| `injection` _(opt-in)_ | `sql_injection_signal`, `nosql_injection_signal` | CRITICAL | Probes scalar arguments for SQL/NoSQL injection via error-based (and, with `--active`, time-based) fuzzing |
| `websocket` _(opt-in)_ | `websocket_unauth_subscription`, `websocket_introspection`, `websocket_no_tls`, `websocket_cswsh` | HIGH | Tests the GraphQL-over-WebSocket subscription transport for unauthenticated handshakes, schema reachability, plaintext `ws://`, and Cross-Site WebSocket Hijacking |

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
