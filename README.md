# enshroud

Modern GraphQL attack-surface scanner for bug bounty and penetration testing.

enshroud replaces the abandoned [GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) and expands coverage to the full modern GraphQL attack surface: introspection leakage, depth-based DoS, alias batching, field suggestion oracles, dangerous mutation enumeration, CORS misconfiguration, CSRF via content-type bypass, GraphQL engine fingerprinting, Automatic Persisted Query (APQ) abuse, and Clairvoyance-style schema reconstruction.

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
                        Opt-in (not in 'all'): schema-fuzz
--format {json,h1md}    Output format (default: json)
--auth-header HEADER    Auth header, e.g. "Authorization: Bearer TOKEN"
--timeout SECONDS       Request timeout in seconds (default: 10)
--fuzz-rate RPS         schema-fuzz probe rate, req/s (default: 5; <=0 = no limit)
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

## Attribution

Inspired by [GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) by Swissky. See NOTICE for details.
