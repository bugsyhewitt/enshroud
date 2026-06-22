# Changelog

All notable changes to enshroud are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-22

### Added
- 36 checks across the GraphQL attack-surface (34 always-on + 7 opt-in): introspection (#20), introspection-bypass (#20), introspection-bypass fragment-spread (#21), depth-dos, depth-bypass (#22), alias-batch, alias-overloading (#33), batch-array (#8), field-dup (#10), fragment-cycle (#14), directive-abuse (#11), directive-enforcement (#29), defer-abuse (#17), field-oracle, suggestion-leak (#30), enum-value-leak (#34), auth-alias (#16), verbose-errors (#15), mutation-enum, mutation-allowlist-bypass (#28), cors, csrf (#1), csrf-multipart (#19), query-get (#26), cookie-posture (#9), graphql-ide (#18), fingerprint (#2), apq, apq-collision (#23), apq-get (#25), pq-enum (#27), operation-name-enum (#31), trace-exposure (#24), federation (#13), response-cache-poison (#35), pq-brute (#32); opt-in: schema-fuzz (#3), schema-export (#36), injection (#4), websocket (#5), pq-brute (#32), bola (#36), field-authz (#36).
- `--fail-on` severity gate with CI/CD exit-code contract (#7).
- Correlate findings with fingerprint engine defaults (#6).
- Blind-SQLi time-based control to kill false positives (#12).
- Engine fingerprinting check (#2).

### Infrastructure
- Wheel-ship-gate test suite (`tests/test_wheel_ship_gate.py`, 5 `@pytest.mark.ship_gate` tests) pinning wheel-build + wheel-install + module-import + editable-install + CHANGELOG contracts.
- `ship_gate` pytest marker registered in `pyproject.toml [tool.pytest.ini_options].markers`.

### Notes
- This is the **first v1.0 RELEASE** of enshroud (it entered the necromancer suite as the slot-20 successor to familiar, retired 2026-05-26).
- 36 PRs shipped since initial commit (HEAD `d832cf9` at v0.1.0, bumped to 1.0.0). All 41 checks ship in the `enshroud-1.0.0-py3-none-any.whl` wheel; both bundled data files (`src/enshroud/data/gql_fields.txt`, `src/enshroud/data/signatures.json`) are included in the wheel via `[tool.setuptools.package-data]`.
