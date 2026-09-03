"""CLI entry point for enshroud."""
from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Any

from enshroud.client import GraphQLClient
from enshroud.correlate import correlate_findings
from enshroud.output import render_h1md, render_json
from enshroud.scope import get_target_host, load_scope, target_in_scope
from enshroud.severity import (
    FAIL_ON_EXIT_CODE,
    SEVERITY_ORDER,
    findings_meet_threshold,
    normalize_threshold,
)

ALL_CHECKS = [
    "introspection",
    "introspection-bypass",
    "depth-dos",
    "depth-bypass",
    "alias-batch",
    "alias-overloading",
    "batch-array",
    "field-dup",
    "fragment-cycle",
    "directive-abuse",
    "directive-enforcement",
    "defer-abuse",
    "field-oracle",
    "suggestion-leak",
    "enum-value-leak",
    "auth-alias",
    "verbose-errors",
    "mutation-enum",
    "mutation-allowlist-bypass",
    "cors",
    "csrf",
    "csrf-multipart",
    "query-get",
    "cookie-posture",
    "graphql-ide",
    "fingerprint",
    "apq",
    "apq-collision",
    "apq-get",
    "pq-enum",
    "operation-name-enum",
    "trace-exposure",
    "federation",
    "response-cache-poison",
]

# Opt-in checks: valid to request explicitly, but excluded from "all" because
# they are slow, noisy, or actively probe the target.
OPT_IN_CHECKS = [
    "schema-fuzz",
    "schema-export",
    "injection",
    "websocket",
    "pq-brute",
    "bola",
    "field-authz",
]

VALID_CHECKS = ALL_CHECKS + OPT_IN_CHECKS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="enshroud",
        description="Modern GraphQL attack-surface scanner for bug bounty and penetration testing.",
    )
    parser.add_argument(
        "--target",
        required=True,
        metavar="URL",
        help="GraphQL endpoint URL (required)",
    )
    parser.add_argument(
        "--scope-file",
        required=True,
        metavar="FILE",
        help="Path to scope file (one hostname/IP/CIDR per line, # comments ignored)",
    )
    parser.add_argument(
        "--checks",
        default="all",
        metavar="CHECK",
        help=(
            "Comma-separated checks to run (default: all). "
            "Choices: introspection, introspection-bypass, depth-dos, "
            "depth-bypass, alias-batch, alias-overloading, batch-array, "
            "field-dup, fragment-cycle, directive-abuse, "
            "directive-enforcement, defer-abuse, "
            "field-oracle, suggestion-leak, auth-alias, verbose-errors, mutation-enum, "
            "mutation-allowlist-bypass, cors, csrf, "
            "csrf-multipart, query-get, cookie-posture, graphql-ide, fingerprint, apq, "
            "apq-collision, apq-get, pq-enum, operation-name-enum, "
            "trace-exposure, federation, response-cache-poison, all. "
            "Opt-in (not in 'all'): schema-fuzz, schema-export, injection, "
            "websocket, pq-brute, bola, field-authz."
        ),
    )
    parser.add_argument(
        "--format",
        choices=["json", "h1md"],
        default="json",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--auth-header",
        metavar="HEADER",
        default=None,
        help='Optional auth header, e.g. "Authorization: Bearer TOKEN"',
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SECONDS",
        help="Request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--fuzz-rate",
        type=float,
        default=5.0,
        metavar="RPS",
        help=(
            "schema-fuzz / pq-brute probe rate in requests/second "
            "(default: 5). Set <= 0 to disable throttling."
        ),
    )
    parser.add_argument(
        "--active",
        action="store_true",
        help=(
            "Enable active probing for checks that touch another principal's "
            "data or make the backend sleep: injection (time-based SQLi), "
            "bola (object-level ID-swap), and field-authz (sensitive-field "
            "over-fetch). Off by default. The bola/field-authz hard caps still "
            "apply — one benign request each, no enumeration."
        ),
    )
    # ── schema-export options (read-only schema reconstruction artifact) ───
    parser.add_argument(
        "--schema-out",
        metavar="FILE",
        default=None,
        help=(
            "For --checks schema-export: also write the reconstructed "
            "InQL/Voyager-compatible introspection JSON to this path."
        ),
    )
    # ── bola options (object-level authorization confirmation) ──────────────
    # The bola check reads ONE object the operator names here — ideally two test
    # accounts the operator controls. No enumeration; hard-capped at one request.
    parser.add_argument(
        "--bola-field",
        metavar="FIELD",
        default=None,
        help="For --checks bola: the query field that fetches an object by ID.",
    )
    parser.add_argument(
        "--bola-id-arg",
        metavar="ARG",
        default="id",
        help="For --checks bola: the ID argument name (default: id).",
    )
    parser.add_argument(
        "--bola-my-id",
        metavar="ID",
        default=None,
        help=(
            "For --checks bola: an object ID the caller's session owns "
            "(optional; used to assert the swap reads a DIFFERENT object)."
        ),
    )
    parser.add_argument(
        "--bola-other-id",
        metavar="ID",
        default=None,
        help=(
            "For --checks bola: another principal's object ID to attempt to "
            "read (required to run the check)."
        ),
    )
    parser.add_argument(
        "--bola-fields",
        metavar="F1,F2",
        default=None,
        help=(
            "For --checks bola: optional extra fields to select on the object "
            "(comma-separated). The confirmation rests on the returned id."
        ),
    )
    # ── field-authz options (field-level authorization confirmation) ────────
    parser.add_argument(
        "--authz-field",
        metavar="FIELD",
        default=None,
        help=(
            "For --checks field-authz: the query field exposing sensitive "
            "sub-fields (required to run the check)."
        ),
    )
    parser.add_argument(
        "--authz-sensitive",
        metavar="F1,F2",
        default=None,
        help=(
            "For --checks field-authz: comma-separated sensitive sub-fields to "
            "request (e.g. ssn,creditCard,passwordHash). Required to run."
        ),
    )
    parser.add_argument(
        "--fail-on",
        metavar="SEVERITY",
        default=None,
        help=(
            "Exit with code 3 if any finding is at or above this severity "
            "(for CI/CD gating). One of: "
            f"{', '.join(SEVERITY_ORDER)}. Case-insensitive. "
            "Output is still printed. Off by default (always exit 0 on a "
            "successful scan)."
        ),
    )
    return parser


def parse_checks(checks_str: str) -> list[str]:
    """Parse the --checks argument into a list of check names."""
    raw = [c.strip() for c in checks_str.replace(",", " ").split()]
    if "all" in raw:
        return list(ALL_CHECKS)
    result: list[str] = []
    for c in raw:
        if c not in VALID_CHECKS:
            print(
                f"Warning: unknown check '{c}'. Valid choices: "
                f"{', '.join(VALID_CHECKS)}, all",
                file=sys.stderr,
            )
        else:
            result.append(c)
    return result


def _split_csv(value: str | None) -> list[str] | None:
    """Split a comma-separated CLI value into a clean list (None passes through)."""
    if value is None:
        return None
    items = [v.strip() for v in value.split(",")]
    return [v for v in items if v]


async def run_checks(
    checks: list[str],
    client: GraphQLClient,
    fuzz_rate: float = 5.0,
    active: bool = False,
    options: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Run selected checks and aggregate findings.

    ``options`` carries the per-check configuration the targeted confirmers
    need (bola object IDs, field-authz sensitive fields, schema-export output
    path). It is ignored by checks that don't read it.
    """
    opts = options or {}
    from enshroud.checks import (
        alias_batch,
        alias_overloading,
        apq,
        apq_collision,
        apq_get,
        auth_alias,
        batch_array,
        bola,
        cookie_posture,
        cors,
        csrf,
        csrf_multipart,
        debug_errors,
        defer_abuse,
        depth_bypass,
        depth_dos,
        directive_abuse,
        directive_enforcement,
        enum_value_leak,
        federation,
        field_authz,
        field_dup,
        field_oracle,
        fingerprint,
        fragment_cycle,
        graphql_ide,
        injection,
        introspection,
        introspection_bypass,
        mutation_allowlist_bypass,
        mutation_enum,
        operation_name_enum,
        pq_brute,
        pq_enum,
        query_get,
        response_cache_poison,
        schema_export,
        schema_fuzz,
        suggestion_leak,
        trace_exposure,
        websocket,
    )

    # Checks with the uniform (client) -> findings signature.
    check_map = {
        "introspection": introspection.check,
        "introspection-bypass": introspection_bypass.check,
        "depth-dos": depth_dos.check,
        "depth-bypass": depth_bypass.check,
        "alias-batch": alias_batch.check,
        "alias-overloading": alias_overloading.check,
        "batch-array": batch_array.check,
        "field-dup": field_dup.check,
        "fragment-cycle": fragment_cycle.check,
        "directive-abuse": directive_abuse.check,
        "directive-enforcement": directive_enforcement.check,
        "defer-abuse": defer_abuse.check,
        "field-oracle": field_oracle.check,
        "suggestion-leak": suggestion_leak.check,
        "enum-value-leak": enum_value_leak.check,
        "auth-alias": auth_alias.check,
        "verbose-errors": debug_errors.check,
        "mutation-enum": mutation_enum.check,
        "mutation-allowlist-bypass": mutation_allowlist_bypass.check,
        "cors": cors.check,
        "csrf": csrf.check,
        "csrf-multipart": csrf_multipart.check,
        "query-get": query_get.check,
        "cookie-posture": cookie_posture.check,
        "graphql-ide": graphql_ide.check,
        "fingerprint": fingerprint.check,
        "apq": apq.check,
        "apq-collision": apq_collision.check,
        "apq-get": apq_get.check,
        "pq-enum": pq_enum.check,
        "operation-name-enum": operation_name_enum.check,
        "response-cache-poison": response_cache_poison.check,
        "trace-exposure": trace_exposure.check,
        "federation": federation.check,
        "websocket": websocket.check,
    }

    findings: list[dict[str, Any]] = []
    for check_name in checks:
        if check_name == "schema-fuzz":
            findings.extend(
                await schema_fuzz.check(client, fuzz_rate=fuzz_rate)
            )
            continue
        if check_name == "schema-export":
            findings.extend(
                await schema_export.check(
                    client,
                    fuzz_rate=fuzz_rate,
                    schema_out=opts.get("schema_out"),
                )
            )
            continue
        if check_name == "pq-brute":
            findings.extend(
                await pq_brute.check(client, fuzz_rate=fuzz_rate)
            )
            continue
        if check_name == "injection":
            findings.extend(
                await injection.check(client, active=active)
            )
            continue
        if check_name == "bola":
            findings.extend(
                await bola.check(
                    client,
                    active=active,
                    query_field=opts.get("bola_field"),
                    id_arg=opts.get("bola_id_arg", "id"),
                    my_id=opts.get("bola_my_id"),
                    other_id=opts.get("bola_other_id"),
                    extra_fields=opts.get("bola_fields"),
                )
            )
            continue
        if check_name == "field-authz":
            findings.extend(
                await field_authz.check(
                    client,
                    active=active,
                    query_field=opts.get("authz_field"),
                    sensitive_fields=opts.get("authz_sensitive"),
                )
            )
            continue
        fn = check_map.get(check_name)
        if fn:
            result = await fn(client)
            findings.extend(result)

    # Fingerprint-informed correlation: when the engine was identified this
    # lap, annotate any vulnerability finding that matches a documented
    # default-insecure behaviour of that engine (POST_V01 direction #2). No-op
    # if 'fingerprint' was not run or the engine is unrecognised.
    findings = correlate_findings(findings)

    return findings


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Validate --fail-on up front so a typo fails fast instead of after a scan.
    fail_on: str | None = None
    if args.fail_on is not None:
        try:
            fail_on = normalize_threshold(args.fail_on)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)

    # Load scope and validate target
    try:
        scope_entries = load_scope(args.scope_file)
    except FileNotFoundError:
        print(f"Error: scope file not found: {args.scope_file}", file=sys.stderr)
        sys.exit(1)

    if not target_in_scope(args.target, scope_entries):
        host = get_target_host(args.target)
        print(f"Error: target {host} is out of scope", file=sys.stderr)
        sys.exit(2)

    checks = parse_checks(args.checks)
    if not checks:
        print("Error: no valid checks specified", file=sys.stderr)
        sys.exit(1)

    client = GraphQLClient(
        endpoint=args.target,
        auth_header=args.auth_header,
        timeout=args.timeout,
    )

    # Per-check configuration for the targeted confirmers / artifact export.
    options = {
        "schema_out": args.schema_out,
        "bola_field": args.bola_field,
        "bola_id_arg": args.bola_id_arg,
        "bola_my_id": args.bola_my_id,
        "bola_other_id": args.bola_other_id,
        "bola_fields": _split_csv(args.bola_fields),
        "authz_field": args.authz_field,
        "authz_sensitive": _split_csv(args.authz_sensitive),
    }

    findings = asyncio.run(
        run_checks(
            checks,
            client,
            fuzz_rate=args.fuzz_rate,
            active=args.active,
            options=options,
        )
    )

    if args.format == "h1md":
        print(render_h1md(findings))
    else:
        print(render_json(findings))

    # CI/CD gating: exit non-zero if a finding meets the --fail-on threshold.
    # Output above is always emitted first so reports are never suppressed.
    if fail_on is not None and findings_meet_threshold(findings, fail_on):
        print(
            f"fail-on: at least one finding is >= {fail_on}; "
            f"exiting {FAIL_ON_EXIT_CODE}",
            file=sys.stderr,
        )
        sys.exit(FAIL_ON_EXIT_CODE)


if __name__ == "__main__":
    main()
