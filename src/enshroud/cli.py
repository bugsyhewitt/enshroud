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
    "depth-dos",
    "alias-batch",
    "batch-array",
    "field-dup",
    "fragment-cycle",
    "directive-abuse",
    "field-oracle",
    "verbose-errors",
    "mutation-enum",
    "cors",
    "csrf",
    "cookie-posture",
    "fingerprint",
    "apq",
    "federation",
]

# Opt-in checks: valid to request explicitly, but excluded from "all" because
# they are slow, noisy, or actively probe the target.
OPT_IN_CHECKS = [
    "schema-fuzz",
    "injection",
    "websocket",
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
            "Choices: introspection, depth-dos, alias-batch, batch-array, "
            "field-dup, fragment-cycle, directive-abuse, field-oracle, "
            "verbose-errors, mutation-enum, cors, csrf, cookie-posture, "
            "fingerprint, apq, federation, all. "
            "Opt-in (not in 'all'): schema-fuzz, injection, websocket."
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
            "schema-fuzz probe rate in requests/second (default: 5). "
            "Set <= 0 to disable throttling."
        ),
    )
    parser.add_argument(
        "--active",
        action="store_true",
        help=(
            "Enable active/blind probing for the injection check (time-based "
            "SQLi). Off by default; only affects --checks injection."
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


async def run_checks(
    checks: list[str],
    client: GraphQLClient,
    fuzz_rate: float = 5.0,
    active: bool = False,
) -> list[dict[str, Any]]:
    """Run selected checks and aggregate findings."""
    from enshroud.checks import (
        alias_batch,
        apq,
        batch_array,
        cookie_posture,
        cors,
        csrf,
        debug_errors,
        depth_dos,
        directive_abuse,
        federation,
        field_dup,
        field_oracle,
        fingerprint,
        fragment_cycle,
        injection,
        introspection,
        mutation_enum,
        schema_fuzz,
        websocket,
    )

    # Checks with the uniform (client) -> findings signature.
    check_map = {
        "introspection": introspection.check,
        "depth-dos": depth_dos.check,
        "alias-batch": alias_batch.check,
        "batch-array": batch_array.check,
        "field-dup": field_dup.check,
        "fragment-cycle": fragment_cycle.check,
        "directive-abuse": directive_abuse.check,
        "field-oracle": field_oracle.check,
        "verbose-errors": debug_errors.check,
        "mutation-enum": mutation_enum.check,
        "cors": cors.check,
        "csrf": csrf.check,
        "cookie-posture": cookie_posture.check,
        "fingerprint": fingerprint.check,
        "apq": apq.check,
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
        if check_name == "injection":
            findings.extend(
                await injection.check(client, active=active)
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

    findings = asyncio.run(
        run_checks(checks, client, fuzz_rate=args.fuzz_rate, active=args.active)
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
