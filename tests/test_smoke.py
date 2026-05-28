"""End-to-end smoke test: --checks all against mock server."""
from __future__ import annotations

import json
import subprocess
import sys


def test_smoke_all_checks_json(mock_url, scope_file):
    """Run enshroud --checks all against mock, verify JSON output has all categories."""
    result = subprocess.run(
        [
            sys.executable, "-m", "enshroud",
            "--target", mock_url,
            "--scope-file", scope_file,
            "--checks", "all",
            "--format", "json",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, f"stderr: {result.stderr}\nstdout: {result.stdout}"

    findings = json.loads(result.stdout)
    assert isinstance(findings, list)
    assert len(findings) >= 1

    categories = {f["category"] for f in findings}
    assert "introspection_enabled" in categories
    assert "depth_dos" in categories
    assert "alias_batching" in categories
    assert "array_batching" in categories
    assert "directive_abuse" in categories
    assert "field_suggestion_oracle" in categories
    assert "dangerous_mutation_exposed" in categories
    assert "cors_misconfiguration" in categories


def test_smoke_h1md_output(mock_url, scope_file):
    """Run enshroud with --format h1md and verify sections."""
    result = subprocess.run(
        [
            sys.executable, "-m", "enshroud",
            "--target", mock_url,
            "--scope-file", scope_file,
            "--checks", "introspection",
            "--format", "h1md",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, f"stderr: {result.stderr}\nstdout: {result.stdout}"
    output = result.stdout

    assert "## Summary" in output
    assert "## Steps to Reproduce" in output
    assert "## Impact" in output
    assert "## Proof of Concept" in output
    assert "## Recommended Mitigation" in output
    assert "[MEDIUM]" in output


def test_smoke_out_of_scope(mock_url, tmp_path):
    """Target out of scope exits with code 2."""
    scope = tmp_path / "scope.txt"
    scope.write_text("example.com\n")

    result = subprocess.run(
        [
            sys.executable, "-m", "enshroud",
            "--target", mock_url,
            "--scope-file", str(scope),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "out of scope" in result.stderr.lower()


def test_smoke_specific_checks(mock_url, scope_file):
    """Running specific checks returns only those categories."""
    result = subprocess.run(
        [
            sys.executable, "-m", "enshroud",
            "--target", mock_url,
            "--scope-file", scope_file,
            "--checks", "cors,introspection",
            "--format", "json",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, f"stderr: {result.stderr}"
    findings = json.loads(result.stdout)
    categories = {f["category"] for f in findings}
    assert "cors_misconfiguration" in categories
    assert "introspection_enabled" in categories
    # Should NOT include depth_dos, alias_batching, etc.
    assert "depth_dos" not in categories


def test_schema_fuzz_is_opt_in_not_in_all():
    """schema-fuzz is excluded from 'all' but accepted as an explicit check."""
    from enshroud.cli import OPT_IN_CHECKS, VALID_CHECKS, parse_checks

    assert "schema-fuzz" in OPT_IN_CHECKS
    assert "schema-fuzz" in VALID_CHECKS
    # 'all' must not pull in opt-in checks.
    assert "schema-fuzz" not in parse_checks("all")
    # But an explicit request is honoured.
    assert parse_checks("schema-fuzz") == ["schema-fuzz"]


def test_fuzz_rate_flag_parses():
    """--fuzz-rate is exposed and parsed as a float."""
    from enshroud.cli import build_parser

    args = build_parser().parse_args(
        ["--target", "http://x/graphql", "--scope-file", "s.txt", "--fuzz-rate", "12.5"]
    )
    assert args.fuzz_rate == 12.5


def test_injection_is_opt_in_not_in_all():
    """injection is excluded from 'all' but accepted as an explicit check."""
    from enshroud.cli import OPT_IN_CHECKS, VALID_CHECKS, parse_checks

    assert "injection" in OPT_IN_CHECKS
    assert "injection" in VALID_CHECKS
    # 'all' must not pull in the active-probing injection check.
    assert "injection" not in parse_checks("all")
    # But an explicit request is honoured.
    assert parse_checks("injection") == ["injection"]


def test_active_flag_parses():
    """--active is exposed and defaults to False."""
    from enshroud.cli import build_parser

    default = build_parser().parse_args(
        ["--target", "http://x/graphql", "--scope-file", "s.txt"]
    )
    assert default.active is False
    enabled = build_parser().parse_args(
        ["--target", "http://x/graphql", "--scope-file", "s.txt", "--active"]
    )
    assert enabled.active is True
