"""Unit tests for the severity ranking and --fail-on policy."""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from enshroud.severity import (
    FAIL_ON_EXIT_CODE,
    findings_meet_threshold,
    normalize_threshold,
    severity_rank,
)


# --- pure unit tests --------------------------------------------------------


def test_severity_rank_ordering():
    assert (
        severity_rank("CRITICAL")
        > severity_rank("HIGH")
        > severity_rank("MEDIUM")
        > severity_rank("LOW")
        > severity_rank("INFO")
    )


def test_severity_rank_case_insensitive():
    assert severity_rank("high") == severity_rank("HIGH")


def test_severity_rank_unknown_is_info_floor():
    # Unknown/None must never trip a HIGH gate.
    assert severity_rank("WAT") == severity_rank("INFO")
    assert severity_rank(None) == severity_rank("INFO")


def test_normalize_threshold_canonicalizes():
    assert normalize_threshold("high") == "HIGH"
    assert normalize_threshold("  Critical ") == "CRITICAL"


def test_normalize_threshold_rejects_garbage():
    with pytest.raises(ValueError):
        normalize_threshold("severe")


def test_findings_meet_threshold_at_boundary():
    findings = [{"severity": "HIGH"}]
    assert findings_meet_threshold(findings, "HIGH") is True
    assert findings_meet_threshold(findings, "CRITICAL") is False
    assert findings_meet_threshold(findings, "MEDIUM") is True


def test_findings_meet_threshold_empty_is_false():
    assert findings_meet_threshold([], "INFO") is False


def test_findings_meet_threshold_missing_severity_is_info():
    assert findings_meet_threshold([{}], "LOW") is False
    assert findings_meet_threshold([{}], "INFO") is True


# --- CLI integration: exit-code contract ------------------------------------


def _run(mock_url, scope_file, *extra):
    return subprocess.run(
        [
            sys.executable, "-m", "enshroud",
            "--target", mock_url,
            "--scope-file", scope_file,
            "--checks", "all",
            "--format", "json",
            *extra,
        ],
        capture_output=True,
        text=True,
    )


def test_fail_on_high_trips_exit_3(mock_url, scope_file):
    # The mock server exposes a HIGH cors_misconfiguration finding.
    result = _run(mock_url, scope_file, "--fail-on", "high")
    assert result.returncode == FAIL_ON_EXIT_CODE, result.stderr
    # Output is still emitted, not suppressed.
    findings = json.loads(result.stdout)
    assert any(f["severity"] == "HIGH" for f in findings)
    assert "fail-on" in result.stderr.lower()


def test_fail_on_critical_does_not_trip_when_no_critical(mock_url, scope_file):
    # No CRITICAL findings from --checks all on the mock, so exit stays 0.
    result = _run(mock_url, scope_file, "--fail-on", "critical")
    assert result.returncode == 0, result.stderr
    findings = json.loads(result.stdout)
    assert all(f["severity"] != "CRITICAL" for f in findings)


def test_no_fail_on_always_exits_zero(mock_url, scope_file):
    result = _run(mock_url, scope_file)
    assert result.returncode == 0, result.stderr


def test_fail_on_invalid_value_exits_1(mock_url, scope_file):
    result = _run(mock_url, scope_file, "--fail-on", "bogus")
    assert result.returncode == 1
    assert "invalid severity" in result.stderr.lower()


def test_fail_on_flag_parses():
    from enshroud.cli import build_parser

    args = build_parser().parse_args(
        ["--target", "http://x/graphql", "--scope-file", "s.txt", "--fail-on", "MEDIUM"]
    )
    assert args.fail_on == "MEDIUM"
    default = build_parser().parse_args(
        ["--target", "http://x/graphql", "--scope-file", "s.txt"]
    )
    assert default.fail_on is None
