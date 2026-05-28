"""Severity ordering and the --fail-on exit-code policy.

enshroud is built to run in bug-bounty and pentest automation. A scanner that
always exits 0 cannot gate a CI/CD pipeline, so this module provides the
severity ranking and the policy decision behind the ``--fail-on`` flag.

Exit-code contract (see also cli.main):
    0  checks ran; no finding met or exceeded the --fail-on threshold
       (also the exit code when --fail-on is not supplied)
    1  tool/usage error (bad scope file, no valid checks)
    2  target out of scope
    3  checks ran and at least one finding met or exceeded the --fail-on
       threshold (a policy failure, distinct from a tool error)

Keeping the threshold logic here — rather than inline in main() — keeps it unit
testable without spawning a subprocess.
"""
from __future__ import annotations

from typing import Any

# Highest first. INFO is the floor; anything at or above the requested
# threshold trips the policy. Unknown/missing severities are treated as INFO so
# they never accidentally trip a HIGH gate.
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Numeric rank: higher number == more severe. Used for threshold comparisons.
_RANK = {name: len(SEVERITY_ORDER) - i for i, name in enumerate(SEVERITY_ORDER)}

# Exit code returned when --fail-on is supplied and a qualifying finding exists.
FAIL_ON_EXIT_CODE = 3


def severity_rank(severity: str | None) -> int:
    """Rank a severity string. Unknown/None ranks as INFO (the floor)."""
    if not severity:
        return _RANK["INFO"]
    return _RANK.get(severity.strip().upper(), _RANK["INFO"])


def normalize_threshold(value: str) -> str:
    """Normalise a user-supplied --fail-on value to a canonical severity.

    Raises ValueError if the value is not a recognised severity name so the CLI
    can reject it at parse time rather than silently doing nothing.
    """
    canon = value.strip().upper()
    if canon not in _RANK:
        raise ValueError(
            f"invalid severity '{value}'. Choose one of: "
            f"{', '.join(SEVERITY_ORDER)}"
        )
    return canon


def findings_meet_threshold(
    findings: list[dict[str, Any]], threshold: str
) -> bool:
    """True if any finding's severity is >= the threshold severity."""
    cutoff = severity_rank(threshold)
    return any(severity_rank(f.get("severity")) >= cutoff for f in findings)
