"""Output rendering: JSON and H1-markdown."""
from __future__ import annotations

import json
from typing import Any


def render_json(findings: list[dict[str, Any]]) -> str:
    """Render findings as JSON."""
    return json.dumps(findings, indent=2)


def render_h1md(findings: list[dict[str, Any]]) -> str:
    """Render findings as HackerOne-style markdown."""
    if not findings:
        return "No findings.\n"

    sections: list[str] = []

    for finding in findings:
        severity = finding.get("severity", "INFO")
        title = finding.get("title", "Untitled Finding")
        description = finding.get("description", "")
        reproduction = finding.get("reproduction", "")
        impact = finding.get("impact", "")
        evidence = finding.get("evidence", "")
        remediation = finding.get("remediation", "")

        block = f"# [{severity}] {title}\n\n"
        block += "## Summary\n"
        block += f"{description}\n\n"
        block += "## Steps to Reproduce\n"
        block += f"{reproduction}\n\n"
        block += "## Impact\n"
        block += f"{impact}\n\n"
        block += "## Proof of Concept\n"
        block += f"{evidence}\n\n"
        block += "## Recommended Mitigation\n"
        block += f"{remediation}\n"

        sections.append(block)

    return "\n---\n\n".join(sections)
