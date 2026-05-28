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

        engine_context = finding.get("engine_context")
        if isinstance(engine_context, dict):
            display = engine_context.get("engine_display_name") or engine_context.get(
                "engine_name", "identified engine"
            )
            confidence = engine_context.get("confidence", "")
            block += "## Engine Correlation\n"
            block += f"Identified engine: **{display}**"
            if confidence:
                block += f" (confidence: {confidence})"
            block += "\n\n"
            note = engine_context.get("note")
            if note:
                block += f"{note}\n\n"
            matched = engine_context.get("matched_behaviors") or []
            for behavior in matched:
                block += f"- {behavior}\n"
            if matched:
                block += "\n"

        block += "## Recommended Mitigation\n"
        block += f"{remediation}\n"

        sections.append(block)

    return "\n---\n\n".join(sections)
