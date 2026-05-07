from __future__ import annotations

from pathlib import Path
from typing import Any


_LEVEL_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_LEVEL_ICON = {
    "CRITICAL": "🚨",
    "HIGH": "⚠️",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "ℹ️",
}


def _short_path(path: str) -> str:
    parts = Path(path).parts
    if len(parts) >= 3:
        return "/".join(parts[-3:])
    return path


def _format_list(items: list[str]) -> str:
    if not items:
        return "- None"
    return "\n".join(f"- `{item}`" for item in items)


def render_markdown_report(report: dict[str, Any]) -> str:
    """Render a human-readable Markdown report from GuardGraph JSON output."""
    meta = report.get("meta", {})
    stats = meta.get("statistics", {})
    findings = report.get("findings", [])

    lines: list[str] = []
    lines.append("# GuardGraph Report")
    lines.append("")
    lines.append("Structural AppSec review for FastAPI code.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Tool:** `{meta.get('tool', 'guardgraph')}`")
    lines.append(f"- **Version:** `{meta.get('version', 'unknown')}`")
    lines.append(f"- **Mode:** `{meta.get('mode', 'unknown')}`")
    lines.append(f"- **Endpoints found:** `{stats.get('endpoints_found', 0)}`")
    lines.append(f"- **Structural gaps found:** `{stats.get('structural_gaps_found', 0)}`")
    lines.append("")

    distribution = stats.get("risk_distribution", {})
    lines.append("## Risk distribution")
    lines.append("")
    lines.append("| Level | Count |")
    lines.append("|---|---:|")
    for level in _LEVEL_ORDER:
        lines.append(f"| {_LEVEL_ICON.get(level, '')} {level} | {distribution.get(level, 0)} |")
    lines.append("")

    if not findings:
        lines.append("## Findings")
        lines.append("")
        lines.append("No structural gaps found.")
        lines.append("")
        return "\n".join(lines)

    lines.append("## Findings")
    lines.append("")

    for level in _LEVEL_ORDER:
        level_findings = [f for f in findings if f.get("risk_level") == level]
        if not level_findings:
            continue
        lines.append(f"### {_LEVEL_ICON.get(level, '')} {level}")
        lines.append("")
        for f in level_findings:
            endpoint = f.get("endpoint", {})
            method = endpoint.get("method", "?")
            path = endpoint.get("path", "?")
            handler = endpoint.get("handler", "?")
            file_path = _short_path(endpoint.get("file", "?"))
            line = endpoint.get("line", "?")
            flow = " → ".join(f.get("flow", []))
            title = f.get("title") or f.get("metric", "Finding")
            display_name = f.get("name")

            lines.append(f"#### {title}")
            lines.append("")
            if display_name and display_name != title:
                lines.append(f"_Display label:_ **{display_name}**")
                lines.append("")
            lines.append(f"`{method} {path}` in `{file_path}:{line}`")
            lines.append("")
            lines.append(f"- **Metric:** `{f.get('metric', 'unknown')}`")
            lines.append(f"- **OWASP:** `{f.get('owasp_category', 'unknown')}`")
            lines.append(f"- **CWE:** `{', '.join(f.get('cwe', [])) or 'unknown'}`")
            lines.append(f"- **Action class:** `{f.get('action_class', 'unknown')}`")
            lines.append(f"- **Confidence:** `{f.get('confidence', 'unknown')}`")
            lines.append(f"- **Evidence strength:** `{f.get('evidence_strength', 'PARTIAL')}`")
            lines.append(f"- **Risk score:** `{f.get('risk_score', 'unknown')}`")
            lines.append(f"- **Review required:** `{str(f.get('review_required', True)).lower()}`")
            lines.append(f"- **Exploit confirmed:** `{str(f.get('exploit_confirmed', False)).lower()}`")
            lines.append(f"- **Handler:** `{handler}`")
            lines.append("")
            lines.append(f.get("summary", "No summary."))
            lines.append("")
            lines.append("**Missing obligations:**")
            lines.append("")
            lines.append(_format_list(f.get("missing_obligations", [])))
            lines.append("")
            if flow:
                lines.append("**Observed flow:**")
                lines.append("")
                lines.append(f"`{flow}`")
                lines.append("")
            lines.append("**Recommendation:**")
            lines.append("")
            lines.append(f.get("recommendation", "Review this structural gap."))
            lines.append("")
            lines.append("---")
            lines.append("")

    lines.append("## Notes")
    lines.append("")
    lines.append("GuardGraph reports structural risk zones, not confirmed exploits. Each finding should be reviewed in code context.")
    lines.append("")
    return "\n".join(lines)
