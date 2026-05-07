from __future__ import annotations

from pathlib import Path
from typing import Any


_LEVEL_TO_SECURITY_SEVERITY = {
    "CRITICAL": "9.0",
    "HIGH": "7.0",
    "MEDIUM": "5.0",
    "LOW": "3.0",
    "INFO": "1.0",
}

_LEVEL_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

_METRIC_TITLE = {
    "PUBLIC_MUTATION": "Unguarded State Change",
    "MISSING_OWNERSHIP_BOUNDARY": "Missing Ownership Boundary",
    "RAW_INPUT_TO_SINK": "Raw Input to Sensitive Sink",
    "CRITICAL_ACTION_WEAK_ZONE": "Critical Action Without Guard",
    "PUBLIC_ACTION_UNVALIDATED": "Unvalidated Public Entry",
}


def render_sarif_report(report: dict[str, Any]) -> dict[str, Any]:
    """Render GuardGraph findings as SARIF 2.1.0.

    GuardGraph findings are structural review items rather than confirmed
    exploits, so each result includes review metadata and the original evidence.
    """
    findings = report.get("findings", [])
    rules = _build_rules(findings)
    results = [_finding_to_result(finding) for finding in findings]

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "GuardGraph",
                        "informationUri": "https://github.com/marieabdlk-art/guardgraph",
                        "semanticVersion": str(report.get("meta", {}).get("version", "0.0.0")),
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _build_rules(findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for finding in findings:
        metric = finding.get("metric", "UNKNOWN")
        if metric in rules:
            continue
        title = finding.get("title") or _METRIC_TITLE.get(metric, metric.replace("_", " ").title())
        level = finding.get("risk_level", "MEDIUM")
        rules[metric] = {
            "id": metric,
            "name": title,
            "shortDescription": {"text": title},
            "fullDescription": {"text": finding.get("summary", title)},
            "help": {"text": finding.get("recommendation", "Review this structural risk zone.")},
            "properties": {
                "tags": ["security", "structural-appsec", "guardgraph"],
                "security-severity": _LEVEL_TO_SECURITY_SEVERITY.get(level, "5.0"),
                "precision": "medium",
            },
        }
    return rules


def _finding_to_result(finding: dict[str, Any]) -> dict[str, Any]:
    endpoint = finding.get("endpoint", {})
    file_path = endpoint.get("file", "unknown")
    line = int(endpoint.get("line") or 1)
    metric = finding.get("metric", "UNKNOWN")
    title = finding.get("title") or _METRIC_TITLE.get(metric, metric.replace("_", " ").title())
    flow = " → ".join(finding.get("flow", []))
    missing = ", ".join(finding.get("missing_obligations", [])) or "none"

    message = (
        f"{title}: {finding.get('summary', '')} "
        f"Missing obligations: {missing}. "
        f"Observed flow: {flow or 'not available'}."
    ).strip()

    return {
        "ruleId": metric,
        "ruleIndex": 0,
        "level": _LEVEL_TO_SARIF_LEVEL.get(finding.get("risk_level", "MEDIUM"), "warning"),
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _normalize_uri(file_path)},
                    "region": {"startLine": max(line, 1)},
                }
            }
        ],
        "properties": {
            "guardgraph_id": finding.get("id"),
            "risk_level": finding.get("risk_level"),
            "risk_score": finding.get("risk_score"),
            "confidence": finding.get("confidence"),
            "evidence_strength": finding.get("evidence_strength", "PARTIAL"),
            "review_required": finding.get("review_required", True),
            "exploit_confirmed": finding.get("exploit_confirmed", False),
            "action_class": finding.get("action_class"),
            "display_name": finding.get("name"),
            "missing_obligations": finding.get("missing_obligations", []),
        },
    }


def _normalize_uri(path: str) -> str:
    return str(Path(path).as_posix())
