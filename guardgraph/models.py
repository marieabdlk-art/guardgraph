from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Endpoint:
    id: str
    method: str
    path: str
    full_path: str
    file: str
    line: int
    handler: str
    prefix: str = ""
    action_class: str = ""


@dataclass
class ObservedGuard:
    type: str
    file: str
    line: int
    evidence: str
    confidence: str = "MEDIUM"


@dataclass
class Operation:
    type: str
    name: str
    file: str
    line: int
    evidence: str
    danger: float = 0.5


@dataclass
class Finding:
    id: str
    metric: str
    name: str
    risk_level: str
    risk_score: float
    confidence: str
    endpoint_id: str
    endpoint: dict[str, Any]
    action_class: str
    summary: str
    evidence: dict[str, Any]
    flow: list[str]
    missing_obligations: list[str]
    recommendation: str
    title: str = ""
    owasp_category: str = ""
    cwe: list[str] = field(default_factory=list)
    evidence_strength: str = "PARTIAL"
    review_required: bool = True
    exploit_confirmed: bool = False

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if not data.get("title"):
            data["title"] = title_for_metric(self.metric)
        if not data.get("owasp_category"):
            data["owasp_category"] = owasp_for_metric(self.metric)
        if not data.get("cwe"):
            data["cwe"] = cwe_for_metric(self.metric)
        return data


@dataclass
class AnalysisReport:
    meta: dict[str, Any]
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)


def title_for_metric(metric: str) -> str:
    return {
        "PUBLIC_MUTATION": "Unguarded State Change",
        "MISSING_OWNERSHIP_BOUNDARY": "Missing Ownership Boundary",
        "RAW_INPUT_TO_SINK": "Raw Input to Sensitive Sink",
        "CRITICAL_ACTION_WEAK_ZONE": "Critical Action Without Guard",
        "PUBLIC_ACTION_UNVALIDATED": "Unvalidated Public Entry",
        "UNRESTRICTED_UPLOAD_BOUNDARY": "Unsafe Upload Boundary",
    }.get(metric, metric.replace("_", " ").title())


def owasp_for_metric(metric: str) -> str:
    return {
        "PUBLIC_MUTATION": "A01:2021-Broken Access Control",
        "MISSING_OWNERSHIP_BOUNDARY": "A01:2021-Broken Access Control",
        "RAW_INPUT_TO_SINK": "A03:2021-Injection",
        "CRITICAL_ACTION_WEAK_ZONE": "A01:2021-Broken Access Control",
        "PUBLIC_ACTION_UNVALIDATED": "A04:2021-Insecure Design",
        "UNRESTRICTED_UPLOAD_BOUNDARY": "A01:2021-Broken Access Control",
    }.get(metric, "A04:2021-Insecure Design")


def cwe_for_metric(metric: str) -> list[str]:
    return {
        "PUBLIC_MUTATION": ["CWE-862", "CWE-306"],
        "MISSING_OWNERSHIP_BOUNDARY": ["CWE-639", "CWE-862"],
        "RAW_INPUT_TO_SINK": ["CWE-89", "CWE-20"],
        "CRITICAL_ACTION_WEAK_ZONE": ["CWE-862", "CWE-732"],
        "PUBLIC_ACTION_UNVALIDATED": ["CWE-20", "CWE-770"],
        "UNRESTRICTED_UPLOAD_BOUNDARY": ["CWE-434", "CWE-284"],
    }.get(metric, ["CWE-284"])
