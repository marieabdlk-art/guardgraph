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
    evidence_strength: str = "PARTIAL"
    review_required: bool = True
    exploit_confirmed: bool = False

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if not data.get("title"):
            data["title"] = title_for_metric(self.metric)
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
    }.get(metric, metric.replace("_", " ").title())
