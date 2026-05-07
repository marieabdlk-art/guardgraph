from __future__ import annotations

import ast
from dataclasses import asdict
from typing import Any

from .models import Endpoint, Finding, ObservedGuard, Operation
from .parser import FastAPIEndpointExtractor
from .utils import contains_keywords, get_call_name, has_fstring, is_resource_id_name, node_to_source


class GuardGraphAnalyzer:
    """GuardGraph MVP analyzer.

    It maps each endpoint as an application action, infers required security
    obligations, matches observed guards, and reports structural gaps.
    """

    VERSION = "0.2.0"

    def __init__(self, extractor: FastAPIEndpointExtractor):
        self.extractor = extractor
        self.endpoints = extractor.extract_endpoints()

    def analyze(self) -> dict[str, Any]:
        findings: list[Finding] = []
        for ep in self.endpoints:
            fn = self.extractor.func_index[(ep.file, ep.handler)]
            facts = self.collect_facts(ep, fn)
            ep.action_class = self.classify_action(ep, facts)
            obligations = self.infer_obligations(ep, facts)
            gaps = self.find_gaps(obligations, facts)
            findings.extend(self.build_findings(ep, facts, gaps))

        findings = sorted(findings, key=lambda f: f.risk_score, reverse=True)
        for i, finding in enumerate(findings, start=1):
            finding.id = f"GG-{i:03d}"
        return self.generate_report(findings)

    def collect_facts(self, ep: Endpoint, fn: ast.AST) -> dict[str, Any]:
        params = self.extract_params(fn)
        guards = self.detect_guards(fn, ep)
        operations = self.detect_operations(fn, ep)
        sinks = self.detect_sinks(fn, ep)
        raw_inputs = self.detect_raw_inputs(fn, ep)
        validators = self.detect_validators(fn, params)
        return {
            "params": params,
            "guards": guards,
            "auth": [g for g in guards if g.type == "AUTH_CHECK"],
            "role": [g for g in guards if g.type in {"ROLE_GATE", "ADMIN_GATE"}],
            "ownership": [g for g in guards if g.type == "OWNERSHIP_CHECK"],
            "operations": operations,
            "sinks": sinks,
            "raw_inputs": raw_inputs,
            "validators": validators,
            "user_controlled_ids": [p for p in params if is_resource_id_name(p["name"])],
        }

    def extract_params(self, fn: ast.AST) -> list[dict[str, Any]]:
        params: list[dict[str, Any]] = []
        args = list(fn.args.args)
        defaults = list(fn.args.defaults)
        default_offset = len(args) - len(defaults)
        default_by_arg = {
            args[i].arg: defaults[i - default_offset]
            for i in range(default_offset, len(args))
        }
        for arg in args:
            if arg.arg in {"self", "cls"}:
                continue
            annotation = node_to_source(arg.annotation) if arg.annotation else None
            default_src = node_to_source(default_by_arg[arg.arg]) if arg.arg in default_by_arg else None
            params.append({"name": arg.arg, "annotation": annotation, "default": default_src})
        return params

    def detect_guards(self, fn: ast.AST, ep: Endpoint) -> list[ObservedGuard]:
        guards: list[ObservedGuard] = []

        for param in self.extract_params(fn):
            text = f"{param.get('default') or ''} {param['name']} {param.get('annotation') or ''}"
            if contains_keywords(text, ["depends", "get_current_user", "current_user", "auth", "jwt", "token"]):
                guards.append(ObservedGuard("AUTH_CHECK", ep.file, ep.line, text, "HIGH"))

        for node in ast.walk(fn):
            src = node_to_source(node)
            low = src.lower()
            if isinstance(node, ast.Call):
                call_name = get_call_name(node).lower()
                if any(k in call_name for k in ["require_admin", "admin_required", "is_admin"]):
                    guards.append(ObservedGuard("ADMIN_GATE", ep.file, getattr(node, "lineno", ep.line), src, "HIGH"))
                if any(k in call_name for k in ["require_auth", "jwt_required", "login_required"]):
                    guards.append(ObservedGuard("AUTH_CHECK", ep.file, getattr(node, "lineno", ep.line), src, "HIGH"))
            if isinstance(node, ast.If):
                if contains_keywords(low, ["current_user.role", ".role", "is_admin", "is_superuser"]):
                    guards.append(ObservedGuard("ROLE_GATE", ep.file, node.lineno, src, "HIGH"))
                if contains_keywords(low, ["user_id", "owner_id", "author_id", "tenant_id"]) and contains_keywords(low, ["current_user.id", "user.id"]):
                    guards.append(ObservedGuard("OWNERSHIP_CHECK", ep.file, node.lineno, src, "HIGH"))
        return guards

    def detect_validators(self, fn: ast.AST, params: list[dict[str, Any]]) -> list[ObservedGuard]:
        validators: list[ObservedGuard] = []
        for param in params:
            annotation = param.get("annotation") or ""
            if annotation in self.extractor.pydantic_models:
                validators.append(ObservedGuard("PYDANTIC_VALIDATION", "<signature>", getattr(fn, "lineno", 0), f"{param['name']}: {annotation}", "HIGH"))
            elif annotation in {"int", "str", "float", "bool"}:
                validators.append(ObservedGuard("TYPE_VALIDATION", "<signature>", getattr(fn, "lineno", 0), f"{param['name']}: {annotation}", "MEDIUM"))
        return validators

    def detect_operations(self, fn: ast.AST, ep: Endpoint) -> list[Operation]:
        ops: list[Operation] = []
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            name = get_call_name(node)
            low = name.lower()
            src = node_to_source(node)
            line = getattr(node, "lineno", ep.line)
            if any(k in low for k in ["charge", "refund", "payment"]):
                ops.append(Operation("PAYMENT_OP", name, ep.file, line, src, 1.0))
            elif any(k in low for k in ["delete", "remove", "destroy"]):
                ops.append(Operation("DELETE_OP", name, ep.file, line, src, 1.0))
            elif any(k in low for k in ["update", "insert", "create", "save", "add", "execute"]):
                if node.args:
                    arg_src = " ".join(node_to_source(a).lower() for a in node.args[:1])
                    if any(sql in arg_src for sql in ["update ", "insert ", "delete ", "create "]):
                        ops.append(Operation("WRITE_OP", name, ep.file, line, src, 0.8))
                    elif "select " in arg_src:
                        ops.append(Operation("READ_OP", name, ep.file, line, src, 0.3))
        return ops

    def detect_sinks(self, fn: ast.AST, ep: Endpoint) -> list[Operation]:
        sinks: list[Operation] = []
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            name = get_call_name(node)
            low = name.lower()
            src = node_to_source(node)
            line = getattr(node, "lineno", ep.line)
            if low.endswith("execute"):
                danger = 1.0 if has_fstring(node) or "+" in src else 0.35
                kind = "RAW_SQL" if danger >= 0.8 else "PARAMETERIZED_SQL_OR_ORM"
                sinks.append(Operation(kind, name, ep.file, line, src, danger))
            if any(k in low for k in ["open", "write", "eval", "exec", "subprocess", "os.system"]):
                sinks.append(Operation("DANGEROUS_SINK", name, ep.file, line, src, 1.0))
        return sinks

    def detect_raw_inputs(self, fn: ast.AST, ep: Endpoint) -> list[dict[str, Any]]:
        raw: list[dict[str, Any]] = []
        for node in ast.walk(fn):
            src = node_to_source(node)
            if contains_keywords(src, ["request.json", "request.body", "request.query", "request.headers", "request.form"]):
                raw.append({"file": ep.file, "line": getattr(node, "lineno", ep.line), "evidence": src})
        return raw

    def classify_action(self, ep: Endpoint, facts: dict[str, Any]) -> str:
        path_low = ep.full_path.lower()
        handler_low = ep.handler.lower()
        text = f"{path_low} {handler_low}"
        op_types = {op.type for op in facts["operations"]}

        if ep.method == "POST" and any(k in text for k in ["signup", "sign_up", "register", "registration", "create_user", "/api/users/"]):
            return "USER_REGISTRATION_ACTION"
        if any(k in text for k in ["login", "signin", "sign_in", "token"]):
            return "AUTH_SESSION_ACTION"
        if any(k in text for k in ["password-reset", "password_reset", "forgot-password", "forgot_password", "reset"]):
            return "PASSWORD_RESET_ACTION"
        if any(k in text for k in ["contact", "feedback", "lead"]):
            return "PUBLIC_CONTACT_ACTION"

        if "PAYMENT_OP" in op_types or any(k in path_low for k in ["pay", "payment", "refund", "charge"]):
            return "PAYMENT_ACTION"
        if any(k in path_low for k in ["admin", "settings"]):
            return "ADMIN_ACTION"
        if ep.method == "DELETE" or "DELETE_OP" in op_types:
            return "DESTRUCTIVE_ACTION"
        if ep.method in {"POST", "PUT", "PATCH"} or "WRITE_OP" in op_types:
            return "USER_RESOURCE_MUTATION" if facts["user_controlled_ids"] else "STATE_MUTATION"
        if facts["user_controlled_ids"]:
            return "USER_RESOURCE_READ"
        return "PUBLIC_READ"

    def infer_obligations(self, ep: Endpoint, facts: dict[str, Any]) -> list[str]:
        action = ep.action_class or self.classify_action(ep, facts)
        obligations: list[str] = []

        if action in {"USER_REGISTRATION_ACTION", "AUTH_SESSION_ACTION", "PASSWORD_RESET_ACTION", "PUBLIC_CONTACT_ACTION"}:
            obligations.append("VALIDATION_REQUIRED")
            obligations.append("ABUSE_PROTECTION_RECOMMENDED")
            if action in {"AUTH_SESSION_ACTION", "PASSWORD_RESET_ACTION"}:
                obligations.append("RATE_LIMIT_RECOMMENDED")
            return obligations

        if action in {"USER_RESOURCE_READ", "USER_RESOURCE_MUTATION", "DESTRUCTIVE_ACTION", "PAYMENT_ACTION", "ADMIN_ACTION", "STATE_MUTATION"}:
            obligations.append("AUTH_REQUIRED")
        if action in {"USER_RESOURCE_READ", "USER_RESOURCE_MUTATION"}:
            obligations.append("OWNERSHIP_REQUIRED")
        if action in {"USER_RESOURCE_MUTATION", "STATE_MUTATION", "PAYMENT_ACTION", "ADMIN_ACTION"}:
            obligations.append("VALIDATION_REQUIRED")
        if action in {"PAYMENT_ACTION", "ADMIN_ACTION"}:
            obligations.append("ROLE_OR_PERMISSION_REQUIRED")
        if action == "DESTRUCTIVE_ACTION":
            obligations.append("ROLE_OR_OWNERSHIP_REQUIRED")
        if any(s.type == "RAW_SQL" and s.danger >= 0.8 for s in facts["sinks"]):
            obligations.append("SAFE_SINK_REQUIRED")
        return obligations

    def find_gaps(self, obligations: list[str], facts: dict[str, Any]) -> list[str]:
        gaps: list[str] = []
        if "AUTH_REQUIRED" in obligations and not facts["auth"]:
            gaps.append("AUTH_REQUIRED")
        if "OWNERSHIP_REQUIRED" in obligations and not facts["ownership"]:
            gaps.append("OWNERSHIP_REQUIRED")
        if "VALIDATION_REQUIRED" in obligations and not facts["validators"]:
            gaps.append("VALIDATION_REQUIRED")
        if "ROLE_OR_PERMISSION_REQUIRED" in obligations and not facts["role"]:
            gaps.append("ROLE_OR_PERMISSION_REQUIRED")
        if "ROLE_OR_OWNERSHIP_REQUIRED" in obligations and not (facts["role"] or facts["ownership"]):
            gaps.append("ROLE_OR_OWNERSHIP_REQUIRED")
        if "SAFE_SINK_REQUIRED" in obligations and any(s.type == "RAW_SQL" and s.danger >= 0.8 for s in facts["sinks"]) and not facts["validators"]:
            gaps.append("SAFE_SINK_REQUIRED")
        return gaps

    def build_findings(self, ep: Endpoint, facts: dict[str, Any], gaps: list[str]) -> list[Finding]:
        out: list[Finding] = []
        legit_public_actions = {"USER_REGISTRATION_ACTION", "AUTH_SESSION_ACTION", "PASSWORD_RESET_ACTION", "PUBLIC_CONTACT_ACTION"}

        if (
            ep.action_class not in legit_public_actions
            and ep.action_class not in {"PAYMENT_ACTION", "ADMIN_ACTION"}
            and "AUTH_REQUIRED" in gaps
            and any(op.type in {"WRITE_OP", "DELETE_OP", "PAYMENT_OP"} for op in facts["operations"])
        ):
            out.append(self.make_finding(ep, facts, "PUBLIC_MUTATION", "Слепой переход", "CRITICAL", 0.90, "Endpoint performs a state-changing operation without a visible authentication boundary.", ["AUTH_REQUIRED"]))

        if "OWNERSHIP_REQUIRED" in gaps:
            out.append(self.make_finding(ep, facts, "MISSING_OWNERSHIP_BOUNDARY", "Чужой паспорт", "HIGH", 0.82, "Endpoint uses a user-controlled resource identifier without a visible ownership boundary.", ["OWNERSHIP_REQUIRED"]))

        if "SAFE_SINK_REQUIRED" in gaps:
            out.append(self.make_finding(ep, facts, "RAW_INPUT_TO_SINK", "Голый провод", "HIGH", 0.78, "User-controlled input reaches a raw SQL or sensitive sink without visible safe handling.", ["SAFE_SINK_REQUIRED"]))

        if ep.action_class in {"PAYMENT_ACTION", "ADMIN_ACTION"} and ("AUTH_REQUIRED" in gaps or "ROLE_OR_PERMISSION_REQUIRED" in gaps):
            level = "CRITICAL" if "AUTH_REQUIRED" in gaps else "HIGH"
            score = 0.95 if level == "CRITICAL" else 0.74
            out.append(self.make_finding(ep, facts, "CRITICAL_ACTION_WEAK_ZONE", "Кнопка без крышки", level, score, "Critical payment/admin action is reachable without a visible strong permission boundary.", [g for g in ["AUTH_REQUIRED", "ROLE_OR_PERMISSION_REQUIRED"] if g in gaps]))

        if ep.action_class in legit_public_actions and "VALIDATION_REQUIRED" in gaps:
            out.append(self.make_finding(ep, facts, "PUBLIC_ACTION_UNVALIDATED", "Открытая форма", "MEDIUM", 0.42, "Public action is intentionally unauthenticated, but no visible input validation was detected.", ["VALIDATION_REQUIRED"]))

        return out

    def make_finding(self, ep: Endpoint, facts: dict[str, Any], metric: str, name: str, level: str, score: float, summary: str, missing: list[str]) -> Finding:
        confidence = "HIGH" if "AUTH_REQUIRED" in missing and not facts["auth"] else "MEDIUM"
        return Finding(
            id="",
            metric=metric,
            name=name,
            risk_level=level,
            risk_score=score,
            confidence=confidence,
            endpoint_id=ep.id,
            endpoint={"method": ep.method, "path": ep.full_path, "handler": ep.handler, "file": ep.file, "line": ep.line},
            action_class=ep.action_class,
            summary=summary,
            evidence={
                "params": facts["params"],
                "observed_guards": [asdict(g) for g in facts["guards"]],
                "validators": [asdict(v) for v in facts["validators"]],
                "operations": [asdict(o) for o in facts["operations"]],
                "sinks": [asdict(s) for s in facts["sinks"]],
                "raw_inputs": facts["raw_inputs"],
            },
            flow=self.format_flow(ep, facts),
            missing_obligations=missing,
            recommendation=self.recommendation(metric),
        )

    def format_flow(self, ep: Endpoint, facts: dict[str, Any]) -> list[str]:
        flow = [f"{ep.method} {ep.full_path}", ep.handler]
        if facts["user_controlled_ids"]:
            flow.extend(p["name"] for p in facts["user_controlled_ids"])
        if facts["operations"]:
            flow.append(facts["operations"][0].name)
        elif facts["sinks"]:
            flow.append(facts["sinks"][0].name)
        return flow

    def recommendation(self, metric: str) -> str:
        return {
            "PUBLIC_MUTATION": "Add an authentication boundary before state-changing operations.",
            "MISSING_OWNERSHIP_BOUNDARY": "Verify that the resource belongs to the authenticated user before read or mutation.",
            "RAW_INPUT_TO_SINK": "Use schema validation and safe parameterized APIs instead of raw string-built queries.",
            "CRITICAL_ACTION_WEAK_ZONE": "Require authentication and explicit role/permission checks for payment/admin/destructive actions.",
            "PUBLIC_ACTION_UNVALIDATED": "Add schema validation and abuse protection for this public endpoint.",
        }.get(metric, "Review the missing security obligation.")

    def generate_report(self, findings: list[Finding]) -> dict[str, Any]:
        dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in findings:
            dist[finding.risk_level] += 1
        return {
            "meta": {
                "tool": "guardgraph",
                "version": self.VERSION,
                "mode": "threefold-structural-gap-analysis-with-business-action-classification",
                "target": {"language": "python", "framework": "fastapi", "entry_path": str(self.extractor.root)},
                "statistics": {"endpoints_found": len(self.endpoints), "structural_gaps_found": len(findings), "risk_distribution": dist},
            },
            "endpoints": [asdict(ep) for ep in self.endpoints],
            "findings": [finding.to_dict() for finding in findings],
            "summary": {
                "top_risks": [finding.id for finding in findings[:5]],
                "architectural_recommendation": "Add centralized auth, ownership checks for user-owned resources, and safe validated data access patterns.",
            },
        }
