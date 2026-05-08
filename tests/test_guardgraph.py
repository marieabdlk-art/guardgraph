import json
from pathlib import Path

from guardgraph.cli import analyze_path, run_with_config, _write_reports
from guardgraph.config import load_config

ROOT = Path(__file__).parent / "test_app"
FIXTURES = Path(__file__).resolve().parents[1] / "benchmarks" / "fixtures"
DI_APP = Path(__file__).resolve().parents[1] / "benchmarks" / "fastapi_di_app"


def metrics(report):
    return {finding["metric"] for finding in report["findings"]}


def handlers_by_metric(report, metric):
    return {finding["endpoint"]["handler"] for finding in report["findings"] if finding["metric"] == metric}


def test_guardgraph_detects_core_structural_gaps():
    report = analyze_path(ROOT)
    found = metrics(report)
    assert "CRITICAL_ACTION_WEAK_ZONE" in found
    assert "PUBLIC_MUTATION" in found
    assert "MISSING_OWNERSHIP_BOUNDARY" in found
    assert "RAW_INPUT_TO_SINK" in found


def test_fastapi_dependency_injection_benchmark_auth_boundaries():
    report = analyze_path(DI_APP)
    public_mutation_handlers = handlers_by_metric(report, "PUBLIC_MUTATION")

    assert "delete_item_without_dependency" in public_mutation_handlers
    assert "delete_item_direct" not in public_mutation_handlers
    assert "delete_item_router_level" not in public_mutation_handlers
    assert "delete_item_route_level" not in public_mutation_handlers
    assert "delete_item_annotated" not in public_mutation_handlers
    assert "delete_admin_item" not in public_mutation_handlers


def test_fastapi_dependency_injection_benchmark_public_action_is_not_auth_required():
    report = analyze_path(DI_APP)
    flagged_handlers = {finding["endpoint"]["handler"] for finding in report["findings"]}
    assert "register" not in flagged_handlers


def test_guardgraph_detects_unsafe_upload_boundary_fixture():
    report = analyze_path(FIXTURES)
    found = metrics(report)
    assert "UNRESTRICTED_UPLOAD_BOUNDARY" in found

    finding = next(f for f in report["findings"] if f["metric"] == "UNRESTRICTED_UPLOAD_BOUNDARY")
    assert finding["title"] == "Unsafe Upload Boundary"
    assert finding["owasp_category"] == "A01:2021-Broken Access Control"
    assert "CWE-434" in finding["cwe"]
    assert "CWE-284" in finding["cwe"]
    assert "AUTH_REQUIRED" in finding["missing_obligations"]
    assert "ROLE_OR_PERMISSION_REQUIRED" in finding["missing_obligations"]
    assert "UPLOAD_VALIDATION_REQUIRED" in finding["missing_obligations"]


def test_registration_login_contact_are_not_reported_as_critical_auth_gaps():
    report = analyze_path(ROOT)
    handlers = {finding["endpoint"]["handler"] for finding in report["findings"]}
    assert "create_user" not in handlers
    assert "login" not in handlers
    assert "password_reset" not in handlers
    assert "send_contact" not in handlers


def test_safe_update_order_is_not_flagged():
    report = analyze_path(ROOT)
    handlers = {finding["endpoint"]["handler"] for finding in report["findings"]}
    assert "update_order" not in handlers


def test_report_shape():
    report = analyze_path(ROOT)
    assert report["meta"]["tool"] == "guardgraph"
    assert report["meta"]["version"] == "0.4.3"
    assert report["meta"]["statistics"]["endpoints_found"] >= 10
    assert isinstance(report["findings"], list)
    first = report["findings"][0]
    assert "title" in first
    assert "owasp_category" in first
    assert first["owasp_category"].startswith("A")
    assert "cwe" in first
    assert first["cwe"]
    assert first["review_required"] is True
    assert first["exploit_confirmed"] is False
    assert first["evidence_strength"] in {"STRONG", "PARTIAL"}


def test_config_mode_writes_json_and_markdown(tmp_path):
    cfg_path = tmp_path / "guardgraph.yml"
    json_path = tmp_path / "out.json"
    md_path = tmp_path / "out.md"
    cfg_path.write_text(
        f"""
        target:
          path: "{ROOT}"
          language: "python"
          framework: "fastapi"
        report:
          json: "{json_path}"
          markdown: "{md_path}"
        github:
          pr_comment: true
        """,
        encoding="utf-8",
    )

    cfg = load_config(cfg_path)
    report = run_with_config(cfg)

    assert report["meta"]["statistics"]["endpoints_found"] >= 10
    assert json_path.exists()
    assert md_path.exists()
    markdown = md_path.read_text(encoding="utf-8")
    assert "# GuardGraph Report" in markdown
    assert "**OWASP:**" in markdown
    assert "**CWE:**" in markdown


def test_sarif_output(tmp_path):
    report = analyze_path(ROOT)
    sarif_path = tmp_path / "guardgraph.sarif"
    _write_reports(report, json_path=None, markdown_path=None, sarif_path=str(sarif_path))

    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "GuardGraph"
    assert run["results"]
    first_result = run["results"][0]
    assert first_result["properties"]["review_required"] is True
    assert first_result["properties"]["owasp_category"].startswith("A")
    assert first_result["properties"]["cwe"]
    first_rule = run["tool"]["driver"]["rules"][0]
    assert first_rule["properties"]["owasp_category"].startswith("A")
    assert first_rule["properties"]["cwe"]
