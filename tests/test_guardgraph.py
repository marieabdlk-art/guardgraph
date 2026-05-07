from pathlib import Path

from guardgraph.cli import analyze_path

ROOT = Path(__file__).parent / "test_app"


def metrics(report):
    return {finding["metric"] for finding in report["findings"]}


def test_guardgraph_detects_core_structural_gaps():
    report = analyze_path(ROOT)
    found = metrics(report)
    assert "CRITICAL_ACTION_WEAK_ZONE" in found
    assert "PUBLIC_MUTATION" in found
    assert "MISSING_OWNERSHIP_BOUNDARY" in found
    assert "RAW_INPUT_TO_SINK" in found


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
    assert report["meta"]["statistics"]["endpoints_found"] >= 10
    assert isinstance(report["findings"], list)
