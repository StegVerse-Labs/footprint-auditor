import json

from src.reporter import FindingReporter


def sample_classifier_summary():
    return {
        "total": 2,
        "by_decision": {"ALLOW": 1, "DENY": 1},
        "by_severity": {"CRITICAL": 1, "LOW": 1},
        "by_invariant": {"INV-001": 1},
        "results": [
            {
                "decision": "DENY",
                "severity": "CRITICAL",
                "invariant_id": "INV-001",
                "rule_name": "no_medical_exposure",
                "remediation": "immediate_removal",
                "confidence": 0.9,
                "reasons": ["keyword matched: medical"],
            },
            {
                "decision": "ALLOW",
                "severity": "LOW",
                "invariant_id": None,
                "rule_name": None,
                "remediation": None,
                "confidence": 0.75,
                "reasons": ["no configured invariant matched"],
            },
        ],
    }


def test_build_report_summary_counts():
    report = FindingReporter("demo report").build_report(sample_classifier_summary())

    assert report.title == "demo report"
    assert report.summary["total"] == 2
    assert report.summary["deny_count"] == 1
    assert report.summary["allow_count"] == 1
    assert report.receipt["result_count"] == 2
    assert report.receipt["deny_count"] == 1
    assert len(report.receipt["hash"]) == 64


def test_markdown_contains_findings_and_receipt():
    reporter = FindingReporter("demo report")
    report = reporter.build_report(sample_classifier_summary())
    markdown = reporter.to_markdown(report)

    assert "# demo report" in markdown
    assert "Finding 1" in markdown
    assert "INV-001" in markdown
    assert "Receipt hash" in markdown


def test_write_report_outputs_json_markdown_and_receipt(tmp_path):
    reporter = FindingReporter("demo report")
    report = reporter.write_report(
        sample_classifier_summary(),
        reports_dir=tmp_path / "reports",
        receipts_dir=tmp_path / "receipts",
    )

    md_path = tmp_path / "reports" / "footprint_audit_report.md"
    json_path = tmp_path / "reports" / "footprint_audit_report.json"
    receipts_path = tmp_path / "receipts" / "footprint_audit_receipts.jsonl"

    assert md_path.exists()
    assert json_path.exists()
    assert receipts_path.exists()

    parsed = json.loads(json_path.read_text(encoding="utf-8"))
    assert parsed["summary"]["deny_count"] == 1

    receipt_line = receipts_path.read_text(encoding="utf-8").strip()
    assert report.receipt["hash"] in receipt_line
