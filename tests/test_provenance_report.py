from src.provenance.report import (
    AuditFindingSummary,
    build_audit_report,
    render_markdown,
    verify_report,
)


def _base_kwargs():
    return {
        "boundary_end": "2026-08-19T23:59:59Z",
        "repository_inventory_digest": "a" * 64,
        "repository_count": 10,
        "installation_count": 2,
        "historical_visibility_complete": True,
        "historical_identity_complete": True,
        "dependency_provenance_complete": True,
        "external_infrastructure_complete": True,
    }


def test_open_finding_prevents_clean_audit():
    finding = AuditFindingSummary(
        finding_id="F-1",
        repository="Org/Repo",
        status="PROVENANCE_GAP",
        title="missing historical actor",
        open=True,
    )
    report = build_audit_report([finding], **_base_kwargs())
    assert report["clean_audit_permitted"] is False
    assert report["finding_counts"]["open"] == 1
    assert verify_report(report)


def test_coverage_gap_prevents_clean_audit_even_without_findings():
    kwargs = _base_kwargs()
    kwargs["historical_visibility_complete"] = False
    report = build_audit_report([], **kwargs)
    assert report["clean_audit_permitted"] is False
    assert report["coverage_complete"] is False


def test_confirmed_compromise_prevents_clean_audit_even_if_marked_closed():
    finding = AuditFindingSummary(
        finding_id="F-2",
        repository="Org/Repo",
        status="AUTHORIZED_EXPECTED",
        title="historical key exposure",
        open=False,
        confirmed_compromise=True,
    )
    report = build_audit_report([finding], **_base_kwargs())
    assert report["clean_audit_permitted"] is False


def test_fully_covered_resolved_report_can_allow_bounded_conclusion():
    finding = AuditFindingSummary(
        finding_id="F-3",
        repository="Org/Repo",
        status="AUTHORIZED_EXPECTED",
        title="resolved expected change",
        open=False,
    )
    report = build_audit_report([finding], **_base_kwargs())
    assert report["clean_audit_permitted"] is True
    assert "fully audited boundary" in report["allowed_conclusion"]
    assert verify_report(report)
    markdown = render_markdown(report)
    assert "F-3" in markdown
    assert report["report_sha256"] in markdown


def test_report_digest_is_deterministic_for_same_inputs():
    findings = [
        AuditFindingSummary("B", "Z/R", "AUTHORIZED_EXPECTED", "b", False),
        AuditFindingSummary("A", "A/R", "AUTHORIZED_EXPECTED", "a", False),
    ]
    first = build_audit_report(findings, **_base_kwargs())
    second = build_audit_report(list(reversed(findings)), **_base_kwargs())
    assert first["report_sha256"] == second["report_sha256"]
