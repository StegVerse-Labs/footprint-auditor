from src.provenance.workflow_dependencies import classify_reference, parse_uses_references, scan_workflow, summarize


def test_mutable_major_tag_is_provenance_gap():
    dep, rev, classification, reason = classify_reference("actions/checkout@v4")
    assert dep == "actions/checkout"
    assert rev == "v4"
    assert classification == "PROVENANCE_GAP"
    assert "mutable" in reason


def test_full_commit_sha_is_immutable_reference():
    sha = "a" * 40
    dep, rev, classification, _ = classify_reference(f"actions/checkout@{sha}")
    assert dep == "actions/checkout"
    assert rev == sha
    assert classification == "AUTHORIZED_EXPECTED"


def test_reference_without_revision_fails_closed():
    _, _, classification, _ = classify_reference("owner/action")
    assert classification == "PROVENANCE_GAP"


def test_parse_and_scan_multiple_uses():
    text = """
steps:
  - uses: actions/checkout@v4
  - uses: owner/action@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  - uses: ./local-action
"""
    assert parse_uses_references(text) == [
        "actions/checkout@v4",
        "owner/action@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "./local-action",
    ]
    findings = scan_workflow("org/repo", ".github/workflows/x.yml", text)
    assert [f.classification for f in findings] == [
        "PROVENANCE_GAP",
        "AUTHORIZED_EXPECTED",
        "AUTHORIZED_EXPECTED",
    ]
    assert findings[0].expected_third_party is True
    assert findings[1].immutable is True
    assert findings[2].dependency_kind == "LOCAL"


def test_docker_tag_is_gap_and_digest_is_immutable():
    tag = scan_workflow("org/repo", ".github/workflows/x.yml", "- uses: docker://alpine:3.20\n")[0]
    digest = scan_workflow(
        "org/repo", ".github/workflows/x.yml",
        "- uses: docker://alpine@sha256:" + ("b" * 64) + "\n",
    )[0]
    assert tag.classification == "PROVENANCE_GAP"
    assert tag.immutable is False
    assert digest.classification == "AUTHORIZED_EXPECTED"
    assert digest.immutable is True


def test_dynamic_uses_reference_fails_closed():
    finding = scan_workflow(
        "org/repo", ".github/workflows/x.yml",
        "- uses: owner/action@${{ inputs.ref }}\n",
    )[0]
    assert finding.classification == "PROVENANCE_GAP"
    assert finding.dependency_kind == "DYNAMIC"


def test_summary_is_deterministic_and_counts_gaps():
    findings = scan_workflow(
        "org/repo",
        ".github/workflows/x.yml",
        "- uses: actions/checkout@v4\n- uses: actions/setup-python@" + ("c" * 40),
    )
    first = summarize(findings)
    second = summarize(reversed(findings))
    assert first["evidence_digest_sha256"] == second["evidence_digest_sha256"]
    assert first["classification_counts"]["PROVENANCE_GAP"] == 1
    assert first["immutable_dependencies"] == 1
    assert first["unresolved_dependencies"] == 1
    assert first["coverage_ratio"] == 0.5
