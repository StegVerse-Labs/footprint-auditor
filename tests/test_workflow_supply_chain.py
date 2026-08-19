from src.provenance.workflow_supply_chain import (
    DependencyKind,
    PinStrength,
    WorkflowSupplyChainScanner,
    summarize_dependencies,
)


def test_official_tag_is_expected_but_mutable():
    scanner = WorkflowSupplyChainScanner()
    findings = scanner.scan_text(
        "example/repo",
        ".github/workflows/test.yml",
        "steps:\n  - uses: actions/checkout@v4\n",
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.kind == DependencyKind.GITHUB_ACTION
    assert finding.expected_third_party is True
    assert finding.pin_strength == PinStrength.MUTABLE
    assert finding.finding_code == "GHA_MUTABLE_EXTERNAL_REF"
    assert finding.unresolved is True


def test_sha_pinned_action_is_immutable():
    scanner = WorkflowSupplyChainScanner()
    sha = "a" * 40
    finding = scanner.scan_text(
        "example/repo",
        ".github/workflows/test.yml",
        f"- uses: actions/checkout@{sha}\n",
    )[0]
    assert finding.pin_strength == PinStrength.IMMUTABLE
    assert finding.immutable is True
    assert finding.finding_code is None


def test_local_action_is_bound_to_repo_commit():
    scanner = WorkflowSupplyChainScanner()
    finding = scanner.scan_text(
        "example/repo",
        ".github/workflows/test.yml",
        "- uses: ./.github/actions/check\n",
    )[0]
    assert finding.kind == DependencyKind.LOCAL
    assert finding.pin_strength == PinStrength.LOCAL_COMMIT
    assert finding.unresolved is False


def test_docker_tag_is_mutable_and_digest_is_immutable():
    scanner = WorkflowSupplyChainScanner()
    findings = scanner.scan_text(
        "example/repo",
        ".github/workflows/test.yml",
        "- uses: docker://alpine:3.20\n"
        "- uses: docker://alpine@sha256:" + "b" * 64 + "\n",
    )
    assert findings[0].pin_strength == PinStrength.MUTABLE
    assert findings[0].finding_code == "GHA_MUTABLE_DOCKER_REF"
    assert findings[1].pin_strength == PinStrength.IMMUTABLE


def test_reusable_workflow_tag_is_unresolved():
    scanner = WorkflowSupplyChainScanner(expected_third_party_owners={"actions", "trusted-org"})
    finding = scanner.scan_text(
        "example/repo",
        ".github/workflows/test.yml",
        "jobs:\n  call:\n    uses: trusted-org/shared/.github/workflows/build.yml@main\n",
    )[0]
    assert finding.kind == DependencyKind.REUSABLE_WORKFLOW
    assert finding.expected_third_party is True
    assert finding.pin_strength == PinStrength.MUTABLE


def test_dynamic_reference_fails_closed():
    scanner = WorkflowSupplyChainScanner()
    finding = scanner.scan_text(
        "example/repo",
        ".github/workflows/test.yml",
        "- uses: owner/action@${{ inputs.ref }}\n",
    )[0]
    assert finding.pin_strength == PinStrength.DYNAMIC
    assert finding.unresolved is True
    assert finding.severity == "HIGH"


def test_summary_counts_provenance_coverage():
    scanner = WorkflowSupplyChainScanner()
    sha = "c" * 40
    findings = scanner.scan_text(
        "example/repo",
        ".github/workflows/test.yml",
        "- uses: actions/checkout@v4\n"
        f"- uses: actions/setup-python@{sha}\n"
        "- uses: ./.github/actions/local\n",
    )
    summary = summarize_dependencies(findings)
    assert summary["dependencies"] == 3
    assert summary["immutable"] == 2
    assert summary["mutable"] == 1
    assert summary["unresolved"] == 1
    assert summary["coverage_ratio"] == 2 / 3
