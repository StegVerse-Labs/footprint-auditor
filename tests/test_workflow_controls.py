from src.provenance.workflow_controls import WorkflowControlScanner


def _codes(findings):
    return [finding.finding_code for finding in findings]


def test_detects_high_write_authority():
    scanner = WorkflowControlScanner()
    findings = scanner.scan_text(
        "example/repo",
        ".github/workflows/test.yml",
        "permissions:\n  contents: write\n  id-token: write\n",
    )
    assert _codes(findings).count("GHA_WRITE_AUTHORITY") == 2
    assert all(f.severity == "CRITICAL" for f in findings)


def test_tv_and_tvc_secret_names_are_allowed_but_generic_pat_is_not():
    scanner = WorkflowControlScanner()
    findings = scanner.scan_text(
        "example/repo",
        ".github/workflows/test.yml",
        "env:\n"
        "  A: ${{ secrets.TV_SIGNING_KEY }}\n"
        "  B: ${{ secrets.TVC_PROVIDER_TOKEN }}\n"
        "  C: ${{ secrets.PAT_WORKFLOW }}\n"
        "  D: ${{ secrets.GITHUB_TOKEN }}\n",
    )
    assert _codes(findings) == ["GHA_NON_TV_TVC_SECRET_REFERENCE"]
    assert "PAT_WORKFLOW" in findings[0].evidence


def test_detects_global_git_token_rewrite_without_exposing_value():
    scanner = WorkflowControlScanner()
    findings = scanner.scan_text(
        "example/repo",
        ".github/workflows/test.yml",
        'git config --global url."https://x-access-token:${TOKEN}@github.com/".insteadOf "https://github.com/"\n',
    )
    assert _codes(findings) == ["GHA_GLOBAL_GIT_TOKEN_REWRITE"]
    assert "${TOKEN}" not in findings[0].evidence


def test_detects_key_material_persistence_patterns():
    scanner = WorkflowControlScanner()
    findings = scanner.scan_text(
        "example/repo",
        ".github/workflows/test.yml",
        'meta_data["fernet_key"] = new_key\nstatus_obj = {"key": key}\n',
    )
    assert _codes(findings).count("GHA_KEY_MATERIAL_PERSISTENCE_PATTERN") == 2
    assert all("new_key" not in f.evidence and '"key": key' not in f.evidence for f in findings)


def test_detects_unpinned_direct_pip_install_but_not_exact_pin():
    scanner = WorkflowControlScanner()
    findings = scanner.scan_text(
        "example/repo",
        ".github/workflows/test.yml",
        "pip install cryptography requests\n"
        "pip install pyyaml==6.0.2\n"
        "pip install -r requirements.txt\n",
    )
    assert _codes(findings).count("GHA_MUTABLE_PACKAGE_INSTALL") == 1


def test_detects_remote_fetch():
    scanner = WorkflowControlScanner()
    findings = scanner.scan_text(
        "example/repo",
        ".github/workflows/test.yml",
        'curl -sL -o /usr/local/bin/tool "https://example.invalid/tool"\n',
    )
    assert _codes(findings) == ["GHA_REMOTE_EXECUTABLE_FETCH"]


def test_detects_status_file_copied_to_summary():
    scanner = WorkflowControlScanner()
    findings = scanner.scan_text(
        "example/repo",
        ".github/workflows/test.yml",
        'cat ".github/token_vault/SCW.bootstrap.status.json" >> "$GITHUB_STEP_SUMMARY"\n',
    )
    assert "GHA_STATUS_OBJECT_TO_STEP_SUMMARY" in _codes(findings)
