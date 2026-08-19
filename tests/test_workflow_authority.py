from src.provenance.workflow_authority import scan_workflow_authority


def types(text: str):
    return [f.finding_type for f in scan_workflow_authority("org/repo", ".github/workflows/x.yml", text)]


def test_detects_write_permission_and_direct_push():
    text = """
on:
  workflow_dispatch:
permissions:
  contents: write
jobs:
  x:
    steps:
      - run: |
          git push
"""
    result = types(text)
    assert "WRITE_PERMISSION" in result
    assert "DIRECT_GIT_PUSH" in result
    assert "MANUAL_TRIGGER_WITH_ELEVATED_PATH" in result


def test_detects_mutable_reusable_workflow_reference():
    result = scan_workflow_authority(
        "org/repo", ".github/workflows/x.yml",
        "jobs:\n  call:\n    uses: SomeOrg/SomeRepo/.github/workflows/reuse.yml@main\n",
    )
    assert result[0].finding_type == "MUTABLE_REUSABLE_WORKFLOW_OR_ACTION"
    assert result[0].classification == "PROVENANCE_GAP"


def test_clean_sha_pinned_read_only_workflow_has_no_authority_findings():
    text = """
permissions:
  contents: read
jobs:
  x:
    steps:
      - uses: owner/action@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
"""
    assert scan_workflow_authority("org/repo", ".github/workflows/x.yml", text) == []


def test_non_tv_tvc_secret_name_is_flagged_without_reading_value():
    result = scan_workflow_authority(
        "org/repo", ".github/workflows/x.yml",
        "env:\n  A: ${{ secrets.TV_SIGNING_KEY }}\n  B: ${{ secrets.PAT_WORKFLOW }}\n  C: ${{ secrets.GITHUB_TOKEN }}\n",
    )
    rows = [f for f in result if f.finding_type == "NON_TV_TVC_SECRET_REFERENCE"]
    assert len(rows) == 1
    assert "PAT_WORKFLOW" in rows[0].evidence
    assert "VALUE_NOT_READ" in rows[0].evidence


def test_global_token_rewrite_and_key_persistence_are_critical():
    text = """
git config --global url.\"https://x-access-token:${TOKEN}@github.com/\".insteadOf \"https://github.com/\"
meta_data[\"fernet_key\"] = new_key
"""
    result = scan_workflow_authority("org/repo", ".github/workflows/x.yml", text)
    lookup = {f.finding_type: f for f in result}
    assert lookup["GLOBAL_GIT_TOKEN_REWRITE"].severity == "CRITICAL"
    assert lookup["KEY_MATERIAL_PERSISTENCE_PATTERN"].severity == "CRITICAL"
    assert "new_key" not in lookup["KEY_MATERIAL_PERSISTENCE_PATTERN"].evidence


def test_unpinned_direct_package_and_remote_fetch_are_provenance_gaps():
    text = """
pip install cryptography requests
pip install pyyaml==6.0.2
curl -sL -o /usr/local/bin/tool https://example.invalid/tool
"""
    result = scan_workflow_authority("org/repo", ".github/workflows/x.yml", text)
    lookup = {f.finding_type: f for f in result}
    assert lookup["MUTABLE_PACKAGE_INSTALL"].classification == "PROVENANCE_GAP"
    assert lookup["REMOTE_EXECUTABLE_FETCH"].classification == "PROVENANCE_GAP"


def test_status_object_to_summary_is_flagged():
    result = scan_workflow_authority(
        "org/repo", ".github/workflows/x.yml",
        'cat ".github/token_vault/SCW.bootstrap.status.json" >> "$GITHUB_STEP_SUMMARY"\n',
    )
    assert any(f.finding_type == "STATUS_OBJECT_TO_STEP_SUMMARY" for f in result)
