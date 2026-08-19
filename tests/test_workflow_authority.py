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
    assert len(result) == 1
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
