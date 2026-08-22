import json
import subprocess
from pathlib import Path

import pytest

from src.provenance.audit_runner import (
    MANIFEST_SCHEMA,
    run_audit,
    validate_manifest,
    verify_execution_receipt,
)


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        text=True,
        capture_output=True,
    )
    return completed.stdout.strip()


def _materialized_repo(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "target"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Audit Runner Test")
    _git(root, "config", "user.email", "runner@example.invalid")
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "validation.yml").write_text(
        """name: validation
on: [push]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""",
        encoding="utf-8",
    )
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "fixture")
    return root, _git(root, "rev-parse", "HEAD")


def _manifest(root: Path, sha: str):
    return {
        "schema": MANIFEST_SCHEMA,
        "repositories": [
            {
                "repository": "Fixture/Repo",
                "path": str(root),
                "expected_sha": sha,
            }
        ],
    }


def test_manifest_rejects_duplicates_and_mutable_refs(tmp_path):
    root, sha = _materialized_repo(tmp_path)
    manifest = _manifest(root, sha)
    manifest["repositories"].append(dict(manifest["repositories"][0]))
    with pytest.raises(ValueError, match="duplicate repository"):
        validate_manifest(manifest)

    mutable = _manifest(root, sha)
    mutable["repositories"][0]["expected_sha"] = "main"
    # Manifest shape is valid; immutable-ref enforcement belongs to the
    # repository executor and must fail before scanning.
    with pytest.raises(ValueError, match="40-character"):
        run_audit(
            mutable,
            findings_dir=tmp_path / "findings",
            boundary_end="2026-08-19T23:59:59Z",
            installation_count=1,
            repository_inventory_digest="a" * 64,
            observed_at="2026-08-21T23:59:00Z",
        )


def test_end_to_end_runner_executes_open_audit_without_false_failure(tmp_path):
    root, sha = _materialized_repo(tmp_path)
    findings = tmp_path / "findings"
    findings.mkdir()
    (findings / "open.json").write_text(
        json.dumps(
            {
                "finding_id": "FIXTURE-GAP-001",
                "repository": "Fixture/Repo",
                "classification": "PROVENANCE_GAP",
                "title": "Fixture historical authority gap",
                "open": True,
            }
        ),
        encoding="utf-8",
    )

    receipt = run_audit(
        _manifest(root, sha),
        findings_dir=findings,
        boundary_end="2026-08-19T23:59:59Z",
        installation_count=1,
        repository_inventory_digest="b" * 64,
        observed_at="2026-08-21T23:59:00Z",
    )

    assert receipt["execution_complete"] is True
    assert receipt["executed_repository_count"] == 1
    assert receipt["credential_received_by_runner"] is False
    assert receipt["network_access_required_by_runner"] is False
    assert receipt["audit_open"] is True
    assert receipt["audit_clean"] is False
    assert receipt["report"]["finding_counts"]["open"] == 1
    assert receipt["repository_receipts"][0]["repository"] == "Fixture/Repo"
    assert verify_execution_receipt(receipt)


def test_runner_receipt_is_deterministic_for_fixed_inputs(tmp_path):
    root, sha = _materialized_repo(tmp_path)
    findings = tmp_path / "findings"
    findings.mkdir()
    kwargs = dict(
        findings_dir=findings,
        boundary_end="2026-08-19T23:59:59Z",
        installation_count=1,
        repository_inventory_digest="c" * 64,
        observed_at="2026-08-21T23:59:00Z",
    )
    first = run_audit(_manifest(root, sha), **kwargs)
    second = run_audit(_manifest(root, sha), **kwargs)
    assert first["execution_receipt_sha256"] == second["execution_receipt_sha256"]
    assert verify_execution_receipt(first)
    assert verify_execution_receipt(second)
