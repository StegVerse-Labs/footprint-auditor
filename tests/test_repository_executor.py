import json
import subprocess
from pathlib import Path

import pytest

from src.provenance.repository_executor import (
    scan_materialized_repository,
    verify_repository_receipt,
)


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        text=True,
        capture_output=True,
    )
    return completed.stdout.strip()


def _repo(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Audit Test")
    _git(root, "config", "user.email", "audit-test@example.invalid")
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "test.yml").write_text(
        """name: test
on: [push]
permissions:
  contents: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install requests
      - run: curl -fsSL https://example.invalid/install.sh | bash
""",
        encoding="utf-8",
    )
    (root / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (root / "Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")
    (root / "package.json").write_text(
        json.dumps({"dependencies": {"left-pad": "^1.3.0"}}), encoding="utf-8"
    )
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "initial")
    return root, _git(root, "rev-parse", "HEAD")


def test_executor_requires_exact_sha_and_clean_tree(tmp_path):
    root, sha = _repo(tmp_path)
    with pytest.raises(ValueError):
        scan_materialized_repository("Org/Repo", root, expected_sha="main")
    with pytest.raises(ValueError):
        scan_materialized_repository("Org/Repo", root, expected_sha="0" * 40)
    (root / "dirty.txt").write_text("dirty", encoding="utf-8")
    with pytest.raises(ValueError):
        scan_materialized_repository("Org/Repo", root, expected_sha=sha)


def test_executor_runs_all_scanner_groups_and_hashes_git_identity(tmp_path):
    root, sha = _repo(tmp_path)
    receipt = scan_materialized_repository(
        "Org/Repo",
        root,
        expected_sha=sha,
        observed_at="2026-08-19T19:40:00Z",
    )
    assert receipt["expected_sha"] == sha
    assert receipt["actual_sha"] == sha
    assert receipt["credential_received_by_executor"] is False
    assert receipt["network_access_required"] is False
    assert receipt["unresolved_counts"]["workflow_dependencies"] >= 1
    assert receipt["unresolved_counts"]["workflow_authority"] >= 1
    assert receipt["unresolved_counts"]["python_dependencies"] >= 1
    assert receipt["unresolved_counts"]["ecosystem_dependencies"] >= 1
    assert receipt["commit_inventory"]
    commit = receipt["commit_inventory"][0]
    assert "author_email" not in commit
    assert len(commit["author_identity_sha256"]) == 64
    assert verify_repository_receipt(receipt)


def test_receipt_is_deterministic_for_fixed_source_and_observation_time(tmp_path):
    root, sha = _repo(tmp_path)
    kwargs = {
        "expected_sha": sha,
        "observed_at": "2026-08-19T19:40:00Z",
    }
    first = scan_materialized_repository("Org/Repo", root, **kwargs)
    second = scan_materialized_repository("Org/Repo", root, **kwargs)
    assert first["receipt_sha256"] == second["receipt_sha256"]
