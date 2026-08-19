#!/usr/bin/env python3
"""Execute the provenance scanner suite against one materialized repository.

This module performs no network access and accepts no credential.  Private
repositories must be materialized by an admitted TV/TVC read boundary before
this code runs.  The executor verifies the exact expected commit, rejects a
dirty worktree, hashes Git identities instead of persisting raw email/name
values, and emits only secret-safe static evidence.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional
import json
import os
import re
import subprocess

from .ecosystem_dependencies import scan_dependency_file
from .python_dependencies import scan_install_commands, scan_requirements
from .workflow_authority import scan_workflow_authority
from .workflow_dependencies import scan_workflow


FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
TEXT_SUFFIXES = {
    ".py", ".sh", ".bash", ".zsh", ".yml", ".yaml", ".json", ".toml",
    ".txt", ".md", ".ini", ".cfg", ".conf", ".lock", ".mod", ".sum",
}
MAX_TEXT_BYTES = 2 * 1024 * 1024

# Conservative static-source scrubbing.  The executor never reads environment
# values or GitHub secret values; this only prevents accidentally retaining a
# literal bearer/token that was already committed in source.
SCRUB_PATTERNS = (
    (re.compile(r"(x-access-token:)[^@/\s]+(@github\.com)", re.I), r"\1[REDACTED]\2"),
    (re.compile(r"(Authorization\s*[:=]\s*[\"']?(?:Bearer|token)\s+)[^\"'\s]+", re.I), r"\1[REDACTED]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GITHUB_TOKEN_LITERAL]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", re.I), "[REDACTED_GITHUB_TOKEN_LITERAL]"),
)


def _run_git(root: Path, args: List[str]) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        text=True,
        capture_output=True,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        timeout=120,
    )
    return completed.stdout


def _sanitize(value: Any) -> Any:
    if isinstance(value, str):
        result = value
        for pattern, replacement in SCRUB_PATTERNS:
            result = pattern.sub(replacement, result)
        return result
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _sanitize(item) for key, item in value.items()}
    return value


def _file_digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _read_text(path: Path) -> Optional[str]:
    try:
        if path.stat().st_size > MAX_TEXT_BYTES:
            return None
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def _identity_digest(*parts: str) -> str:
    canonical = "\x1f".join(part.strip().casefold() for part in parts)
    return sha256(canonical.encode("utf-8")).hexdigest()


def _commit_inventory(root: Path) -> List[Dict[str, Any]]:
    # Record separators avoid ambiguity from spaces/newlines in names.
    fmt = "%H%x1f%aI%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1e"
    raw = _run_git(root, ["log", "--all", f"--format={fmt}"])
    rows: List[Dict[str, Any]] = []
    for record in raw.split("\x1e"):
        record = record.strip("\n\r")
        if not record:
            continue
        fields = record.split("\x1f")
        if len(fields) != 6:
            continue
        commit_sha, timestamp, author_name, author_email, committer_name, committer_email = fields
        rows.append(
            {
                "commit_sha": commit_sha,
                "timestamp": timestamp,
                "author_identity_sha256": _identity_digest(author_name, author_email),
                "committer_identity_sha256": _identity_digest(committer_name, committer_email),
                "identity_attribution": "HASHED_GIT_IDENTITY_ONLY; HISTORICAL_GITHUB_AUTHORITY_REQUIRES_AUDIT_LOG",
            }
        )
    rows.sort(key=lambda row: (row["timestamp"], row["commit_sha"]))
    return rows


def _iter_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if ".git" in path.parts:
            continue
        if path.is_symlink():
            # Symlink targets are not followed; the link itself is represented
            # as an exception by the caller.
            yield path
            continue
        if path.is_file():
            yield path


def scan_materialized_repository(
    repository: str,
    root: Path | str,
    *,
    expected_sha: str,
    observed_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Scan one exact materialized Git repository and return a receipt.

    Raises ``ValueError`` before scanning if the expected ref is not a full SHA,
    the materialized HEAD differs, or the worktree is dirty.
    """
    root_path = Path(root).resolve()
    if not FULL_SHA_RE.fullmatch(expected_sha or ""):
        raise ValueError("expected_sha must be an immutable 40-character commit SHA")
    if not (root_path / ".git").exists():
        raise ValueError("materialized repository must contain .git metadata")

    actual_sha = _run_git(root_path, ["rev-parse", "HEAD"]).strip()
    if actual_sha.lower() != expected_sha.lower():
        raise ValueError(f"materialized HEAD {actual_sha} does not match expected {expected_sha}")
    dirty = _run_git(root_path, ["status", "--porcelain=v1"]).strip()
    if dirty:
        raise ValueError("materialized repository worktree is dirty; exact source identity is ambiguous")

    file_inventory: List[Dict[str, Any]] = []
    workflow_dependency_findings: List[Dict[str, Any]] = []
    workflow_authority_findings: List[Dict[str, Any]] = []
    python_findings: List[Dict[str, Any]] = []
    ecosystem_findings: List[Dict[str, Any]] = []
    executor_exceptions: List[Dict[str, Any]] = []

    for path in _iter_files(root_path):
        relative = path.relative_to(root_path).as_posix()
        if path.is_symlink():
            target = os.readlink(path)
            executor_exceptions.append(
                {
                    "type": "SYMLINK_NOT_FOLLOWED",
                    "path": relative,
                    "target_sha256": sha256(target.encode("utf-8")).hexdigest(),
                    "classification": "PROVENANCE_GAP",
                }
            )
            continue

        digest = _file_digest(path)
        file_inventory.append({"path": relative, "sha256": digest, "size": path.stat().st_size})
        text = _read_text(path)
        if text is None:
            continue

        lower = relative.lower()
        if lower.startswith(".github/workflows/") and lower.endswith((".yml", ".yaml")):
            workflow_dependency_findings.extend(
                finding.to_dict() for finding in scan_workflow(repository, relative, text)
            )
            workflow_authority_findings.extend(
                finding.to_dict() for finding in scan_workflow_authority(repository, relative, text)
            )

        name = path.name.lower()
        if name.startswith("requirements") and name.endswith(".txt"):
            python_findings.extend(finding.to_dict() for finding in scan_requirements(text, relative))
        if path.suffix.lower() in TEXT_SUFFIXES:
            python_findings.extend(finding.to_dict() for finding in scan_install_commands(text, relative))

        ecosystem_findings.extend(
            finding.canonical_dict() for finding in scan_dependency_file(relative, text)
        )

    commits = _commit_inventory(root_path)
    file_inventory.sort(key=lambda row: row["path"])

    wf_dep_unresolved = sum(
        1 for row in workflow_dependency_findings if row.get("classification") != "AUTHORIZED_EXPECTED"
    )
    wf_auth_unresolved = len(workflow_authority_findings)
    py_unresolved = len(python_findings)
    eco_unresolved = sum(
        1
        for row in ecosystem_findings
        if row.get("status") in {"MUTABLE", "REMOTE_EXECUTION_UNBOUND", "DYNAMIC", "LOCKED_NOT_ARTIFACT_BOUND"}
    )

    body: Dict[str, Any] = {
        "schema": "stegverse.materialized-repository-provenance.v1",
        "repository": repository,
        "expected_sha": expected_sha.lower(),
        "actual_sha": actual_sha.lower(),
        "observed_at": observed_at or datetime.now(timezone.utc).isoformat(),
        "credential_received_by_executor": False,
        "network_access_required": False,
        "worktree_clean": True,
        "commit_count": len(commits),
        "file_count": len(file_inventory),
        "unresolved_counts": {
            "workflow_dependencies": wf_dep_unresolved,
            "workflow_authority": wf_auth_unresolved,
            "python_dependencies": py_unresolved,
            "ecosystem_dependencies": eco_unresolved,
            "executor_exceptions": len(executor_exceptions),
            "historical_identity_authority": len(commits),
        },
        "file_inventory": file_inventory,
        "commit_inventory": commits,
        "workflow_dependency_findings": workflow_dependency_findings,
        "workflow_authority_findings": workflow_authority_findings,
        "python_dependency_findings": python_findings,
        "ecosystem_dependency_findings": ecosystem_findings,
        "executor_exceptions": executor_exceptions,
        "historical_identity_note": "Git author/committer identities are hashed. Authorization at event time requires dated GitHub organization/security audit evidence.",
    }
    body = _sanitize(body)
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    body["receipt_sha256"] = sha256(canonical).hexdigest()
    return body


def verify_repository_receipt(receipt: Mapping[str, Any]) -> bool:
    expected = str(receipt.get("receipt_sha256") or "")
    if not expected:
        return False
    copy = dict(receipt)
    copy.pop("receipt_sha256", None)
    canonical = json.dumps(copy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(canonical).hexdigest() == expected
