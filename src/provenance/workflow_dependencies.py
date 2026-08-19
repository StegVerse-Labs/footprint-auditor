"""GitHub Actions workflow dependency provenance analysis.

This module treats mutable action references as provenance gaps because a workflow
file that names a movable tag (for example ``actions/checkout@v4``) does not,
by itself, identify the exact implementation executed historically.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, asdict
from typing import Iterable, List, Dict, Any

USES_RE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
LOCAL_PREFIXES = ("./", "docker://")


@dataclass(frozen=True)
class WorkflowDependencyFinding:
    repository: str
    workflow_path: str
    reference: str
    dependency: str
    revision: str
    classification: str
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def parse_uses_references(workflow_text: str) -> List[str]:
    return USES_RE.findall(workflow_text or "")


def classify_reference(reference: str) -> tuple[str, str, str, str]:
    """Return dependency, revision, classification, reason."""
    if reference.startswith(LOCAL_PREFIXES):
        return reference, "", "AUTHORIZED_EXPECTED", "local/container reference; provenance resolved elsewhere"

    if "@" not in reference:
        return reference, "", "PROVENANCE_GAP", "external action reference has no revision"

    dependency, revision = reference.rsplit("@", 1)
    if FULL_SHA_RE.fullmatch(revision):
        return dependency, revision.lower(), "AUTHORIZED_EXPECTED", "external action pinned to immutable 40-character commit SHA"

    return dependency, revision, "PROVENANCE_GAP", "external action revision is mutable or non-cryptographic; historical implementation requires separate evidence"


def scan_workflow(repository: str, workflow_path: str, workflow_text: str) -> List[WorkflowDependencyFinding]:
    findings: List[WorkflowDependencyFinding] = []
    for reference in parse_uses_references(workflow_text):
        dependency, revision, classification, reason = classify_reference(reference)
        findings.append(
            WorkflowDependencyFinding(
                repository=repository,
                workflow_path=workflow_path,
                reference=reference,
                dependency=dependency,
                revision=revision,
                classification=classification,
                reason=reason,
            )
        )
    return findings


def summarize(findings: Iterable[WorkflowDependencyFinding]) -> Dict[str, Any]:
    rows = sorted(
        (f.to_dict() for f in findings),
        key=lambda r: (r["repository"], r["workflow_path"], r["reference"]),
    )
    counts: Dict[str, int] = {}
    for row in rows:
        counts[row["classification"]] = counts.get(row["classification"], 0) + 1
    canonical = "\n".join(
        "|".join(str(row[k]) for k in ("repository", "workflow_path", "reference", "classification"))
        for row in rows
    )
    return {
        "total_dependencies": len(rows),
        "classification_counts": counts,
        "evidence_digest_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "findings": rows,
    }
