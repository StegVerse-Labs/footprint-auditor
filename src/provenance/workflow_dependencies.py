"""GitHub Actions workflow dependency provenance analysis.

Mutable references are provenance gaps even when the publisher is expected.  The
workflow source must not be treated as proof of the exact external implementation
that executed historically.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, asdict
from typing import Iterable, List, Dict, Any, Optional

USES_RE = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)", re.MULTILINE)
FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
DOCKER_DIGEST_RE = re.compile(r"@sha256:[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class WorkflowDependencyFinding:
    repository: str
    workflow_path: str
    reference: str
    dependency: str
    revision: str
    classification: str
    reason: str
    dependency_kind: str = "UNKNOWN"
    immutable: bool = False
    expected_third_party: bool = False
    line_number: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def parse_uses_references(workflow_text: str) -> List[str]:
    return USES_RE.findall(workflow_text or "")


def _details(reference: str) -> tuple[str, str, str, str, str, bool, bool]:
    """Return dependency, revision, classification, reason, kind, immutable, expected."""
    if "${{" in reference:
        return (
            reference,
            "",
            "PROVENANCE_GAP",
            "dynamic uses reference cannot be reconstructed from workflow source alone",
            "DYNAMIC",
            False,
            False,
        )

    if reference.startswith("./"):
        return (
            reference,
            "",
            "AUTHORIZED_EXPECTED",
            "local action/reusable workflow is bound to the repository commit under audit",
            "LOCAL",
            True,
            False,
        )

    if reference.startswith("docker://"):
        immutable = bool(DOCKER_DIGEST_RE.search(reference))
        return (
            reference[len("docker://"):],
            "sha256" if immutable else "",
            "AUTHORIZED_EXPECTED" if immutable else "PROVENANCE_GAP",
            (
                "container image is pinned by immutable sha256 digest"
                if immutable
                else "container image is not digest-pinned; historical bytes require registry/run evidence"
            ),
            "DOCKER",
            immutable,
            True,
        )

    if "@" not in reference:
        return (
            reference,
            "",
            "PROVENANCE_GAP",
            "external action reference has no revision",
            "EXTERNAL",
            False,
            False,
        )

    dependency, revision = reference.rsplit("@", 1)
    owner = dependency.split("/", 1)[0].lower() if "/" in dependency else ""
    expected = owner == "actions"
    kind = "REUSABLE_WORKFLOW" if "/.github/workflows/" in dependency else "GITHUB_ACTION"
    if FULL_SHA_RE.fullmatch(revision):
        return (
            dependency,
            revision.lower(),
            "AUTHORIZED_EXPECTED",
            "external action/workflow pinned to immutable 40-character commit SHA",
            kind,
            True,
            expected,
        )

    return (
        dependency,
        revision,
        "PROVENANCE_GAP",
        (
            "expected third-party action uses a mutable tag/branch; exact historical implementation requires run evidence"
            if expected
            else "external action/workflow revision is mutable or non-cryptographic; historical implementation requires separate evidence"
        ),
        kind,
        False,
        expected,
    )


def classify_reference(reference: str) -> tuple[str, str, str, str]:
    """Backward-compatible four-field classifier."""
    dependency, revision, classification, reason, _, _, _ = _details(reference)
    return dependency, revision, classification, reason


def scan_workflow(repository: str, workflow_path: str, workflow_text: str) -> List[WorkflowDependencyFinding]:
    findings: List[WorkflowDependencyFinding] = []
    text = workflow_text or ""
    for match in USES_RE.finditer(text):
        reference = match.group(1)
        dependency, revision, classification, reason, kind, immutable, expected = _details(reference)
        findings.append(
            WorkflowDependencyFinding(
                repository=repository,
                workflow_path=workflow_path,
                reference=reference,
                dependency=dependency,
                revision=revision,
                classification=classification,
                reason=reason,
                dependency_kind=kind,
                immutable=immutable,
                expected_third_party=expected,
                line_number=text.count("\n", 0, match.start()) + 1,
            )
        )
    return findings


def unresolved(findings: Iterable[WorkflowDependencyFinding]) -> List[WorkflowDependencyFinding]:
    return [finding for finding in findings if finding.classification != "AUTHORIZED_EXPECTED"]


def summarize(findings: Iterable[WorkflowDependencyFinding]) -> Dict[str, Any]:
    rows = sorted(
        (f.to_dict() for f in findings),
        key=lambda r: (r["repository"], r["workflow_path"], r["reference"]),
    )
    counts: Dict[str, int] = {}
    immutable_count = 0
    expected_third_party_count = 0
    for row in rows:
        counts[row["classification"]] = counts.get(row["classification"], 0) + 1
        immutable_count += int(bool(row["immutable"]))
        expected_third_party_count += int(bool(row["expected_third_party"]))
    canonical = "\n".join(
        "|".join(str(row[k]) for k in ("repository", "workflow_path", "reference", "classification"))
        for row in rows
    )
    return {
        "total_dependencies": len(rows),
        "classification_counts": counts,
        "immutable_dependencies": immutable_count,
        "expected_third_party_dependencies": expected_third_party_count,
        "unresolved_dependencies": sum(1 for row in rows if row["classification"] != "AUTHORIZED_EXPECTED"),
        "coverage_ratio": 1.0 if not rows else immutable_count / len(rows),
        "evidence_digest_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "findings": rows,
    }
