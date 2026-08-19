"""Detect GitHub Actions workflow constructs that widen provenance/authority risk.

Findings are evidence exceptions, not accusations of malicious intent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import List, Dict, Any


@dataclass(frozen=True)
class WorkflowAuthorityFinding:
    repository: str
    workflow_path: str
    finding_type: str
    classification: str
    evidence: str
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


WRITE_PERMISSION_RE = re.compile(r"(?m)^\s*(contents|actions|packages|deployments|pull-requests|issues):\s*write\s*$")
GIT_PUSH_RE = re.compile(r"(?m)^\s*git\s+push(?:\s|$)")
MUTABLE_REUSABLE_RE = re.compile(r"uses:\s*([^\s]+)@(main|master|develop|dev|latest|v\d+(?:\.\d+){0,2})\b")
WORKFLOW_DISPATCH_RE = re.compile(r"(?m)^\s*workflow_dispatch\s*:")


def scan_workflow_authority(repository: str, workflow_path: str, text: str) -> List[WorkflowAuthorityFinding]:
    findings: List[WorkflowAuthorityFinding] = []

    for match in WRITE_PERMISSION_RE.finditer(text or ""):
        findings.append(WorkflowAuthorityFinding(
            repository, workflow_path, "WRITE_PERMISSION", "AUTHORIZED_UNEXPLAINED",
            match.group(0).strip(),
            "workflow requests repository-mutating authority; authorization basis and execution provenance must be reconstructed",
        ))

    if GIT_PUSH_RE.search(text or ""):
        findings.append(WorkflowAuthorityFinding(
            repository, workflow_path, "DIRECT_GIT_PUSH", "AUTHORIZED_UNEXPLAINED",
            "git push",
            "workflow can directly mutate repository refs; historical runs require actor/token/ref evidence",
        ))

    for match in MUTABLE_REUSABLE_RE.finditer(text or ""):
        findings.append(WorkflowAuthorityFinding(
            repository, workflow_path, "MUTABLE_REUSABLE_WORKFLOW_OR_ACTION", "PROVENANCE_GAP",
            match.group(0).strip(),
            "mutable branch/tag reference does not uniquely identify historical executed code",
        ))

    if WORKFLOW_DISPATCH_RE.search(text or "") and findings:
        findings.append(WorkflowAuthorityFinding(
            repository, workflow_path, "MANUAL_TRIGGER_WITH_ELEVATED_PATH", "AUTHORIZED_UNEXPLAINED",
            "workflow_dispatch",
            "manual trigger exists on a workflow with elevated or mutable execution paths; initiating actor must be linked to audit-log evidence",
        ))

    return findings
