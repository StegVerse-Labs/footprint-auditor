"""Detect GitHub Actions constructs that widen provenance or authority risk.

Findings are evidence exceptions, not accusations of malicious intent.  Sensitive
values are never read or reproduced; only secret names and static source patterns
are classified.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Iterable, Optional, Set


@dataclass(frozen=True)
class WorkflowAuthorityFinding:
    repository: str
    workflow_path: str
    finding_type: str
    classification: str
    evidence: str
    reason: str
    severity: str = "HIGH"
    line_number: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


WRITE_PERMISSION_RE = re.compile(r"(?m)^\s*(contents|actions|packages|deployments|pull-requests|issues|checks|id-token):\s*write\s*$")
GIT_PUSH_RE = re.compile(r"(?m)^\s*git\s+push(?:\s|$)")
MUTABLE_REUSABLE_RE = re.compile(r"uses:\s*([^\s]+)@(main|master|develop|dev|latest|v\d+(?:\.\d+){0,2})\b")
WORKFLOW_DISPATCH_RE = re.compile(r"(?m)^\s*workflow_dispatch\s*:")
SECRET_RE = re.compile(r"secrets\.([A-Za-z0-9_]+)")
REMOTE_FETCH_RE = re.compile(r"\b(?:curl|wget)\b.*https?://", re.IGNORECASE)
DIRECT_PIP_RE = re.compile(r"\bpip\s+install\s+(.+)$")


def _line_number(text: str, start: int) -> int:
    return text.count("\n", 0, start) + 1


def _finding(repository: str, workflow_path: str, finding_type: str,
             classification: str, evidence: str, reason: str,
             severity: str, line_number: Optional[int]) -> WorkflowAuthorityFinding:
    return WorkflowAuthorityFinding(
        repository=repository,
        workflow_path=workflow_path,
        finding_type=finding_type,
        classification=classification,
        evidence=evidence,
        reason=reason,
        severity=severity,
        line_number=line_number,
    )


def _contains_unpinned_package(args: str) -> bool:
    tokens = [token for token in args.split() if not token.startswith("-")]
    if not tokens:
        return False
    for token in tokens:
        if token.startswith(("git+", "http://", "https://")):
            if "@" not in token:
                return True
        elif "==" not in token and "@" not in token:
            return True
    return False


def scan_workflow_authority(
    repository: str,
    workflow_path: str,
    text: str,
    allowed_secret_prefixes: Optional[Iterable[str]] = None,
    allowed_platform_secrets: Optional[Iterable[str]] = None,
) -> List[WorkflowAuthorityFinding]:
    """Return static authority/provenance exceptions for one workflow.

    ``allowed_secret_prefixes`` defaults to TV_/TVC_.  This naming check is only
    one signal: even a correctly named secret can violate authority if it is
    interpolated in a repository that is not the admitted credential executor.
    """
    source = text or ""
    allowed_prefixes = tuple(allowed_secret_prefixes or ("TV_", "TVC_"))
    platform: Set[str] = set(allowed_platform_secrets or {"GITHUB_TOKEN"})
    findings: List[WorkflowAuthorityFinding] = []

    for match in WRITE_PERMISSION_RE.finditer(source):
        scope = match.group(1)
        severity = "CRITICAL" if scope in {"contents", "actions", "id-token"} else "HIGH"
        findings.append(_finding(
            repository, workflow_path, "WRITE_PERMISSION", "AUTHORIZED_UNEXPLAINED",
            match.group(0).strip(),
            f"workflow requests '{scope}: write'; authorization basis and execution provenance must be reconstructed",
            severity, _line_number(source, match.start()),
        ))

    for match in GIT_PUSH_RE.finditer(source):
        findings.append(_finding(
            repository, workflow_path, "DIRECT_GIT_PUSH", "AUTHORIZED_UNEXPLAINED",
            "git push",
            "workflow can directly mutate repository refs; historical runs require actor/token/ref evidence",
            "CRITICAL", _line_number(source, match.start()),
        ))

    for match in MUTABLE_REUSABLE_RE.finditer(source):
        findings.append(_finding(
            repository, workflow_path, "MUTABLE_REUSABLE_WORKFLOW_OR_ACTION", "PROVENANCE_GAP",
            match.group(0).strip(),
            "mutable branch/tag reference does not uniquely identify historical executed code",
            "HIGH", _line_number(source, match.start()),
        ))

    for match in SECRET_RE.finditer(source):
        name = match.group(1)
        if name in platform or any(name.startswith(prefix) for prefix in allowed_prefixes):
            continue
        findings.append(_finding(
            repository, workflow_path, "NON_TV_TVC_SECRET_REFERENCE", "AUTHORIZED_UNEXPLAINED",
            f"secrets.{name} [VALUE_NOT_READ]",
            f"workflow directly references secret '{name}' outside the configured TV/TVC naming boundary",
            "CRITICAL", _line_number(source, match.start()),
        ))

    for idx, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if "x-access-token:${TOKEN}@github.com" in line or "x-access-token:$TOKEN@github.com" in line:
            findings.append(_finding(
                repository, workflow_path, "GLOBAL_GIT_TOKEN_REWRITE", "AUTHORIZED_UNEXPLAINED",
                "credential-bearing x-access-token git URL rewrite [VALUE_REDACTED]",
                "global github.com URL rewrite expands bearer credential reach beyond one explicit operation",
                "CRITICAL", idx,
            ))

        if "fernet_key" in line or re.search(r"[\"']key[\"']\s*:\s*key\b", line):
            findings.append(_finding(
                repository, workflow_path, "KEY_MATERIAL_PERSISTENCE_PATTERN", "SUSPICIOUS",
                "encryption key serialization expression [VALUE_REDACTED]",
                "workflow source contains logic that serializes encryption key material into repository/runtime data",
                "CRITICAL", idx,
            ))

        if "GITHUB_STEP_SUMMARY" in line and "cat " in line and "status" in line.lower():
            findings.append(_finding(
                repository, workflow_path, "STATUS_OBJECT_TO_STEP_SUMMARY", "AUTHORIZED_UNEXPLAINED",
                stripped,
                "generated status object is copied to Actions summary and requires sensitivity review",
                "HIGH", idx,
            ))

        pip_match = DIRECT_PIP_RE.search(stripped)
        if pip_match and not stripped.startswith("#"):
            args = pip_match.group(1).strip()
            if not args.startswith("-r ") and _contains_unpinned_package(args):
                findings.append(_finding(
                    repository, workflow_path, "MUTABLE_PACKAGE_INSTALL", "PROVENANCE_GAP",
                    stripped,
                    "direct package installation contains dependencies without immutable version/source binding",
                    "HIGH", idx,
                ))

        if REMOTE_FETCH_RE.search(stripped) and not stripped.startswith("#"):
            findings.append(_finding(
                repository, workflow_path, "REMOTE_EXECUTABLE_FETCH", "PROVENANCE_GAP",
                stripped,
                "remote content is downloaded; exact digest/signature verification must be established for historical attribution",
                "HIGH", idx,
            ))

    if WORKFLOW_DISPATCH_RE.search(source) and findings:
        findings.append(_finding(
            repository, workflow_path, "MANUAL_TRIGGER_WITH_ELEVATED_PATH", "AUTHORIZED_UNEXPLAINED",
            "workflow_dispatch",
            "manual trigger exists on a workflow with elevated or unresolved execution paths; initiating actor must be linked to audit evidence",
            "HIGH", _line_number(source, WORKFLOW_DISPATCH_RE.search(source).start()),
        ))

    # Stable de-duplication.
    seen = set()
    result: List[WorkflowAuthorityFinding] = []
    for finding in findings:
        key = (finding.finding_type, finding.line_number, finding.evidence)
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result
