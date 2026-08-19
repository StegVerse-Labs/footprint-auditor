#!/usr/bin/env python3
"""Static control-surface scanner for GitHub Actions workflow source.

The purpose is provenance and authority auditing, not malware labeling. Findings
identify workflow constructs that can mutate repositories, use credentials, or
fetch executable dependencies in ways that require stronger historical evidence.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import re
from typing import Dict, Iterable, List, Optional, Set


_SECRET_RE = re.compile(r"secrets\.([A-Za-z0-9_]+)")
_WRITE_PERMISSION_RE = re.compile(
    r"^\s*(contents|actions|issues|pull-requests|packages|deployments|checks|id-token)\s*:\s*write\s*$"
)
_DIRECT_PIP_RE = re.compile(r"\bpip\s+install\s+(.+)$")
_REMOTE_EXEC_RE = re.compile(r"\b(?:curl|wget)\b.*https?://", re.IGNORECASE)


@dataclass(frozen=True)
class WorkflowControlFinding:
    repository: str
    workflow_path: str
    finding_code: str
    severity: str
    line_number: int
    evidence: str
    reason: str
    requires_resolution: bool = True

    def canonical_dict(self) -> Dict[str, object]:
        return asdict(self)

    def digest(self) -> str:
        payload = json.dumps(
            self.canonical_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return sha256(payload).hexdigest()


class WorkflowControlScanner:
    def __init__(
        self,
        allowed_secret_prefixes: Optional[Iterable[str]] = None,
        allowed_platform_secrets: Optional[Iterable[str]] = None,
    ) -> None:
        self.allowed_secret_prefixes = tuple(allowed_secret_prefixes or ("TV_", "TVC_"))
        self.allowed_platform_secrets: Set[str] = set(
            allowed_platform_secrets or {"GITHUB_TOKEN"}
        )

    def scan_text(
        self,
        repository: str,
        workflow_path: str,
        text: str,
    ) -> List[WorkflowControlFinding]:
        findings: List[WorkflowControlFinding] = []
        lines = text.splitlines()

        for number, line in enumerate(lines, start=1):
            stripped = line.strip()

            permission = _WRITE_PERMISSION_RE.match(line)
            if permission:
                scope = permission.group(1)
                severity = "CRITICAL" if scope in {"contents", "actions", "id-token"} else "HIGH"
                findings.append(
                    self._finding(
                        repository,
                        workflow_path,
                        "GHA_WRITE_AUTHORITY",
                        severity,
                        number,
                        stripped,
                        f"Workflow requests GitHub write authority for '{scope}'; execution identity and necessity require provenance evidence.",
                    )
                )

            for secret_name in _SECRET_RE.findall(line):
                if self._secret_allowed(secret_name):
                    continue
                findings.append(
                    self._finding(
                        repository,
                        workflow_path,
                        "GHA_NON_TV_TVC_SECRET_REFERENCE",
                        "CRITICAL",
                        number,
                        self._redact_secret_reference(stripped, secret_name),
                        f"Workflow references secret '{secret_name}' outside the configured TV/TVC credential naming boundary.",
                    )
                )

            if "x-access-token:${TOKEN}@github.com" in line or "x-access-token:$TOKEN@github.com" in line:
                findings.append(
                    self._finding(
                        repository,
                        workflow_path,
                        "GHA_GLOBAL_GIT_TOKEN_REWRITE",
                        "CRITICAL",
                        number,
                        "git URL rewrite contains credential-bearing x-access-token form [REDACTED]",
                        "Workflow globally rewrites github.com URLs through a bearer token, expanding credential reach beyond one explicit operation.",
                    )
                )

            if "fernet_key" in line or re.search(r"[\"']key[\"']\s*:\s*key\b", line):
                findings.append(
                    self._finding(
                        repository,
                        workflow_path,
                        "GHA_KEY_MATERIAL_PERSISTENCE_PATTERN",
                        "CRITICAL",
                        number,
                        self._redact_key_line(stripped),
                        "Workflow source contains logic that serializes encryption key material into a data object/file.",
                    )
                )

            if "GITHUB_STEP_SUMMARY" in line and "cat " in line and "status" in line.lower():
                findings.append(
                    self._finding(
                        repository,
                        workflow_path,
                        "GHA_STATUS_OBJECT_TO_STEP_SUMMARY",
                        "HIGH",
                        number,
                        stripped,
                        "Workflow copies a generated status object into the Actions step summary; status content requires sensitivity review.",
                    )
                )

            pip_match = _DIRECT_PIP_RE.search(stripped)
            if pip_match and not stripped.startswith("#"):
                args = pip_match.group(1).strip()
                if not args.startswith("-r ") and self._contains_unpinned_package(args):
                    findings.append(
                        self._finding(
                            repository,
                            workflow_path,
                            "GHA_MUTABLE_PACKAGE_INSTALL",
                            "HIGH",
                            number,
                            stripped,
                            "Direct package installation contains one or more dependencies without an immutable version/source binding.",
                        )
                    )

            if _REMOTE_EXEC_RE.search(stripped) and not stripped.startswith("#"):
                findings.append(
                    self._finding(
                        repository,
                        workflow_path,
                        "GHA_REMOTE_EXECUTABLE_FETCH",
                        "HIGH",
                        number,
                        stripped,
                        "Workflow downloads remote content; exact digest/signature verification must be established before historical execution is attributable.",
                    )
                )

        return self._dedupe(findings)

    def _secret_allowed(self, secret_name: str) -> bool:
        if secret_name in self.allowed_platform_secrets:
            return True
        return any(secret_name.startswith(prefix) for prefix in self.allowed_secret_prefixes)

    @staticmethod
    def _contains_unpinned_package(args: str) -> bool:
        tokens = [token for token in args.split() if not token.startswith("-")]
        if not tokens:
            return False
        for token in tokens:
            if token.startswith(("git+", "http://", "https://")):
                if "@" not in token:
                    return True
                continue
            if "==" not in token and "@" not in token:
                return True
        return False

    @staticmethod
    def _redact_secret_reference(line: str, name: str) -> str:
        return line.replace(f"secrets.{name}", f"secrets.{name} [VALUE_NOT_READ]")

    @staticmethod
    def _redact_key_line(line: str) -> str:
        if "fernet_key" in line:
            return re.sub(r"([\"']?fernet_key[\"']?\s*[:=]\s*).*", r"\1[REDACTED_KEY_EXPRESSION]", line)
        return re.sub(r"([\"']key[\"']\s*:\s*).*", r"\1[REDACTED_KEY_EXPRESSION]", line)

    @staticmethod
    def _finding(
        repository: str,
        workflow_path: str,
        code: str,
        severity: str,
        line_number: int,
        evidence: str,
        reason: str,
    ) -> WorkflowControlFinding:
        return WorkflowControlFinding(
            repository=repository,
            workflow_path=workflow_path,
            finding_code=code,
            severity=severity,
            line_number=line_number,
            evidence=evidence,
            reason=reason,
        )

    @staticmethod
    def _dedupe(findings: List[WorkflowControlFinding]) -> List[WorkflowControlFinding]:
        seen = set()
        result: List[WorkflowControlFinding] = []
        for finding in findings:
            key = (
                finding.repository,
                finding.workflow_path,
                finding.finding_code,
                finding.line_number,
                finding.evidence,
            )
            if key not in seen:
                seen.add(key)
                result.append(finding)
        return result
