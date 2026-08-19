"""Python dependency provenance checks for reproducibility and supply-chain audit.

The scanner distinguishes direct version pins from cryptographically locked inputs.
A ``name==version`` pin narrows resolution but does not prove the exact artifact
without a hash/lock artifact; unconstrained install commands are provenance gaps.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import List, Dict, Any

PIN_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:\[[^\]]+\])?==[^\s;]+(?:\s*;.*)?$")
HASH_RE = re.compile(r"--hash=sha256:[0-9a-fA-F]{64}")
PIP_INSTALL_RE = re.compile(r"(?m)^\s*(?:python\s+-m\s+pip|pip)\s+install\s+(.+)$")


@dataclass(frozen=True)
class PythonDependencyFinding:
    source: str
    finding_type: str
    classification: str
    evidence: str
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def scan_requirements(text: str, source: str = "requirements.txt") -> List[PythonDependencyFinding]:
    findings: List[PythonDependencyFinding] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("--"):
            continue
        if HASH_RE.search(line):
            continue
        if PIN_RE.fullmatch(line):
            findings.append(PythonDependencyFinding(
                source, "VERSION_PIN_WITHOUT_ARTIFACT_HASH", "PROVENANCE_GAP", line,
                "direct version is pinned but exact distribution artifact is not cryptographically identified",
            ))
        else:
            findings.append(PythonDependencyFinding(
                source, "UNPINNED_OR_DYNAMIC_REQUIREMENT", "PROVENANCE_GAP", line,
                "requirement can resolve differently over time or requires external resolution evidence",
            ))
    return findings


def scan_install_commands(text: str, source: str) -> List[PythonDependencyFinding]:
    findings: List[PythonDependencyFinding] = []
    for match in PIP_INSTALL_RE.finditer(text or ""):
        args = match.group(1).strip()
        if args.startswith("-r ") or args.startswith("--requirement "):
            continue
        if "--require-hashes" in args:
            continue
        findings.append(PythonDependencyFinding(
            source, "DIRECT_PIP_INSTALL_WITHOUT_HASH_LOCK", "PROVENANCE_GAP", args,
            "install command depends on package-index resolution not uniquely identified by repository evidence",
        ))
    return findings
