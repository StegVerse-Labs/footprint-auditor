#!/usr/bin/env python3
"""Dependency provenance signals beyond Python and GitHub Actions.

This scanner is evidence-oriented.  It identifies whether a dependency or
remote executable reference is cryptographically fixed enough to reconstruct
what was consumed.  It does not label a publisher or package malicious merely
because provenance is incomplete.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from enum import Enum
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Mapping, Optional
import json
import re


class DependencyStatus(str, Enum):
    IMMUTABLE = "IMMUTABLE"
    LOCKED_NOT_ARTIFACT_BOUND = "LOCKED_NOT_ARTIFACT_BOUND"
    MUTABLE = "MUTABLE"
    REMOTE_EXECUTION_UNBOUND = "REMOTE_EXECUTION_UNBOUND"
    DYNAMIC = "DYNAMIC"


@dataclass(frozen=True)
class DependencyFinding:
    ecosystem: str
    source_path: str
    locator: str
    status: DependencyStatus
    reason: str
    line: Optional[int] = None

    def canonical_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        value["status"] = self.status.value
        return value


def scan_dependency_file(path: str, content: str) -> List[DependencyFinding]:
    lower = path.lower()
    if lower.endswith("package.json"):
        return _scan_package_json(path, content)
    if lower.endswith("package-lock.json") or lower.endswith("npm-shrinkwrap.json"):
        return _scan_package_lock(path, content)
    if lower.endswith("cargo.toml"):
        return _scan_cargo_toml(path, content)
    if lower.endswith("cargo.lock"):
        return _scan_cargo_lock(path, content)
    if lower.endswith("go.mod"):
        return _scan_go_mod(path, content)
    if lower.endswith("go.sum"):
        return _scan_go_sum(path, content)
    if lower.endswith("dockerfile") or "/dockerfile" in lower:
        return _scan_dockerfile(path, content)
    if lower.endswith((".sh", ".bash", ".zsh", ".yml", ".yaml")):
        return _scan_remote_execution(path, content)
    return []


def summarize(findings: Iterable[DependencyFinding]) -> Dict[str, Any]:
    ordered = sorted(
        findings,
        key=lambda finding: (
            finding.ecosystem,
            finding.source_path,
            finding.line or 0,
            finding.locator,
        ),
    )
    counts: Dict[str, int] = {status.value: 0 for status in DependencyStatus}
    for finding in ordered:
        counts[finding.status.value] += 1
    unresolved = sum(
        counts[status.value]
        for status in (
            DependencyStatus.MUTABLE,
            DependencyStatus.REMOTE_EXECUTION_UNBOUND,
            DependencyStatus.DYNAMIC,
        )
    )
    payload = [finding.canonical_dict() for finding in ordered]
    digest = sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "total": len(ordered),
        "unresolved": unresolved,
        "status_counts": counts,
        "findings_sha256": digest,
        "findings": payload,
    }


def _scan_package_json(path: str, content: str) -> List[DependencyFinding]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return [DependencyFinding("npm", path, "<invalid-json>", DependencyStatus.DYNAMIC, "package.json is not valid JSON")]
    findings: List[DependencyFinding] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        values = data.get(section) or {}
        if not isinstance(values, Mapping):
            continue
        for name, spec in sorted(values.items()):
            spec = str(spec)
            locator = f"{name}@{spec}"
            if spec.startswith(("git+", "http://", "https://", "github:")):
                immutable = bool(re.search(r"(?:#|@)[0-9a-fA-F]{40}$", spec))
                status = DependencyStatus.IMMUTABLE if immutable else DependencyStatus.MUTABLE
                reason = "git dependency fixed to 40-character commit" if immutable else "remote/git dependency is not fixed to an immutable commit"
            elif spec.startswith(("file:", "link:", "workspace:")):
                status = DependencyStatus.DYNAMIC
                reason = "dependency resolution depends on workspace/local state"
            elif re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", spec):
                status = DependencyStatus.LOCKED_NOT_ARTIFACT_BOUND
                reason = "exact semantic version specified; artifact integrity still depends on lockfile/registry integrity metadata"
            else:
                status = DependencyStatus.MUTABLE
                reason = "semver range/tag/alias is mutable"
            findings.append(DependencyFinding("npm", path, locator, status, reason))
    return findings


def _scan_package_lock(path: str, content: str) -> List[DependencyFinding]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return [DependencyFinding("npm", path, "<invalid-lock>", DependencyStatus.DYNAMIC, "lockfile is not valid JSON")]
    findings: List[DependencyFinding] = []
    packages = data.get("packages")
    if isinstance(packages, Mapping):
        for name, value in sorted(packages.items()):
            if not name or not isinstance(value, Mapping):
                continue
            resolved = str(value.get("resolved") or name)
            integrity = value.get("integrity")
            status = DependencyStatus.IMMUTABLE if integrity else DependencyStatus.LOCKED_NOT_ARTIFACT_BOUND
            reason = "lockfile includes package integrity hash" if integrity else "lockfile entry lacks integrity hash"
            findings.append(DependencyFinding("npm-lock", path, resolved, status, reason))
    return findings


def _scan_cargo_toml(path: str, content: str) -> List[DependencyFinding]:
    findings: List[DependencyFinding] = []
    in_deps = False
    for lineno, raw in enumerate(content.splitlines(), 1):
        line = raw.strip()
        if line.startswith("["):
            in_deps = "dependencies" in line
            continue
        if not in_deps or not line or line.startswith("#") or "=" not in line:
            continue
        name, spec = [piece.strip() for piece in line.split("=", 1)]
        if "git" in spec:
            immutable = bool(re.search(r"rev\s*=\s*[\"'][0-9a-fA-F]{40}[\"']", spec))
            status = DependencyStatus.IMMUTABLE if immutable else DependencyStatus.MUTABLE
            reason = "git dependency has immutable rev" if immutable else "git dependency lacks immutable 40-character rev"
        elif re.fullmatch(r'[\"']=?\d+\.\d+(?:\.\d+)?[\"']', spec):
            status = DependencyStatus.LOCKED_NOT_ARTIFACT_BOUND
            reason = "Cargo version constraint requires Cargo.lock/checksum evidence"
        else:
            status = DependencyStatus.DYNAMIC
            reason = "Cargo dependency form requires lockfile resolution"
        findings.append(DependencyFinding("cargo", path, f"{name}={spec}", status, reason, lineno))
    return findings


def _scan_cargo_lock(path: str, content: str) -> List[DependencyFinding]:
    findings: List[DependencyFinding] = []
    current_name: Optional[str] = None
    checksum: Optional[str] = None
    source: Optional[str] = None
    start_line: Optional[int] = None
    def flush() -> None:
        if not current_name:
            return
        if checksum and (not source or source.startswith("registry+")):
            status, reason = DependencyStatus.IMMUTABLE, "Cargo.lock includes registry checksum"
        elif source and "#" in source and re.search(r"#[0-9a-fA-F]{40}$", source):
            status, reason = DependencyStatus.IMMUTABLE, "git source fixed to immutable commit"
        else:
            status, reason = DependencyStatus.LOCKED_NOT_ARTIFACT_BOUND, "lock entry lacks checksum or immutable git commit"
        findings.append(DependencyFinding("cargo-lock", path, current_name, status, reason, start_line))
    for lineno, raw in enumerate(content.splitlines(), 1):
        line = raw.strip()
        if line == "[[package]]":
            flush(); current_name = None; checksum = None; source = None; start_line = lineno
        elif line.startswith("name ="):
            current_name = line.split("=",1)[1].strip().strip('"')
        elif line.startswith("checksum ="):
            checksum = line.split("=",1)[1].strip().strip('"')
        elif line.startswith("source ="):
            source = line.split("=",1)[1].strip().strip('"')
    flush()
    return findings


def _scan_go_mod(path: str, content: str) -> List[DependencyFinding]:
    findings: List[DependencyFinding] = []
    for lineno, raw in enumerate(content.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("module ", "go ", "toolchain ", "//", "require (", ")")):
            continue
        line = line.split("//",1)[0].strip()
        parts = line.split()
        if len(parts) >= 2 and (parts[0].startswith(".") is False):
            module, version = parts[0], parts[1]
            if version.startswith("v") and re.search(r"-0\.\d{14}-[0-9a-f]{12}$", version):
                status, reason = DependencyStatus.LOCKED_NOT_ARTIFACT_BOUND, "Go pseudo-version binds a source commit prefix; go.sum still required for content integrity"
            elif version.startswith("v"):
                status, reason = DependencyStatus.LOCKED_NOT_ARTIFACT_BOUND, "exact module version requires go.sum checksum evidence"
            else:
                status, reason = DependencyStatus.DYNAMIC, "non-version Go dependency requires resolution"
            findings.append(DependencyFinding("go", path, f"{module}@{version}", status, reason, lineno))
    return findings


def _scan_go_sum(path: str, content: str) -> List[DependencyFinding]:
    findings: List[DependencyFinding] = []
    for lineno, raw in enumerate(content.splitlines(), 1):
        parts = raw.strip().split()
        if len(parts) == 3 and parts[2].startswith("h1:"):
            findings.append(DependencyFinding("go-sum", path, f"{parts[0]}@{parts[1]}", DependencyStatus.IMMUTABLE, "go.sum includes module content hash", lineno))
    return findings


def _scan_dockerfile(path: str, content: str) -> List[DependencyFinding]:
    findings: List[DependencyFinding] = []
    for lineno, raw in enumerate(content.splitlines(), 1):
        match = re.match(r"\s*FROM\s+([^\s]+)", raw, re.IGNORECASE)
        if not match:
            continue
        image = match.group(1)
        if "@sha256:" in image and re.search(r"@sha256:[0-9a-fA-F]{64}$", image):
            status, reason = DependencyStatus.IMMUTABLE, "container base image is digest-bound"
        elif "$" in image or "${" in image:
            status, reason = DependencyStatus.DYNAMIC, "container base image is dynamically selected"
        else:
            status, reason = DependencyStatus.MUTABLE, "container base image uses mutable tag/default tag rather than digest"
        findings.append(DependencyFinding("container", path, image, status, reason, lineno))
    return findings


def _scan_remote_execution(path: str, content: str) -> List[DependencyFinding]:
    findings: List[DependencyFinding] = []
    lines = content.splitlines()
    for lineno, raw in enumerate(lines, 1):
        line = raw.strip()
        if re.search(r"\b(curl|wget)\b", line) and re.search(r"https?://", line):
            piped = bool(re.search(r"\|\s*(sh|bash|python|python3|node)\b", line))
            has_hash = bool(re.search(r"sha256(sum)?|shasum\s+-a\s+256|openssl\s+dgst\s+-sha256", line, re.IGNORECASE))
            if piped:
                status, reason = DependencyStatus.REMOTE_EXECUTION_UNBOUND, "remote content is streamed directly into an interpreter/shell"
            elif has_hash:
                status, reason = DependencyStatus.LOCKED_NOT_ARTIFACT_BOUND, "remote download line references hash verification; exact expected digest must be preserved separately"
            else:
                status, reason = DependencyStatus.REMOTE_EXECUTION_UNBOUND, "remote download lacks adjacent cryptographic artifact binding"
            findings.append(DependencyFinding("remote-download", path, line, status, reason, lineno))
    return findings
