#!/usr/bin/env python3
"""Cross-ecosystem dependency provenance scanner.

The scanner measures reconstructability, not publisher intent. Mutable or
unhashed references remain evidence gaps; they are not classified as malicious.
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
        return _package_json(path, content)
    if lower.endswith(("package-lock.json", "npm-shrinkwrap.json")):
        return _package_lock(path, content)
    if lower.endswith("cargo.toml"):
        return _cargo_toml(path, content)
    if lower.endswith("cargo.lock"):
        return _cargo_lock(path, content)
    if lower.endswith("go.mod"):
        return _go_mod(path, content)
    if lower.endswith("go.sum"):
        return _go_sum(path, content)
    if lower.endswith("dockerfile") or "/dockerfile" in lower:
        return _dockerfile(path, content)
    if lower.endswith((".sh", ".bash", ".zsh", ".yml", ".yaml")):
        return _remote_downloads(path, content)
    return []


def summarize(findings: Iterable[DependencyFinding]) -> Dict[str, Any]:
    ordered = sorted(findings, key=lambda f: (f.ecosystem, f.source_path, f.line or 0, f.locator))
    counts = {status.value: 0 for status in DependencyStatus}
    for finding in ordered:
        counts[finding.status.value] += 1
    unresolved = sum(counts[s.value] for s in (
        DependencyStatus.MUTABLE,
        DependencyStatus.REMOTE_EXECUTION_UNBOUND,
        DependencyStatus.DYNAMIC,
    ))
    payload = [finding.canonical_dict() for finding in ordered]
    return {
        "total": len(payload),
        "unresolved": unresolved,
        "status_counts": counts,
        "findings_sha256": sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "findings": payload,
    }


def _package_json(path: str, content: str) -> List[DependencyFinding]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return [_f("npm", path, "<invalid-json>", DependencyStatus.DYNAMIC, "invalid package.json")]
    out: List[DependencyFinding] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section) or {}
        if not isinstance(deps, Mapping):
            continue
        for name, raw in sorted(deps.items()):
            spec = str(raw)
            locator = f"{name}@{spec}"
            if spec.startswith(("git+", "http://", "https://", "github:")):
                fixed = bool(re.search(r"(?:#|@)[0-9a-fA-F]{40}$", spec))
                out.append(_f("npm", path, locator,
                    DependencyStatus.IMMUTABLE if fixed else DependencyStatus.MUTABLE,
                    "remote dependency fixed to commit" if fixed else "remote dependency not fixed to 40-character commit"))
            elif spec.startswith(("file:", "link:", "workspace:")):
                out.append(_f("npm", path, locator, DependencyStatus.DYNAMIC, "resolution depends on local/workspace state"))
            elif re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", spec):
                out.append(_f("npm", path, locator, DependencyStatus.LOCKED_NOT_ARTIFACT_BOUND, "exact version still requires lockfile integrity evidence"))
            else:
                out.append(_f("npm", path, locator, DependencyStatus.MUTABLE, "semver range/tag/alias is mutable"))
    return out


def _package_lock(path: str, content: str) -> List[DependencyFinding]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return [_f("npm-lock", path, "<invalid-lock>", DependencyStatus.DYNAMIC, "invalid npm lockfile")]
    out: List[DependencyFinding] = []
    packages = data.get("packages") or {}
    if isinstance(packages, Mapping):
        for name, entry in sorted(packages.items()):
            if not name or not isinstance(entry, Mapping):
                continue
            locator = str(entry.get("resolved") or name)
            integrity = entry.get("integrity")
            out.append(_f("npm-lock", path, locator,
                DependencyStatus.IMMUTABLE if integrity else DependencyStatus.LOCKED_NOT_ARTIFACT_BOUND,
                "lockfile includes artifact integrity hash" if integrity else "lock entry lacks integrity hash"))
    return out


def _cargo_toml(path: str, content: str) -> List[DependencyFinding]:
    out: List[DependencyFinding] = []
    in_deps = False
    exact_version = re.compile(r'^["\']=?\d+\.\d+(?:\.\d+)?["\']$')
    for lineno, raw in enumerate(content.splitlines(), 1):
        line = raw.strip()
        if line.startswith("["):
            in_deps = "dependencies" in line
            continue
        if not in_deps or not line or line.startswith("#") or "=" not in line:
            continue
        name, spec = [piece.strip() for piece in line.split("=", 1)]
        if "git" in spec:
            fixed = bool(re.search(r'rev\s*=\s*["\'][0-9a-fA-F]{40}["\']', spec))
            status = DependencyStatus.IMMUTABLE if fixed else DependencyStatus.MUTABLE
            reason = "git dependency has immutable rev" if fixed else "git dependency lacks immutable rev"
        elif exact_version.fullmatch(spec):
            status, reason = DependencyStatus.LOCKED_NOT_ARTIFACT_BOUND, "version requires Cargo.lock checksum evidence"
        else:
            status, reason = DependencyStatus.DYNAMIC, "dependency form requires Cargo.lock resolution"
        out.append(_f("cargo", path, f"{name}={spec}", status, reason, lineno))
    return out


def _cargo_lock(path: str, content: str) -> List[DependencyFinding]:
    out: List[DependencyFinding] = []
    blocks = re.split(r"(?m)^\[\[package\]\]\s*$", content)[1:]
    for block in blocks:
        name_m = re.search(r'(?m)^name\s*=\s*"([^"]+)"', block)
        if not name_m:
            continue
        checksum = re.search(r'(?m)^checksum\s*=\s*"([0-9a-fA-F]+)"', block)
        source = re.search(r'(?m)^source\s*=\s*"([^"]+)"', block)
        git_fixed = bool(source and re.search(r"#[0-9a-fA-F]{40}$", source.group(1)))
        immutable = bool(checksum or git_fixed)
        out.append(_f("cargo-lock", path, name_m.group(1),
            DependencyStatus.IMMUTABLE if immutable else DependencyStatus.LOCKED_NOT_ARTIFACT_BOUND,
            "lock entry contains checksum/immutable git commit" if immutable else "lock entry lacks checksum/immutable git commit"))
    return out


def _go_mod(path: str, content: str) -> List[DependencyFinding]:
    out: List[DependencyFinding] = []
    for lineno, raw in enumerate(content.splitlines(), 1):
        line = raw.split("//", 1)[0].strip()
        if not line or line.startswith(("module ", "go ", "toolchain ", "require (", ")", "replace ")):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith("v"):
            out.append(_f("go", path, f"{parts[0]}@{parts[1]}", DependencyStatus.LOCKED_NOT_ARTIFACT_BOUND, "module version requires go.sum content hash", lineno))
    return out


def _go_sum(path: str, content: str) -> List[DependencyFinding]:
    out: List[DependencyFinding] = []
    for lineno, raw in enumerate(content.splitlines(), 1):
        parts = raw.strip().split()
        if len(parts) == 3 and parts[2].startswith("h1:"):
            out.append(_f("go-sum", path, f"{parts[0]}@{parts[1]}", DependencyStatus.IMMUTABLE, "go.sum content hash present", lineno))
    return out


def _dockerfile(path: str, content: str) -> List[DependencyFinding]:
    out: List[DependencyFinding] = []
    for lineno, raw in enumerate(content.splitlines(), 1):
        match = re.match(r"\s*FROM\s+([^\s]+)", raw, re.IGNORECASE)
        if not match:
            continue
        image = match.group(1)
        digest_bound = bool(re.search(r"@sha256:[0-9a-fA-F]{64}$", image))
        dynamic = "$" in image
        status = DependencyStatus.IMMUTABLE if digest_bound else (DependencyStatus.DYNAMIC if dynamic else DependencyStatus.MUTABLE)
        reason = "base image digest-bound" if digest_bound else ("base image dynamically selected" if dynamic else "base image tag/default tag is mutable")
        out.append(_f("container", path, image, status, reason, lineno))
    return out


def _remote_downloads(path: str, content: str) -> List[DependencyFinding]:
    out: List[DependencyFinding] = []
    for lineno, raw in enumerate(content.splitlines(), 1):
        line = raw.strip()
        if not re.search(r"\b(curl|wget)\b", line) or not re.search(r"https?://", line):
            continue
        piped = bool(re.search(r"\|\s*(sh|bash|python|python3|node)\b", line))
        hash_check = bool(re.search(r"sha256(sum)?|shasum\s+-a\s+256|openssl\s+dgst\s+-sha256", line, re.I))
        if piped:
            status, reason = DependencyStatus.REMOTE_EXECUTION_UNBOUND, "remote content streamed directly to interpreter/shell"
        elif hash_check:
            status, reason = DependencyStatus.LOCKED_NOT_ARTIFACT_BOUND, "download line references hash verification; expected digest must also be preserved"
        else:
            status, reason = DependencyStatus.REMOTE_EXECUTION_UNBOUND, "remote download lacks cryptographic binding"
        out.append(_f("remote-download", path, line, status, reason, lineno))
    return out


def _f(ecosystem: str, path: str, locator: str, status: DependencyStatus, reason: str, line: Optional[int] = None) -> DependencyFinding:
    return DependencyFinding(ecosystem, path, locator, status, reason, line)
