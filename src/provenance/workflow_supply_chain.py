#!/usr/bin/env python3
"""GitHub Actions workflow supply-chain provenance scanner.

The scanner treats an expected third-party dependency and an immutable dependency
as different properties.  A familiar action such as ``actions/checkout@v4`` may
be expected, but the tag is mutable and therefore does not by itself establish
which action commit executed historically.

This module does not claim malice from mutable references.  It produces explicit
provenance findings that remain open until exact run/action evidence resolves the
executed source revision.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from hashlib import sha256
import json
import re
from typing import Dict, Iterable, List, Optional, Sequence, Set


_GITHUB_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_DOCKER_DIGEST_RE = re.compile(r"@sha256:[0-9a-fA-F]{64}$")
_USES_RE = re.compile(r"^\s*(?:-\s*)?uses\s*:\s*['\"]?([^'\"\s#]+)", re.MULTILINE)


class DependencyKind(str, Enum):
    LOCAL = "LOCAL"
    GITHUB_ACTION = "GITHUB_ACTION"
    REUSABLE_WORKFLOW = "REUSABLE_WORKFLOW"
    DOCKER = "DOCKER"
    DYNAMIC = "DYNAMIC"
    UNKNOWN = "UNKNOWN"


class PinStrength(str, Enum):
    LOCAL_COMMIT = "LOCAL_COMMIT"
    IMMUTABLE = "IMMUTABLE"
    MUTABLE = "MUTABLE"
    DYNAMIC = "DYNAMIC"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True)
class WorkflowDependency:
    repository: str
    workflow_path: str
    reference: str
    kind: DependencyKind
    owner: Optional[str]
    target: str
    ref: Optional[str]
    pin_strength: PinStrength
    expected_third_party: bool
    line_number: int
    finding_code: Optional[str]
    severity: Optional[str]
    reason: str

    @property
    def immutable(self) -> bool:
        return self.pin_strength in {PinStrength.IMMUTABLE, PinStrength.LOCAL_COMMIT}

    @property
    def unresolved(self) -> bool:
        return self.pin_strength in {
            PinStrength.MUTABLE,
            PinStrength.DYNAMIC,
            PinStrength.UNRESOLVED,
        }

    def canonical_dict(self) -> Dict[str, object]:
        data = asdict(self)
        data["kind"] = self.kind.value
        data["pin_strength"] = self.pin_strength.value
        data["immutable"] = self.immutable
        data["unresolved"] = self.unresolved
        return data

    def digest(self) -> str:
        payload = json.dumps(
            self.canonical_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return sha256(payload).hexdigest()


class WorkflowSupplyChainScanner:
    """Extract and classify ``uses:`` dependencies from workflow source."""

    def __init__(self, expected_third_party_owners: Optional[Iterable[str]] = None) -> None:
        self.expected_third_party_owners: Set[str] = {
            value.lower() for value in (expected_third_party_owners or {"actions"})
        }

    def scan_text(
        self,
        repository: str,
        workflow_path: str,
        text: str,
    ) -> List[WorkflowDependency]:
        results: List[WorkflowDependency] = []
        for match in _USES_RE.finditer(text):
            reference = match.group(1).strip()
            line_number = text.count("\n", 0, match.start()) + 1
            results.append(
                self._classify_reference(
                    repository=repository,
                    workflow_path=workflow_path,
                    reference=reference,
                    line_number=line_number,
                )
            )
        return results

    def scan_many(
        self,
        repository: str,
        workflows: Dict[str, str],
    ) -> List[WorkflowDependency]:
        findings: List[WorkflowDependency] = []
        for path in sorted(workflows):
            findings.extend(self.scan_text(repository, path, workflows[path]))
        return findings

    def _classify_reference(
        self,
        repository: str,
        workflow_path: str,
        reference: str,
        line_number: int,
    ) -> WorkflowDependency:
        if "${{" in reference:
            return WorkflowDependency(
                repository=repository,
                workflow_path=workflow_path,
                reference=reference,
                kind=DependencyKind.DYNAMIC,
                owner=None,
                target=reference,
                ref=None,
                pin_strength=PinStrength.DYNAMIC,
                expected_third_party=False,
                line_number=line_number,
                finding_code="GHA_DYNAMIC_USES_REF",
                severity="HIGH",
                reason="Dynamic uses reference cannot be reconstructed from workflow source alone.",
            )

        if reference.startswith("./"):
            return WorkflowDependency(
                repository=repository,
                workflow_path=workflow_path,
                reference=reference,
                kind=DependencyKind.LOCAL,
                owner=None,
                target=reference,
                ref=None,
                pin_strength=PinStrength.LOCAL_COMMIT,
                expected_third_party=False,
                line_number=line_number,
                finding_code=None,
                severity=None,
                reason="Local action/workflow is bound to the repository commit under audit.",
            )

        if reference.startswith("docker://"):
            immutable = bool(_DOCKER_DIGEST_RE.search(reference))
            return WorkflowDependency(
                repository=repository,
                workflow_path=workflow_path,
                reference=reference,
                kind=DependencyKind.DOCKER,
                owner=None,
                target=reference[len("docker://"):],
                ref=None,
                pin_strength=PinStrength.IMMUTABLE if immutable else PinStrength.MUTABLE,
                expected_third_party=True,
                line_number=line_number,
                finding_code=None if immutable else "GHA_MUTABLE_DOCKER_REF",
                severity=None if immutable else "HIGH",
                reason=(
                    "Container image is digest pinned."
                    if immutable
                    else "Container image is not digest pinned; historical executed bytes require registry/run evidence."
                ),
            )

        if "@" not in reference:
            return WorkflowDependency(
                repository=repository,
                workflow_path=workflow_path,
                reference=reference,
                kind=DependencyKind.UNKNOWN,
                owner=None,
                target=reference,
                ref=None,
                pin_strength=PinStrength.UNRESOLVED,
                expected_third_party=False,
                line_number=line_number,
                finding_code="GHA_UNRESOLVED_USES_REF",
                severity="HIGH",
                reason="External uses reference has no explicit ref.",
            )

        target, ref = reference.rsplit("@", 1)
        parts = target.split("/")
        owner = parts[0] if len(parts) >= 2 else None
        reusable = "/.github/workflows/" in target
        kind = DependencyKind.REUSABLE_WORKFLOW if reusable else DependencyKind.GITHUB_ACTION
        immutable = bool(_GITHUB_SHA_RE.fullmatch(ref))
        expected = bool(owner and owner.lower() in self.expected_third_party_owners)

        if immutable:
            code = None
            severity = None
            reason = "External workflow/action is pinned to an immutable Git commit SHA."
            strength = PinStrength.IMMUTABLE
        else:
            code = "GHA_MUTABLE_EXTERNAL_REF"
            severity = "HIGH"
            reason = (
                "Expected third-party reference uses a movable tag/branch; exact historical source requires run evidence."
                if expected
                else "External reference uses a movable tag/branch; exact historical source and authority remain unresolved."
            )
            strength = PinStrength.MUTABLE

        return WorkflowDependency(
            repository=repository,
            workflow_path=workflow_path,
            reference=reference,
            kind=kind,
            owner=owner,
            target=target,
            ref=ref,
            pin_strength=strength,
            expected_third_party=expected,
            line_number=line_number,
            finding_code=code,
            severity=severity,
            reason=reason,
        )


def unresolved_dependencies(findings: Sequence[WorkflowDependency]) -> List[WorkflowDependency]:
    return [finding for finding in findings if finding.unresolved]


def summarize_dependencies(findings: Sequence[WorkflowDependency]) -> Dict[str, object]:
    unresolved = unresolved_dependencies(findings)
    mutable = [f for f in findings if f.pin_strength == PinStrength.MUTABLE]
    immutable = [f for f in findings if f.immutable]
    return {
        "dependencies": len(findings),
        "immutable": len(immutable),
        "mutable": len(mutable),
        "unresolved": len(unresolved),
        "coverage_ratio": 1.0 if not findings else len(immutable) / len(findings),
        "finding_codes": sorted({f.finding_code for f in unresolved if f.finding_code}),
    }
