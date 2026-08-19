#!/usr/bin/env python3
"""Deterministic ecosystem-audit report and receipt generation.

The report generator is intentionally fail-closed: a clean-audit statement is
never permitted while coverage is incomplete, unresolved provenance remains,
or a confirmed compromise is still open.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence
import json

from .historical import AuditStatus


UNRESOLVED_STATUSES = {
    AuditStatus.AUTHORIZED_UNEXPLAINED.value,
    AuditStatus.THIRD_PARTY_UNEXPLAINED.value,
    AuditStatus.PROVENANCE_GAP.value,
    AuditStatus.SUSPICIOUS.value,
    AuditStatus.CONFIRMED_UNAUTHORIZED.value,
    AuditStatus.CONFIRMED_MALICIOUS.value,
}


@dataclass(frozen=True)
class AuditFindingSummary:
    finding_id: str
    repository: str
    status: str
    title: str
    open: bool
    confirmed_compromise: bool = False
    malicious_confirmed: bool = False
    unauthorized_actor_confirmed: bool = False
    source_ref: Optional[str] = None

    def canonical_dict(self) -> Dict[str, Any]:
        return asdict(self)


def normalize_finding(
    finding: Mapping[str, Any], *, source_ref: Optional[str] = None
) -> AuditFindingSummary:
    finding_id = str(finding.get("finding_id") or finding.get("id") or "UNKNOWN")
    repository = str(finding.get("repository") or "UNKNOWN")
    status = str(
        finding.get("audit_status")
        or finding.get("status")
        or finding.get("classification")
        or AuditStatus.PROVENANCE_GAP.value
    )
    title = str(finding.get("title") or finding.get("event_type") or finding_id)
    completion_gate = str(finding.get("completion_gate") or "").upper()
    explicit_open = finding.get("open")
    if explicit_open is None:
        open_state = (
            status in UNRESOLVED_STATUSES
            or "OPEN" in completion_gate
            or "PENDING" in completion_gate
            or bool(finding.get("rotation_required"))
        )
    else:
        open_state = bool(explicit_open)

    compromise = bool(
        finding.get("confirmed_compromise")
        or finding.get("confirmed_security_compromise")
        or finding.get("credential_key_exposure_confirmed")
        or finding.get("key_compromise_treatment_required")
    )
    malicious = bool(finding.get("malice_confirmed") or finding.get("malicious_confirmed"))
    unauthorized = bool(
        finding.get("unauthorized_actor_confirmed")
        or finding.get("confirmed_unauthorized_actor")
    )
    return AuditFindingSummary(
        finding_id=finding_id,
        repository=repository,
        status=status,
        title=title,
        open=open_state,
        confirmed_compromise=compromise,
        malicious_confirmed=malicious,
        unauthorized_actor_confirmed=unauthorized,
        source_ref=source_ref,
    )


def build_audit_report(
    findings: Iterable[AuditFindingSummary],
    *,
    boundary_end: str,
    repository_inventory_digest: str,
    repository_count: int,
    installation_count: int,
    historical_visibility_complete: bool,
    historical_identity_complete: bool,
    dependency_provenance_complete: bool,
    external_infrastructure_complete: bool,
    notes: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    ordered = sorted(
        findings,
        key=lambda item: (item.repository, item.finding_id, item.status),
    )
    status_counts: Dict[str, int] = {}
    for finding in ordered:
        status_counts[finding.status] = status_counts.get(finding.status, 0) + 1

    open_findings = [finding for finding in ordered if finding.open]
    confirmed_compromises = [f for f in ordered if f.confirmed_compromise]
    malicious = [f for f in ordered if f.malicious_confirmed]
    unauthorized = [f for f in ordered if f.unauthorized_actor_confirmed]

    coverage = {
        "historical_visibility_complete": historical_visibility_complete,
        "historical_identity_complete": historical_identity_complete,
        "dependency_provenance_complete": dependency_provenance_complete,
        "external_infrastructure_complete": external_infrastructure_complete,
    }
    coverage_complete = all(coverage.values())
    clean_audit_permitted = (
        coverage_complete
        and not open_findings
        and not confirmed_compromises
        and not malicious
        and not unauthorized
    )

    body: Dict[str, Any] = {
        "schema": "stegverse.ecosystem-provenance-audit.v1",
        "boundary_end": boundary_end,
        "inventory": {
            "installations": installation_count,
            "repositories": repository_count,
            "digest_sha256": repository_inventory_digest,
        },
        "coverage": coverage,
        "coverage_complete": coverage_complete,
        "findings": [finding.canonical_dict() for finding in ordered],
        "finding_counts": {
            "total": len(ordered),
            "open": len(open_findings),
            "confirmed_compromise": len(confirmed_compromises),
            "confirmed_malicious": len(malicious),
            "confirmed_unauthorized_actor": len(unauthorized),
            "by_status": dict(sorted(status_counts.items())),
        },
        "clean_audit_permitted": clean_audit_permitted,
        "allowed_conclusion": (
            "no evidence of unauthorized third-party influence within the fully audited boundary"
            if clean_audit_permitted
            else "audit remains open; unresolved evidence or coverage gaps prevent a clean-audit conclusion"
        ),
        "notes": sorted(set(notes or [])),
    }
    body["report_sha256"] = _digest_without_self(body)
    return body


def verify_report(report: Mapping[str, Any]) -> bool:
    expected = str(report.get("report_sha256") or "")
    if not expected:
        return False
    copy = dict(report)
    copy.pop("report_sha256", None)
    payload = json.dumps(copy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(payload).hexdigest() == expected


def render_markdown(report: Mapping[str, Any]) -> str:
    counts = report["finding_counts"]
    coverage = report["coverage"]
    lines = [
        "# Ecosystem provenance audit",
        "",
        f"Boundary end: `{report['boundary_end']}`",
        f"Report SHA-256: `{report['report_sha256']}`",
        "",
        "## Result",
        "",
        str(report["allowed_conclusion"]),
        "",
        "## Coverage",
        "",
    ]
    for key in sorted(coverage):
        lines.append(f"- {key}: {'YES' if coverage[key] else 'NO'}")
    lines.extend(
        [
            "",
            "## Findings",
            "",
            f"- total: {counts['total']}",
            f"- open: {counts['open']}",
            f"- confirmed compromise: {counts['confirmed_compromise']}",
            f"- confirmed malicious: {counts['confirmed_malicious']}",
            f"- confirmed unauthorized actor: {counts['confirmed_unauthorized_actor']}",
        ]
    )
    for finding in report["findings"]:
        lines.append(
            f"- `{finding['finding_id']}` — {finding['repository']} — {finding['status']} — "
            f"{'OPEN' if finding['open'] else 'CLOSED'}"
        )
    return "\n".join(lines) + "\n"


def _digest_without_self(report: Mapping[str, Any]) -> str:
    copy = dict(report)
    copy.pop("report_sha256", None)
    payload = json.dumps(copy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(payload).hexdigest()
