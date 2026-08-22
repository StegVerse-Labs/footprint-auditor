#!/usr/bin/env python3
"""End-to-end execution surface for the ecosystem provenance audit.

The runner deliberately separates *execution success* from *audit cleanliness*.
A successful run may still produce an open/fail-closed audit report.  This keeps
observation/execution machinery operational while unresolved provenance remains
visible instead of turning every legitimate open finding into a broken runtime.

No credentials are accepted or read by this module.  Repositories must already
be materialized at immutable SHAs by an admitted TV/TVC read boundary.
"""

from __future__ import annotations

from argparse import ArgumentParser
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional
import json

from .report import build_audit_report, normalize_finding, verify_report
from .repository_executor import scan_materialized_repository, verify_repository_receipt


RUNNER_SCHEMA = "stegverse.ecosystem-provenance-execution.v1"
MANIFEST_SCHEMA = "stegverse.materialized-repository-manifest.v1"


def _canonical_digest(value: Mapping[str, Any], *, omit: Iterable[str] = ()) -> str:
    copy = dict(value)
    for key in omit:
        copy.pop(key, None)
    encoded = json.dumps(copy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(encoded).hexdigest()


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_findings(findings_dir: Path) -> List[Any]:
    findings = []
    if not findings_dir.exists():
        return findings
    for path in sorted(findings_dir.glob("*.json")):
        payload = _load_json(path)
        if not isinstance(payload, Mapping):
            raise ValueError(f"finding must be a JSON object: {path}")
        findings.append(normalize_finding(payload, source_ref=path.as_posix()))
    return findings


def validate_manifest(manifest: Mapping[str, Any]) -> None:
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise ValueError(f"manifest schema must be {MANIFEST_SCHEMA}")
    repositories = manifest.get("repositories")
    if not isinstance(repositories, list) or not repositories:
        raise ValueError("manifest repositories must be a non-empty list")
    seen = set()
    for index, row in enumerate(repositories):
        if not isinstance(row, Mapping):
            raise ValueError(f"manifest repository row {index} must be an object")
        full_name = str(row.get("repository") or row.get("full_name") or "").strip()
        root = str(row.get("path") or "").strip()
        expected_sha = str(row.get("expected_sha") or "").strip()
        if not full_name or not root or not expected_sha:
            raise ValueError(f"manifest repository row {index} requires repository, path, expected_sha")
        if full_name in seen:
            raise ValueError(f"duplicate repository in manifest: {full_name}")
        seen.add(full_name)


def run_audit(
    manifest: Mapping[str, Any],
    *,
    findings_dir: Path | str,
    boundary_end: str,
    installation_count: int,
    repository_inventory_digest: str,
    historical_visibility_complete: bool = False,
    historical_identity_complete: bool = False,
    dependency_provenance_complete: bool = False,
    external_infrastructure_complete: bool = False,
    observed_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute every materialized repository and build one deterministic bundle."""
    validate_manifest(manifest)
    repository_receipts: List[Dict[str, Any]] = []

    for row in sorted(
        manifest["repositories"],
        key=lambda item: str(item.get("repository") or item.get("full_name") or ""),
    ):
        repository = str(row.get("repository") or row.get("full_name"))
        receipt = scan_materialized_repository(
            repository,
            Path(str(row["path"])),
            expected_sha=str(row["expected_sha"]),
            observed_at=observed_at,
        )
        if not verify_repository_receipt(receipt):
            raise RuntimeError(f"repository receipt verification failed: {repository}")
        repository_receipts.append(receipt)

    findings = _load_findings(Path(findings_dir))
    report = build_audit_report(
        findings,
        boundary_end=boundary_end,
        repository_inventory_digest=repository_inventory_digest,
        repository_count=len(repository_receipts),
        installation_count=installation_count,
        historical_visibility_complete=historical_visibility_complete,
        historical_identity_complete=historical_identity_complete,
        dependency_provenance_complete=dependency_provenance_complete,
        external_infrastructure_complete=external_infrastructure_complete,
        notes=[
            "Execution success does not imply a clean audit.",
            "Repositories are scanned only after immutable-SHA materialization outside this credential-free runner.",
        ],
    )
    if not verify_report(report):
        raise RuntimeError("aggregate report verification failed")

    unresolved_totals: Dict[str, int] = {}
    for receipt in repository_receipts:
        for key, value in receipt.get("unresolved_counts", {}).items():
            unresolved_totals[key] = unresolved_totals.get(key, 0) + int(value)

    body: Dict[str, Any] = {
        "schema": RUNNER_SCHEMA,
        "manifest_schema": MANIFEST_SCHEMA,
        "manifest_repository_count": len(manifest["repositories"]),
        "executed_repository_count": len(repository_receipts),
        "credential_received_by_runner": False,
        "network_access_required_by_runner": False,
        "execution_complete": True,
        "audit_clean": bool(report["clean_audit_permitted"]),
        "audit_open": not bool(report["clean_audit_permitted"]),
        "unresolved_repository_scan_counts": dict(sorted(unresolved_totals.items())),
        "repository_receipts": repository_receipts,
        "report": report,
    }
    body["execution_receipt_sha256"] = _canonical_digest(body)
    return body


def verify_execution_receipt(receipt: Mapping[str, Any]) -> bool:
    expected = str(receipt.get("execution_receipt_sha256") or "")
    return bool(expected) and _canonical_digest(receipt, omit=("execution_receipt_sha256",)) == expected


def main(argv: Optional[List[str]] = None) -> int:
    parser = ArgumentParser(description="Execute the footprint-auditor provenance pipeline")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--findings-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--boundary-end", required=True)
    parser.add_argument("--installation-count", required=True, type=int)
    parser.add_argument("--inventory-digest", required=True)
    parser.add_argument("--observed-at")
    parser.add_argument("--historical-visibility-complete", action="store_true")
    parser.add_argument("--historical-identity-complete", action="store_true")
    parser.add_argument("--dependency-provenance-complete", action="store_true")
    parser.add_argument("--external-infrastructure-complete", action="store_true")
    args = parser.parse_args(argv)

    try:
        manifest = _load_json(args.manifest)
        if not isinstance(manifest, Mapping):
            raise ValueError("manifest must contain a JSON object")
        result = run_audit(
            manifest,
            findings_dir=args.findings_dir,
            boundary_end=args.boundary_end,
            installation_count=args.installation_count,
            repository_inventory_digest=args.inventory_digest,
            historical_visibility_complete=args.historical_visibility_complete,
            historical_identity_complete=args.historical_identity_complete,
            dependency_provenance_complete=args.dependency_provenance_complete,
            external_infrastructure_complete=args.external_infrastructure_complete,
            observed_at=args.observed_at,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({
            "execution_complete": True,
            "audit_clean": result["audit_clean"],
            "executed_repository_count": result["executed_repository_count"],
            "execution_receipt_sha256": result["execution_receipt_sha256"],
        }, sort_keys=True))
        # Open findings are an audit result, not an execution failure.
        return 0
    except Exception as exc:
        print(json.dumps({"execution_complete": False, "error": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
