#!/usr/bin/env python3
"""Import exported GitHub audit-log evidence into deterministic audit receipts.

The importer is intentionally credential-free. It consumes an already exported
JSON/JSONL audit-log file, reconstructs explicit repository visibility evidence,
and emits a secret-safe receipt. Raw actor identifiers are never persisted in
the receipt; they are represented only by SHA-256 digests.
"""

from __future__ import annotations

import argparse
import csv
from hashlib import sha256
import json
from pathlib import Path
import sys
from typing import Any, Iterable, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.provenance.github_audit_log import (
    build_exposure_intervals,
    coverage_summary,
    extract_visibility_transitions,
    normalize_actor_events,
    parse_timestamp,
)

SCHEMA = "stegverse.github-audit-log-import-receipt.v1"


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def load_records(path: Path) -> list[Mapping[str, Any]]:
    raw = path.read_text(encoding="utf-8")
    stripped = raw.lstrip()
    if not stripped:
        return []
    if stripped.startswith("[") or stripped.startswith("{"):
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            records = parsed
        elif isinstance(parsed, dict) and isinstance(parsed.get("records"), list):
            records = parsed["records"]
        else:
            records = [parsed]
    else:
        records = [json.loads(line) for line in raw.splitlines() if line.strip()]
    if not all(isinstance(item, dict) for item in records):
        raise ValueError("audit-log input must contain JSON objects")
    return records


def load_expected_repositories(path: Path, *, organization: str | None = None) -> list[str]:
    expected: list[str] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            full_name = (row.get("full_name") or "").strip()
            if not full_name:
                continue
            if organization and not full_name.startswith(f"{organization}/"):
                continue
            expected.append(full_name)
    return sorted(set(expected))


def _actor_digest(actor: str | None) -> str | None:
    if not actor:
        return None
    return sha256(actor.encode("utf-8")).hexdigest()


def _filter_boundary(records: Iterable[Mapping[str, Any]], boundary_end: str | None) -> list[Mapping[str, Any]]:
    if not boundary_end:
        return list(records)
    end = parse_timestamp(boundary_end)
    kept: list[Mapping[str, Any]] = []
    time_keys = ("created_at", "@timestamp", "timestamp", "created_at_ms")
    for record in records:
        raw_time = next((record.get(key) for key in time_keys if record.get(key) not in (None, "")), None)
        if raw_time is None:
            kept.append(record)
            continue
        try:
            if parse_timestamp(raw_time) <= end:
                kept.append(record)
        except (TypeError, ValueError):
            kept.append(record)
    return kept


def _safe_transition(item: Any) -> dict[str, Any]:
    return {
        "repository": item.repository,
        "timestamp": item.timestamp.isoformat(),
        "visibility": item.visibility,
        "previous_visibility": item.previous_visibility,
        "action": item.action,
        "actor_sha256": _actor_digest(item.actor),
        "actor_identifier_persisted": False,
        "evidence_ref": item.evidence_ref,
        "record_sha256": item.record_sha256,
    }


def build_receipt(
    records: list[Mapping[str, Any]],
    *,
    source_sha256: str,
    expected_repositories: Iterable[str] = (),
    organization: str | None = None,
    boundary_end: str | None = None,
) -> dict[str, Any]:
    bounded = _filter_boundary(records, boundary_end)
    transitions = extract_visibility_transitions(bounded, organization=organization)
    intervals = build_exposure_intervals(transitions)
    actor_events = normalize_actor_events(bounded, organization=organization)
    coverage = coverage_summary(
        bounded,
        expected_repositories=expected_repositories,
        organization=organization,
    )

    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "organization": organization,
        "boundary_end": boundary_end,
        "source_sha256": source_sha256,
        "records_received": len(records),
        "records_within_boundary_or_undated": len(bounded),
        "coverage": coverage,
        "visibility_transitions": [_safe_transition(item) for item in transitions],
        "exposure_intervals": [
            {
                "repository": item.repo,
                "visibility": item.visibility,
                "start": item.start.isoformat(),
                "end": item.end.isoformat() if item.end else None,
                "evidence_ref": item.evidence_ref,
            }
            for item in intervals
        ],
        "actor_events": [
            {
                "event_id": event.event_id,
                "repository": event.repo,
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type,
                "actor_sha256": _actor_digest(event.actor),
                "actor_identifier_persisted": False,
                "status": event.status.value,
                "evidence_refs": sorted(event.evidence_refs),
                "record_sha256": event.details.get("record_sha256"),
            }
            for event in actor_events
        ],
        "raw_actor_identifiers_persisted": False,
        "historical_visibility_complete": coverage["historical_visibility_complete"],
        "historical_actor_authority_complete": False,
        "clean_audit_effect": False,
        "authority_effect": False,
    }
    payload["receipt_sha256"] = sha256(_canonical_bytes(payload)).hexdigest()
    return payload


def verify_receipt(receipt: Mapping[str, Any]) -> bool:
    claimed = receipt.get("receipt_sha256")
    if not isinstance(claimed, str) or len(claimed) != 64:
        return False
    body = dict(receipt)
    body.pop("receipt_sha256", None)
    return sha256(_canonical_bytes(body)).hexdigest() == claimed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inventory-csv", type=Path)
    parser.add_argument("--organization")
    parser.add_argument("--boundary-end")
    args = parser.parse_args()

    source_bytes = args.input.read_bytes()
    records = load_records(args.input)
    expected = (
        load_expected_repositories(args.inventory_csv, organization=args.organization)
        if args.inventory_csv
        else []
    )
    receipt = build_receipt(
        records,
        source_sha256=sha256(source_bytes).hexdigest(),
        expected_repositories=expected,
        organization=args.organization,
        boundary_end=args.boundary_end,
    )
    if not verify_receipt(receipt):
        raise RuntimeError("generated audit-log receipt failed deterministic verification")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "records_received": receipt["records_received"],
        "visibility_transitions": len(receipt["visibility_transitions"]),
        "actor_events": len(receipt["actor_events"]),
        "historical_visibility_complete": receipt["historical_visibility_complete"],
        "receipt_sha256": receipt["receipt_sha256"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
