#!/usr/bin/env python3
"""Normalize GitHub organization audit-log evidence for historical provenance.

The connected GitHub tool does not currently expose the organization audit-log
endpoint, so this module intentionally accepts exported/collected records as
input and never treats their absence as benign. It extracts repository
visibility transitions and actor-bearing audit events into the canonical
historical provenance model without guessing historical authorization.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Iterable, Mapping, Sequence
import json

from .historical import AuditEvent, ExposureInterval


_VISIBILITIES = {"public", "private", "internal"}
_REPO_KEYS = ("repo", "repository", "repository_name", "repo_name")
_ACTOR_KEYS = ("actor", "actor_login", "user", "user_login")
_TIME_KEYS = ("created_at", "@timestamp", "timestamp", "created_at_ms")
_NEW_VISIBILITY_KEYS = (
    "visibility",
    "repository_visibility",
    "repo_visibility",
    "new_visibility",
)
_OLD_VISIBILITY_KEYS = ("previous_visibility", "old_visibility", "from_visibility")


@dataclass(frozen=True)
class VisibilityTransition:
    repository: str
    timestamp: datetime
    visibility: str
    actor: str | None
    action: str
    previous_visibility: str | None = None
    evidence_ref: str | None = None
    record_sha256: str | None = None

    def canonical_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["timestamp"] = _utc(self.timestamp).isoformat()
        return value


def canonical_record_digest(record: Mapping[str, Any]) -> str:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(payload.encode("utf-8")).hexdigest()


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return _utc(value)
    if isinstance(value, (int, float)):
        numeric = float(value)
        if numeric > 10_000_000_000:
            numeric /= 1000.0
        return datetime.fromtimestamp(numeric, tz=timezone.utc)
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return parse_timestamp(int(text))
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        return _utc(parsed)
    raise ValueError(f"unsupported audit-log timestamp: {value!r}")


def normalize_repository(value: Any, *, organization: str | None = None) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    name = value.strip().strip("/")
    if "/" in name:
        return name
    if organization:
        return f"{organization}/{name}"
    return name


def extract_visibility_transitions(
    records: Iterable[Mapping[str, Any]],
    *,
    organization: str | None = None,
    evidence_prefix: str = "github-org-audit-log",
) -> list[VisibilityTransition]:
    transitions: list[VisibilityTransition] = []
    for index, record in enumerate(records):
        repository = normalize_repository(_first(record, _REPO_KEYS), organization=organization)
        visibility = _visibility(_first(record, _NEW_VISIBILITY_KEYS))
        timestamp_value = _first(record, _TIME_KEYS)
        if repository is None or visibility is None or timestamp_value is None:
            continue
        action = str(record.get("action") or record.get("event") or "unknown")
        actor_value = _first(record, _ACTOR_KEYS)
        actor = str(actor_value) if actor_value not in (None, "") else None
        previous = _visibility(_first(record, _OLD_VISIBILITY_KEYS))
        digest = canonical_record_digest(record)
        transitions.append(
            VisibilityTransition(
                repository=repository,
                timestamp=parse_timestamp(timestamp_value),
                visibility=visibility,
                previous_visibility=previous,
                actor=actor,
                action=action,
                evidence_ref=f"{evidence_prefix}:{index}:{digest[:16]}",
                record_sha256=digest,
            )
        )
    return sorted(transitions, key=lambda item: (item.timestamp, item.repository, item.action))


def build_exposure_intervals(
    transitions: Sequence[VisibilityTransition],
) -> list[ExposureInterval]:
    by_repo: dict[str, list[VisibilityTransition]] = {}
    for transition in transitions:
        by_repo.setdefault(transition.repository, []).append(transition)

    intervals: list[ExposureInterval] = []
    for repository, repo_transitions in sorted(by_repo.items()):
        ordered = sorted(repo_transitions, key=lambda item: (item.timestamp, item.action))
        for index, transition in enumerate(ordered):
            end = ordered[index + 1].timestamp if index + 1 < len(ordered) else None
            intervals.append(
                ExposureInterval(
                    repo=repository,
                    visibility=transition.visibility,
                    start=transition.timestamp,
                    end=end,
                    evidence_ref=transition.evidence_ref,
                )
            )
    return intervals


def normalize_actor_events(
    records: Iterable[Mapping[str, Any]],
    *,
    organization: str | None = None,
    evidence_prefix: str = "github-org-audit-log",
) -> list[AuditEvent]:
    """Convert actor-bearing repository records into fail-closed audit events.

    Historical authorization is deliberately left unset. Dated authority records
    must be reconciled separately by ``commit_authority`` or equivalent evidence.
    """
    events: list[AuditEvent] = []
    for index, record in enumerate(records):
        repository = normalize_repository(_first(record, _REPO_KEYS), organization=organization)
        timestamp_value = _first(record, _TIME_KEYS)
        if repository is None or timestamp_value is None:
            continue
        actor_value = _first(record, _ACTOR_KEYS)
        actor = str(actor_value) if actor_value not in (None, "") else None
        action = str(record.get("action") or record.get("event") or "github.audit.unknown")
        digest = canonical_record_digest(record)
        events.append(
            AuditEvent(
                event_id=f"github-audit:{digest}",
                repo=repository,
                timestamp=parse_timestamp(timestamp_value),
                event_type=action,
                actor=actor,
                source="github_org_audit_log",
                authorized=None,
                expected=None,
                third_party=None,
                evidence_refs=[f"{evidence_prefix}:{index}:{digest[:16]}"],
                details={
                    "record_sha256": digest,
                    "visibility": _visibility(_first(record, _NEW_VISIBILITY_KEYS)),
                    "previous_visibility": _visibility(_first(record, _OLD_VISIBILITY_KEYS)),
                },
            )
        )
    return sorted(events, key=lambda event: (event.timestamp, event.repo, event.event_type, event.event_id))


def coverage_summary(
    records: Sequence[Mapping[str, Any]],
    *,
    expected_repositories: Iterable[str] = (),
    organization: str | None = None,
) -> dict[str, Any]:
    transitions = extract_visibility_transitions(records, organization=organization)
    repositories_with_visibility = {item.repository for item in transitions}
    expected = set(expected_repositories)
    missing = sorted(expected - repositories_with_visibility)
    return {
        "records_received": len(records),
        "visibility_transition_count": len(transitions),
        "repositories_with_visibility_evidence": len(repositories_with_visibility),
        "expected_repository_count": len(expected),
        "repositories_missing_visibility_evidence": missing,
        "historical_visibility_complete": bool(expected) and not missing,
        "clean_audit_effect": False,
    }


def _first(record: Mapping[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in record and record[key] not in (None, ""):
            return record[key]
    return None


def _visibility(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    return normalized if normalized in _VISIBILITIES else None


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
