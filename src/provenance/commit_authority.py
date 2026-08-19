#!/usr/bin/env python3
"""Historical commit actor/authority resolution.

Current repository membership is not historical authorization evidence.  This
module therefore resolves an actor only when a dated authority record covers
the event time. Missing actor metadata or missing historical authority evidence
fails closed to an unresolved status.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence
import json

from .historical import AuditStatus


@dataclass(frozen=True)
class AuthorityRecord:
    actor: str
    authority: str
    source_ref: str
    start: datetime
    end: Optional[datetime] = None
    actor_kind: Optional[str] = None
    expected: bool = True
    third_party: bool = False
    token_hash: Optional[str] = None
    app_slug: Optional[str] = None

    def covers(self, timestamp: datetime) -> bool:
        timestamp = _utc(timestamp)
        if timestamp < _utc(self.start):
            return False
        return self.end is None or timestamp <= _utc(self.end)


@dataclass(frozen=True)
class CommitAuthorityResolution:
    repository: str
    commit_sha: str
    timestamp: datetime
    actor: Optional[str]
    actor_kind: Optional[str]
    status: AuditStatus
    authority: Optional[str]
    authority_source_ref: Optional[str]
    reason: str
    evidence_refs: Sequence[str]

    def canonical_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        value["timestamp"] = _utc(self.timestamp).isoformat()
        value["status"] = self.status.value
        value["evidence_refs"] = sorted(set(self.evidence_refs))
        return value

    def digest(self) -> str:
        encoded = json.dumps(
            self.canonical_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return sha256(encoded).hexdigest()


def resolve_commit_authority(
    commit: Mapping[str, Any],
    records: Iterable[AuthorityRecord],
    *,
    repository: Optional[str] = None,
    actor_override: Optional[str] = None,
    actor_kind_override: Optional[str] = None,
    evidence_refs: Optional[Iterable[str]] = None,
) -> CommitAuthorityResolution:
    """Resolve one commit without inferring historical authority from today.

    ``commit`` may be a connector-normalized commit or a GitHub REST-shaped
    commit mapping. A dated ``AuthorityRecord`` must cover the commit time for
    the event to become attributable.
    """

    repo = repository or str(commit.get("repository_full_name") or "")
    sha = str(commit.get("sha") or commit.get("commit_sha") or "")
    timestamp = _extract_timestamp(commit)
    actor, actor_kind = _extract_actor(commit)
    actor = actor_override or actor
    actor_kind = actor_kind_override or actor_kind
    refs = list(evidence_refs or [])

    if not sha:
        return CommitAuthorityResolution(
            repository=repo,
            commit_sha="",
            timestamp=timestamp,
            actor=actor,
            actor_kind=actor_kind,
            status=AuditStatus.PROVENANCE_GAP,
            authority=None,
            authority_source_ref=None,
            reason="commit SHA missing",
            evidence_refs=refs,
        )

    if not actor:
        return CommitAuthorityResolution(
            repository=repo,
            commit_sha=sha,
            timestamp=timestamp,
            actor=None,
            actor_kind=actor_kind,
            status=AuditStatus.PROVENANCE_GAP,
            authority=None,
            authority_source_ref=None,
            reason="actor metadata missing; historical authority cannot be inferred",
            evidence_refs=refs,
        )

    matching: List[AuthorityRecord] = [
        record
        for record in records
        if record.actor.casefold() == actor.casefold()
        and record.covers(timestamp)
        and (record.actor_kind is None or actor_kind is None or record.actor_kind == actor_kind)
    ]

    if not matching:
        return CommitAuthorityResolution(
            repository=repo,
            commit_sha=sha,
            timestamp=timestamp,
            actor=actor,
            actor_kind=actor_kind,
            status=AuditStatus.THIRD_PARTY_UNEXPLAINED,
            authority=None,
            authority_source_ref=None,
            reason="actor observed but no dated historical authority record covers the event",
            evidence_refs=refs,
        )

    matching.sort(key=lambda record: _utc(record.start), reverse=True)
    record = matching[0]
    refs.append(record.source_ref)
    if record.third_party:
        status = (
            AuditStatus.THIRD_PARTY_EXPECTED
            if record.expected
            else AuditStatus.THIRD_PARTY_UNEXPLAINED
        )
    else:
        status = (
            AuditStatus.AUTHORIZED_EXPECTED
            if record.expected
            else AuditStatus.AUTHORIZED_UNEXPLAINED
        )

    return CommitAuthorityResolution(
        repository=repo,
        commit_sha=sha,
        timestamp=timestamp,
        actor=actor,
        actor_kind=actor_kind or record.actor_kind,
        status=status,
        authority=record.authority,
        authority_source_ref=record.source_ref,
        reason="dated authority evidence covers event time",
        evidence_refs=refs,
    )


def normalize_audit_log_authority_record(event: Mapping[str, Any]) -> AuthorityRecord:
    """Normalize a pre-filtered GitHub audit/security-log authority record.

    The caller is responsible for choosing events that actually establish an
    authorization interval; this function only normalizes fields and preserves
    the source reference.
    """

    actor = str(event.get("actor") or event.get("user") or "").strip()
    if not actor:
        raise ValueError("audit authority record requires actor")
    start = _parse_datetime(event.get("start") or event.get("created_at") or event.get("timestamp"))
    end_raw = event.get("end") or event.get("revoked_at") or event.get("removed_at")
    end = _parse_datetime(end_raw) if end_raw else None
    source_ref = str(event.get("source_ref") or event.get("request_id") or "").strip()
    if not source_ref:
        raise ValueError("audit authority record requires source_ref")
    return AuthorityRecord(
        actor=actor,
        actor_kind=event.get("actor_kind"),
        authority=str(event.get("authority") or event.get("role") or "UNKNOWN"),
        source_ref=source_ref,
        start=start,
        end=end,
        expected=bool(event.get("expected", True)),
        third_party=bool(event.get("third_party", False)),
        token_hash=event.get("token_hash"),
        app_slug=event.get("app_slug"),
    )


def _extract_actor(commit: Mapping[str, Any]) -> tuple[Optional[str], Optional[str]]:
    for key in ("author", "committer"):
        value = commit.get(key)
        if isinstance(value, Mapping):
            login = value.get("login")
            if login:
                return str(login), str(value.get("type") or "github_login")
        elif isinstance(value, str) and value.strip():
            return value.strip(), "text_identity"
    nested = commit.get("commit")
    if isinstance(nested, Mapping):
        for key in ("author", "committer"):
            value = nested.get(key)
            if isinstance(value, Mapping):
                name = value.get("name") or value.get("email")
                if name:
                    return str(name), "git_identity"
    return None, None


def _extract_timestamp(commit: Mapping[str, Any]) -> datetime:
    for key in ("created_at", "timestamp", "committed_at", "authored_at"):
        if commit.get(key):
            return _parse_datetime(commit[key])
    nested = commit.get("commit")
    if isinstance(nested, Mapping):
        for who in ("committer", "author"):
            value = nested.get(who)
            if isinstance(value, Mapping) and value.get("date"):
                return _parse_datetime(value["date"])
    raise ValueError("commit timestamp missing")


def _parse_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return _utc(value)
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    return _utc(parsed)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
