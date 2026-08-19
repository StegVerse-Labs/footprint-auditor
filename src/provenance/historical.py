#!/usr/bin/env python3
"""Historical provenance model for ecosystem-wide integrity auditing.

The module deliberately separates *evidence coverage* from *malice claims*.
An event may be technically valid yet remain unresolved if the actor,
authority, or causal chain cannot be established from available evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set
import json


class AuditStatus(str, Enum):
    AUTHORIZED_EXPECTED = "AUTHORIZED_EXPECTED"
    AUTHORIZED_UNEXPLAINED = "AUTHORIZED_UNEXPLAINED"
    THIRD_PARTY_EXPECTED = "THIRD_PARTY_EXPECTED"
    THIRD_PARTY_UNEXPLAINED = "THIRD_PARTY_UNEXPLAINED"
    PROVENANCE_GAP = "PROVENANCE_GAP"
    SUSPICIOUS = "SUSPICIOUS"
    CONFIRMED_UNAUTHORIZED = "CONFIRMED_UNAUTHORIZED"
    CONFIRMED_MALICIOUS = "CONFIRMED_MALICIOUS"


@dataclass(frozen=True)
class AuditBoundary:
    start: Optional[datetime] = None
    end: Optional[datetime] = None

    def contains(self, timestamp: datetime) -> bool:
        timestamp = _utc(timestamp)
        if self.start is not None and timestamp < _utc(self.start):
            return False
        if self.end is not None and timestamp > _utc(self.end):
            return False
        return True


@dataclass(frozen=True)
class ExposureInterval:
    repo: str
    visibility: str
    start: datetime
    end: Optional[datetime] = None
    evidence_ref: Optional[str] = None

    def contains(self, timestamp: datetime) -> bool:
        timestamp = _utc(timestamp)
        if timestamp < _utc(self.start):
            return False
        return self.end is None or timestamp <= _utc(self.end)


@dataclass
class AuditEvent:
    event_id: str
    repo: str
    timestamp: datetime
    event_type: str
    actor: Optional[str] = None
    actor_kind: Optional[str] = None
    commit_sha: Optional[str] = None
    parent_shas: List[str] = field(default_factory=list)
    source: str = "git"
    authorized: Optional[bool] = None
    expected: Optional[bool] = None
    third_party: Optional[bool] = None
    malicious_evidence: bool = False
    suspicious_evidence: bool = False
    evidence_refs: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    status: AuditStatus = AuditStatus.PROVENANCE_GAP

    def canonical_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        value["timestamp"] = _utc(self.timestamp).isoformat()
        value["status"] = self.status.value
        value["parent_shas"] = sorted(self.parent_shas)
        value["evidence_refs"] = sorted(self.evidence_refs)
        return value

    def digest(self) -> str:
        payload = json.dumps(
            self.canonical_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return sha256(payload).hexdigest()


def classify_event(event: AuditEvent) -> AuditStatus:
    """Classify without treating missing evidence as benign."""
    if event.malicious_evidence:
        return AuditStatus.CONFIRMED_MALICIOUS
    if event.authorized is False:
        return AuditStatus.CONFIRMED_UNAUTHORIZED
    if event.suspicious_evidence:
        return AuditStatus.SUSPICIOUS
    if event.authorized is None:
        return AuditStatus.PROVENANCE_GAP
    if event.third_party:
        if event.expected is True:
            return AuditStatus.THIRD_PARTY_EXPECTED
        return AuditStatus.THIRD_PARTY_UNEXPLAINED
    if event.authorized is True:
        if event.expected is True:
            return AuditStatus.AUTHORIZED_EXPECTED
        return AuditStatus.AUTHORIZED_UNEXPLAINED
    return AuditStatus.PROVENANCE_GAP


class AuditLedger:
    """Deterministic event ledger with explicit evidence-coverage accounting."""

    def __init__(
        self,
        boundary: Optional[AuditBoundary] = None,
        authorized_actors: Optional[Iterable[str]] = None,
        expected_third_parties: Optional[Iterable[str]] = None,
    ) -> None:
        self.boundary = boundary or AuditBoundary()
        self.authorized_actors: Set[str] = set(authorized_actors or [])
        self.expected_third_parties: Set[str] = set(expected_third_parties or [])
        self.events: List[AuditEvent] = []
        self.exposure_intervals: List[ExposureInterval] = []

    def add_exposure_interval(self, interval: ExposureInterval) -> None:
        self.exposure_intervals.append(interval)

    def visibility_at(self, repo: str, timestamp: datetime) -> Optional[str]:
        matches = [
            interval for interval in self.exposure_intervals
            if interval.repo == repo and interval.contains(timestamp)
        ]
        if not matches:
            return None
        matches.sort(key=lambda item: _utc(item.start), reverse=True)
        return matches[0].visibility

    def add_event(self, event: AuditEvent) -> AuditEvent:
        if not self.boundary.contains(event.timestamp):
            return event

        if event.actor and event.authorized is None:
            event.authorized = event.actor in self.authorized_actors
        if event.actor and event.third_party is None:
            event.third_party = event.actor not in self.authorized_actors
        if event.actor and event.expected is None and event.third_party:
            event.expected = event.actor in self.expected_third_parties

        event.details.setdefault("visibility", self.visibility_at(event.repo, event.timestamp))
        event.status = classify_event(event)
        self.events.append(event)
        return event

    def unresolved(self) -> List[AuditEvent]:
        unresolved_statuses = {
            AuditStatus.AUTHORIZED_UNEXPLAINED,
            AuditStatus.THIRD_PARTY_UNEXPLAINED,
            AuditStatus.PROVENANCE_GAP,
            AuditStatus.SUSPICIOUS,
            AuditStatus.CONFIRMED_UNAUTHORIZED,
            AuditStatus.CONFIRMED_MALICIOUS,
        }
        return [event for event in self.events if event.status in unresolved_statuses]

    def coverage(self) -> Dict[str, Any]:
        total = len(self.events)
        attributable = sum(
            event.status
            in {
                AuditStatus.AUTHORIZED_EXPECTED,
                AuditStatus.THIRD_PARTY_EXPECTED,
            }
            for event in self.events
        )
        unresolved = total - attributable
        ratio = 1.0 if total == 0 else attributable / total
        return {
            "events": total,
            "fully_attributable": attributable,
            "unresolved": unresolved,
            "coverage_ratio": ratio,
        }

    def summary(self) -> Dict[str, Any]:
        counts = {status.value: 0 for status in AuditStatus}
        for event in self.events:
            counts[event.status.value] += 1
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "boundary": {
                "start": _iso(self.boundary.start),
                "end": _iso(self.boundary.end),
            },
            "coverage": self.coverage(),
            "status_counts": counts,
            "unresolved_event_ids": [event.event_id for event in self.unresolved()],
            "ledger_root": self.merkleish_root(),
        }

    def merkleish_root(self) -> str:
        """Stable aggregate digest for replay/reconstruction evidence.

        This is not represented as a formal Merkle tree; it is a deterministic
        root over sorted event digests and is named conservatively to avoid
        implying tree proofs that are not implemented here.
        """
        digests = sorted(event.digest() for event in self.events)
        return sha256("".join(digests).encode("ascii")).hexdigest()

    def to_jsonl(self) -> str:
        ordered = sorted(
            self.events,
            key=lambda e: (_utc(e.timestamp), e.repo, e.event_type, e.event_id),
        )
        return "\n".join(json.dumps(e.canonical_dict(), sort_keys=True) for e in ordered)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return None if value is None else _utc(value).isoformat()
