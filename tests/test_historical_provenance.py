from datetime import datetime, timezone

from src.provenance.historical import (
    AuditBoundary,
    AuditEvent,
    AuditLedger,
    AuditStatus,
    ExposureInterval,
)


def dt(day: int) -> datetime:
    return datetime(2026, 8, day, 12, 0, tzinfo=timezone.utc)


def test_public_then_private_visibility_is_time_aware():
    ledger = AuditLedger(boundary=AuditBoundary(start=dt(1), end=dt(19)))
    ledger.add_exposure_interval(
        ExposureInterval("StegVerse-Labs/demo", "public", dt(1), dt(9))
    )
    ledger.add_exposure_interval(
        ExposureInterval("StegVerse-Labs/demo", "private", dt(10), None)
    )

    first = ledger.add_event(
        AuditEvent(
            event_id="e1",
            repo="StegVerse-Labs/demo",
            timestamp=dt(5),
            event_type="commit",
            actor="TVC Agent",
            authorized=True,
            expected=True,
        )
    )
    second = ledger.add_event(
        AuditEvent(
            event_id="e2",
            repo="StegVerse-Labs/demo",
            timestamp=dt(15),
            event_type="commit",
            actor="TVC Agent",
            authorized=True,
            expected=True,
        )
    )

    assert first.details["visibility"] == "public"
    assert second.details["visibility"] == "private"


def test_missing_authority_evidence_never_becomes_benign():
    ledger = AuditLedger()
    event = ledger.add_event(
        AuditEvent(
            event_id="gap",
            repo="StegVerse-Labs/demo",
            timestamp=dt(5),
            event_type="workflow_change",
        )
    )
    assert event.status == AuditStatus.PROVENANCE_GAP
    assert ledger.coverage()["unresolved"] == 1


def test_expected_third_party_is_distinct_from_internal_authority():
    ledger = AuditLedger(
        authorized_actors={"TVC Agent"},
        expected_third_parties={"dependabot[bot]"},
    )
    event = ledger.add_event(
        AuditEvent(
            event_id="dep",
            repo="StegVerse-Labs/demo",
            timestamp=dt(5),
            event_type="dependency_update",
            actor="dependabot[bot]",
        )
    )
    assert event.status == AuditStatus.THIRD_PARTY_EXPECTED


def test_unexpected_actor_does_not_silently_pass():
    ledger = AuditLedger(authorized_actors={"TVC Agent"})
    event = ledger.add_event(
        AuditEvent(
            event_id="unknown",
            repo="StegVerse-Labs/demo",
            timestamp=dt(5),
            event_type="commit",
            actor="unknown-bot",
        )
    )
    assert event.status == AuditStatus.CONFIRMED_UNAUTHORIZED


def test_malicious_evidence_has_highest_precedence():
    ledger = AuditLedger(authorized_actors={"TVC Agent"})
    event = ledger.add_event(
        AuditEvent(
            event_id="mal",
            repo="StegVerse-Labs/demo",
            timestamp=dt(5),
            event_type="artifact",
            actor="TVC Agent",
            malicious_evidence=True,
        )
    )
    assert event.status == AuditStatus.CONFIRMED_MALICIOUS


def test_ledger_output_is_deterministic_for_same_events():
    events = [
        AuditEvent("b", "r", dt(5), "commit", authorized=True, expected=True),
        AuditEvent("a", "r", dt(4), "commit", authorized=True, expected=True),
    ]
    first = AuditLedger()
    second = AuditLedger()
    for event in events:
        first.add_event(event)
    for event in reversed(events):
        clone = AuditEvent(
            event_id=event.event_id,
            repo=event.repo,
            timestamp=event.timestamp,
            event_type=event.event_type,
            authorized=True,
            expected=True,
        )
        second.add_event(clone)

    assert first.to_jsonl() == second.to_jsonl()
    assert first.merkleish_root() == second.merkleish_root()
