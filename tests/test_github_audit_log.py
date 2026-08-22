from datetime import datetime, timezone

from src.provenance.github_audit_log import (
    build_exposure_intervals,
    coverage_summary,
    extract_visibility_transitions,
    normalize_actor_events,
    parse_timestamp,
)
from src.provenance.historical import AuditStatus


def test_parse_timestamp_accepts_iso_epoch_seconds_and_milliseconds():
    expected = datetime(2026, 8, 19, 12, 0, tzinfo=timezone.utc)
    assert parse_timestamp("2026-08-19T12:00:00Z") == expected
    assert parse_timestamp(1787140800) == expected
    assert parse_timestamp(1787140800000) == expected


def test_visibility_transitions_are_normalized_and_blob_bound():
    records = [
        {
            "action": "repo.create",
            "repo": "example",
            "actor": "owner",
            "created_at": "2026-01-01T00:00:00Z",
            "visibility": "public",
        },
        {
            "action": "repo.change_visibility",
            "repository": "ExampleOrg/example",
            "actor_login": "owner",
            "@timestamp": "2026-02-01T00:00:00Z",
            "previous_visibility": "public",
            "new_visibility": "private",
        },
    ]
    transitions = extract_visibility_transitions(records, organization="ExampleOrg")
    assert [item.repository for item in transitions] == ["ExampleOrg/example", "ExampleOrg/example"]
    assert [item.visibility for item in transitions] == ["public", "private"]
    assert transitions[1].previous_visibility == "public"
    assert len(transitions[0].record_sha256) == 64
    assert transitions[0].evidence_ref.startswith("github-org-audit-log:0:")


def test_exposure_intervals_reconstruct_ordered_visibility_without_guessing_pre_history():
    records = [
        {
            "action": "repo.create",
            "repo": "ExampleOrg/example",
            "created_at": "2026-01-01T00:00:00Z",
            "visibility": "public",
        },
        {
            "action": "repo.change_visibility",
            "repo": "ExampleOrg/example",
            "created_at": "2026-03-01T00:00:00Z",
            "new_visibility": "private",
        },
    ]
    intervals = build_exposure_intervals(extract_visibility_transitions(records))
    assert len(intervals) == 2
    assert intervals[0].visibility == "public"
    assert intervals[0].start == datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert intervals[0].end == datetime(2026, 3, 1, tzinfo=timezone.utc)
    assert intervals[1].visibility == "private"
    assert intervals[1].end is None


def test_actor_events_remain_provenance_gap_until_dated_authority_is_reconciled():
    records = [
        {
            "action": "repo.change_visibility",
            "repo": "ExampleOrg/example",
            "actor": "some-actor",
            "created_at": "2026-03-01T00:00:00Z",
            "previous_visibility": "public",
            "visibility": "private",
        }
    ]
    events = normalize_actor_events(records)
    assert len(events) == 1
    event = events[0]
    assert event.actor == "some-actor"
    assert event.authorized is None
    assert event.third_party is None
    assert event.status is AuditStatus.PROVENANCE_GAP
    assert event.details["visibility"] == "private"
    assert event.details["previous_visibility"] == "public"


def test_coverage_summary_fails_open_claim_when_expected_repo_has_no_visibility_evidence():
    records = [
        {
            "action": "repo.create",
            "repo": "ExampleOrg/one",
            "created_at": "2026-01-01T00:00:00Z",
            "visibility": "public",
        }
    ]
    summary = coverage_summary(
        records,
        expected_repositories=["ExampleOrg/one", "ExampleOrg/two"],
    )
    assert summary["visibility_transition_count"] == 1
    assert summary["repositories_missing_visibility_evidence"] == ["ExampleOrg/two"]
    assert summary["historical_visibility_complete"] is False
    assert summary["clean_audit_effect"] is False
