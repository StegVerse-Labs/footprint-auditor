from datetime import datetime, timezone

from src.provenance.commit_authority import (
    AuthorityRecord,
    normalize_audit_log_authority_record,
    resolve_commit_authority,
)
from src.provenance.historical import AuditStatus


def _commit(actor="StegVerse", when="2026-08-19T18:44:13Z"):
    return {
        "sha": "a" * 40,
        "repository_full_name": "StegVerse-Labs/TV",
        "created_at": when,
        "author": {"login": actor, "type": "User"} if actor else None,
        "committer": {"login": actor, "type": "User"} if actor else None,
    }


def test_missing_actor_fails_closed():
    result = resolve_commit_authority(_commit(actor=None), [])
    assert result.status is AuditStatus.PROVENANCE_GAP
    assert "actor metadata missing" in result.reason


def test_current_name_without_historical_record_is_unresolved():
    result = resolve_commit_authority(_commit(), [])
    assert result.status is AuditStatus.THIRD_PARTY_UNEXPLAINED
    assert result.authority is None


def test_dated_authority_record_resolves_expected_actor():
    record = AuthorityRecord(
        actor="StegVerse",
        actor_kind="User",
        authority="TV/TVC governed primary account",
        source_ref="audit-log:req-123",
        start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        expected=True,
        third_party=False,
    )
    result = resolve_commit_authority(_commit(), [record])
    assert result.status is AuditStatus.AUTHORIZED_EXPECTED
    assert result.authority_source_ref == "audit-log:req-123"
    assert "audit-log:req-123" in result.evidence_refs


def test_record_outside_time_window_does_not_backfill_history():
    record = AuthorityRecord(
        actor="StegVerse",
        actor_kind="User",
        authority="current owner",
        source_ref="membership:today",
        start=datetime(2026, 8, 20, tzinfo=timezone.utc),
    )
    result = resolve_commit_authority(_commit(), [record])
    assert result.status is AuditStatus.THIRD_PARTY_UNEXPLAINED


def test_expected_third_party_remains_distinct_from_primary_authority():
    record = AuthorityRecord(
        actor="dependabot[bot]",
        authority="approved dependency bot",
        source_ref="audit-log:app-install",
        start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        third_party=True,
        expected=True,
    )
    result = resolve_commit_authority(_commit(actor="dependabot[bot]"), [record])
    assert result.status is AuditStatus.THIRD_PARTY_EXPECTED


def test_audit_log_record_normalization_preserves_token_and_app_evidence():
    record = normalize_audit_log_authority_record(
        {
            "actor": "actions-user",
            "actor_kind": "github_app",
            "authority": "bounded write test",
            "created_at": "2026-05-01T00:00:00Z",
            "revoked_at": "2026-05-31T00:00:00Z",
            "source_ref": "audit-log:abc",
            "token_hash": "sha256:deadbeef",
            "app_slug": "example-app",
            "third_party": True,
            "expected": False,
        }
    )
    assert record.token_hash == "sha256:deadbeef"
    assert record.app_slug == "example-app"
    assert record.third_party is True
    assert record.expected is False
