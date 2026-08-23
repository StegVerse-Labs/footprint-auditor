from hashlib import sha256
import json
from pathlib import Path
import tempfile

from scripts.import_github_audit_log import (
    build_receipt,
    load_expected_repositories,
    load_records,
    verify_receipt,
)


def test_load_records_accepts_array_wrapped_records_and_jsonl():
    sample = [{"action": "repo.create", "repo": "Org/one", "created_at": "2026-01-01T00:00:00Z"}]
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        array_path = root / "array.json"
        wrapped_path = root / "wrapped.json"
        jsonl_path = root / "events.jsonl"
        array_path.write_text(json.dumps(sample), encoding="utf-8")
        wrapped_path.write_text(json.dumps({"records": sample}), encoding="utf-8")
        jsonl_path.write_text(json.dumps(sample[0]) + "\n", encoding="utf-8")
        assert load_records(array_path) == sample
        assert load_records(wrapped_path) == sample
        assert load_records(jsonl_path) == sample


def test_expected_repository_loader_filters_organization():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "inventory.csv"
        path.write_text(
            "full_name,visibility\nOrg/one,public\nOther/two,private\nOrg/three,private\n",
            encoding="utf-8",
        )
        assert load_expected_repositories(path, organization="Org") == ["Org/one", "Org/three"]


def test_receipt_is_deterministic_actor_safe_and_fail_closed_on_missing_visibility():
    records = [
        {
            "action": "repo.create",
            "repo": "Org/one",
            "actor": "external-actor-value",
            "created_at": "2026-01-01T00:00:00Z",
            "visibility": "public",
        },
        {
            "action": "repo.change_visibility",
            "repo": "Org/one",
            "actor": "external-actor-value",
            "created_at": "2026-02-01T00:00:00Z",
            "previous_visibility": "public",
            "new_visibility": "private",
        },
    ]
    kwargs = {
        "source_sha256": "a" * 64,
        "expected_repositories": ["Org/one", "Org/two"],
        "organization": "Org",
        "boundary_end": "2026-08-19T23:59:59Z",
    }
    first = build_receipt(records, **kwargs)
    second = build_receipt(records, **kwargs)
    assert first == second
    assert verify_receipt(first)
    assert first["historical_visibility_complete"] is False
    assert first["coverage"]["repositories_missing_visibility_evidence"] == ["Org/two"]
    assert first["clean_audit_effect"] is False
    assert first["authority_effect"] is False
    assert first["raw_actor_identifiers_persisted"] is False
    serialized = json.dumps(first, sort_keys=True)
    assert "external-actor-value" not in serialized
    expected_actor_hash = sha256(b"external-actor-value").hexdigest()
    assert {item["actor_sha256"] for item in first["actor_events"]} == {expected_actor_hash}
    assert all(item["actor_identifier_persisted"] is False for item in first["actor_events"])


def test_boundary_excludes_dated_post_cutoff_records_without_dropping_undated_gap_evidence():
    records = [
        {
            "action": "repo.create",
            "repo": "Org/one",
            "created_at": "2026-01-01T00:00:00Z",
            "visibility": "public",
        },
        {
            "action": "repo.change_visibility",
            "repo": "Org/one",
            "created_at": "2026-08-20T00:00:00Z",
            "new_visibility": "private",
        },
        {"action": "repo.access", "repo": "Org/one", "actor": "undated-actor"},
    ]
    receipt = build_receipt(
        records,
        source_sha256="b" * 64,
        expected_repositories=["Org/one"],
        organization="Org",
        boundary_end="2026-08-19T23:59:59Z",
    )
    assert receipt["records_received"] == 3
    assert receipt["records_within_boundary_or_undated"] == 2
    assert len(receipt["visibility_transitions"]) == 1
    assert receipt["visibility_transitions"][0]["visibility"] == "public"
    assert receipt["historical_visibility_complete"] is True
    assert verify_receipt(receipt)


def test_receipt_verification_rejects_mutation():
    receipt = build_receipt([], source_sha256="c" * 64)
    assert verify_receipt(receipt)
    receipt["records_received"] = 99
    assert verify_receipt(receipt) is False
