from src.provenance.inventory import (
    RepositorySnapshot,
    build_inventory_snapshot,
    verify_inventory_snapshot,
)


def _repo(repo_id, full_name, visibility):
    owner, name = full_name.split("/", 1)
    return RepositorySnapshot(
        repository_id=str(repo_id),
        full_name=full_name,
        owner=owner,
        name=name,
        visibility=visibility,
        default_branch="main",
        archived=False,
        installation_id="1",
        permissions={"pull": True, "push": True},
    )


def test_inventory_is_deterministic_and_counts_visibility():
    repos = [_repo(2, "Org/private", "private"), _repo(1, "Org/public", "public")]
    first = build_inventory_snapshot(
        repos, as_of="2026-08-19T18:55:00Z", installation_count=1
    )
    second = build_inventory_snapshot(
        list(reversed(repos)), as_of="2026-08-19T18:55:00Z", installation_count=1
    )
    assert first["inventory_sha256"] == second["inventory_sha256"]
    assert first["visibility_counts"] == {"private": 1, "public": 1}
    assert verify_inventory_snapshot(first)


def test_connector_normalization_preserves_current_visibility_not_history():
    repo = RepositorySnapshot.from_connector(
        {
            "id": "42",
            "name": "Example",
            "repository_full_name": "Org/Example",
            "owner": {"login": "Org"},
            "visibility": "private",
            "default_branch": "main",
            "archived": False,
            "permissions": {"pull": True, "push": False},
        },
        installation_id="99",
    )
    assert repo.visibility == "private"
    assert repo.installation_id == "99"
    assert repo.permissions["push"] is False
