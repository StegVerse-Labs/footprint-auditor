#!/usr/bin/env python3
"""Current repository inventory snapshots for historical reconciliation."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Mapping, Optional
import json


@dataclass(frozen=True)
class RepositorySnapshot:
    repository_id: str
    full_name: str
    owner: str
    name: str
    visibility: str
    default_branch: str
    archived: bool
    installation_id: Optional[str] = None
    permissions: Optional[Dict[str, bool]] = None

    @classmethod
    def from_connector(
        cls, repo: Mapping[str, Any], *, installation_id: Optional[str] = None
    ) -> "RepositorySnapshot":
        owner_value = repo.get("owner") or {}
        owner = (
            str(owner_value.get("login") or "")
            if isinstance(owner_value, Mapping)
            else str(owner_value)
        )
        full_name = str(
            repo.get("repository_full_name")
            or repo.get("full_name")
            or f"{owner}/{repo.get('name', '')}"
        )
        return cls(
            repository_id=str(repo.get("id") or ""),
            full_name=full_name,
            owner=owner,
            name=str(repo.get("name") or full_name.rsplit("/", 1)[-1]),
            visibility=str(repo.get("visibility") or "unknown"),
            default_branch=str(repo.get("default_branch") or ""),
            archived=bool(repo.get("archived", False)),
            installation_id=str(installation_id) if installation_id is not None else None,
            permissions=(
                {str(k): bool(v) for k, v in sorted(repo.get("permissions", {}).items())}
                if isinstance(repo.get("permissions"), Mapping)
                else None
            ),
        )

    def canonical_dict(self) -> Dict[str, Any]:
        return asdict(self)


def build_inventory_snapshot(
    repositories: Iterable[RepositorySnapshot],
    *,
    as_of: str,
    installation_count: int,
    source: str = "connected-github-installations",
) -> Dict[str, Any]:
    ordered = sorted(repositories, key=lambda repo: (repo.full_name, repo.repository_id))
    visibility_counts: Dict[str, int] = {}
    owner_counts: Dict[str, int] = {}
    for repo in ordered:
        visibility_counts[repo.visibility] = visibility_counts.get(repo.visibility, 0) + 1
        owner_counts[repo.owner] = owner_counts.get(repo.owner, 0) + 1
    body: Dict[str, Any] = {
        "schema": "stegverse.repository-inventory.v1",
        "as_of": as_of,
        "source": source,
        "installation_count": installation_count,
        "repository_count": len(ordered),
        "visibility_counts": dict(sorted(visibility_counts.items())),
        "owner_counts": dict(sorted(owner_counts.items())),
        "repositories": [repo.canonical_dict() for repo in ordered],
    }
    body["inventory_sha256"] = inventory_digest(body)
    return body


def inventory_digest(snapshot: Mapping[str, Any]) -> str:
    copy = dict(snapshot)
    copy.pop("inventory_sha256", None)
    encoded = json.dumps(copy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(encoded).hexdigest()


def verify_inventory_snapshot(snapshot: Mapping[str, Any]) -> bool:
    expected = str(snapshot.get("inventory_sha256") or "")
    return bool(expected) and inventory_digest(snapshot) == expected
