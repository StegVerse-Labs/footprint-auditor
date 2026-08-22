#!/usr/bin/env python3
"""Materialize public repositories at an immutable historical cutoff.

This helper is intentionally credentialless. It accepts only repositories marked
public in the retained ecosystem manifest, clones them through anonymous HTTPS,
resolves the last commit on the remote default branch at or before the requested
cutoff, checks out that exact SHA, and emits the manifest consumed by audit_runner.

It grants no write, release, runtime, or credential authority.
"""

from __future__ import annotations

from argparse import ArgumentParser
from pathlib import Path
from typing import Iterable, List, Mapping, Optional
import csv
import json
import re
import subprocess


OUTPUT_SCHEMA = "stegverse.materialized-repository-manifest.v1"
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _run(args: List[str], *, cwd: Optional[Path] = None) -> str:
    completed = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={
            "PATH": __import__("os").environ.get("PATH", ""),
            "HOME": __import__("os").environ.get("HOME", ""),
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
        },
    )
    return completed.stdout.strip()


def load_public_inventory(path: Path) -> Mapping[str, str]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    inventory = {}
    for row in rows:
        name = str(row.get("full_name") or "").strip()
        visibility = str(row.get("visibility") or "").strip().lower()
        if not _REPOSITORY.fullmatch(name):
            raise ValueError(f"invalid repository name in inventory: {name!r}")
        if visibility not in {"public", "private"}:
            raise ValueError(f"invalid visibility for {name}: {visibility!r}")
        if name in inventory:
            raise ValueError(f"duplicate repository in inventory: {name}")
        inventory[name] = visibility
    return inventory


def validate_selection(inventory: Mapping[str, str], repositories: Iterable[str]) -> List[str]:
    selected = []
    seen = set()
    for raw in repositories:
        name = raw.strip()
        if not name:
            continue
        if not _REPOSITORY.fullmatch(name):
            raise ValueError(f"invalid repository selection: {name!r}")
        if name in seen:
            raise ValueError(f"duplicate repository selection: {name}")
        seen.add(name)
        visibility = inventory.get(name)
        if visibility is None:
            raise ValueError(f"repository is not in exact inventory: {name}")
        if visibility != "public":
            raise ValueError(f"credentialless materializer refuses non-public repository: {name}")
        selected.append(name)
    if not selected:
        raise ValueError("at least one public repository must be selected")
    return sorted(selected)


def materialize_repository(repository: str, root: Path, cutoff: str) -> dict:
    owner, name = repository.split("/", 1)
    destination = root / owner / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise ValueError(f"destination already exists: {destination}")

    url = f"https://github.com/{owner}/{name}.git"
    _run(["git", "clone", "--no-tags", url, str(destination)])

    remote_head = _run(
        ["git", "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"],
        cwd=destination,
    )
    if not remote_head.startswith("origin/"):
        raise RuntimeError(f"unexpected remote HEAD for {repository}: {remote_head}")
    target_sha = _run(
        ["git", "rev-list", "-1", f"--before={cutoff}", remote_head],
        cwd=destination,
    )
    if not re.fullmatch(r"[0-9a-f]{40}", target_sha):
        raise RuntimeError(f"no exact cutoff commit resolved for {repository}")

    _run(["git", "checkout", "--detach", target_sha], cwd=destination)
    _run(["git", "reset", "--hard", target_sha], cwd=destination)
    _run(["git", "clean", "-fdx"], cwd=destination)
    observed = _run(["git", "rev-parse", "HEAD"], cwd=destination)
    if observed != target_sha:
        raise RuntimeError(f"checkout mismatch for {repository}: {observed} != {target_sha}")
    if _run(["git", "status", "--porcelain=v1"], cwd=destination):
        raise RuntimeError(f"materialized worktree is dirty: {repository}")

    return {
        "repository": repository,
        "path": str(destination.resolve()),
        "expected_sha": target_sha,
    }


def build_manifest(inventory_path: Path, selected_path: Path, root: Path, cutoff: str) -> dict:
    inventory = load_public_inventory(inventory_path)
    repositories = validate_selection(
        inventory,
        selected_path.read_text(encoding="utf-8").splitlines(),
    )
    rows = [materialize_repository(repo, root, cutoff) for repo in repositories]
    return {"schema": OUTPUT_SCHEMA, "repositories": rows}


def main(argv: Optional[List[str]] = None) -> int:
    parser = ArgumentParser(description="Materialize exact public repository commits without credentials")
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--selection", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--cutoff", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        manifest = build_manifest(args.inventory, args.selection, args.root, args.cutoff)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({"materialized": len(manifest["repositories"]), "credential_received": False}, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"materialized": 0, "credential_received": False, "error": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
