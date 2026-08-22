from pathlib import Path

import pytest

from scripts.materialize_public_batch import load_public_inventory, validate_selection


def test_exact_inventory_allows_public_selection(tmp_path: Path):
    path = tmp_path / "inventory.csv"
    path.write_text("full_name,visibility\nOrg/Public,public\nOrg/Private,private\n", encoding="utf-8")
    inventory = load_public_inventory(path)
    assert validate_selection(inventory, ["Org/Public"]) == ["Org/Public"]


def test_credentialless_materializer_rejects_private_repository(tmp_path: Path):
    path = tmp_path / "inventory.csv"
    path.write_text("full_name,visibility\nOrg/Public,public\nOrg/Private,private\n", encoding="utf-8")
    inventory = load_public_inventory(path)
    with pytest.raises(ValueError, match="refuses non-public"):
        validate_selection(inventory, ["Org/Private"])


def test_selection_must_be_unique_and_inventory_bound(tmp_path: Path):
    path = tmp_path / "inventory.csv"
    path.write_text("full_name,visibility\nOrg/Public,public\n", encoding="utf-8")
    inventory = load_public_inventory(path)
    with pytest.raises(ValueError, match="duplicate repository selection"):
        validate_selection(inventory, ["Org/Public", "Org/Public"])
    with pytest.raises(ValueError, match="not in exact inventory"):
        validate_selection(inventory, ["Org/Other"])
