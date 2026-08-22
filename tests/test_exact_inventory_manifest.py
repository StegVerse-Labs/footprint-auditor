import csv
from pathlib import Path


MANIFEST = Path("evidence/inventory/connected-repositories-2026-08-19-v2.csv")


def _rows():
    with MANIFEST.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_exact_manifest_has_expected_denominator_and_visibility_counts():
    rows = _rows()
    assert len(rows) == 219
    assert len({row["full_name"] for row in rows}) == 219
    assert sum(row["visibility"] == "public" for row in rows) == 76
    assert sum(row["visibility"] == "private" for row in rows) == 143


def test_exact_manifest_contains_all_sixteen_repositories_missing_from_truncated_baseline():
    names = {row["full_name"] for row in _rows()}
    expected = {
        "StegVerse-Labs/Comms-Gateway",
        "StegVerse-Labs/Consumer-Redress-Ledger",
        "StegVerse-Labs/StegBrowser",
        "StegVerse-Labs/StegHealth",
        "StegVerse-Labs/StegMemory",
        "StegVerse-Labs/StegNeuro",
        "StegVerse-Labs/StegNutrition",
        "StegVerse-Labs/StegOps-Notifs",
        "StegVerse-Labs/VCCL",
        "StegVerse-Labs/continuity-search",
        "StegVerse-Labs/device-continuity-layer",
        "StegVerse-Labs/fresh-fruit-scanning",
        "StegVerse-Labs/governed-llm",
        "StegVerse-Labs/media-governance",
        "StegVerse-Labs/repo-standards",
        "StegVerse-Labs/video-engine",
    }
    assert expected <= names
