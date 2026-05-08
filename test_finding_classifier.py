from pathlib import Path

from src.classifier import FindingClassifier


def write_rules(path: Path) -> None:
    path.write_text(
        """
version: "0.2.0"
invariants:
  - id: INV-001
    name: no_medical_exposure
    description: Medical references are inadmissible
    severity: CRITICAL
    action: DENY
    remediation: immediate_removal
    patterns:
      - keyword: seizure
      - keyword: medical
  - id: INV-006
    name: service_identity_required
    description: Service identity required
    severity: HIGH
    action: DENY
    remediation: commit_rewriter
""",
        encoding="utf-8",
    )


def test_medical_keyword_denied(tmp_path):
    rules = tmp_path / "severity_rules.yaml"
    write_rules(rules)

    classifier = FindingClassifier(rules)
    result = classifier.classify(
        {
            "repo": "demo",
            "message": "remove medical note from public metadata",
            "author_email": "bot@stegverse.org",
            "author_name": "StegVerse Bot",
        }
    )

    assert result.decision == "DENY"
    assert result.severity == "CRITICAL"
    assert result.invariant_id == "INV-001"
    assert result.remediation == "immediate_removal"


def test_non_service_identity_denied(tmp_path):
    rules = tmp_path / "severity_rules.yaml"
    write_rules(rules)

    classifier = FindingClassifier(rules)
    result = classifier.classify(
        {
            "repo": "demo",
            "message": "normal commit message",
            "author_email": "person@example.com",
            "author_name": "Person",
        }
    )

    assert result.decision == "DENY"
    assert result.severity == "HIGH"
    assert result.invariant_id == "INV-006"
    assert result.remediation == "commit_rewriter"


def test_service_identity_allowed_when_no_rule_matches(tmp_path):
    rules = tmp_path / "severity_rules.yaml"
    write_rules(rules)

    classifier = FindingClassifier(rules)
    result = classifier.classify(
        {
            "repo": "demo",
            "message": "routine product update",
            "author_email": "builder@stegverse.org",
            "author_name": "StegVerse Bot",
        }
    )

    assert result.decision == "ALLOW"
    assert result.severity == "LOW"
    assert result.invariant_id is None


def test_preclassified_scanner_finding_preserved(tmp_path):
    rules = tmp_path / "severity_rules.yaml"
    write_rules(rules)

    classifier = FindingClassifier(rules)
    result = classifier.classify(
        {
            "repo": "demo",
            "message": "already found",
            "severity": "HIGH",
            "invariant_id": "INV-006",
            "description": "Commit from non-service identity",
            "remediation": "commit_rewriter",
        }
    )

    assert result.decision == "DENY"
    assert result.invariant_id == "INV-006"
    assert result.source == "scanner_preclassified"


def test_summary_counts(tmp_path):
    rules = tmp_path / "severity_rules.yaml"
    write_rules(rules)

    classifier = FindingClassifier(rules)
    results = classifier.classify_many(
        [
            {"message": "medical metadata", "author_email": "bot@stegverse.org", "author_name": "StegVerse Bot"},
            {"message": "routine update", "author_email": "bot@stegverse.org", "author_name": "StegVerse Bot"},
        ]
    )
    summary = classifier.summarize(results)

    assert summary["total"] == 2
    assert summary["by_decision"]["DENY"] == 1
    assert summary["by_decision"]["ALLOW"] == 1
