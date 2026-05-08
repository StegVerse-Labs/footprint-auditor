#!/usr/bin/env python3
"""
footprint-auditor finding classifier.

Reads config/severity_rules.yaml when available and classifies scanner findings
into deterministic ALLOW / DENY records for sanitizer, reporter, workflow, and
receipt layers.

This module performs no repository mutation.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml
except ImportError as exc:
    raise SystemExit("Missing dependency: PyYAML. Install with: python -m pip install pyyaml") from exc


SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
DEFAULT_ALLOWED_SERVICE_DOMAINS = {"@stegverse.org", "@gcat-bcat.engine", "@aact-e.org", "@stegghost.io"}
DEFAULT_ALLOWED_SERVICE_NAMES = {"StegVerse Bot", "GCAT-BCAT Builder", "TVC Agent"}


@dataclass(frozen=True)
class SeverityRule:
    invariant_id: str
    name: str
    description: str
    severity: str
    action: str
    remediation: str
    keywords: tuple[str, ...] = ()
    regexes: tuple[str, ...] = ()
    context_boost: tuple[str, ...] = ()


@dataclass(frozen=True)
class ClassificationResult:
    decision: str
    severity: str
    invariant_id: str | None
    rule_name: str | None
    remediation: str | None
    confidence: float
    reasons: tuple[str, ...]
    source: str
    original: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class FindingClassifier:
    """Classify scanner findings against configured GCAT/BCAT exposure rules."""

    def __init__(self, severity_rules_path: str | Path = "config/severity_rules.yaml") -> None:
        self.severity_rules_path = Path(severity_rules_path)
        self.rules = self._load_rules(self.severity_rules_path)

    def classify(self, finding: dict[str, Any]) -> ClassificationResult:
        normalized = dict(finding)

        preclassified = self._classify_preexisting_finding(normalized)
        if preclassified is not None:
            return preclassified

        service_identity = self._classify_service_identity(normalized)
        if service_identity is not None:
            return service_identity

        matches = self._match_rules(self._combined_text(normalized))
        if matches:
            rule, reasons, confidence = self._select_best_match(matches)
            return ClassificationResult(
                decision=rule.action,
                severity=rule.severity,
                invariant_id=rule.invariant_id,
                rule_name=rule.name,
                remediation=rule.remediation,
                confidence=confidence,
                reasons=tuple(reasons),
                source="rule_match",
                original=normalized,
            )

        return ClassificationResult(
            decision="ALLOW",
            severity="LOW",
            invariant_id=None,
            rule_name=None,
            remediation=None,
            confidence=0.75,
            reasons=("no configured invariant matched",),
            source="default_allow",
            original=normalized,
        )

    def classify_many(self, findings: Iterable[dict[str, Any]]) -> list[ClassificationResult]:
        return [self.classify(finding) for finding in findings]

    def summarize(self, results: Iterable[ClassificationResult]) -> dict[str, Any]:
        materialized = list(results)
        by_decision: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        by_invariant: dict[str, int] = {}

        for result in materialized:
            by_decision[result.decision] = by_decision.get(result.decision, 0) + 1
            by_severity[result.severity] = by_severity.get(result.severity, 0) + 1
            if result.invariant_id:
                by_invariant[result.invariant_id] = by_invariant.get(result.invariant_id, 0) + 1

        return {
            "total": len(materialized),
            "by_decision": dict(sorted(by_decision.items())),
            "by_severity": dict(sorted(by_severity.items())),
            "by_invariant": dict(sorted(by_invariant.items())),
            "results": [result.to_dict() for result in materialized],
        }

    def classify_json_file(self, input_path: str | Path, output_path: str | Path | None = None) -> dict[str, Any]:
        payload = json.loads(Path(input_path).read_text(encoding="utf-8"))
        raw_findings = payload.get("findings", []) if isinstance(payload, dict) else payload
        if not isinstance(raw_findings, list):
            raise ValueError("input JSON must be a list or an object containing a findings list")

        results = self.classify_many([item for item in raw_findings if isinstance(item, dict)])
        summary = self.summarize(results)

        if output_path is not None:
            Path(output_path).write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")

        return summary

    def _classify_preexisting_finding(self, finding: dict[str, Any]) -> ClassificationResult | None:
        invariant_id = self._string_or_none(finding.get("invariant_id"))
        if not invariant_id:
            return None

        rule = self._rule_by_id(invariant_id)
        severity = self._normalize_severity(finding.get("severity") or (rule.severity if rule else "MEDIUM"))
        remediation = self._string_or_none(finding.get("remediation")) or (rule.remediation if rule else None)
        description = self._string_or_none(finding.get("description")) or "preclassified scanner finding"

        return ClassificationResult(
            decision="DENY" if severity in {"MEDIUM", "HIGH", "CRITICAL"} else "ALLOW",
            severity=severity,
            invariant_id=invariant_id,
            rule_name=rule.name if rule else None,
            remediation=remediation,
            confidence=0.95,
            reasons=(f"scanner supplied invariant_id={invariant_id}", description),
            source="scanner_preclassified",
            original=finding,
        )

    def _classify_service_identity(self, finding: dict[str, Any]) -> ClassificationResult | None:
        author_email = str(finding.get("author_email", "") or "").lower()
        author_name = str(finding.get("author_name", "") or "")

        if not author_email and not author_name:
            return None

        allowed_domain = any(domain in author_email for domain in DEFAULT_ALLOWED_SERVICE_DOMAINS)
        allowed_name = author_name in DEFAULT_ALLOWED_SERVICE_NAMES
        if allowed_domain or allowed_name:
            return None

        rule = self._rule_by_id("INV-006")
        return ClassificationResult(
            decision="DENY",
            severity=rule.severity if rule else "HIGH",
            invariant_id="INV-006",
            rule_name=rule.name if rule else "service_identity_required",
            remediation=rule.remediation if rule else "commit_rewriter",
            confidence=0.9,
            reasons=(f"non-service commit identity: {author_email or author_name}",),
            source="service_identity",
            original=finding,
        )

    def _match_rules(self, text: str) -> list[tuple[SeverityRule, list[str], float]]:
        matches: list[tuple[SeverityRule, list[str], float]] = []

        for rule in self.rules:
            reasons: list[str] = []
            score = 0.0

            for keyword in rule.keywords:
                if keyword and keyword.lower() in text:
                    reasons.append(f"keyword matched: {keyword}")
                    score += 1.0

            for regex in rule.regexes:
                if not regex:
                    continue
                try:
                    if re.search(regex, text, flags=re.IGNORECASE):
                        reasons.append(f"regex matched: {regex}")
                        score += 1.5
                except re.error:
                    continue

            for boost in rule.context_boost:
                if boost and boost.lower() in text:
                    reasons.append(f"context matched: {boost}")
                    score += 0.25

            if reasons:
                matches.append((rule, reasons, min(0.99, 0.55 + score * 0.12)))

        return matches

    def _select_best_match(self, matches: list[tuple[SeverityRule, list[str], float]]) -> tuple[SeverityRule, list[str], float]:
        def key(item: tuple[SeverityRule, list[str], float]) -> tuple[int, float, int]:
            rule, reasons, confidence = item
            return (SEVERITY_RANK.get(rule.severity, 0), confidence, len(reasons))

        return max(matches, key=key)

    def _combined_text(self, finding: dict[str, Any]) -> str:
        fields = ("message", "title", "body", "description", "repo", "repository", "author_name", "author_email")
        return "\n".join(str(finding.get(key, "")) for key in fields).lower()

    def _rule_by_id(self, invariant_id: str) -> SeverityRule | None:
        for rule in self.rules:
            if rule.invariant_id == invariant_id:
                return rule
        return None

    def _load_rules(self, path: Path) -> list[SeverityRule]:
        if not path.exists():
            return self._default_rules()

        text = path.read_text(encoding="utf-8")
        parsed = self._try_parse_yaml(text)
        rules = self._rules_from_parsed_yaml(parsed)
        if rules:
            return rules

        fallback = self._rules_from_text_fallback(text)
        if fallback:
            return fallback

        return self._default_rules()

    def _try_parse_yaml(self, text: str) -> Any:
        try:
            return yaml.safe_load(text)
        except Exception:
            return None

    def _rules_from_parsed_yaml(self, parsed: Any) -> list[SeverityRule]:
        if not isinstance(parsed, dict) or not isinstance(parsed.get("invariants"), list):
            return []

        rules: list[SeverityRule] = []
        for raw in parsed["invariants"]:
            if not isinstance(raw, dict):
                continue

            keywords: list[str] = []
            regexes: list[str] = []
            for item in raw.get("patterns", []) or []:
                if isinstance(item, dict):
                    if item.get("keyword"):
                        keywords.append(str(item["keyword"]))
                    if item.get("regex"):
                        regexes.append(str(item["regex"]))

            context_boost = raw.get("context_boost", [])
            if not isinstance(context_boost, list):
                context_boost = []

            rule = SeverityRule(
                invariant_id=str(raw.get("id", "")),
                name=str(raw.get("name", "")),
                description=str(raw.get("description", "")),
                severity=self._normalize_severity(raw.get("severity", "MEDIUM")),
                action=str(raw.get("action", "DENY")),
                remediation=str(raw.get("remediation", "review")),
                keywords=tuple(keywords),
                regexes=tuple(regexes),
                context_boost=tuple(str(item) for item in context_boost),
            )
            if rule.invariant_id:
                rules.append(rule)

        return rules

    def _rules_from_text_fallback(self, text: str) -> list[SeverityRule]:
        defaults = {rule.invariant_id: rule for rule in self._default_rules()}
        found_ids = set(re.findall(r"id:\s*(INV-\d{3})", text))
        return [defaults[item] for item in sorted(found_ids) if item in defaults]

    def _default_rules(self) -> list[SeverityRule]:
        return [
            SeverityRule("INV-001", "no_medical_exposure", "Medical or health references are inadmissible", "CRITICAL", "DENY", "immediate_removal", ("seizure", "epilepsy", "medical", "diagnosis", "condition", "disability", "health", "hospital", "doctor", "medication")),
            SeverityRule("INV-002", "no_family_identity", "Family identity and relationship narratives are inadmissible", "CRITICAL", "DENY", "immediate_removal", ("wife", "husband", "spouse", "married", "children", "kids", "son", "daughter", "family", "mother", "father")),
            SeverityRule("INV-003", "no_location_precision", "City-level or finer location data is inadmissible", "HIGH", "DENY", "immediate_removal", (), (r"\b[A-Z][a-z]+,\s*(TX|Texas|FL|Florida|CA|California|NY|New York|WA|Washington)\b", r"\b[0-9]{5}(-[0-9]{4})?\b")),
            SeverityRule("INV-004", "no_behavioral_pattern", "Commit timestamps revealing behavioral patterns are inadmissible", "HIGH", "DENY", "timestamp_obfuscation"),
            SeverityRule("INV-005", "no_personal_narrative", "Personal narratives of struggle or constraint are inadmissible", "MEDIUM", "DENY", "content_rewrite", ("struggle", "difficult", "hard", "challenge", "overcome", "battle", "survive", "cope", "grateful", "thankful")),
            SeverityRule("INV-006", "service_identity_required", "Public commits must originate from approved service identity", "HIGH", "DENY", "commit_rewriter"),
            SeverityRule("INV-007", "no_financial_vulnerability", "Financial stress or urgency is inadmissible", "MEDIUM", "DENY", "content_rewrite", ("broke", "poor", "need money", "urgent", "desperate", "running out", "can't afford")),
            SeverityRule("INV-008", "no_temporal_anchor", "Dates or durations that reveal age, health timeline, or life events are inadmissible", "MEDIUM", "DENY", "content_rewrite", (), (r"since [0-9]{4}", r"for [0-9]+ years", r"[0-9]+ years ago", r"in [0-9]{4}", r"[0-9]{4}-present")),
        ]

    def _normalize_severity(self, value: Any) -> str:
        text = str(value or "MEDIUM").upper()
        return text if text in SEVERITY_RANK else "MEDIUM"

    def _string_or_none(self, value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Classify footprint-auditor findings.")
    parser.add_argument("--rules", default="config/severity_rules.yaml")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=False)
    args = parser.parse_args()

    classifier = FindingClassifier(args.rules)
    summary = classifier.classify_json_file(args.input, args.output)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
