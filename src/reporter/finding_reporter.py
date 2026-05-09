#!/usr/bin/env python3
"""
footprint-auditor finding reporter.

Purpose:
- convert classifier summaries/results into stable Markdown and JSON reports
- append receipt records for generated audit reports
- perform no repository mutation outside requested output files
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class FindingReport:
    generated_at: str
    title: str
    summary: dict[str, Any]
    results: list[dict[str, Any]]
    receipt: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class FindingReporter:
    """Render classifier output to Markdown, JSON, and receipt artifacts."""

    def __init__(self, title: str = "footprint-auditor report") -> None:
        self.title = title

    def build_report(self, classifier_summary: dict[str, Any]) -> FindingReport:
        results = classifier_summary.get("results", [])
        if not isinstance(results, list):
            raise ValueError("classifier summary field 'results' must be a list")

        summary = {
            "total": int(classifier_summary.get("total", len(results))),
            "by_decision": dict(classifier_summary.get("by_decision", {})),
            "by_severity": dict(classifier_summary.get("by_severity", {})),
            "by_invariant": dict(classifier_summary.get("by_invariant", {})),
            "deny_count": int(dict(classifier_summary.get("by_decision", {})).get("DENY", 0)),
            "allow_count": int(dict(classifier_summary.get("by_decision", {})).get("ALLOW", 0)),
        }

        payload = {
            "title": self.title,
            "summary": summary,
            "results": results,
        }

        receipt = {
            "receipt_type": "footprint_auditor.finding_report",
            "timestamp": self._now(),
            "result_count": summary["total"],
            "deny_count": summary["deny_count"],
            "allow_count": summary["allow_count"],
            "hash": self._hash(payload),
        }

        return FindingReport(
            generated_at=receipt["timestamp"],
            title=self.title,
            summary=summary,
            results=results,
            receipt=receipt,
        )

    def write_report(
        self,
        classifier_summary: dict[str, Any],
        reports_dir: str | Path = "reports",
        receipts_dir: str | Path = "receipts",
    ) -> FindingReport:
        report = self.build_report(classifier_summary)

        reports_path = Path(reports_dir)
        receipts_path = Path(receipts_dir)
        reports_path.mkdir(parents=True, exist_ok=True)
        receipts_path.mkdir(parents=True, exist_ok=True)

        (reports_path / "footprint_audit_report.json").write_text(
            json.dumps(report.to_dict(), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        (reports_path / "footprint_audit_report.md").write_text(
            self.to_markdown(report),
            encoding="utf-8",
        )

        with (receipts_path / "footprint_audit_receipts.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(report.receipt, sort_keys=True) + "\n")

        return report

    def to_markdown(self, report: FindingReport) -> str:
        lines: list[str] = []
        lines.append(f"# {report.title}")
        lines.append("")
        lines.append(f"Generated: `{report.generated_at}`")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        for key, value in report.summary.items():
            lines.append(f"- {key}: `{value}`")
        lines.append("")
        lines.append("## Findings")
        lines.append("")

        if not report.results:
            lines.append("- No findings.")
            lines.append("")
        else:
            for index, item in enumerate(report.results, start=1):
                lines.append(f"### Finding {index}")
                lines.append("")
                lines.append(f"- Decision: `{item.get('decision')}`")
                lines.append(f"- Severity: `{item.get('severity')}`")
                lines.append(f"- Invariant: `{item.get('invariant_id')}`")
                lines.append(f"- Rule: `{item.get('rule_name')}`")
                lines.append(f"- Remediation: `{item.get('remediation')}`")
                lines.append(f"- Confidence: `{item.get('confidence')}`")
                reasons = item.get("reasons") or []
                if reasons:
                    lines.append("- Reasons:")
                    for reason in reasons:
                        lines.append(f"  - {reason}")
                lines.append("")

        lines.append("## Receipt")
        lines.append("")
        lines.append(f"- Receipt hash: `{report.receipt['hash']}`")
        lines.append("- Receipt path: `receipts/footprint_audit_receipts.jsonl`")
        lines.append("")
        return "\n".join(lines)

    def _now(self) -> str:
        return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")

    def _hash(self, payload: Any) -> str:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Render footprint-auditor classifier summary.")
    parser.add_argument("--input", required=True, help="Classifier summary JSON file.")
    parser.add_argument("--reports-dir", default="reports")
    parser.add_argument("--receipts-dir", default="receipts")
    args = parser.parse_args()

    summary = json.loads(Path(args.input).read_text(encoding="utf-8"))
    report = FindingReporter().write_report(summary, args.reports_dir, args.receipts_dir)

    print(f"Wrote {Path(args.reports_dir) / 'footprint_audit_report.md'}")
    print(f"Wrote {Path(args.reports_dir) / 'footprint_audit_report.json'}")
    print(f"Wrote {Path(args.receipts_dir) / 'footprint_audit_receipts.jsonl'}")
    print(f"Receipt hash: {report.receipt['hash']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
