# footprint-auditor report

Generated: `2026-10-25T03:51:44+00:00`

## Summary

- total: `3`
- by_decision: `{'ALLOW': 1, 'DENY': 2}`
- by_severity: `{'CRITICAL': 1, 'HIGH': 1, 'LOW': 1}`
- by_invariant: `{'INV-001': 1, 'INV-006': 1}`
- deny_count: `2`
- allow_count: `1`

## Findings

### Finding 1

- Decision: `ALLOW`
- Severity: `LOW`
- Invariant: `None`
- Rule: `None`
- Remediation: `None`
- Confidence: `0.75`
- Reasons:
  - no configured invariant matched

### Finding 2

- Decision: `DENY`
- Severity: `CRITICAL`
- Invariant: `INV-001`
- Rule: `no_medical_exposure`
- Remediation: `immediate_removal`
- Confidence: `0.67`
- Reasons:
  - keyword matched: medical

### Finding 3

- Decision: `DENY`
- Severity: `HIGH`
- Invariant: `INV-006`
- Rule: `service_identity_required`
- Remediation: `commit_rewriter`
- Confidence: `0.9`
- Reasons:
  - non-service commit identity: person@example.com

## Receipt

- Receipt hash: `113bc2bcbe6a59b53cbce4395e00cf479feec5e9a8a6ed5cf6e30d61274abbed`
- Receipt path: `receipts/footprint_audit_receipts.jsonl`
