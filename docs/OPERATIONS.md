# Footprint Auditor Operations Guide

## Purpose

The footprint-auditor scans all StegVerse ecosystem repositories for behavioral metadata exposure that could compromise operational security or reveal personal vulnerability patterns.

## GCAT/BCAT Invariants

All findings are classified by geometric invariants defined in `config/severity_rules.yaml`:

| Invariant | Description | Severity | Auto-Remediate |
|-----------|-------------|----------|----------------|
| INV-001 | No medical/health exposure | CRITICAL | Yes |
| INV-002 | No family identity exposure | CRITICAL | Yes |
| INV-003 | No precise location data | HIGH | No |
| INV-004 | No behavioral pattern exposure | HIGH | No |
| INV-005 | No personal narrative | MEDIUM | No |
| INV-006 | Service identity required | HIGH | No |
| INV-007 | No financial vulnerability | MEDIUM | No |
| INV-008 | No temporal anchors | MEDIUM | No |

## Running Locally

```bash
# Set TV/TVC ephemeral token
export TVC_GITHUB_TOKEN=$(tvc generate --scope repo:read,org:read)

# Run full ecosystem scan
python -m src.main --config config/ecosystems.yaml

# Run against specific org
python -m src.main --orgs StegVerse-org

# Run with severity threshold
python -m src.main --threshold HIGH
```

## Remediation Actions

| Action | Description | When to Use |
|--------|-------------|-------------|
| immediate_removal | Delete content, rewrite history if needed | CRITICAL findings |
| commit_rewriter | Rewrite commit author/timestamp | INV-006 violations |
| timestamp_obfuscation | Batch and randomize commit times | INV-004 violations |
| content_rewrite | Edit issue/PR content | MEDIUM findings |
| metadata_cleaner | Update profile/repo settings | Profile/org metadata |

## Receipts

Every scan generates a `%Reality`-compatible receipt uploaded to StegDB. Receipts include:
- Scan timestamp
- Total findings
- Findings by severity and invariant
- Remediation status
- Verification hash

## Platform Agnosticism

While GitHub is the default adapter, the core scanner modules work with any git host. To add a new platform:

1. Implement `PlatformAdapter` interface in `src/platforms/`
2. Add platform config to `ecosystems.yaml`
3. TV/TVC handles authentication uniformly

## Security Notes

- All API access uses TV/TVC ephemeral tokens
- No long-lived secrets in repository
- Findings reports are encrypted at rest
- StegDB canonical monitoring ensures audit trail integrity
