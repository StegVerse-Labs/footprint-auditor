# footprint-auditor

**StegVerse-Labs | Experimental | v0.2.0**

Automated ecosystem-wide footprint auditing and sanitization for the StegVerse organization network.

## What It Does

Scans all StegVerse ecosystem repositories for behavioral metadata exposure:
- Commit history (author identity, timestamps, messages)
- Issue and PR content (titles, descriptions, comments)
- Repository settings and descriptions
- Organization profiles
- Personal account metadata

## How It Works

Uses GCAT/BCAT geometric invariants to classify findings:

```
Proposed metadata → Admit Gate (INV-001 through INV-008)
                    ↓
              ALLOW or DENY
                    ↓
         If DENY → Remediate per severity_rules.yaml
                    ↓
         Generate receipt → StegDB canonical monitoring
```

## Quick Start

```bash
# Install
pip install pyyaml requests

# Configure TV/TVC authentication
export TVC_MASTER_KEY=your_master_key

# Run scan
python -m src.main
```

## Architecture

```
footprint-auditor/
├── config/
│   ├── ecosystems.yaml      # Orgs and repos to scan
│   ├── severity_rules.yaml  # GCAT/BCAT invariants
│   └── patterns.yaml        # Detection patterns
├── src/
│   ├── scanner/
│   │   ├── commit_metadata.py
│   │   └── issue_pr_content.py
│   ├── classifier/
│   ├── sanitizer/
│   └── reporter/
└── .github/workflows/
    └── audit.yml            # Scheduled + on-demand CI
```

## Security

- TV/TVC ephemeral authentication only
- Platform-agnostic by design
- Receipts to StegDB for canonical monitoring
- No persistent secrets in repository

## License

StegVerse Internal Use - See StegVerse-org/Governance for licensing terms
