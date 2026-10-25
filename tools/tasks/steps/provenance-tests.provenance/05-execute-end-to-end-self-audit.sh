manifest_digest="$(sha256sum /tmp/footprint-auditor-manifest.json | awk '{print $1}')"
PYTHONDONTWRITEBYTECODE=1 python -m src.provenance.audit_runner \
  --manifest /tmp/footprint-auditor-manifest.json \
  --findings-dir evidence/findings \
  --output /tmp/footprint-auditor-execution-receipt.json \
  --boundary-end 2026-08-19T23:59:59Z \
  --installation-count 1 \
  --inventory-digest "$manifest_digest" \
  --observed-at 2026-08-21T23:59:00Z
