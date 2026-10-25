inventory_digest="$(sha256sum evidence/inventory/connected-repositories-2026-08-19-v2.csv | awk '{print $1}')"
python -m src.provenance.audit_runner \
  --manifest /tmp/public-manifest.json \
  --findings-dir evidence/findings \
  --output "$PUBLIC_AUDIT_RECEIPT" \
  --boundary-end "$PUBLIC_AUDIT_CUTOFF" \
  --installation-count 5 \
  --inventory-digest "$inventory_digest" \
  --observed-at 2026-08-22T23:18:00Z
