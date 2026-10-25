rm -rf /tmp/public-materialized /tmp/public-manifest.json "$PUBLIC_AUDIT_RECEIPT"
python scripts/materialize_public_batch.py \
  --inventory evidence/inventory/connected-repositories-2026-08-19-v2.csv \
  --selection "$PUBLIC_AUDIT_SELECTION" \
  --root /tmp/public-materialized \
  --cutoff "$PUBLIC_AUDIT_CUTOFF" \
  --output /tmp/public-manifest.json
