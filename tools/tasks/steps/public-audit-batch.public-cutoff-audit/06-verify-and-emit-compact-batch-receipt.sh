python - <<'PY'
import json, os
from pathlib import Path
from src.provenance.audit_runner import verify_execution_receipt
receipt = json.loads(Path(os.environ['PUBLIC_AUDIT_RECEIPT']).read_text())
assert receipt['execution_complete'] is True
assert receipt['executed_repository_count'] == int(os.environ['PUBLIC_AUDIT_EXPECTED_COUNT'])
assert receipt['audit_open'] is True
assert receipt['credential_received_by_runner'] is False
assert receipt['network_access_required_by_runner'] is False
assert verify_execution_receipt(receipt)
print('BATCH_EXECUTION_RECEIPT', receipt['execution_receipt_sha256'])
print('BATCH_UNRESOLVED', json.dumps(receipt['unresolved_repository_scan_counts'], sort_keys=True, separators=(',', ':')))
for row in sorted(receipt['repository_receipts'], key=lambda x: x['repository']):
    assert row['credential_received_by_executor'] is False
    assert row['network_access_required'] is False
    print('REPOSITORY_RECEIPT', row['repository'], row['expected_sha'], row['receipt_sha256'])
PY
