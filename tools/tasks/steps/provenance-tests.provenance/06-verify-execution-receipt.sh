PYTHONDONTWRITEBYTECODE=1 python - <<'PY'
import json
from src.provenance.audit_runner import verify_execution_receipt
with open("/tmp/footprint-auditor-execution-receipt.json", "r", encoding="utf-8") as handle:
    receipt = json.load(handle)
assert receipt["execution_complete"] is True
assert receipt["executed_repository_count"] == 1
assert receipt["audit_open"] is True
assert verify_execution_receipt(receipt)
print(receipt["execution_receipt_sha256"])
PY
