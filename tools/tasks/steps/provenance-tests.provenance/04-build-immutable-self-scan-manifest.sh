PYTHONDONTWRITEBYTECODE=1 python - <<'PY'
import json, os
payload = {
    "schema": "stegverse.materialized-repository-manifest.v1",
    "repositories": [{
        "repository": os.environ["GITHUB_REPOSITORY"],
        "path": os.environ["GITHUB_WORKSPACE"],
        "expected_sha": os.environ["GITHUB_SHA"],
    }],
}
with open("/tmp/footprint-auditor-manifest.json", "w", encoding="utf-8") as handle:
    json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
PY
