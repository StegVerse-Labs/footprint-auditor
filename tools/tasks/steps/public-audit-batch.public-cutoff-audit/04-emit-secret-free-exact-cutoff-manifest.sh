python - <<'PY'
import json, os
from pathlib import Path
manifest = json.loads(Path('/tmp/public-manifest.json').read_text())
assert manifest['schema'] == 'stegverse.materialized-repository-manifest.v1'
assert len(manifest['repositories']) == int(os.environ['PUBLIC_AUDIT_EXPECTED_COUNT'])
for row in sorted(manifest['repositories'], key=lambda x: x['repository']):
    print(f"MATERIALIZED {row['repository']} {row['expected_sha']}")
PY
