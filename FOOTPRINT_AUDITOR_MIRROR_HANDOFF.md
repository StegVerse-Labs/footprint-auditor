# FOOTPRINT_AUDITOR_MIRROR_HANDOFF

Status: ACTIVE — PUBLIC 76/76 COMPLETE / PRIVATE 0/143 / RESIDENT TVC ACTIVATION BRIDGE VALIDATION PENDING

Date established: 2026-08-19  
Last updated: 2026-08-23 17:06 America/Chicago

## Governing objective
Perform a historical ecosystem security/provenance audit from ecosystem origin through `2026-08-19T23:59:59Z`. Attribute consequential transitions to dated actor, automation, dependency, build, release, deployment, runtime, or explicit third-party evidence. Missing evidence is never silently benign.

## Authority contract
- StegVerse primary; third-party fallback only where required.
- Credential/secret/token authority: **TV/TVC ONLY**.
- NON-TV/TVC secret/token authority: prohibited.
- GitHub Actions: validation/transport/evidence only; no production/runtime/control-plane authority.
- The audit engine never receives the private-source credential.
- `plan != done`, `issue != done`, `task != done`, `handoff != done`, `assigned != done`, `machine_owned != done`, `ready != done`, `source_complete != activated`, `workflow_pass != runtime`, `release_ready != released`.
- Unresolved transitions remain open and fail closed.

Canonical task: `tasks/ECOSYSTEM-PROVENANCE-AUDIT-001.json`.

## Exact ecosystem denominator — COMPLETE / VALIDATED
Canonical inventory: `evidence/inventory/connected-repositories-2026-08-19-v2.csv`.

- 219 unique repositories
- 76 current-public
- 143 current-private
- 11 connected installations/accounts
- denominator validation run `32571449626`, job `97027372810`

Current visibility is not historical visibility evidence.

## Public exact-cutoff execution — COMPLETE
All **76/76** current-public repositories were anonymously materialized at the immutable last default-branch commit at or before the cutoff, scanned, retained, and independently reverified.

Canonical coverage receipt: `evidence/execution/public-cutoff-coverage-2026-08-22.json`  
Receipt SHA-256: `2f086eff80c2fe33173eec9814e76944d7abac19434fa5fe5f4051f5b908fe02`.

## Audit engine — VALIDATED
Installed provenance/audit implementation includes historical, commit-authority, workflow dependency/authority, Python/ecosystem dependency, inventory/report, repository executor, audit runner, GitHub audit-log parser, public materializer, and GitHub audit-log importer.

Execution-complete and audit-clean remain distinct. The engine may truthfully emit `execution_complete=true` and `audit_clean=false`.

## GitHub organization audit-log path — VALIDATED / SOURCE DATA PENDING
Importer validation:
- PR #21 merged at `107023834c0df5d6ed35a61b45eb54253b18b172`
- run `32608506740`, job `97117462150`
- **69/69 PASS**
- durable validation receipt `evidence/verification/2026-08-22-github-audit-log-importer-validation.json`

Raw actor identifiers are not retained in importer receipts. Actual organization audit-log records remain unavailable through the connected GitHub surface, so historical actor/token/App authority and visibility reconstruction remain incomplete.

## Private exact-cutoff execution — 0/143 / PRIMARY EXECUTION GAP
Sole admitted capability: `tvc.private-source-read.v1`, canonical owner `StegVerse-Labs/TVC#33`.

### TV policy — VALIDATED / MERGED
`StegVerse-Labs/TV/policies/private_source_read_capability_policy.json` at `c6eede495c18b8b19156cf68576702b93e77f593` admits:
- `TRACKED_REF` for current moving refs with stale-SHA rejection;
- `IMMUTABLE_COMMIT` for exact historical commits, requiring exact fetchability and materialized HEAD equality without current-branch substitution.

### TVC immutable historical mode — VALIDATED / MERGED
PR #95 merged at `47b742c7ce141925020812cdddbf23ccd99cdc56`.
Validation run `32608428996`, job `97117259662`: **15/15 PASS** plus generic-GitHub-token fallback source check PASS.

### TVC historical cutoff resolver — VALIDATED / MERGED
PR #96 merged at `f7ae8cbcdc04fff028ecb2923d7728ab45594224`.
Initial run correctly found one target-shape regression. Repair `b7dc8beb1dee2a67a46422d0661c52395041ec67`; successful run `32609026197`, job `97118810251`: **21/21 PASS** plus generic-GitHub-token fallback check PASS.

TVC can now, after genuine TV/TVC credential injection, fetch branch history with `--filter=blob:none`, resolve the last commit at or before the audit cutoff, convert it to `commit:<sha>`, and continue through the exact immutable grant/materialization/HEAD-equality path. Manual precomputation of all 143 historical SHAs is no longer required.

### Resident activation bridge — SOURCE IMPLEMENTED / VALIDATION PENDING
Fresh live-state inspection found TVC now has a resident `systemd LoadCredential` pattern for another TV/TVC capability, including fail-closed revocation on activation failure. The nonfunctioning repository heartbeat (`.github#81` reports incomplete live coverage) is therefore not used as the private-source execution dependency.

TVC PR #97 installs an analogous private-source activation bridge:
- `scripts/execute_private_source_read_resident.py`
- `scripts/authorize_and_activate_private_source_read.py`
- `deploy/systemd/stegtvc-private-source-read.service`
- `tests/test_private_source_read_resident_activation.py`
- expanded read-only private-source validation workflow

Security boundary:
- systemd `LoadCredential` only;
- credential source remains under `/run/stegverse`;
- credential injected into the validated executor only inside the resident process;
- materialization constrained to `/var/lib/stegverse/private-source-read/materialized`;
- activation request is non-secret and rejects unsupported/credential-bearing fields;
- failed service activation revokes/removes the staged request;
- receipts retain no credential value;
- no generic GitHub/provider/user credential fallback;
- no write/release/publication/runtime/production/wallet/trade authority.

PR #97 head: `2ef7e266a4d8100058d8e27d93b5c901c166291b`.  
Validation run `32669511949` is currently queued. **Do not count this bridge as validated or activated until the run succeeds and, separately, a real resident materialization receipt exists.**

### Prepared private batch 001 — PREPARATION ONLY
`config/private-audit-batch-001.json` contains five immutable seed targets. It is not execution evidence. Private execution remains **0/143** until TVC produces exact materialization receipts and the credential-free auditor produces corresponding verified audit receipts.

## Confirmed security event
### TV SCW vault key exposure
Finding: `evidence/findings/2026-08-19-tv-scw-vault-key-exposure.json`.
A usable SCW Fernet key was committed historically on 2025-11-25. Never reproduce the key value.
Current-tree containment exists; replacement-key rotation, affected payload re-encryption, secret-free rotation proof, and historical visibility resolution remain required under `StegVerse-Labs/TVC#88`.

## Current finding ledger
Canonical ledger: `evidence/reports/ecosystem-provenance-audit-2026-08-19-v5.json`.

Open findings: 13
- AUTHORIZED_UNEXPLAINED: 10
- PROVENANCE_GAP: 2
- THIRD_PARTY_UNEXPLAINED: 1
- confirmed malicious events: 0
- confirmed unauthorized actors: 0
- confirmed security compromises: 1

v5 predates completed public execution and is not a final ecosystem receipt.

## Existing machine-owned remediation boundaries
- TVC #33 — private source-read activation/consumption
- TVC #88 — SCW replacement-key rotation/re-encryption
- TVC #89 — remaining TV credential migration
- StegDB #13 — deferred workflow/dependency security work
- Governance #1 — StegTrace bootstrap credential migration
- GCAT workflows #15/#16 — verifier/provider authority migration
- hybrid-collab-bridge #14 — provider replacement
- Site #398 — latent bundle-ingest TVC mutation path

## Remaining hard gates
1. Obtain PASS for TVC PR #97 resident activation bridge.
2. Install/activate the resident service under genuine TV/TVC sole-host authority with the scoped ephemeral credential present.
3. Execute one private historical target; retain secret-free TVC materialization receipt proving authorized SHA == observed HEAD.
4. Pass only the materialized tree to `footprint-auditor`; retain verified audit receipt.
5. Repeat until private execution is **143/143**.
6. Obtain/import dated GitHub organization/security evidence for actor/token/App/OAuth/programmatic authority and historical visibility.
7. Reconcile external package registry, DNS, signing, deployment/runtime, device, and other non-GitHub provenance.
8. Complete required TV/TVC security remediations including SCW replacement rotation/re-encryption.
9. Generate a superseding aggregate ecosystem receipt with explicit unresolved-exception accounting.

## Current conclusion
- Exact manifest: **219/219 COMPLETE / VALIDATED**
- Audit engine: **VALIDATED**
- GitHub audit-log importer: **VALIDATED; SOURCE DATA PENDING**
- Public exact-cutoff execution: **76/76 COMPLETE**
- Private exact-cutoff execution: **0/143**
- TV immutable-read policy: **MERGED**
- TVC immutable-read implementation: **VALIDATED / MERGED**
- TVC historical cutoff resolver: **VALIDATED / MERGED**
- TVC resident private-source activation bridge: **PR #97 SOURCE IMPLEMENTED / VALIDATION QUEUED / NOT ACTIVATED**
- Historical actor authority reconstruction: **INCOMPLETE**
- Historical exposure reconstruction: **INCOMPLETE**
- Confirmed malicious third-party event: **NONE ESTABLISHED**
- Confirmed unauthorized actor: **NONE ESTABLISHED**
- Confirmed security compromise: **YES — SCW historical key exposure; full remediation unproven**
- Clean-audit conclusion permitted: **NO**

## Next nonduplicate execution priority
1. Consume PR #97 validation result; repair immediately if failed.
2. If PASS, merge #97 and update TVC #33 canonical task/handoff.
3. Inspect for actual sole-host `/run/stegverse` private-source credential availability/activation evidence; if present, execute the first resident historical materialization and audit it.
4. If resident authority remains unavailable, keep private coverage at 0/143 and advance non-colliding historical/external evidence and security-remediation work.

## Completion rule
This goal remains open. Do not archive, release, deploy, activate, or publish a clean-audit claim while private execution, historical authority/visibility evidence, external provenance, required remediation, or unresolved findings remain pending.

Do not request routine approval checkpoints.
