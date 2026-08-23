# FOOTPRINT_AUDITOR_MIRROR_HANDOFF

Status: ACTIVE — PUBLIC 76/76 COMPLETE / PRIVATE 0/143 / IMMUTABLE PRIVATE-SOURCE VALIDATION + AUTHORITY PENDING

Date established: 2026-08-19  
Last updated: 2026-08-22 19:46 America/Chicago

## Governing objective
Perform a historical ecosystem security/provenance audit from ecosystem origin through `2026-08-19T23:59:59Z`. Attribute consequential transitions to dated actor, automation, dependency, build, release, deployment, runtime, or explicit third-party evidence. Missing evidence is never silently benign.

## Authority contract
- StegVerse primary; third-party fallback only where required.
- Credential/secret/token authority: **TV/TVC ONLY**.
- NON-TV/TVC secret/token authority: prohibited.
- GitHub Actions: validation/transport/evidence only; no production/runtime/control-plane authority.
- The audit engine must never receive the private-source credential.
- `plan != done`, `issue != done`, `task != done`, `handoff != done`, `assigned != done`, `machine_owned != done`, `ready != done`, `source_complete != activated`, `workflow_pass != runtime`, `release_ready != released`.
- Unresolved transitions remain open and fail closed.

## Canonical execution task
`tasks/ECOSYSTEM-PROVENANCE-AUDIT-001.json`

## Exact ecosystem denominator — COMPLETE / VALIDATED
Canonical inventory: `evidence/inventory/connected-repositories-2026-08-19-v2.csv`  
Git blob: `434f03951354d8959e863c3f9aa0b6e5748a2d7b`

- 219 unique repositories
- 76 current-public
- 143 current-private
- 11 connected installations/accounts
- denominator validation run `32571449626`, job `97027372810`

Current visibility is not historical visibility evidence.

## Public exact-cutoff execution — COMPLETE
All **76/76** current-public repositories were anonymously materialized at the immutable last default-branch commit at or before the cutoff, scanned by the credential-free exact-SHA runner, retained, and independently reverified.

Canonical coverage receipt:
- `evidence/execution/public-cutoff-coverage-2026-08-22.json`
- blob `db2a25f3110e42e1cdcb90b6f65555eb65ac320f`
- receipt SHA-256 `2f086eff80c2fe33173eec9814e76944d7abac19434fa5fe5f4051f5b908fe02`
- verdict `PUBLIC_EXACT_CUTOFF_EXECUTION_COMPLETE_FULL_ECOSYSTEM_AUDIT_OPEN`

Public states complete/reverified: **76/76**.  
Public states remaining: **0**.

Per-batch execution evidence remains under `evidence/execution/public-audit-batch-00*-2026-08-22.json`; Git history preserves the full prior handoff narrative and batch details.

## Audit engine — VALIDATED
Canonical implementation includes:
- `src/provenance/historical.py`
- `src/provenance/commit_authority.py`
- `src/provenance/workflow_dependencies.py`
- `src/provenance/workflow_authority.py`
- `src/provenance/python_dependencies.py`
- `src/provenance/ecosystem_dependencies.py`
- `src/provenance/inventory.py`
- `src/provenance/report.py`
- `src/provenance/repository_executor.py`
- `src/provenance/audit_runner.py`
- `src/provenance/github_audit_log.py`
- `scripts/materialize_public_batch.py`
- `scripts/import_github_audit_log.py`

The executor binds immutable 40-character SHAs, verifies exact HEAD and clean worktrees, hashes Git identities in retained evidence, scans workflows/dependencies/control surfaces, scrubs committed token literals from receipts, and emits deterministic secret-safe evidence.

Execution-complete and audit-clean are deliberately separate. A working executor may truthfully return `execution_complete=true` and `audit_clean=false`.

## GitHub organization audit-log evidence path — IMPLEMENTED + VALIDATED / DATA PENDING
Parser: `src/provenance/github_audit_log.py`  
Importer: `scripts/import_github_audit_log.py`

The importer accepts JSON/JSONL exports, binds source bytes by SHA-256, applies the historical cutoff, reconstructs explicit visibility transitions/exposure intervals, hashes actor identifiers rather than retaining them raw, records missing expected repository evidence, and produces a deterministic self-verifying receipt.

Latest importer validation:
- PR #21
- merged commit `107023834c0df5d6ed35a61b45eb54253b18b172`
- validating run `32608506740`
- job `97117462150`
- result **69/69 PASS**
- end-to-end self-audit receipt `841d4b04f643ec590358f1e0035b7c5c257a76d87952c894f508ceefa3d45688`
- durable proof `evidence/verification/2026-08-22-github-audit-log-importer-validation.json`

The first importer run correctly exposed a privacy defect: visibility-transition receipts still carried raw actor names. That defect was repaired before merge; the successful validation proves the retained importer no longer persists raw actor identifiers in either transition or actor-event receipts.

Actual organization audit-log records are still unavailable through the connected GitHub tool. Therefore:
- organization audit-log data ingested: **NO**
- historical visibility reconstruction complete: **NO**
- historical actor/token/App authority reconstruction complete: **NO**

## Private exact-cutoff execution — 0/143 / CURRENT PRIMARY BLOCKER
Sole admitted materialization capability: `tvc.private-source-read.v1` owned by `StegVerse-Labs/TVC#33`.

### Contract defect discovered and corrected at TV policy layer
The prior policy required the authorized SHA to remain equal to a currently re-resolved live ref. That is valid for current-state validation but cannot reproduce an August 19 historical commit after `main` advances.

TV policy has now been corrected and merged:
- repository `StegVerse-Labs/TV`
- policy `policies/private_source_read_capability_policy.json`
- merged commit `c6eede495c18b8b19156cf68576702b93e77f593`
- modes:
  - `TRACKED_REF` — preserve live-ref re-resolution and stale-SHA rejection
  - `IMMUTABLE_COMMIT` — `exact_ref=commit:<exact_sha>`, no moving-ref substitution, exact commit must be fetchable under TVC read authority, and materialized HEAD must equal exact SHA

No credential/write/release/publication/runtime/production/wallet/trade authority was added.

### TVC implementation
Canonical implementation PR: `StegVerse-Labs/TVC#95`.

PR #95 carries:
- schema binding to TV policy commit `c6eede...`
- `reference_mode` support
- immutable-commit grant authorization
- exact historical commit fetchability check
- immutable materialization without resolving today's branch tip
- exact HEAD equality proof
- existing tracked-ref behavior retained
- zero generic GitHub credential fallback
- tests for both reference modes and authority boundaries

State: **SOURCE IMPLEMENTED / VALIDATION NOT YET PROVEN / AUTHORITY NOT ACTIVATED**.

TVC PR #94 was closed as superseded without claiming PASS because no attached validation run was observed.

Do not merge or count PR #95 as validated merely because source is present. A real admitted validation path is still required.

### Prepared private batch 001 — PREPARATION ONLY
`config/private-audit-batch-001.json`

Five immutable historical targets are prepared:
- `Admissible-Existence/AE@53c8eedddc4e54d8fa0660039d65ab9ac63057a1`
- `Admissible-Existence/BC@f457b9c38fd9f17da83101b02bdf248fc18256c1`
- `Admissible-Existence/CHF@2d87454922b5c172023ad66ecf6824867484e8f5`
- `Admissible-Existence/DaCo@3b99db0a2bfb445f27dc1ef3e722e78e209c0744`
- `Admissible-Existence/ET@9630a8d2a624022d097f8b46b0be82311ffa04d5`

Each repository reports default branch `main`; each selected commit was observed at or before the cutoff. This file is **not** materialization or execution evidence. Exact commit fetchability and materialized HEAD equality remain pending TVC execution.

Private execution count remains **0/143**.

## Confirmed security event
### TV SCW vault key exposure
Finding: `evidence/findings/2026-08-19-tv-scw-vault-key-exposure.json`

A usable SCW Fernet key was committed historically on 2025-11-25. Never reproduce the key value.

Current-tree containment is complete, but remediation is not complete. `StegVerse-Labs/TVC#88` still requires observed replacement-key rotation, affected payload re-encryption, secret-free rotation evidence, and historical visibility resolution.

## Current finding ledger
Canonical ledger: `evidence/reports/ecosystem-provenance-audit-2026-08-19-v5.json`  
Report digest: `91af76ca27027d70bb9cb40d439d68590ac05f1dd06aa8526c74c9dd472afbaa`

Open findings: 13
- AUTHORIZED_UNEXPLAINED: 10
- PROVENANCE_GAP: 2
- THIRD_PARTY_UNEXPLAINED: 1
- confirmed malicious events: 0
- confirmed unauthorized actors: 0
- confirmed security compromises: 1

v5 predates the completed public population and is not a final ecosystem receipt.

## Existing machine-owned remediation boundaries
Do not duplicate/race these owners without fresh live-state evidence:
- TVC #33 — private source-read activation/consumption
- TVC #88 — SCW replacement-key rotation/re-encryption
- TVC #89 — remaining TV credential migration
- StegDB #13 — deferred workflow/dependency security work
- Governance #1 — StegTrace bootstrap credential migration
- GCAT workflows #15 — immutable remote verifier successor
- GCAT workflows #16 — provider credential/admissibility migration
- hybrid-collab-bridge #14 — provider replacement
- Site #398 — latent bundle-ingest TVC mutation path

## Remaining hard gates
1. Obtain a real validation result for TVC PR #95 / immutable historical commit mode.
2. Activate `tvc.private-source-read.v1` under actual TV/TVC credential authority.
3. Materialize private batch 001 via `IMMUTABLE_COMMIT`; retain secret-free TVC receipts proving exact SHA and HEAD equality.
4. Feed those materialized trees into `footprint-auditor` and retain deterministic audit receipts.
5. Repeat until private execution is **143/143**.
6. Obtain and import dated GitHub organization/security evidence for actor/token/App/OAuth/programmatic authority and visibility transitions.
7. Reconcile external package registry, DNS, signing, deployment/runtime, device, and other non-GitHub provenance.
8. Complete required machine-owned security remediations, including SCW replacement rotation/re-encryption.
9. Generate a superseding aggregate ecosystem receipt with explicit unresolved-exception accounting.

## Current conclusion
- Exact manifest: **219/219 COMPLETE / VALIDATED**
- Audit engine: **VALIDATED**
- GitHub audit-log parser/importer: **VALIDATED; SOURCE DATA PENDING**
- Public exact-cutoff execution: **76/76 COMPLETE**
- Private exact-cutoff execution: **0/143**
- First private immutable batch: **5 TARGETS PREPARED / NOT EXECUTED**
- TV historical immutable-read policy: **MERGED**
- TVC immutable-read implementation: **PR #95 SOURCE IMPLEMENTED / UNVALIDATED / NOT ACTIVATED**
- Historical actor authority reconstruction: **INCOMPLETE**
- Historical exposure reconstruction: **INCOMPLETE**
- Confirmed malicious third-party event: **NONE ESTABLISHED**
- Confirmed unauthorized actor: **NONE ESTABLISHED**
- Confirmed security compromise: **YES — SCW historical key exposure; full remediation unproven**
- Clean-audit conclusion permitted: **NO**

## Next nonduplicate execution priority
1. Inspect PR #95 for an actual admitted validation result; consume it if present.
2. If validated and TV/TVC authority activates, execute `config/private-audit-batch-001.json` immediately using immutable commit bindings.
3. If validation/authority remains unavailable, keep private execution at 0/143 and continue preparing exact immutable private batches and other non-colliding historical/external evidence surfaces.
4. Never substitute a moving current ref for an historical cutoff SHA.

## Completion rule
This goal remains open. Do not archive, release, deploy, activate, or publish a clean-audit claim while private execution, historical actor/visibility evidence, external provenance, required remediation, or unresolved findings remain pending.

Do not request routine approval checkpoints.
