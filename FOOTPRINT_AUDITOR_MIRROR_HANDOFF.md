# FOOTPRINT_AUDITOR_MIRROR_HANDOFF

Status: ACTIVE — 30/76 PUBLIC CUTOFF STATES EXECUTED / PRIVATE SOURCE ACTIVATION PENDING

Date established: 2026-08-19  
Last updated: 2026-08-22 07:10 America/Chicago

## Governing objective
Perform a historical ecosystem security/provenance audit from ecosystem origin through 2026-08-19. Attribute every consequential transition to dated actor, automation, dependency, build, release, deployment, runtime, or explicitly documented third-party evidence. Never treat missing evidence, current privacy, current membership, source containment, issue creation, machine ownership, readiness, or workflow success as proof of historical authorization, activation, runtime, completion, or benign intent.

## Authority contract
- StegVerse primary; third-party fallback only when required.
- Credential/secret/token authority: TV/TVC ONLY.
- NON-TV/TVC secret/token authority: prohibited.
- GitHub Actions: validation/transport/evidence only; no production/runtime/control-plane authority.
- Audit engine receives no private-source credential.
- Unresolved transitions remain open and fail closed.

## Exact accessible boundary — COMPLETE / VALIDATED
The accessible denominator is retained as one exact-name manifest containing **219 unique repositories across 11 installations/accounts**:
- public: 76
- private: 143

Canonical manifest:
- `evidence/inventory/connected-repositories-2026-08-19-v2.csv`
- Git blob: `434f03951354d8959e863c3f9aa0b6e5748a2d7b`

The superseding manifest reconciles the old 203-row installation listing with the 16 StegVerse-Labs repositories omitted by that installation surface's 100-repository truncation. Validation-only run `32571449626`, job `97027372810` proved 219 rows, 219 unique names, 76 public, 143 private, and all sixteen omissions present; the full provenance suite passed 54/54.

Current visibility remains only current visibility. Historical public/private intervals still require dated audit/security-log evidence.

## Public exact-cutoff execution — ACTIVE
Credentialless public execution is operational independently of the private-source dependency.

Materializer:
- `scripts/materialize_public_batch.py`
- accepts no credential;
- refuses repositories not marked public in the exact manifest;
- uses anonymous HTTPS Git clone;
- resolves the remote default branch's last commit at or before `2026-08-19T23:59:59Z`;
- checks out the immutable 40-character SHA detached and clean;
- emits only the exact materialized manifest consumed by the credential-free audit runner.

Canonical public workflow:
- `.github/workflows/public-audit-batch.yml`
- `contents: read` only;
- checkout credential is not persisted;
- external Actions are immutable-SHA pinned;
- complete sanitized receipt retention uses `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02` as validation/evidence transport only;
- no production, runtime, release, publication, mutation, or credential authority is granted.

### Batch 001 — EXECUTED / COMPACT PROOF RETAINED
Evidence: `evidence/execution/public-audit-batch-001-2026-08-22.json`

Run `32571701868`, job `97027947462`:
- 5/5 materialization-boundary tests PASS;
- 5 public repositories anonymously materialized at exact cutoff SHAs;
- five-repository audit execution PASS;
- execution receipt verification PASS;
- `execution_complete=true`;
- `audit_clean=false`;
- execution receipt SHA-256: `56b7601b818d11367f5840406e011d122d77407c6a973261288cd89e0a5e89ca`.

Exact states:
- `AdmittedCode/code-admit-gate@576d40e0f7a178c0f52146a68cf5a491b28921d5`
- `Data-Continuation/core-lite@c2c24186cd8a2ae4b7327c7f88bc868a25f6b619`
- `GCAT-BCAT-Engine/workflows@cc9b467d732a5e1a03c1266b38f023c2a50590a3`
- `StegVerse-002/core-lite@9c56c8e309542f7f1c23d0b0fbbfc7876e28bfec`
- `StegVerse-org/StegVerse-SDK@e5cee8bc404c90be00eb5592fa394111818eb3ec`

Batch 001 predates complete artifact retention. Its exact SHAs and receipt hashes are durable, but the complete 1-run sanitized receipt was temporary. It remains eligible for deterministic re-execution to upgrade that evidence; do not pretend compact proof equals complete retained receipt.

### Batch 002 — EXECUTED / COMPLETE RECEIPT RETAINED AND REVERIFIED
Evidence: `evidence/execution/public-audit-batch-002-2026-08-22.json`

Canonical retained run `32571942363`, job `97028507067`:
- 10 public repositories anonymously materialized at exact cutoff SHAs;
- ten-repository audit execution PASS;
- complete receipt and exact manifest retained;
- artifact ID `9475532566`;
- artifact SHA-256 `7906e0a880280c7f60b810c8dca7b2ea9a6f09e8c86c8312dfdf6e0b5b870fe1`;
- artifact download/hash re-verification PASS;
- downloaded execution receipt file SHA-256 `6784bebbfbb07fc7bd4ffc11145aebdaa0bb56aa7d7e6ad4b65d89831946a966`;
- downloaded exact manifest SHA-256 `7f9cdccbacddcbc74619206eccf517c439cc48ed5b7e9207e173d3e4fd220f38`;
- receipt internal hash recomputation PASS;
- execution receipt SHA-256 `76c224989be5b598b252c61ab2bf21980aa9556e9d941fbabdf858b51f186748`;
- `execution_complete=true`;
- `audit_clean=false`.

### Batch 003 — EXECUTED / COMPLETE RECEIPT RETAINED AND REVERIFIED
Evidence: `evidence/execution/public-audit-batch-003-2026-08-22.json`

Canonical run `32572145027`, job `97029030499`:
- 15 previously unscanned public repositories anonymously materialized at exact cutoff SHAs;
- fifteen-repository audit execution PASS;
- execution receipt verification PASS;
- complete sanitized receipt + exact manifest retained through immutable-pinned artifact action;
- artifact ID `9475588782`;
- artifact size `355143` bytes;
- artifact SHA-256 `297175dae07720b239d0cb4f06bc58f1111f8b1cbed71916b32a1a6f6954669b`;
- artifact downloaded and its SHA-256 independently reverified;
- downloaded execution receipt file SHA-256 `b9b338a3810fafcc41d88d93258e52b9e2f642df5be961e48f7b74c3156a3136`;
- downloaded exact manifest SHA-256 `8225e196a2fbdd68865c2151fdcd5e63b5482cc8ea089c9a96a06ebc8d1308fa`;
- receipt internal hash recomputation PASS;
- execution receipt SHA-256 `b360090e83cb960d25482b1989a0006b63b99e6c0220aaf6792382ec6298ff9a`;
- `execution_complete=true`;
- `audit_clean=false`.

Batch 003 exact states are retained in its evidence record. Aggregate unresolved scanner counts for the batch were:
- ecosystem dependencies: 1
- executor exceptions: 0
- historical identity authority: 8074
- Python dependencies: 32
- workflow authority: 245
- workflow dependencies: 135

Public execution denominator now stands at **30/76 unique repositories**, with **46 public repositories remaining**. Complete retained/reverified receipt evidence exists for 25 of those 30 states; the five batch-001 states remain compact-proof-only pending deterministic evidence upgrade. The 143 private repositories remain on the sole admitted `tvc.private-source-read.v1` path.

## Canonical audit receipt
Current aggregate finding receipt remains:
- `evidence/reports/ecosystem-provenance-audit-2026-08-19-v5.json`
- deterministic report SHA-256 excluding the self-hash field: `91af76ca27027d70bb9cb40d439d68590ac05f1dd06aa8526c74c9dd472afbaa`
- finding artifacts bound by exact Git blob SHA: 13
- clean audit permitted: false
- open findings: 13

v5 predates the public multi-repository execution expansion. It remains the canonical finding ledger until a superseding aggregate receipt is generated from the expanded execution population; do not silently reinterpret v5 as a 30-repository execution report.

## Installed audit engine
Canonical modules:
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
- `scripts/materialize_public_batch.py`

The exact-SHA repository executor accepts no credential and performs no network access. It requires an immutable expected SHA, verifies HEAD and worktree cleanliness, hashes Git identities rather than retaining raw identity values, runs workflow/dependency/control scans, scrubs committed token literals from retained evidence, and emits a deterministic secret-safe receipt. Private source must first be materialized by admitted TVC read authority.

## Confirmed security event
### TV SCW vault key exposure
Finding: `evidence/findings/2026-08-19-tv-scw-vault-key-exposure.json`

A usable SCW Fernet key was committed into `StegVerse-Labs/TV` Git history on 2025-11-25 in the same transition as the encrypted vault artifact. The raw historical key must never be reproduced.

Current-tree containment is complete: live key value redacted/marked compromised and unsafe bootstrap/rotation/check paths fail closed. Actual remediation is NOT complete. `StegVerse-Labs/TVC#88` / `TVC-SCW-VAULT-ROTATION-088` still lacks observed replacement-key rotation, payload re-encryption, secret-free rotation receipt, and historical visibility resolution.

## Current finding ledger
**13 findings remain open**:
- AUTHORIZED_UNEXPLAINED: 10
- PROVENANCE_GAP: 2
- THIRD_PARTY_UNEXPLAINED: 1
- confirmed malicious events: 0
- confirmed unauthorized actors: 0
- confirmed security compromises: 1

## Machine-owned remediation / collision boundaries
Do not race these owners:
- `StegVerse-Labs/TVC#33` — `tvc.private-source-read.v1`; source implemented, authority activation not yet observed. The ecosystem audit is registered as a bounded consumer.
- `StegVerse-Labs/TVC#88` — actual SCW replacement-key rotation/re-encryption; blocked dependency/machine owned.
- `StegVerse-Labs/TVC#89` — migrate remaining TV credential-bearing operations into bounded TVC execution; actual credential-bearing migrated execution not observed.
- `StegVerse-Labs/StegDB#13` — deferred workflow/immutable dependency security work and historical attribution remain.
- `StegVerse-Labs/Governance#1` — machine-owned StegTrace bootstrap credential migration.
- `GCAT-BCAT-Engine/workflows#15` — immutable remote verifier successor task.
- `GCAT-BCAT-Engine/workflows#16` — provider credential/admissibility authority migration.
- `StegVerse-Labs/hybrid-collab-bridge#14` — StegVerse-primary / TV-TVC provider replacement.
- `StegVerse-Labs/Site#398` — remove/refactor latent bundle-ingest token-export apply code into TVC mutation authority.

Canonical execution task: `tasks/ECOSYSTEM-PROVENANCE-AUDIT-001.json`.

## Hard evidence/tool boundaries
The audit cannot truthfully certify the full historical ecosystem until all of the following occur:
1. complete exact-cutoff execution for the remaining 46 public repositories and upgrade/supersede compact-only batch 001 evidence;
2. obtain GitHub organization/security audit-log evidence for historical actor/token/application access and public/private visibility intervals;
3. recover historical private workflow-run/artifact evidence where the connected tool cannot enumerate it;
4. activate `tvc.private-source-read.v1` and materialize each private source at exact SHA without credential export;
5. run the validated exact-SHA audit runner over all 219 repositories/reachable history and preserve complete receipts;
6. execute TVC SCW replacement-key rotation and affected payload re-encryption with secret-free proof;
7. execute remaining TV credential migration under TVC and obtain fresh TV operational proof;
8. finish StegDB deferred workflow security/immutable dependency batches;
9. migrate the Governance machine-owned bootstrap credential path;
10. resolve both GCAT verifier and provider-authority successor tasks;
11. complete the hybrid provider replacement and Site bundle-ingest TVC mutation refactor;
12. reconcile package registries, runtime/deployment, DNS, signing, and other external infrastructure where claims exceed GitHub observability.

## Current conclusion
- Exact 219-repository manifest: **COMPLETE / VALIDATED**.
- End-to-end audit execution engine: **VALIDATED**.
- Credentialless public exact-cutoff execution: **30/76 COMPLETE; 46 REMAINING**.
- Complete retained public receipt evidence: **25/30 executed states**; batch 001 needs deterministic evidence upgrade.
- Private source execution: **0/143 through TVC capability; authority activation not yet observed**.
- Full 219-repository ecosystem execution: **NOT YET COMPLETE**.
- Confirmed malicious third-party event: **NONE ESTABLISHED**.
- Confirmed unauthorized actor: **NONE ESTABLISHED**.
- Confirmed security compromise: **YES** — SCW vault key material was committed into TV Git history; replacement rotation/re-encryption is not yet proven.
- Historical public/private exposure certified: **NO**.
- Clean-audit conclusion permitted: **NO**.

## Completion rule
This goal remains open. Do not archive, release, tag, propagate, or publish a clean-audit claim while required evidence/remediation remains blocked, unresolved, unvalidated, unexecuted, unreleased, undeployed, or unactivated.

## Propagation targets when release-ready
Only after a legitimate release threshold, propagate the exact released audit state to:
- `StegVerse-Labs/Site`
- `GCAT-BCAT-Engine/Publisher`
- `StegVerse-Labs/admissibility-wiki`
- `StegVerse-002/stegguardian-wiki`

## Session continuity
The repository now contains a validated end-to-end audit runner, a validated exact-name 219-repository denominator, direct public execution evidence for 30 exact historical cutoff states, complete retained/reverified receipt evidence for batches 002 and 003, 13 current findings, v5 finding receipt, and the machine-owned blocker registry. The next nonduplicate execution priority is to continue public batches using complete retained receipt artifacts while `tvc.private-source-read.v1` remains the sole private-source authority path. Do not request routine approval checkpoints.
