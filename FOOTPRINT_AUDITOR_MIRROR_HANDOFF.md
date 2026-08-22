# FOOTPRINT_AUDITOR_MIRROR_HANDOFF

Status: ACTIVE — END-TO-END RUNNER VALIDATED / ECOSYSTEM AUDIT BLOCKED DEPENDENCY

Date established: 2026-08-19  
Last updated: 2026-08-22 00:08 America/Chicago

## Governing objective
Perform a historical ecosystem security/provenance audit from ecosystem origin through 2026-08-19. Attribute every consequential transition to dated actor, automation, dependency, build, release, deployment, runtime, or explicitly documented third-party evidence. Never treat missing evidence, current privacy, current membership, source containment, issue creation, machine ownership, readiness, or workflow success as proof of historical authorization, activation, runtime, completion, or benign intent.

## Authority contract
- StegVerse primary; third-party fallback only when required.
- Credential/secret/token authority: TV/TVC ONLY.
- NON-TV/TVC secret/token authority: prohibited.
- GitHub Actions: validation/transport/evidence only; no production/runtime/control-plane authority.
- Audit engine receives no private-source credential.
- Unresolved transitions remain open and fail closed.

## Current accessible boundary
Exact accessible count is **219 repositories across 11 installations/accounts**:
- current public: 76
- current private: 143

Exact-count evidence:
- `evidence/inventory/accessible-repository-count-2026-08-19-v2.json`
- Git blob: `6e74825f2f222341fcdbdb978ec60f9fe8be3c73`

The earlier 203-row installation-listing CSV is retained only as a superseded baseline. StegVerse-Labs installation listing truncates at 100 while repository search establishes 116 accessible Labs repositories. A complete exact-name 219-row manifest has not yet been reconstructed from one reliable connector listing surface. Current visibility is not historical visibility evidence.

## Canonical audit receipt
Current superseding receipt:
- `evidence/reports/ecosystem-provenance-audit-2026-08-19-v5.json`
- deterministic report SHA-256 excluding the self-hash field: `91af76ca27027d70bb9cb40d439d68590ac05f1dd06aa8526c74c9dd472afbaa`
- finding artifacts bound by exact Git blob SHA: 13
- clean audit permitted: false
- open findings: 13

v5 supersedes the original, v2, v3, and v4 receipts.

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

The exact-SHA repository executor accepts no credential and performs no network access. It requires an immutable expected SHA, verifies HEAD and worktree cleanliness, hashes Git identities rather than retaining raw identity values, runs workflow/dependency/control scans, scrubs committed token literals from retained evidence, and emits a deterministic secret-safe receipt. Private source must first be materialized by admitted TVC read authority.

The end-to-end runner consumes a manifest of already materialized repositories bound to immutable expected SHAs, verifies each repository receipt, loads durable finding evidence, builds the aggregate audit report, and emits a deterministic execution receipt. Execution success is explicitly distinct from audit cleanliness: unresolved findings keep the audit open without falsely making the execution engine appear broken.

### End-to-end validation proof — 2026-08-22
A qualifying latest-source pull-request validation was directly observed through the connected GitHub Actions surface:
- validation PR: `StegVerse-Labs/footprint-auditor#8` (disposable validation only; not product authority)
- source base commit: `9b8ec0bddbc5d94a088fc41f25cab50617ebad8f`
- validation merge commit: `22360cef5dd1f53aaaee2fa23f15f6e0f0183e64`
- workflow run: `32553535659`
- job: `96984020347`
- provenance suite: **52/52 PASS**
- exact-SHA worktree cleanup/verification: PASS
- immutable self-scan manifest construction: PASS
- end-to-end self audit: PASS
- execution receipt verification: PASS
- executed repository count: 1
- execution complete: true
- audit clean: false, correctly preserving the open audit state
- execution receipt SHA-256: `d47bd9af93911ff3661b75f933e424b49421a33d0671fe893f99daa0b3622d9c`

The validation workflow uses `contents: read`, disables persisted checkout credentials, fetches full history for the exact-SHA self-scan, and does not grant GitHub Actions production/runtime/control-plane authority. This proves the `footprint-auditor` execution path works end to end on an exact materialized repository. It does **not** prove the 219-repository ecosystem audit is complete or clean.

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

Canonical finding files:
1. `2026-08-19-consumer-credential-export-mutation-paths.json`
2. `2026-08-19-gcat-provider-credential-authority-drift.json`
3. `2026-08-19-gcat-verifier-remote-execution-provenance-gap.json`
4. `2026-08-19-governance-bootstrap-credential-authority-gap.json`
5. `2026-08-19-hybrid-bridge-provider-credential-authority.json`
6. `2026-08-19-labs-residual-credential-control-containment.json`
7. `2026-08-19-pat-backed-autopatch-authority-containment.json`
8. `2026-08-19-scw-admin-credential-bootstrap-export.json`
9. `2026-08-19-scw-legacy-bridge-credential-path.json`
10. `2026-08-19-stegdb-secret-contract-policy-drift.json`
11. `2026-08-19-tv-credential-processing-policy-drift.json`
12. `2026-08-19-tv-scw-vault-key-exposure.json`
13. `2026-08-19-tvc-actions-user-write-test.json`

## Current-tree containment performed/consumed
Major durable containment/migration groups now include:
- 23 legacy PAT/autopatch/cross-repository mutation paths in the StegVerse-SCW/HCB cluster;
- 14 additional Labs credential/control-plane paths;
- 2 SCW admin bootstrap/config seeding paths;
- 4 hosted-provider hybrid bridge paths;
- obsolete TV generic-PAT/bridge/self-repair paths;
- TV SCW unsafe vault bootstrap/rotate/check paths;
- StegDB generic-PAT contract replaced by TV/TVC contract v2 and multiple token-backed paths contained/hardened;
- stale FREE-DOM, Governance, Maxwellality, StegAgents, StegBrain, and SCW credential/control paths;
- `StegVerse-Labs/Comms-Gateway/tools/push_m1_tag_via_git.py` contained; exact M1 tag mutation remains exclusively in the repository's existing TVC lifecycle;
- `StegVerse-Labs/crypto-bot/.github/workflows/finalize-paper-release.yml` converted from hosted credential-bearing tag mutation to validation-only; exact tag authority remains TVC-only;
- `StegVerse-Labs/StegOps-Orchestrator/.github/workflows/stegops-mirror-status-to-deliverables.yml` retired fail-closed;
- Site bundle-ingest latent apply source remains present, but live `app/resolver.py` prohibits raw credential export and makes that path unreachable; Site #398 owns removal/refactor to TVC mutation authority.

Containment preserves history. It does not prove historical executions were authorized or benign, and it is not replacement activation.

## Bounded negative evidence
`evidence/verification/2026-08-19-nonlabs-high-risk-signature-sweep.json` records no current indexed hits across the nine non-Labs organization installations for the named high-risk signature sweep. This is bounded search evidence only; search-index freshness, deleted history, alternate names/encodings, runtime values, artifacts, dependencies, binaries, logs, and external infrastructure remain outside that result.

## Machine-owned remediation / collision boundaries
Do not race these owners:
- `StegVerse-Labs/TVC#33` — activate `tvc.private-source-read.v1`; currently open/not activated.
- `StegVerse-Labs/TVC#88` — actual SCW replacement-key rotation/re-encryption; blocked dependency/machine owned.
- `StegVerse-Labs/TVC#89` — migrate remaining TV credential-bearing operations into bounded TVC execution; actual credential-bearing migrated execution not observed.
- `StegVerse-Labs/StegDB#13` — `STEGDB-SEC-001`; current TV/TVC contract v2 observed, but deferred workflows/immutable dependency work and historical attribution remain.
- `StegVerse-Labs/Governance#1` — machine-owned StegTrace bootstrap credential migration.
- `GCAT-BCAT-Engine/workflows#15` — immutable remote verifier successor task.
- `GCAT-BCAT-Engine/workflows#16` — provider credential/admissibility authority migration.
- `StegVerse-Labs/hybrid-collab-bridge#14` — StegVerse-primary / TV-TVC provider replacement.
- `StegVerse-Labs/Site#398` — remove/refactor latent bundle-ingest token-export apply code into TVC mutation authority.

Canonical execution task: `tasks/ECOSYSTEM-PROVENANCE-AUDIT-001.json`.

## Hard evidence/tool boundaries
The audit cannot truthfully certify the full historical ecosystem until all of the following occur:
1. reconstruct a complete exact-name manifest for all 219 accessible repositories;
2. obtain GitHub organization/security audit-log evidence for historical actor/token/application access and public/private visibility intervals;
3. recover historical private workflow-run/artifact evidence where the connected tool cannot enumerate it;
4. activate `tvc.private-source-read.v1` and materialize each private source at exact SHA without credential export;
5. run the validated exact-SHA audit runner over all 219 repositories/reachable history and preserve receipts;
6. execute TVC SCW replacement-key rotation and affected payload re-encryption with secret-free proof;
7. execute remaining TV credential migration under TVC and obtain fresh TV operational proof;
8. finish StegDB deferred workflow security/immutable dependency batches;
9. migrate the Governance machine-owned bootstrap credential path;
10. resolve both GCAT verifier and provider-authority successor tasks;
11. complete the hybrid provider replacement and Site bundle-ingest TVC mutation refactor;
12. reconcile package registries, runtime/deployment, DNS, signing, and other external infrastructure where claims exceed GitHub observability.

## Current conclusion
- End-to-end audit execution engine: **VALIDATED for an exact materialized repository**.
- Full 219-repository ecosystem execution: **NOT YET COMPLETE**.
- Confirmed malicious third-party event: **NONE ESTABLISHED**.
- Confirmed unauthorized actor: **NONE ESTABLISHED**.
- Confirmed security compromise: **YES** — SCW vault key material was committed into TV Git history; replacement rotation/re-encryption is not yet proven.
- Unresolved third-party identity: **YES** — TVC `actions-user` write test remains historically unattributed to admitted actor/token/application evidence.
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
The repository now contains a validated end-to-end audit runner, exact-count evidence, 13 current findings, v5 receipt, task registry, and blocker state sufficient to continue without this chat history. The next nonduplicate execution priority is full manifest/materialization activation and multi-repository execution; continue automatically when TVC/private-source and other machine-owned dependencies produce evidence. Do not request routine approval checkpoints.
