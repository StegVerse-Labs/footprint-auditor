# FOOTPRINT_AUDITOR_MIRROR_HANDOFF

Status: ACTIVE — BLOCKED DEPENDENCY / MACHINE OWNED

Date established: 2026-08-19
Last updated: 2026-08-19 14:38 America/Chicago

## Governing objective
Perform a historical ecosystem security/provenance audit from ecosystem origin through 2026-08-19. Attribute every consequential transition to dated actor, automation, dependency, build, release, deployment, runtime, or explicitly documented third-party evidence. Never treat missing evidence, current privacy, current membership, source containment, issue creation, or workflow success as proof of historical authorization or benign intent.

## Authority contract
- StegVerse primary; third-party fallback only when required.
- Credential/secret/token authority: TV/TVC ONLY.
- NON-TV/TVC secret/token authority: prohibited.
- GitHub Actions: validation/transport/evidence only; no production/runtime/control-plane authority.
- Audit engine receives no private-source credential.
- Unresolved transitions remain open and fail closed.

## Current connected boundary
Exact current accessible count is **219 repositories across 11 installations**:
- current public: 76
- current private: 143

Exact-count evidence:
- `evidence/inventory/accessible-repository-count-2026-08-19-v2.json`
- receipt SHA-256: `add29415fb80543aeaf285c3d69d197f28999b93cb151a95ae935c7ee248ae9d`

The earlier 203-row installation-listing CSV is retained only as a baseline. StegVerse-Labs installation listing truncates at 100 while repository search establishes 116 accessible Labs repositories. A complete exact-name 219-row manifest has not yet been reconstructed from one reliable connector listing surface. Current visibility is not historical visibility evidence.

## Canonical audit receipt
Current superseding receipt:
- `evidence/reports/ecosystem-provenance-audit-2026-08-19-v4.json`
- deterministic report SHA-256 excluding its self-hash field: `88f8d87cf6e1920959fafd3ef69eded97b015d4658e4b007bcae067c9bd48575`
- clean audit permitted: false
- open findings: 11

v4 supersedes the original, v2, and v3 receipts. v3 used the superseded 203-repository denominator and is not authoritative.

## Installed audit engine
Canonical modules now include:
- `src/provenance/historical.py`
- `src/provenance/commit_authority.py`
- `src/provenance/workflow_dependencies.py`
- `src/provenance/workflow_authority.py`
- `src/provenance/python_dependencies.py`
- `src/provenance/ecosystem_dependencies.py`
- `src/provenance/inventory.py`
- `src/provenance/report.py`
- `src/provenance/repository_executor.py`

`repository_executor.py` is the exact-SHA materialized-repository execution path. It accepts no credential and performs no network access; it requires immutable expected SHA, verifies HEAD/worktree cleanliness, hashes Git identities, scans workflow/dependency/control surfaces, scrubs committed token literals from retained evidence, and emits a deterministic secret-safe receipt. Private source must be materialized before it runs by an admitted TVC read capability.

Workflow authority scanning additionally detects credential/bootstrap issuance, credential-to-GitHub-output propagation, credential-like artifact export, and credential/bootstrap response logging without reading secret values.

## Confirmed security event
### TV SCW vault key exposure
Finding: `evidence/findings/2026-08-19-tv-scw-vault-key-exposure.json`

A usable SCW Fernet key was committed into `StegVerse-Labs/TV` Git history on 2025-11-25 in the same transition as the encrypted vault artifact. The raw key must never be reproduced.

Current-tree containment is complete:
- live key value redacted and marked compromised;
- legacy bootstrap, rotation, and checker workflows fail closed.

Actual remediation is NOT complete. `StegVerse-Labs/TVC#88` / `tasks/TVC-SCW-VAULT-ROTATION-088.json` remains `BLOCKED_DEPENDENCY_MACHINE_OWNED` with:
- replacement key rotation observed: false
- payload re-encryption observed: false
- secret-free rotation receipt observed: false
- historical visibility resolved: false

## Current finding ledger
11 findings remain open:
- AUTHORIZED_UNEXPLAINED: 8
- PROVENANCE_GAP: 2
- THIRD_PARTY_UNEXPLAINED: 1
- CONFIRMED_MALICIOUS: 0
- CONFIRMED_UNAUTHORIZED actor: 0
- confirmed security compromise: 1

Key durable findings:
- `2026-08-19-tv-scw-vault-key-exposure.json`
- `2026-08-19-tvc-actions-user-write-test.json`
- `2026-08-19-tv-credential-processing-policy-drift.json`
- `2026-08-19-stegdb-secret-contract-policy-drift.json`
- `2026-08-19-pat-backed-autopatch-authority-containment.json`
- `2026-08-19-scw-admin-credential-bootstrap-export.json`
- `2026-08-19-scw-legacy-bridge-credential-path.json`
- `2026-08-19-gcat-verifier-remote-execution-provenance-gap.json`
- `2026-08-19-governance-bootstrap-credential-authority-gap.json`
- `2026-08-19-hybrid-bridge-provider-credential-authority.json`
- `2026-08-19-labs-residual-credential-control-containment.json`

## Current-tree containment performed/consumed
The audit has durably contained or consumed containment for dozens of credential/control-plane paths. Major groups include:
- 23 legacy PAT/autopatch/cross-repository mutation paths recorded in `2026-08-19-pat-backed-autopatch-authority-containment.json`;
- 14 additional Labs credential/control paths recorded in `2026-08-19-labs-residual-credential-control-containment.json`;
- 2 SCW admin bootstrap/config seeding paths, including former credential-to-output/artifact behavior;
- 4 hybrid bridge hosted-provider/entity paths;
- obsolete TV generic-PAT/bridge/self-repair paths;
- TV SCW unsafe vault bootstrap/rotate/check paths;
- StegDB generic-PAT contract and multiple token-backed mutation/ingest paths;
- stale FREE-DOM and Governance bridge forwarders;
- legacy StegAgents scheduled provider indexer;
- StegBrain generic-PAT auto-heal path;
- legacy `StegVerse-Labs/SCW` generic-token bridge;
- currently public Maxwellality generic-token bridge.

Containment preserves history. It does not prove historical executions were authorized/benign and does not constitute replacement or activation.

## Bounded negative evidence
`evidence/verification/2026-08-19-nonlabs-high-risk-signature-sweep.json` records no current indexed hits across the nine non-Labs organization installations for four named signatures:
- `x-access-token`
- `secrets.GH_`
- `ADMIN_TOKEN`
- `fernet_key`

This is a bounded signature result only, not a clean-audit conclusion. Search-index freshness, historical deleted content, different names/encodings, runtime-only values, artifacts, dependencies, binaries, logs, and external infrastructure remain outside that result.

## Machine-owned remediation / collision boundaries
Do not race these owners:
- `StegVerse-Labs/TVC#33` — activate `tvc.private-source-read.v1`; currently open/not activated.
- `StegVerse-Labs/TVC#88` — actual SCW replacement-key rotation/re-encryption; blocked dependency/machine owned.
- `StegVerse-Labs/TVC#89` — migrate remaining TV credential-bearing operations into bounded TVC execution; actual credential-bearing migrated execution not yet observed.
- `StegVerse-Labs/StegDB#13` — `STEGDB-SEC-001`; TV/TVC secret contract v2 and substantial containment landed, but deferred workflows/immutable dependency enforcement remain and issue is open.
- `StegVerse-Labs/Governance#1` — machine-owned StegTrace bootstrap; credential migration required, audit recorded/routed exception but did not race workflow ownership.
- `GCAT-BCAT-Engine/workflows#15` — mutable remote verifier provenance successor task.
- `StegVerse-Labs/hybrid-collab-bridge#14` — StegVerse-primary/TV-TVC replacement for contained hosted-provider paths.

## Hard evidence/tool boundaries
The audit cannot truthfully certify the full historical ecosystem until all of the following occur:
1. reconstruct a complete exact-name manifest for all 219 accessible repositories;
2. obtain GitHub organization/security audit-log evidence for historical actor/token/application access and public/private visibility intervals;
3. recover historical private workflow-run/artifact evidence where the connected tool cannot enumerate run IDs;
4. activate `tvc.private-source-read.v1` and materialize each private source at exact SHA without credential export;
5. run the exact-SHA repository executor over all 219 repositories/reachable history and preserve receipts;
6. execute TVC SCW replacement-key rotation and affected payload re-encryption with secret-free proof;
7. execute remaining TV credential migration under TVC and obtain fresh TV operational proof;
8. finish StegDB deferred workflow security/immutable dependency batches;
9. migrate the Governance machine-owned bootstrap credential path;
10. resolve GCAT mutable verifier and other mutable third-party execution provenance;
11. reconcile package registries, runtime/deployment, DNS, signing, and other external infrastructure where claims exceed GitHub observability.

## Validation state
Source and tests are installed, including tests for the exact-SHA repository executor and credential-export detection. The connected GitHub surface has not produced a qualifying status/run proving the latest consolidated state passed, and the local sandbox cannot clone GitHub. Therefore latest-source validation remains unproven; source-installed is not equated with validated/runtime.

## Current conclusion
- Confirmed malicious third-party event: **NONE ESTABLISHED**.
- Confirmed unauthorized actor: **NONE ESTABLISHED**.
- Confirmed security compromise: **YES** — SCW vault key material was committed into TV Git history; replacement rotation/re-encryption is not yet proven.
- Unresolved third-party identity: **YES** — TVC write-test identity remains historically unattributed to admitted TV/TVC actor/token/application evidence.
- Historical public/private exposure certified: **NO**.
- Clean-audit conclusion permitted: **NO**.

## Completion rule
This session goal remains open. Do not archive, release, tag, or publish a clean-audit claim while any required evidence/remediation above remains blocked, unresolved, unvalidated, unexecuted, unreleased, undeployed, or unactivated.

## Propagation targets when release-ready
Only after the audit reaches a legitimate release threshold, propagate the exact released audit state to:
- `StegVerse-Labs/Site`
- `GCAT-BCAT-Engine/Publisher`
- `StegVerse-Labs/admissibility-wiki`
- `StegVerse-002/stegguardian-wiki`

## Session continuity
The repository now contains the implementation, findings, v4 receipt, task registry, and blocker state needed to continue without this chat thread. Continue automatically when machine-owned dependencies produce evidence; do not request routine approval checkpoints.
