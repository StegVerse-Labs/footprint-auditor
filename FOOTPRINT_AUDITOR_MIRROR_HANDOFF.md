# FOOTPRINT_AUDITOR_MIRROR_HANDOFF

Status: ACTIVE — ECOSYSTEM PROVENANCE / THIRD-PARTY INFLUENCE AUDIT

Date established: 2026-08-19
Last updated: 2026-08-19 13:54 America/Chicago

## Governing objective
Perform a historical ecosystem audit from ecosystem origin through 2026-08-19 and determine whether every consequential state transition can be attributed to an authorized actor, automation, dependency, build, release, deployment, or explicitly documented third party. Do not equate absence of detected malware with absence of unexplained influence.

## Audit boundary
- Public and private repository history where GitHub access remains available.
- Repository visibility transitions and historical public exposure intervals.
- Commits, branches, tags, releases, pull requests, reviews, workflows, artifacts, dependencies, generated files, deleted files, and force/rewrite indicators.
- Identity and authority provenance for humans, GitHub Apps, Actions, bots, deploy keys, OAuth/programmatic access, and external collaborators where evidence is obtainable.
- Build -> artifact -> release -> deployment -> runtime/receipt provenance where available.
- Cross-repository causality across StegVerse ecosystem organizations.
- External infrastructure evidence is required for claims that exceed GitHub's observability.

## Required classifications
Every consequential transition must resolve to one of:
- AUTHORIZED_EXPECTED
- AUTHORIZED_UNEXPLAINED
- THIRD_PARTY_EXPECTED
- THIRD_PARTY_UNEXPLAINED
- PROVENANCE_GAP
- SUSPICIOUS
- CONFIRMED_UNAUTHORIZED
- CONFIRMED_MALICIOUS

Unresolved transitions remain open; they are never silently treated as benign.

## Authority requirements
- StegVerse is primary; third-party fallback only when required.
- TV/TVC-managed authority is the intended credential/control boundary.
- No NON-TV/TVC secret or token should be introduced by this work.
- GitHub Actions may provide evidence/validation but must not become production/runtime/control-plane authority.

## Current implementation state
Canonical provenance modules:
- `src/provenance/__init__.py`
- `src/provenance/historical.py`
- `src/provenance/workflow_dependencies.py`
- `src/provenance/workflow_authority.py`
- `src/provenance/python_dependencies.py`

Canonical tests:
- `tests/test_historical_provenance.py`
- `tests/test_workflow_dependencies.py`
- `tests/test_workflow_authority.py`
- `tests/test_python_dependencies.py`

Configuration/validation:
- `config/provenance_audit.yaml`
- `.github/workflows/provenance-tests.yml`

The workflow scanners were converged after parallel implementation landed. Duplicate `workflow_supply_chain.py` / `workflow_controls.py` and duplicate tests were removed only after their additional behavior was folded into the canonical modules. The canonical dependency scanner now handles immutable 40-character GitHub SHAs, mutable tags/branches, local actions, dynamic `uses`, Docker digest vs tag references, expected third-party metadata, line numbers, deterministic summaries, and coverage ratios. The canonical authority scanner now additionally detects write/OIDC authority, direct pushes, mutable reusable references, non-TV/TVC-named secret references without reading values, global bearer-token Git URL rewrites, key-material serialization patterns, status-object summary exposure, mutable direct package installs, and remote executable fetches.

## Connected ecosystem inventory state
Connected GitHub installations have been enumerated for:
- StegVerse
- StegVerse-Labs
- Admissible-Existence
- AdmittedCode
- Data-Continuation
- GCAT-BCAT-Engine
- master-records
- StegGhost
- StegVerse-002
- StegVerse-org
- formalism-tests

The StegVerse user/account installation currently exposes zero repositories through the connector. Organization installations expose mixed public/private repository sets, proving current visibility cannot stand in for historical exposure state.

## Confirmed critical security event — TV SCW vault key
Finding artifact:
`evidence/findings/2026-08-19-tv-scw-vault-key-exposure.json`

Observed event:
- Repository: `StegVerse-Labs/TV`
- Commit: `1a6892c19eaf7892a5db6b7e3db8f8dfdd73c9c8`
- Time: 2025-11-25T12:32:01Z
- Commit identity observed: `StegVerse Bot`
- Workflow-generated commit message: `chore(vault): bootstrap SCW token vault`
- Raw Fernet key material was committed into Git history in the same transition as the encrypted SCW vault artifact.
- The bootstrap workflow also had source logic to place the key into a status object and Actions step summary.
- The current ciphertext inspected during this audit matched the ciphertext introduced by the exposure commit.
- No subsequent SCW rotation commit was found in the current commit-search pass.
- Current repository visibility is private. Visibility at the 2025-11-25 event remains unresolved pending organization audit-log evidence.

Security classification:
- confirmed credential-key exposure: YES
- confirmed malicious actor: NO
- confirmed unauthorized actor: NO
- key compromise treatment required: YES

The raw key value MUST NOT be reproduced in chat, issues, audit summaries, or future artifacts.

Live containment completed:
- `.github/vault/SCW.bootstrap.status.json` current-tree key value replaced with a non-secret compromised marker; historical Git exposure remains.
- `.github/workflows/vault_bootstrap.yml` contained/fail-closed and stripped of write/key-emission behavior.
- `.github/workflows/vault_rotate.yml` contained/fail-closed and stripped of repository key serialization.
- `.github/workflows/vault_check.yml` contained/fail-closed because it expected key material in repository metadata.
- TV issue #5 records required TV/TVC key rotation, re-encryption, workflow replacement, and historical visibility resolution.

Containment != remediation completion. Rotation/re-encryption evidence is still required through the TV/TVC credential authority.

## Unresolved external-identity mutation — TVC write test
Finding artifact:
`evidence/findings/2026-08-19-tvc-actions-user-write-test.json`

Observed event:
- Repository: `StegVerse-Labs/TVC`
- Commit: `3e74e0979ec91b55e47395eb2282bd936a118a05`
- Time: 2026-05-18T22:04:45Z
- Commit author/committer login from fetched commit metadata: `actions-user`
- Change: one `.stegverse-verified` marker line
- Historical workflow intent: `test: verify AI write permissions`
- TVC PR #2 was opened under the `StegVerse` account and later merged to `main` with the exact test commit as its head.
- `actions-user` has no current collaborator permission on TVC.

Assessment:
The content and PR context are consistent with an intentional credential/write-capability test, not covert payload injection. The historical identity/token authority behind `actions-user` remains unresolved and therefore the event stays `THIRD_PARTY_UNEXPLAINED` until audit-log/token/application evidence resolves it.

Live containment completed:
- TVC `.github/workflows/write_test.yml` retired/fail-closed; no legacy AI-token mutation remains executable through that file.
- TVC `.github/workflows/autopatch.yml` retired/fail-closed; generic PAT fallback/global token rewrite mutation path removed from live execution.
- SCW `.github/workflows/scw_core.yml` reconciled with its current sovereign Python core: write permissions and legacy AI-token injection removed; the core already rejects GitHub-token production authority and remote autopatch.

## Current TV credential-processing policy drift
Finding artifact:
`evidence/findings/2026-08-19-tv-credential-processing-policy-drift.json`

TV policy `policies/external_secret_processing_authority_policy.json` declares TV/TVC credential authority, `StegVerse-Labs/TVC` as credential-bearing executor, and prohibits consumer-repository direct secret interpolation. Current TV workflows still contain credential-bearing operations and/or mutable supply-chain authority, including:
- `.github/workflows/tv_apply_reusable.yml`
- `.github/workflows/tv_integrity_check.yml`
- `.github/workflows/tv_apply_verify_chain.yml`
- `.github/workflows/tv_auto_heal.yml`
- `.github/workflows/forward-to-bridge.yml`
- `.github/workflows/autopatch.yml`
- `.github/workflows/fix_workflows.yml`

TV issue #6 tracks migration to bounded TVC execution, retirement of obsolete generic-PAT/one-time mutation paths, immutable dependency binding, and preservation of TV operational-proof behavior. This is policy/control drift, not proof of malicious intent.

## Workflow/dependency provenance findings
Open evidence exceptions include:
1. Ecosystem workflows use mutable external GitHub Action tags such as `actions/checkout@v4`, `actions/setup-python@v5`, and `actions/upload-artifact@v4`. Trusted/expected publisher identity does not identify the exact historically executed commit.
2. `GCAT-BCAT-Engine/workflows/.github/workflows/gcat_bcat_tamper_detection.yml` is a concrete example of mutable action dependencies in a tamper-detection path.
3. `StegVerse-Labs/TV` contains or contained manually dispatchable/write-authority/self-modifying paths whose initiating actor/token/run evidence must be reconstructed before resulting mutations are certified authorized.
4. `StegVerse-Labs/TVC/.github/workflows/stegtvc_ci.yml` contains mutable Actions and package installation without complete artifact-hash/transitive resolution evidence.
5. TV signing paths have included runtime package installs and remote executable downloads without complete immutable artifact binding in the workflow source.

These are audit exceptions, not accusations of malicious intent.

## Durable audit exceptions/issues
Footprint auditor:
- Issue #1: ingest GitHub organization audit logs for identity/visibility provenance.
- Issue #2: reconstruct and retire mutable/write-authority workflow paths.
- Issue #3: cryptographically lock third-party package/build dependencies.

TV:
- Issue #5: rotate compromised SCW vault key and eliminate key-in-repository paths.
- Issue #6: migrate credential-bearing TV workflows into bounded TVC execution.

## Current preliminary result
Confirmed malicious third-party event: NONE ESTABLISHED.
Confirmed unauthorized actor: NONE ESTABLISHED.
Confirmed security compromise: YES — SCW Fernet key material was committed into TV Git history and the affected current ciphertext has not yet been proven re-encrypted under a replacement key.
Unresolved third-party identity event: YES — `actions-user` TVC mutation/test remains historically unattributed to an admitted TV/TVC identity.
Unresolved supply-chain provenance: YES — mutable Actions, package artifacts, remote downloads, and historical run identities remain incomplete.

This is NOT a clean-audit conclusion.

## Validation state
Canonical provenance tests/source are installed and `.github/workflows/provenance-tests.yml` targets the canonical four test files. The connected GitHub surface has not yet provided a qualifying workflow-run/status proving this consolidated state passed, so source-installed is not being equated with validated/runtime.

## Current tool boundary
Connected GitHub access can inspect repositories, private/public state, files, commit history, PRs, diffs, branches, workflow runs/jobs/logs/artifacts, statuses, repository metadata, and current collaborator permission. The current connector does not expose the full GitHub organization audit-log API. Final identity/access/visibility certification requires later audit-log ingestion/export or equivalent evidence.

## Immediate executable work
1. Continue ecosystem-wide `.github/workflows/**` inventory and mutable/write-authority classification, prioritizing StegVerse-Labs/.github, StegOps-Orchestrator, master-records/orchestration, GCAT-BCAT-Engine/workflows, SCW/StegVerse-SCW, Healer, and bridge paths.
2. Continue historical commit/PR provenance sampling for credential-bearing or self-mutating workflows.
3. Build durable current repository/visibility inventory snapshot suitable for later visibility-interval reconciliation.
4. Add commit-authority resolver/normalizer that fails closed on absent actor metadata and can ingest later organization audit-log evidence.
5. Extend dependency scanning to npm/Cargo/Go/containers/downloaded binaries/install scripts and SBOM/transitive evidence.
6. Resolve TV SCW key rotation/re-encryption through TV/TVC authority; do not treat live-tree redaction as rotation.
7. Migrate TV direct credential-bearing workflows into TVC without breaking TV operational-proof requirements.
8. Add deterministic report/receipt generation over real ecosystem findings.
9. Reconcile organization audit-log/security-log evidence when accessible.
10. Extend to external package/runtime/DNS/deployment evidence where the claim crosses GitHub's boundary.

## Completion criteria
This goal is not complete merely because source code exists, a workflow passes, an issue exists, a dangerous path is contained, or a key is removed from the current tree. Completion requires implemented audit ingestion, historical coverage, validated classification, durable evidence, cross-repo execution, unresolved-exception accounting, required credential rotation/re-encryption, and an explicit statement of coverage limits. A finding of "no evidence of unauthorized third-party influence" is permitted only when unresolved provenance gaps are zero within the stated audited boundary.

## Propagation targets when release-ready
Verify pertinent audit model/results are reflected where applicable in:
- StegVerse-Labs/Site
- GCAT-BCAT-Engine/Publisher
- StegVerse-Labs/admissibility-wiki
- StegVerse-002/stegguardian-wiki

## Session continuity
Continue without approval checkpoints. Stop only for a real authority/tooling boundary, an unsafe/destructive action requiring explicit confirmation, or completion of the stated goal. This handoff contains the state required to continue without this chat thread.
