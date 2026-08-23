# FOOTPRINT_AUDITOR_MIRROR_HANDOFF

Status: ACTIVE — PUBLIC 76/76 COMPLETE / PRIVATE 0/143 / PRIVATE SOURCE EXECUTION SOURCE-COMPLETE, SOLE-HOST ACTIVATION PENDING

Date established: 2026-08-19  
Last updated: 2026-08-23 17:12 America/Chicago

## Governing objective
Perform a historical ecosystem security/provenance audit from ecosystem origin through `2026-08-19T23:59:59Z`. Attribute consequential transitions to dated actor, automation, dependency, build, release, deployment, runtime, or explicit third-party evidence. Missing evidence is never silently benign.

## Authority contract
- StegVerse primary; third-party fallback only where required.
- Credential/secret/token authority: **TV/TVC ONLY**.
- NON-TV/TVC secret/token authority: prohibited.
- GitHub Actions: validation/transport/evidence only; no production/runtime/control-plane authority.
- The audit engine never receives the private-source credential.
- `source_complete != activated`, `workflow_pass != runtime`, and unresolved transitions remain open/fail closed.

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
All **76/76** current-public repositories were anonymously materialized at the immutable last default-branch commit at or before cutoff, scanned, retained, and independently reverified.

Coverage receipt: `evidence/execution/public-cutoff-coverage-2026-08-22.json`  
SHA-256: `2f086eff80c2fe33173eec9814e76944d7abac19434fa5fe5f4051f5b908fe02`.

## Audit engine — VALIDATED
Historical, authority, workflow/dependency, inventory/report, exact repository executor, audit runner, GitHub audit-log parser/importer, and public materialization paths are installed. Execution-complete and audit-clean remain distinct.

## GitHub organization audit-log path — VALIDATED / SOURCE DATA PENDING
PR #21 merged at `107023834c0df5d6ed35a61b45eb54253b18b172`; run `32608506740`, job `97117462150`: **69/69 PASS**. Actual organization audit-log records remain unavailable through the connected GitHub surface, so historical actor/token/App authority and visibility reconstruction remain incomplete.

## Private exact-cutoff execution — 0/143 / CURRENT PRIMARY RUNTIME GAP
Sole admitted capability: `tvc.private-source-read.v1`, owned by `StegVerse-Labs/TVC#33`.

### TV policy
Historical immutable-read policy merged at `StegVerse-Labs/TV@c6eede495c18b8b19156cf68576702b93e77f593` with `TRACKED_REF` and `IMMUTABLE_COMMIT` modes.

### TVC exact immutable source
PR #95 merged `47b742c7ce141925020812cdddbf23ccd99cdc56`; run `32608428996`, job `97117259662`: **15/15 PASS** plus no-generic-token fallback PASS.

### TVC historical cutoff resolver
PR #96 merged `f7ae8cbcdc04fff028ecb2923d7728ab45594224`; run `32609026197`, job `97118810251`: **21/21 PASS** plus no-generic-token fallback PASS. TVC can resolve the last branch commit at/before cutoff after actual TVC credential injection, so manual SHA precomputation for all 143 private repos is unnecessary.

### TVC resident activation bridge
PR #97 merged `15dae9e726a1383b71ca36f0f3404a63d9c3c579`; run `32669511949`, job `97268014050`: **25/25 PASS**.

Validated:
- systemd `LoadCredential` transport;
- credential process-only and absent from retained receipts;
- non-secret activation requests only;
- materialization restricted to `/var/lib/stegverse/private-source-read/materialized`;
- hardened read-only service boundary;
- generic GitHub/provider/user credential fallback absent.

### TVC deterministic service installer
PR #99 merged `fc8aee86f96e52d5852dc6ded8c0ad689591fabe`; run `32669693792`, job `97268480481`: **28/28 PASS** plus no-generic-token fallback PASS.

Installer `scripts/install_private_source_read_service.py` renders the exact systemd unit using only absolute paths and a credential source under `/run/stegverse`, never reads/persists the credential value, and does not start the service implicitly.

### Canonical first private-audit activation request
TVC now contains `requests/private-source-read/footprint-auditor-private-001-ae.json`, commit `9d8baaee3ac776a9c5583903dd9a7a8109dd05f4`.

It is non-secret and binds:
- caller `StegVerse-Labs/footprint-auditor`;
- source `Admissible-Existence/AE`;
- task `ECOSYSTEM-PROVENANCE-AUDIT-001`;
- branch `main`;
- cutoff `2026-08-19T23:59:59Z`;
- mode `IMMUTABLE_COMMIT`;
- materialization id `private-audit-001-ae`;
- TTL 600 seconds.

The exact historical SHA is resolved by TVC under admitted read authority at execution time, then frozen into the immutable grant/materialization path.

### Current observed runtime boundary
No GitHub-visible evidence currently proves:
- `stegtvc-private-source-read.service` is installed on the sole host;
- the scoped `TVC_PRIVATE_SOURCE_READ_TOKEN` exists in `/run/stegverse`;
- a resident private-source invocation completed;
- any exact private checkout has been materialized.

Therefore **private execution remains 0/143** and capability activation remains unproven.

The source-complete bounded host sequence is now:
```text
TVC install_private_source_read_service.py --daemon-reload
  -> authorize_and_activate_private_source_read.py --request requests/private-source-read/footprint-auditor-private-001-ae.json
  -> systemd LoadCredential
  -> historical cutoff resolution
  -> immutable exact grant/materialization
  -> verify authorized_exact_sha == observed_exact_sha
  -> hand only materialized checkout to footprint-auditor
  -> verify deterministic audit receipt
```

No second heartbeat, scheduler, credential broker, generic GitHub token, or alternate runtime authority is introduced.

## Prepared private batch 001
`config/private-audit-batch-001.json` remains preparation only. It contains five seed targets; none count toward execution until TVC materialization and footprint audit receipts both verify.

## Confirmed security event
Historical SCW Fernet key exposure remains confirmed in `evidence/findings/2026-08-19-tv-scw-vault-key-exposure.json`. Never reproduce the key value. Current-tree containment exists; replacement-key rotation/re-encryption and historical visibility proof remain required under TVC #88.

## Current finding ledger
`evidence/reports/ecosystem-provenance-audit-2026-08-19-v5.json` records 13 open findings:
- AUTHORIZED_UNEXPLAINED: 10
- PROVENANCE_GAP: 2
- THIRD_PARTY_UNEXPLAINED: 1
- confirmed malicious events: 0
- confirmed unauthorized actors: 0
- confirmed security compromises: 1

v5 predates completed public execution and is not a final ecosystem receipt.

## Remaining hard gates
1. Observe/install the validated private-source resident service on the sole host.
2. Observe scoped TVC credential availability without exposing the value.
3. Execute the canonical first private request; verify secret-free TVC materialization receipt and exact HEAD.
4. Run `footprint-auditor` over that materialized checkout and retain verified audit receipt.
5. Repeat until private execution is **143/143**.
6. Obtain/import dated GitHub organization/security evidence for actor/token/App/OAuth/programmatic authority and historical visibility.
7. Reconcile external registry/DNS/signing/deployment/runtime/device provenance.
8. Complete required TV/TVC remediations including SCW replacement rotation/re-encryption.
9. Generate a superseding aggregate ecosystem receipt with explicit unresolved-exception accounting.

## Current conclusion
- Exact manifest: **219/219 COMPLETE / VALIDATED**
- Audit engine: **VALIDATED**
- GitHub audit-log importer: **VALIDATED; SOURCE DATA PENDING**
- Public exact-cutoff execution: **76/76 COMPLETE**
- Private exact-cutoff execution: **0/143**
- TV immutable-read policy: **VALIDATED / MERGED**
- TVC immutable exact-source path: **VALIDATED / MERGED**
- TVC historical cutoff resolver: **VALIDATED / MERGED**
- TVC resident activation bridge: **VALIDATED / MERGED**
- TVC resident service installer: **VALIDATED / MERGED**
- Canonical first activation request: **INSTALLED / NON-SECRET**
- Sole-host installation/credential/materialization: **NOT OBSERVED**
- Historical actor authority reconstruction: **INCOMPLETE**
- Historical exposure reconstruction: **INCOMPLETE**
- Confirmed malicious third-party event: **NONE ESTABLISHED**
- Confirmed unauthorized actor: **NONE ESTABLISHED**
- Confirmed security compromise: **YES — historical SCW key exposure; full remediation unproven**
- Clean-audit conclusion permitted: **NO**

## Next nonduplicate execution priority
1. Consume any new sole-host private-source installation/credential/materialization evidence immediately.
2. If present, execute/verify the first private audit and begin scaling the private denominator.
3. If absent, keep private coverage at 0/143 and advance other non-colliding historical/external provenance and security-remediation work.

## Completion rule
This goal remains open. Do not archive, release, deploy, activate, or publish a clean-audit claim while private execution, historical authority/visibility evidence, external provenance, required remediation, or unresolved findings remain pending.

Do not request routine approval checkpoints.
