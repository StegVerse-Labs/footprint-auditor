# Ecosystem Provenance Audit — 2026-08-19

Report SHA-256: `acc0ff3d920ecbfc56e7116cdbc8a845bc779791ce0d02ce673699d975dfc472`  
Boundary: `ecosystem-origin` → `2026-08-19T19:16:00Z`

## Current inventory baseline

- Connected installations: 11
- Connected repositories: 203
- Currently public: 75
- Currently private: 128
- Canonical inventory manifest SHA-256: `59879f7dc3e07f40bb7b5b8143e0368e470074c060ef5440ceb393261e030166`

Current visibility is an observation baseline only. It is not historical visibility evidence.

## Security result

- Confirmed malicious third-party event: **NONE ESTABLISHED**
- Confirmed unauthorized actor: **NONE ESTABLISHED**
- Confirmed security compromise: **YES — SCW vault key material was committed into TV Git history**
- Unresolved third-party identity: **YES — TVC `actions-user` write test**
- Clean-audit conclusion permitted: **NO**

## Finding counts

- Total findings: 8
- Open findings: 8
- `AUTHORIZED_UNEXPLAINED`: 5
- `PROVENANCE_GAP`: 2
- `THIRD_PARTY_UNEXPLAINED`: 1

## Findings

- `GCAT-WORKFLOWS-REMOTE-VERIFIER-PROVENANCE-2026-08-19` — `GCAT-BCAT-Engine/workflows` — **PROVENANCE_GAP** — OPEN
- `ECOSYSTEM-PAT-AUTOPATCH-AUTHORITY-2026-08-19` — `MULTI_REPOSITORY` — **AUTHORIZED_UNEXPLAINED** — OPEN
- `SV-AUDIT-SCW-LEGACY-BRIDGE-CREDENTIAL-001` — `StegVerse-Labs/SCW` — **PROVENANCE_GAP** — OPEN
- `SCW-ADMIN-CREDENTIAL-BOOTSTRAP-EXPORT-2026-08-19` — `StegVerse-Labs/StegVerse-SCW` — **AUTHORIZED_UNEXPLAINED** — OPEN
- `STEGDB-SECRET-CONTRACT-POLICY-DRIFT-2026-08-19` — `StegVerse-Labs/StegDB` — **AUTHORIZED_UNEXPLAINED** — OPEN
- `TV-CREDENTIAL-PROCESSING-POLICY-DRIFT-2026-08-19` — `StegVerse-Labs/TV` — **AUTHORIZED_UNEXPLAINED** — OPEN
- `TV-SCW-VAULT-KEY-EXPOSURE-2025-11-25` — `StegVerse-Labs/TV` — **AUTHORIZED_UNEXPLAINED** — OPEN
- `TVC-ACTIONS-USER-WRITE-TEST-2026-05-18` — `StegVerse-Labs/TVC` — **THIRD_PARTY_UNEXPLAINED** — OPEN

## Containment completed during audit

- 19 legacy PAT/autopatch/guardian mutation paths recorded as contained.
- SCW legacy bridge credential dispatch contained.
- TV legacy bridge dispatch contained.
- TV generic-PAT autopatch contained.
- TV one-time hosted workflow self-repair contained.
- TV SCW vault key removed from live status and unsafe bootstrap/rotate/check workflow paths contained.
- TVC legacy write-test and generic-PAT autopatch paths contained.

Containment is not historical attribution, rotation, migration, runtime proof, or clean-audit completion.

## Machine-owned remediation

- `TVC-SCW-VAULT-ROTATION-088` / TVC #88 — actual rotation/re-encryption not yet observed.
- `TVC-TV-CREDENTIAL-MIGRATION-089` / TVC #89 — bounded credential-bearing TVC execution not yet observed.
- GCAT workflow #15 / `SV-CONT-20260819-PROVENANCE-012` — immutable verifier successor contract not yet installed.
- StegDB #13 / `STEGDB-SEC-001` — stale generic-PAT authority resolution not yet observed.

## Hard evidence gates

- GitHub organization/security audit-log evidence for historical actor/token/app and repository visibility intervals.
- Actual TV/TVC secret-bearing SCW key rotation and payload re-encryption receipt.
- Actual bounded TVC migration/execution for remaining TV credential-bearing functions followed by fresh TV operational proof.
- Full 203-repository dependency/workflow execution using the installed scanners.
- External runtime/DNS/package-registry/deployment provenance for claims outside GitHub observability.

## Permitted conclusion

**Audit remains open; unresolved evidence or coverage gaps prevent a clean-audit conclusion.**

No secret values are contained in this report.
