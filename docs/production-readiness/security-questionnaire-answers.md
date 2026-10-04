# Vendor security questionnaire answer sheet (CAIQ-lite / SIG-lite style)

**Product:** Singularity AIDR (AI Agent Detection and Response)
**Prepared for:** enterprise procurement and security review (large-enterprise buyer, for example BMC)
**Bound to repository commit:** `377b9c10` (branch `readiness/enterprise-hardening`)
**Prepared:** 5 October 2026

## Read this first

- This is an **engineering-prepared draft**. It is **not** a legal, privacy, audit or compliance attestation, and it is not a contractual commitment. Nothing here replaces a signed DPA, order form, support schedule or independent report.
- Every answer was written from reading code, configuration and documents in this repository at the commit above. Where an answer depends on a human, process, legal or external party (certifications, penetration test, DPA, subprocessor contracts, insurance, staffing, training, retainers, live operations), the status is `Not yet` with the owner who must act. Absence of evidence is reported as absence, never as a pass.
- Evidence was **read, not re-executed**: this sheet does not assert that any test, gate or build passed at this commit. The current release decision per `docs/production-readiness/first-customer-ready.md` is **NO-GO** for a live pilot offer or production deployment, and the 13 hard-gate receipts in `docs/production-readiness/commercial-gate-receipts.json` are open. Re-verify against a signed, candidate-bound release before sending to a customer.
- Statements about behavior describe what the code is designed to do. They are not measurements of a deployed environment. No deployed environment, packet capture, live Identity Provider (IdP) acceptance or restore on a second host has been accepted.
- Wording follows the repository claim controls (`claimPatterns` in `docs/production-readiness/commercial-go-evidence-registry.json`). Do not paraphrase answers into broader claims.

### Status values

| Status | Meaning |
|---|---|
| `Implemented (verified in code)` | A mechanism exists in the repository and was read at the cited path. It does not mean accepted, deployed or independently tested. |
| `Partially implemented` | Mechanism exists with a stated gap or limitation. |
| `Not yet — owner action: <who/what>` | No evidence in the repository; needs the named owner. |
| `Not applicable` | The question does not apply to this product or model. |

## Table of contents

1. [Governance and policy](#1-governance-and-policy) (GOV)
2. [Secure development lifecycle and supply chain](#2-secure-development-lifecycle-and-supply-chain) (SDL)
3. [Identity and access management](#3-identity-and-access-management) (IAM)
4. [Multi-tenancy and data segregation](#4-multi-tenancy-and-data-segregation) (TEN)
5. [Encryption and key management](#5-encryption-and-key-management) (CRY)
6. [Logging, audit and SIEM](#6-logging-audit-and-siem) (LOG)
7. [Data privacy, retention, deletion and residency](#7-data-privacy-retention-deletion-and-residency) (PRV)
8. [Subprocessors and third parties](#8-subprocessors-and-third-parties) (SUB)
9. [Vulnerability and patch management](#9-vulnerability-and-patch-management) (VUL)
10. [Business continuity and disaster recovery](#10-business-continuity-and-disaster-recovery) (BCP)
11. [Incident response](#11-incident-response) (INC)
12. [Deployment models](#12-deployment-models) (DEP)
13. [Endpoint agent security](#13-endpoint-agent-security) (END)
14. [Compliance, certifications and penetration testing](#14-compliance-certifications-and-penetration-testing) (CMP)
15. [AI-specific questions](#15-ai-specific-questions) (AI)
16. [Open items by owner](#16-open-items-by-owner)

---

## 1. Governance and policy

**GOV-01. Is there a documented information security policy set approved by management?**
Status: `Not yet — owner action: Security Lead / executive sponsor`
Answer: The repository holds engineering policy and runbooks (`SECURITY.md`, `docs/runbooks/*.md`, `docs/production-readiness/*.md`) but no management-approved information security policy, acceptable-use policy or annual review record. Several runbooks label themselves "operating draft".
Evidence: `docs/runbooks/incident-response.md` (header: "Operating draft"), `docs/runbooks/support-v7.md` (header: "operating procedure draft").

**GOV-02. Is a named security officer / security function responsible for the program?**
Status: `Not yet — owner action: executive sponsor to appoint and record a named Security Lead`
Answer: Gate documents refer to a "Security Lead", "Privacy/DPO" and "Operations" as roles to be named, but no names, rota or appointment record exist in the repository.
Evidence: `docs/production-readiness/sec-ext-001-assessment-acceptance.md`, `docs/production-readiness/com-003-privacy-acceptance-2026-09-23.md`, `docs/runbooks/support-v7.md` ("Named primary and backup" table).

**GOV-03. Is there a tracked risk register and defect/readiness ledger?**
Status: `Partially implemented`
Answer: A manually maintained readiness ledger and generated gap maps exist and are validated by scripts. The repository states the ledger's baseline and verification fields are historical and not proof for the current checkout. There is no enterprise risk register with risk owners and treatment decisions.
Evidence: `READINESS_BACKLOG.json`, `scripts/validate-backlog.mjs`, `PRODUCTION_SALES_GAPS.json`, `docs/production-readiness/remaining-local-gaps.md` (header note).

**GOV-04. Are commercial and security claims controlled before they reach customers?**
Status: `Implemented (verified in code)`
Answer: A claim registry with blocked-claim regex patterns (latency, privacy-absolutes, certification, readiness, automated-response and similar categories) is enforced by scripts in the static quality gate. Approval of the final claim text remains a human gate.
Evidence: `docs/production-readiness/commercial-go-evidence-registry.json` (`claimPatterns`), `scripts/check-commercial-surface.mjs`, `scripts/verify-commercial-compliance.mjs`, `package.json` script `quality:static`.

**GOV-05. Is there a defined release decision process with named approvers?**
Status: `Partially implemented`
Answer: Release promotion is gated in code (protected GitHub environment `release-candidate`, signer policy, attestation verification). The named human approvers and sign-off records are not in the repository; all 13 commercial gate receipts are open.
Evidence: `.github/workflows/release-rc.yml` (job `final-sign-publish`, `environment: release-candidate`), `.github/workflows/release-promote.yml`, `docs/production-readiness/commercial-gate-receipts.json`.

**GOV-06. Is security awareness training delivered to personnel, with background screening?**
Status: `Not yet — owner action: HR / Security Lead`
Answer: No training program, completion records or background-check process exist in the repository. The `skills/security-awareness/SKILL.md` file is knowledge for AI agents, not a workforce training record.
Evidence: none in repository.

**GOV-07. Are there confidentiality agreements, acceptable-use rules and contractor controls for personnel with production access?**
Status: `Not yet — owner action: Legal / HR`
Answer: Contributor and employee/contractor chain-of-title is listed as an open requirement in the licensing audit. No NDA or access-agreement records exist in the repository.
Evidence: `docs/production-readiness/com-002-license-audit-2026-09-23.md` ("chain of title").

**GOV-08. Is cyber/professional liability insurance in place?**
Status: `Not yet — owner action: Finance / Legal (broker evidence)`
Answer: No insurance information exists in the repository.
Evidence: none.

---

## 2. Secure development lifecycle and supply chain

**SDL-01. Is source code under version control with enforced code review before merge?**
Status: `Partially implemented`
Answer: The repository is in Git with a `CODEOWNERS` file (all paths owned by `@SingularityRD`) and a PR template with a pre-PR checklist. Whether GitHub branch protection (required reviews, required status checks, no force-push) is enabled is a platform setting that is not visible in the repository and was not verified. Note the PR template still contains a stale line, "verify the fail-open behavior is preserved for error paths", that contradicts the current fail-closed connector policy in `CLAUDE.md`; correct it before sharing.
Evidence: `.github/CODEOWNERS`, `.github/pull_request_template.md`. Owner action for branch-protection evidence: repository admin (export of protection rules).

**SDL-02. Is there a continuous integration pipeline with automated tests and static checks on every change?**
Status: `Implemented (verified in code)`
Answer: CI runs the `quality:gate` aggregate (lint, type check, dead-code and duplicate checks, production and build dependency audits, tests, coverage, release build), Postgres-backed row-level-security and tenant tests, fleet lifecycle checks, package-install verification, a Python bridge job with `pip-audit`, and a clean-diff enforcement step.
Evidence: `.github/workflows/ci.yml` (step "Type, lint, audit, tests, coverage and release build"; `pip-audit -r requirements.txt`; "Enforce clean diff after verification/build"), `package.json` scripts `quality:gate`, `quality:static`.

**SDL-03. Is static application security testing (SAST) performed?**
Status: `Implemented (verified in code)`
Answer: CodeQL runs on push/PR and weekly (cron `0 9 * * 1`); Semgrep (`semgrep ci --config=auto`, container image pinned by digest) uploads SARIF to GitHub code scanning. Biome lint is part of the gate. Triage and closure of findings is a process item with no recorded SLA.
Evidence: `.github/workflows/codeql.yml`, `.github/workflows/semgrep.yml`, `biome.json`.

**SDL-04. Are third-party CI actions and tools pinned against tampering?**
Status: `Implemented (verified in code)`
Answer: Workflow actions are referenced by full commit SHA with a version comment (for example `actions/checkout@3d3c42e5…`), the Semgrep container by digest, the Gitleaks binary by exact version (8.30.1), and the pnpm version by `packageManager`. Dependency-bump automation (Dependabot, weekly) is configured and its updates are reviewed in PRs.
Evidence: `.github/workflows/ci.yml`, `.github/workflows/release-rc.yml`, `.github/workflows/semgrep.yml`, `.github/dependabot.yml`, `package.json` (`packageManager`).

**SDL-05. Are dependencies audited for known vulnerabilities, and does the build fail on new advisories?**
Status: `Implemented (verified in code)`
Answer: `audit:prod` wraps `pnpm audit --prod --json` and fails closed on any new advisory or path outside a narrowly scoped, documented exception; `audit:build` covers build dependencies; the Python bridge uses hash-pinned requirements plus `pip-audit`. Both audits are in `quality:gate` and the release-candidate workflow.
Evidence: `scripts/audit-production-deps.mjs` (header comment), `scripts/audit-production-deps-report.mjs`, `scripts/audit-build-deps.mjs`, `.github/workflows/ci.yml`, `.github/workflows/release-rc.yml` (`pnpm audit:prod && pnpm audit:build`).

**SDL-06. Is secret scanning performed on source and history?**
Status: `Partially implemented`
Answer: Gitleaks 8.30.1 scans the current checkout in CI (`verify:secrets:current`) and the release workflow runs `verify:secrets`. A redacted full-history scan with a partial-scan guard (2026-10-05, `scripts/scan-history-secrets.mjs`) returned 184 findings (92 distinct values, 56 commits): 182 classified as synthetic/identifier false positives with per-row rationale, 2 owner-confirm items, 0 confirmed live credentials. This is an engineering triage; the gate stays open until a security owner signs the owner-confirm rows and the scan is repeated with the pinned official gitleaks on the release candidate. The earlier 2026-09-23 counts (296) were obtained without `--no-textconv` and may reflect a partial scan. A tracked `.env.aig` was removed from the index; its history held only empty secret-bearing keys.
Evidence: `.github/workflows/ci.yml` (lines ~54-62), `.github/workflows/release-rc.yml` (lines ~154-161), `.gitleaks.toml`, `scripts/scan-current-secrets.mjs`, `docs/production-readiness/secret-history-triage-2026-10-05.md`, `docs/production-readiness/evidence/secret-history-ledger-2026-10-05.csv`. Owner action: Security Lead to sign the owner-confirm rows and repeat with the pinned binary.

**SDL-07. Is a Software Bill of Materials (SBOM) produced for releases?**
Status: `Implemented (verified in code)`
Answer: A deterministic CycloneDX SBOM is generated from the frozen pnpm lockfile (and hash-pinned Python requirements) and is uploaded and digest-checked in the release-candidate workflow. Licence metadata for shipped Python wheels is incomplete; commercial SBOM generation fails rather than emitting a promotion-incompatible file.
Evidence: `scripts/generate-sbom.mjs`, `scripts/lib/python-requirements-sbom.mjs`, `.github/workflows/release-rc.yml` (`aidr-sbom.cdx.json`), `docs/production-readiness/com-002-license-audit-2026-09-23.md`.

**SDL-08. Are releases signed, and can a customer verify provenance?**
Status: `Implemented (verified in code)`
Answer: Release bundles are signed with an Ed25519 key in the protected `final-sign-publish` job; the public key and its SHA-256 fingerprint are cross-checked before signing; `scripts/release-verify.mjs` verifies signature, signer policy, expiry, anti-rollback state, inventory and every artifact digest before running an installer. The workflow also emits a GitHub SLSA build-provenance attestation (`actions/attest-build-provenance`) and the promote/rollback workflows verify attestations with `gh attestation verify`. The local `generate-provenance.mjs` statement is explicitly **unsigned** and only detects drift. Publisher key custody and registry publication remain external. This is design/verification tooling; no signed candidate has been accepted (evidence index shows all gates `NOT_RUN` as of the 24 September 2026 inspection recorded in the readiness profile).
Evidence: `scripts/release-sign.mjs`, `scripts/release-signing-lib.mjs`, `scripts/release-verify.mjs`, `scripts/generate-provenance.mjs` (header "Boundary"), `.github/workflows/release-rc.yml` (lines ~1058-1197), `.github/workflows/release-promote.yml` (attestation verification steps), `docs/integrity.md`.

**SDL-09. Is the release signing private key isolated from build and from distributed artifacts?**
Status: `Implemented (verified in code)`
Answer: The signing key exists only as a secret in the `release-candidate` environment job, is written with `umask 077` to a temporary path and removed by a `trap`. Builds refuse to include private signing material (`assertNoPrivateSigningMaterial`, `exposedSigningMaterial` guards), and a test asserts publication cannot be bypassed from package scripts. Hardware-backed custody (HSM/KMS) is not implemented in the repository.
Evidence: `.github/workflows/release-rc.yml` (final-sign-publish), `scripts/release-key-isolation.test.mjs`, `scripts/build-workspace.mjs` (`assertNoPrivateSigningMaterial`), `scripts/generate-sbom.mjs` (`exposedSigningMaterial`). Owner action for HSM/KMS custody: Release Engineering.

**SDL-10. Do commercial endpoint builds verify their own integrity at startup?**
Status: `Implemented (verified in code)`
Answer: Commercial connectors verify a signed artifact manifest with provisioned Ed25519 public keys; failure enters degraded safe mode and the connector must not register hooks. Developer builds may skip verification.
Evidence: `docs/integrity.md`, `packages/core/src/integrity/` (`verify.ts`, `runtime.ts`, `degraded-safe-mode.ts`).

**SDL-11. Are builds reproducible and is source-tree cleanliness enforced for release?**
Status: `Partially implemented`
Answer: The SBOM generator is deterministic (`SOURCE_DATE_EPOCH`), generator determinism and release-source-clean checks exist, and CI fails on a dirty tree after build. Bit-for-bit reproducible builds across independent builders are not demonstrated.
Evidence: `scripts/check-generator-determinism.mjs`, `scripts/lib/release-source-clean.mjs` (referenced in `.github/workflows/release-rc.yml`), `scripts/generate-sbom.mjs`.

**SDL-12. Is open-source licence compliance managed?**
Status: `Partially implemented`
Answer: A licence report generator, an exception register and an audit exist. The audit decision is **open**: the notice file covers only direct dependencies, transitive notices and Python wheel licences are incomplete, and Legal approval is absent.
Evidence: `scripts/generate-license-report.mjs`, `docs/production-readiness/license-exception-register.json`, `docs/production-readiness/com-002-license-audit-2026-09-23.md`, `THIRD_PARTY_NOTICES`. Owner action: Legal.

---

## 3. Identity and access management

**IAM-01. How do customer users authenticate to the dashboard/control plane?**
Status: `Partially implemented`
Answer: Authentication is delegated to Supabase Auth (email/password plus configured OAuth providers; the set is deployment-specific). The Edge Functions verify the bearer token, a session-revocation barrier and tenant membership on each request. Auth provider choices, CAPTCHA and email delivery for a given deployment are not accepted; the readiness probe of 24 September 2026 recorded that Auth, email delivery and callback were unverified.
Evidence: `supabase/functions/_shared/auth.ts`, `supabase/functions/_shared/identity-barrier.ts`, `docs/device-auth.md`, `docs/production-readiness/first-customer-ready.md` (deployment diagnostics table).

**IAM-02. Is SAML single sign-on supported?**
Status: `Partially implemented`
Answer: The dashboard supports Supabase SAML providers configured through `AIDR_SAML_PROVIDERS`/`AIDR_SAML_PROVIDER_ID`/`AIDR_SAML_DOMAIN` (validated by `deploy/saml-config.mjs`), and a tenant can require exactly one SAML provider (`required_saml_provider_id`) with email/password sessions denied by RLS and Edge barriers. **Live Entra ID and Okta acceptance has not been performed**, there is no audited operation for setting or clearing the required provider, and the repository's own text says to keep the policy unset and not claim GA SSO continuity. Supabase-hosted SAML needs a Pro or higher plan. One tenant accepts exactly one required provider.
Evidence: `deploy/saml-config.mjs` (`parseSamlRuntimeConfig`), `docs/production-readiness/scim-directory-admin.md` ("Entra and Okta SAML cutover"), `supabase/functions/identity-security/index.ts` (`required_saml_provider_id`). Owner action: Identity engineering to run two-IdP acceptance with redacted receipts.

**IAM-03. Is OpenID Connect (OIDC) supported for enterprise SSO?**
Status: `Partially implemented`
Answer: Microsoft Entra ID sign-in through Supabase's Azure OAuth provider exists in the dashboard. Group claims in the browser are display-only; roles come only from server-side membership. There is no generic customer-configurable OIDC IdP onboarding flow in the repository.
Evidence: `packages/dashboard/src/auth/azure-ad.ts` (header comment), `packages/dashboard/src/ui/pages/LoginPage.tsx`.

**IAM-04. Is SCIM user and group provisioning supported?**
Status: `Partially implemented`
Answer: A tenant-scoped SCIM v2 endpoint and an owner-only `scim-admin` surface exist. Tokens are stored as SHA-256 hashes, shown once, default to a 90-day life (maximum 365 days), support overlap rotation and permanent revocation. Roles come only from an exact immutable `Group.externalId` mapping; SCIM cannot grant `owner`. Limitations stated by the repository: no immediate session revocation guarantee for an IdP-disabled SSO owner, and live Entra/Okta SCIM acceptance is not done.
Evidence: `supabase/functions/scim/index.ts`, `supabase/functions/scim-admin/`, `supabase/migrations/20260912000012_scim_directory.sql`, `docs/production-readiness/scim-directory-admin.md`, `scripts/scim-saml-identity-postgres.mjs`.

**IAM-05. Is role-based access control (RBAC) enforced?**
Status: `Implemented (verified in code)`
Answer: Roles are `owner`, `admin`, `member`, `viewer` with a hierarchy enforced in the database by `is_team_member` / `is_team_member_with_role` and the tenant equivalents `app.is_tenant_member_with_role`; Edge Functions repeat the role check server-side before privileged actions (for example DLP policy publish requires owner/admin; SCIM administration requires owner). Custom roles are not supported.
Evidence: `supabase/migrations/20260528000000_team_rbac.sql` (lines ~1-30, 138-175), `supabase/migrations/20260922000002_database_boundary_hardening.sql`, `docs/production-readiness/dlp-policy-storage.md`.

**IAM-06. Is multi-factor authentication supported and enforceable?**
Status: `Partially implemented`
Answer: A per-tenant `require_mfa` policy exists; when set, protected actions require an `aal2` session (`policyAllowsAssurance`). Policy publication, SCIM administration and recovery-code issuance explicitly require AAL2 regardless. Second-factor enrollment itself is provided by Supabase Auth; MFA enforcement for the platform operator's own administrative accounts (Supabase, GitHub, Cloudflare consoles) is an organizational control not evidenced here.
Evidence: `supabase/functions/identity-security/logic.ts` (`policyAllowsAssurance`, line ~152), `supabase/functions/identity-security/index.ts`, `docs/production-readiness/dlp-policy-storage.md`, `docs/security/recovery-codes.md`. Owner action for operator-console MFA: Security Lead.

**IAM-07. How are machine/API credentials issued, stored and rotated?**
Status: `Implemented (verified in code)`
Answer: API keys are shown once at issuance and stored only as SHA-256 hashes; create, revoke and renew operations are audited via database functions (`revoke_api_key_with_audit`, renew with expected-hash check). Renewal keeps the old hash valid for a bounded overlap (default 24 hours, clamped to 1 hour through 7 days, never longer than the old key's own validity). A revoked key cannot be revived through rotation. Keys expire with a trial and are checked against tenant membership at use.
Evidence: `supabase/functions/api-keys/index.ts`, `supabase/functions/_shared/key-rotation.ts`, `supabase/functions/_shared/api-key-auth.ts`, `scripts/api-key-lifecycle-postgres.test.mjs`.

**IAM-08. How are endpoints enrolled and de-authorized (device authorization)?**
Status: `Partially implemented`
Answer: Browser-verified device authorization uses short-lived single-use codes; enrollment tokens are hash-only; enrollment binds the bearer key to an installation identifier (explicitly "not hardware or OS attestation"). Revocation concurrency, membership-revocation races and global session revocation have Postgres regression scripts. The device-authorization path is described as not a currently available customer enrollment path until a control plane is accepted.
Evidence: `docs/device-auth.md`, `supabase/functions/device-start/`, `device-verify/`, `device-poll/`, `enroll/`, `packages/core/src/device-attestation.ts` (header), `scripts/device-revocation-concurrency-postgres.mjs`, `scripts/identity-global-revocation-saga.test.mjs`.

**IAM-09. Is there a privileged break-glass / account recovery process?**
Status: `Implemented (verified in code)`
Answer: Break-glass recovery codes are self-issued only, from an AAL2 session, with the tenant's break-glass policy enabled; codes are shown once and stored as hashes; the policy toggle and issuance are serialized by tenant and user locks. Password recovery does not bypass a required SAML provider.
Evidence: `docs/security/recovery-codes.md`, `supabase/migrations/20260912000013_identity_security.sql`, `scripts/identity-recovery-saga.test.mjs`, `scripts/identity-recovery-policy-race-postgres.test.mjs`.

**IAM-10. Are password and session policies configurable (length, complexity, lockout, session lifetime)?**
Status: `Not yet — owner action: Platform engineering to set and document Supabase Auth password/session settings per deployment`
Answer: `supabase/config.toml` does not set minimum password length, password requirements, CAPTCHA, or JWT/session lifetime values beyond defaults; the Auth settings of a deployed project were not inspected. Open sign-up is `enable_signup = true` in the file.
Evidence: `supabase/config.toml` (line 44 `enable_signup = true`; no password-policy keys found).

**IAM-11. Is access to production administration restricted and logged (least privilege for operators)?**
Status: `Partially implemented`
Answer: In the database, the browser roles (`anon`, `authenticated`) are reset to a small table allowlist, `service_role` use is confined to Edge Functions and maintenance workers, and privileged tenant actions write audit records. Operator-level access to the Supabase/Cloudflare/GitHub consoles, joiner-mover-leaver reviews and access recertification are organizational processes with no repository evidence.
Evidence: `supabase/migrations/20260922000002_database_boundary_hardening.sql`, `supabase/migrations/20260922000005_rls_audit_owner_hardening.sql`, `deploy/monitoring/oncall-ownership.yml.example` (example only). Owner action: Security Lead / IT.

---

## 4. Multi-tenancy and data segregation

**TEN-01. How is customer data segregated in the managed multi-tenant control plane?**
Status: `Implemented (verified in code)`
Answer: Logical segregation through a canonical `tenant_id` on tenant-owned tables with PostgreSQL row-level security (RLS). 33 migration files enable RLS and the schema defines 84 `create policy` statements in `supabase/migrations/`. Membership predicates are `SECURITY DEFINER` helpers (`is_team_member`, `is_team_member_with_role`, `app.is_tenant_member*`). Segregation is logical, not physical or per-tenant-database; a single-tenant option exists only through the self-hosted deployment model.
Evidence: `supabase/migrations/20260805000000_hybrid_tenancy.sql`, `supabase/migrations/20260528000000_team_rbac.sql`, `supabase/migrations/20260922000002_database_boundary_hardening.sql`.

**TEN-02. Are browser-reachable database privileges minimized?**
Status: `Implemented (verified in code)`
Answer: The hardening migration revokes broad default grants on tables, sequences and functions from `public`/`anon`/`authenticated`, revokes `CREATE` on schema, then re-grants a small `SELECT` allowlist and a few narrow writes. Team creation moved to an atomic RPC (`create_team_tenant`) instead of direct table writes; direct `teams` insert/update/delete policies were dropped.
Evidence: `supabase/migrations/20260922000002_database_boundary_hardening.sql` (lines ~1-60), `scripts/database-boundary-hardening.test.mjs`.

**TEN-03. Is tenant isolation tested automatically?**
Status: `Partially implemented`
Answer: Postgres-backed regression scripts (run in CI against a pinned `supabase/postgres` image) cover cross-tenant identity recovery, team resource read RLS, tenant lifecycle RLS, tenant admission, role and removal audits, API-key and device revocation races. These are local/CI contract tests; no external isolation assessment has been done (see CMP-05).
Evidence: `.github/workflows/ci.yml` (Postgres steps), `scripts/team-resource-read-rls-postgres.mjs`, `scripts/tenant-lifecycle-rls-postgres.test.mjs`, `scripts/identity-recovery-cross-tenant-postgres.test.mjs`, `scripts/rls-audit-owner-hardening.test.mjs`.

**TEN-04. Are noisy-neighbor and tenant quota controls in place?**
Status: `Partially implemented`
Answer: Per-tenant request rate limiting (`consume_tenant_rate_limit`) and per-tenant stored-byte quotas for exports (default budget with a hard ceiling, 8 MiB maximum object) exist, plus a noisy-neighbor load profile and verifier. Capacity numbers are local-host measurements; no production SLA or high-availability claim is supported.
Evidence: `supabase/functions/_shared/tenant-quotas.ts`, `supabase/migrations/20260913000005_tenant_storage_queue_quotas.sql`, `scripts/tenant-rate-limit-postgres.test.mjs`, `deploy/ha/workload.noisy-neighbor.template.json`, `deploy/ha/README.md`.

**TEN-05. Is cross-origin access restricted?**
Status: `Implemented (verified in code)`
Answer: CORS origins are echoed only after an explicit allowlist check (`AIDR_ALLOWED_ORIGINS`); an empty list fails closed for cross-origin browser calls. Dashboard responses carry CSP with `frame-ancestors 'none'`, `X-Frame-Options: DENY` and HSTS (`max-age=31536000`) in the static headers file.
Evidence: `supabase/functions/_shared/cors.ts`, `supabase/functions/_shared/origin.ts`, `packages/dashboard/public/_headers`, `deploy/dashboard/server.mjs` (lines ~100-101).

**TEN-06. Are webhook and inbound integration endpoints authenticated?**
Status: `Implemented (verified in code)`
Answer: The Stripe webhook verifies signature and timestamp tolerance and fails closed on a missing secret or invalid signature; the earlier unsigned payment webhook was removed. Self-service billing endpoints are behind a fail-closed gate (`AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING`, kept `false` for direct sale). The Stripe endpoint is documented as **not deployed** and its secrets not provisioned.
Evidence: `supabase/functions/stripe-webhook/index.ts` (header), `docs/runbooks/secrets-management.md` (Payment Provider Secrets).

---

## 5. Encryption and key management

**CRY-01. Is data encrypted in transit?**
Status: `Partially implemented`
Answer: Control-plane clients use HTTPS origins (SIEM adapters reject non-HTTPS unless an explicit loopback test flag is set; production preparation requires HTTPS dashboard/API origins and a TLS reverse proxy; the reference nginx configuration allows TLS 1.2 and 1.3; Cloudflare/Supabase terminate TLS in managed mode). For self-hosted deployments, TLS termination, certificates and cipher policy are customer-provided ingress; the repository ships a reference configuration and a renewal timer only. TLS configuration of a deployed environment has not been scanned.
Evidence: `packages/core/src/siem-delivery.ts` (line ~324, protocol check), `deploy/README.md` ("Production requires … TLS reverse proxy"), `deploy/ingress/nginx.device-start.reference.conf` (line 23), `deploy/ingress/aidr-tls-renew.timer`, `scripts/deployment-tls-renew.mjs`.

**CRY-02. Is data encrypted at rest in the managed control plane?**
Status: `Not yet — owner action: Operations to obtain provider evidence (Supabase/Cloudflare storage encryption statements) for the production project`
Answer: The repository relies on the hosted database/storage provider for volume-level encryption and does not itself prove it. No production project exists in the repository evidence (only a pilot project region observation). Application-level encryption is limited to specific items below.
Evidence: `docs/production-readiness/com-011-region-residency-audit-2026-09-23.md` (what is actually known).

**CRY-03. Are endpoint-local cache and audit files encrypted at rest?**
Status: `Partially implemented`
Answer: An AES-256-GCM file encryption helper exists (12-byte IV, 16-byte tag, `AIDRENC:1:` header, PBKDF2-SHA256 key derived from the installation ID and hostname). It is **off by default** (`encryption.enabled` defaults to `false`) and the key is derived from local identifiers, so it protects against casual disclosure, not an attacker with host access. The verdict cache wires it; confirm per file before claiming audit-file coverage. Local files are otherwise created with private modes (0700 directories, 0600 files; symlink rejection) on POSIX and ACL hardening on Windows.
Evidence: `packages/core/src/encryption.ts`, `packages/core/src/types.ts` (lines ~525-534), `packages/core/src/cache.ts` (lines ~48-57, 200), `packages/core/src/audit-log.ts` (private-file preparation), `packages/core/src/private-local-file.ts`.

**CRY-04. How are endpoint credentials (API keys/tokens) stored?**
Status: `Implemented (verified in code)`
Answer: The CLI stores the managed credential in the platform vault where available (Windows DPAPI, macOS Keychain, Linux Secret Service) and never silently falls back to a plaintext file: with no selection and a failing probe it throws; `file-acl` is an explicit, labelled fallback. Backends shell out to OS tooling and are covered by injected-runner tests; **no real OS vault is exercised by the test suite** (stated in the module header).
Evidence: `packages/core/src/secret-store.ts` (header and `SECRET_STORE_KINDS`), `packages/core/src/__tests__/secret-store.test.ts`.

**CRY-05. How are signing keys managed (release, artifact, entitlement, control-plane)?**
Status: `Partially implemented`
Answer: Ed25519 is used for release manifests, artifact manifests, entitlement snapshots, intel-pack manifests and the optional tamper-evident response audit chain. Public keys are expected to arrive through a channel independent of the package. Bounded-overlap rotation exists for API keys, enrollment tokens and SCIM tokens. Entitlement signing keys are supplied to Edge Functions as environment secrets; a scheduled canary verifies the self-hosted active signing key (managed cloud signing readiness stays failed until a provider-side canary is implemented). No documented key-ceremony, split custody, HSM/KMS use or annual rotation schedule exists.
Evidence: `scripts/release-sign.mjs`, `scripts/sign-artifact-manifest.mjs`, `scripts/sign-intel-pack-manifest.mjs`, `packages/core/src/managed.ts` (`verifyEd25519SignedEntitlementSnapshot`), `supabase/functions/ingest/index.ts` (lines ~31-36), `deploy/maintenance/README.md`. Owner action: Security Lead / Release Engineering for key ceremony and custody policy.

**CRY-06. Is premium threat-intel content encrypted per tenant?**
Status: `Implemented (verified in code)`
Answer: Intel packs use AES-256-GCM envelopes; the server derives per-tenant pack keys from a server-side master key with HKDF-SHA256 and delivers only derived, time-bound keys through entitlements; the manifest is Ed25519-signed and the endpoint loader verifies before use. The pack master key is a server secret (`AIDR_PACK_MASTER_KEY_B64`).
Evidence: `scripts/encrypt-intel-pack-file.mjs`, `packages/core/src/intel/crypto.ts`, `packages/core/src/intel/keyring.ts`, `supabase/functions/ingest/index.ts` (lines ~36-37), `supabase/functions/_shared/pack-delivery.ts`.

**CRY-07. Are backups encrypted and is key custody separated from backup storage?**
Status: `Implemented (verified in code)`
Answer: `deployment-backup.mjs` produces encrypted, authenticated cold backups; the offsite transfer never receives the recovery key (only a non-secret `--key-reference`), verifies every digest and authentication tag after download, and recommends separate principals for key custody and target administration. Native S3 Object Lock (GOVERNANCE or COMPLIANCE) is requested when configured; without it the retention date is metadata only. Not accepted on an independent host.
Evidence: `deploy/backup/README.md`, `scripts/deployment-backup.mjs`, `scripts/deployment-backup-offsite.mjs`, `docs/production-readiness/backup-restore-v6.md`.

**CRY-08. How are application secrets managed in CI, deployments and repositories?**
Status: `Partially implemented`
Answer: CI secrets live in GitHub Actions secrets/environments; Edge Function secrets are set through an approved secret-entry workflow and are never `VITE_*` browser variables; the secrets runbook forbids secrets in shell history, tickets or chat; the self-hosted deployment keeps secrets in owner-only env files. A dedicated secrets manager (vault) integration for the managed platform is not shown, and the history scan issue in SDL-06 is open.
Evidence: `docs/runbooks/secrets-management.md`, `deploy/maintenance/README.md` (owner-only `.env.functions`), `.github/workflows/release-rc.yml`.

---

## 6. Logging, audit and SIEM

**LOG-01. What does the endpoint log, and is it protected?**
Status: `Implemented (verified in code)`
Answer: Verdicts are appended to a local JSONL audit log with redaction of telemetry values, bounded summary length (200 characters), size-based rotation (default 5 MiB and three rotated files), serialized writes, and private file/directory modes with symlink rejection. The logs are sensitive and customer must apply retention and filesystem protection (stated in `SECURITY.md`).
Evidence: `packages/core/src/audit-log.ts`, `packages/core/src/telemetry-redaction.ts`, `docs/privacy.md` ("Local audit retention and deletion semantics"), `SECURITY.md`.

**LOG-02. Is the audit trail tamper-evident?**
Status: `Partially implemented`
Answer: An optional `ResponseAuditor` mode (`signEntries: true`) creates an Ed25519-signed SHA-256 hash chain with a signed `.head` checkpoint and signed retention-deletion manifest; verification fails closed on malformed lines, bad signatures, missing checkpoints or tail deletion. It is **opt-in**, local, and not an independent immutable archive. `SECURITY.md` states production use needs export to an append-only store with controlled key custody.
Evidence: `packages/core/src/response-audit.ts`, `SECURITY.md` ("Telemetry and audit-data boundary").

**LOG-03. Are administrative actions in the control plane audited?**
Status: `Implemented (verified in code)`
Answer: Role changes, member removal, owner changes, API key lifecycle, pilot decisions, device authorization, team invitations and trial legal acceptance write audit rows atomically with the change inside database functions; Postgres tests assert the atomicity. Completeness across every administrative action has not been independently reviewed.
Evidence: `scripts/owner-role-audit-postgres.mjs`, `scripts/member-role-audit-postgres.mjs`, `scripts/member-removal-audit-postgres.mjs`, `scripts/team-invitation-atomic-audit-postgres.mjs`, `scripts/pilot-application-atomic-audit-postgres.mjs`, `supabase/migrations/20260923000013_device_authorization_atomic_audit.sql`.

**LOG-04. Can a customer export audit data?**
Status: `Implemented (verified in code)`
Answer: The `audit-export` function exports JSON or CSV pages for a tenant to a private bucket, authenticated and role-checked, using signed pagination cursors, an 8 KiB request body limit, per-export size cap and tenant byte quota. Exported objects expire (default one day) and are deleted by an authorized reaper that honors legal holds. Storage absence is not proof of erasure from replicas, caches or backups.
Evidence: `supabase/functions/audit-export/index.ts`, `supabase/functions/_shared/audit-export.ts`, `supabase/functions/_shared/export-cursor.ts`, `supabase/migrations/20260912000000_export_retention.sql`, `docs/production-readiness/retention-holds.md`.

**LOG-05. Can events be forwarded to a customer SIEM?**
Status: `Partially implemented`
Answer: A delivery layer supports generic webhook, Splunk HEC, Microsoft Sentinel and Elastic adapters over HTTPS with a versioned JSON event schema, event-id echo for generic receivers and CEF, LEEF, JSON and RFC 5424 syslog *formatters* (no syslog network transport is shipped; CR/LF in field values is neutralised in CEF, LEEF and syslog output); a systemd timer drains the durable queue (one-minute cadence template) with state files treated as secrets. SIEM is excluded from the first-customer evaluation scope until separately proven; the SIEM unit tests were run in the 2026-10-05 hardening pass (see `docs/production-readiness/enterprise-feature-verification-2026-10-05.md`). Delivery is queue-and-timer based, not guaranteed-latency.
Evidence: `packages/core/src/siem-delivery.ts` (adapter configs, schema `siem-event-v1`), `packages/core/src/siem-export.ts` (CEF, LEEF, JSON, syslog formatters), `scripts/siem-delivery-worker.mjs`, `deploy/maintenance/README.md`, `docs/production-readiness/first-customer-ready.md` (scope exclusions).

**LOG-06. Is operational monitoring and alerting defined?**
Status: `Partially implemented`
Answer: Dashboard `/livez`, `/readyz` (fails on missing signing, queue, backup or certificate evidence) and token-authenticated Prometheus `/metrics` are implemented, with alert rules and a rule test. The on-call ownership file is an `.example`; no live monitoring, paging route or status page is configured, and the public pilot's endpoints were observed returning the SPA instead of health JSON.
Evidence: `deploy/monitoring/README.md`, `deploy/monitoring/prometheus-alerts.yml`, `deploy/monitoring/prometheus-alerts.test.yml`, `deploy/monitoring/oncall-ownership.yml.example`, `docs/production-readiness/first-customer-ready.md` (probe table).

**LOG-07. What log retention applies to platform logs, and who can access them?**
Status: `Not yet — owner action: Operations`
Answer: Retention for hosting, CDN, function and edge logs is provider-controlled and is listed as an unknown in the privacy matrix. No platform log retention schedule or access review is recorded.
Evidence: `docs/production-readiness/privacy-data-flow-matrix.json` (DF-008, DF-018 `retention: unknown`).

---

## 7. Data privacy, retention, deletion and residency

**PRV-01. What customer data does the product process, and where does it go?**
Status: `Partially implemented`
Answer: A source-grounded data-flow register (19 flows, DF-001 to DF-019) and a user-facing description exist. Detection runs on the endpoint; optional outbound legs are URL reputation, file/package reputation, version check, managed telemetry, deep scan, diagnostics and response webhooks. In the machine-readable matrix the matrix status is `open`, and destination, region, subprocessor, lawful basis, retention, deletion, access and transfer mechanism are `unknown` for most flows. It is an inventory, not a deployed egress capture. Do not describe the product as keeping data only on the device.
Evidence: `docs/privacy.md`, `docs/production-readiness/privacy-data-flow-matrix.json`, `docs/production-readiness/data-flow-privacy-v6.md`, `docs/production-readiness/com-003-privacy-acceptance-2026-09-23.md`.

**PRV-02. Which outbound data flows are enabled by default?**
Status: `Implemented (verified in code)`
Answer: In source defaults, mode is `local` (no account or network needed to evaluate), URL/file/package reputation checks and automatic version checks are disabled (`enabled` defaults to `false`), runtime Sentry requires both `SENTRY_ENABLED` and a real DSN, and the Cursor and VS Code extensions do not initialize Sentry. Enabling managed mode, control-plane sync, reputation or deep scan opts into the corresponding flows. Packaged or customer configuration may differ and must be captured per deployment.
Evidence: `packages/core/src/types.ts` (`mode: OperatingModeSchema.default("local")`, line ~614; check-config `enabled: z.boolean().default(false)`, line ~564), `packages/core/src/sentry.ts` (line ~51), `docs/privacy.md`, `CLAUDE.md` (Key Conventions).

**PRV-03. Is data redacted before leaving the endpoint?**
Status: `Implemented (verified in code)`
Answer: The control-plane client applies a mandatory credential scrub at the final outbound boundary; default `redact_mode` is `hash` (tool summaries and artifacts replaced by SHA-256 digests); `full` omits them; `none` still strips bearer credentials, API keys, JWTs, URL credentials and secret query values but can carry ordinary command/URL text and is not a production default. Sentry events are scrubbed; arbitrary prose still needs customer review. A local canary tests selected redaction boundaries and its pass does not close field acceptance.
Evidence: `packages/core/src/telemetry-redaction.ts`, `packages/core/src/clients/control-plane.ts`, `docs/privacy.md`, `scripts/privacy-verify.mjs`, `scripts/privacy-canary.test.mjs`.

**PRV-04. What are the retention periods for customer data?**
Status: `Partially implemented`
Answer: Mechanisms exist but approved periods do not. Verified defaults in migrations: audit export objects expire after 1 day; billing webhook rows default to 90 days and another billing table to 30 days; team invitations have pruning; telemetry and rate-limit pruning have scripts. The privacy matrix lists retention as `unknown` for most flows; approved retention by data class needs Privacy/Legal sign-off. Local endpoint log retention is customer-configured.
Evidence: `supabase/migrations/20260912000000_export_retention.sql`, `supabase/migrations/20260914000001_billing_retention_pruning.sql`, `scripts/telemetry-retention-migration.test.mjs`, `scripts/team-invitation-retention-postgres.test.mjs`, `docs/production-readiness/privacy-data-flow-matrix.json`. Owner action: Privacy/DPO.

**PRV-05. Can a customer's data be deleted on termination (offboarding)?**
Status: `Partially implemented`
Answer: A phased, receipt-producing tenant offboarding exists (`request_tenant_offboarding`, `run_tenant_offboarding_batch`, storage-object and pack acknowledgement, cache invalidation), plus a deployment offboarding script. The repository states Storage absence checks are not proof of erasure from replicas, caches, offsite backups or third-party processors, and that real tenant export and offboarding receipts, backup expiry and provider requests are still required. Offsite backup pruning is not legal-hold aware.
Evidence: `supabase/migrations/20260912140000_tenant_offboarding_retention.sql`, `supabase/migrations/20260916000007_offboarding_storage_authorizations.sql`, `scripts/deployment-offboarding.mjs`, `scripts/tenant-offboarding-migration.test.mjs`, `docs/production-readiness/retention-holds.md`, `deploy/backup/README.md` ("Download and retention").

**PRV-06. Is legal hold supported?**
Status: `Implemented (verified in code)`
Answer: Tenant legal holds serialize with retention under a tenant advisory lock; held tenants are excluded from pruning and a hold placement is refused (not silently accepted) while export deletion authorizations are pending. Holds do not extend to offsite backups (see PRV-05).
Evidence: `supabase/migrations/20260916000004_retention_legal_holds.sql`, `docs/production-readiness/retention-holds.md`, `scripts/retention-holds-postgres.test.mjs`.

**PRV-07. Can the vendor support data-subject requests (access, rectification, deletion)?**
Status: `Not yet — owner action: Privacy/DPO and Customer Success`
Answer: No DSAR procedure, intake route or tooling is documented as approved. Export and offboarding mechanisms exist (PRV-05, LOG-04) but the process and customer-facing wording are open.
Evidence: `docs/production-readiness/com-003-privacy-acceptance-2026-09-23.md` (approval table), `SECURITY.md` ("DSAR/deletion process" listed as required before customer use).

**PRV-08. Is a Data Processing Agreement (DPA) available, with processor/controller responsibilities defined?**
Status: `Not yet — owner action: Legal / Privacy-DPO`
Answer: `docs/privacy.md` states it is not a DPA. The privacy/legal review template is unsigned. No signed customer-facing notice, DPA, technical and organizational measures annex or transfer documentation exists.
Evidence: `docs/privacy.md` (first paragraph), `docs/production-readiness/privacy-legal-review-template.md`, `docs/production-readiness/com-003-privacy-acceptance-2026-09-23.md`.

**PRV-09. Where is data hosted (data residency), and can a region be selected?**
Status: `Partially implemented`
Answer: A declarative region manifest (`unassigned`, `self-hosted`, `managed-cloud` template) is enforced by deployment preparation (placeholder and region mismatch are refused), and tenant and deployment region records must agree. The only region fact observed was that the internal pilot Supabase project reported `eu-central-1` on 23 September 2026. The repository provisions no multi-region service and has not demonstrated or approved end-to-end residency: Cloudflare Worker execution is global (the pilot uses `workers.dev`), Edge Function invocation region is not pinned, and backup/log regions are unknown. Customer on-prem places the data wherever the customer designates.
Evidence: `deploy/regions.manifest.json`, `scripts/deployment-prepare.mjs`, `docs/production-readiness/com-011-region-residency-audit-2026-09-23.md` (including the "current sale-safe statement"), `deploy/cloudflare/wrangler.jsonc`.

**PRV-10. Are cross-border transfers documented?**
Status: `Not yet — owner action: Legal / Privacy-DPO`
Answer: Transfer mechanism is `unknown` for every flow in the matrix; no transfer impact assessment or transfer clauses exist.
Evidence: `docs/production-readiness/privacy-data-flow-matrix.json`.

**PRV-11. Is customer data used for product analytics or advertising?**
Status: `Partially implemented`
Answer: The repository contains no advertising integration. Optional runtime and browser Sentry diagnostics, a version check and (if configured) managed telemetry exist, each opt-in as described in PRV-02. A CI workflow named "Product Analytics Instrumentation" (`analytics-check.yml`) exists, which indicates product analytics instrumentation; its contents were not reviewed for this sheet, and the full set of production browser analytics was not inventoried, and DF-009 (browser diagnostics) is `unknown` in the matrix.
Evidence: `docs/privacy.md`, `packages/dashboard/src/sentry.ts`, `docs/production-readiness/privacy-data-flow-matrix.json` (DF-007, DF-008, DF-009), `.github/workflows/analytics-check.yml`.

**PRV-12. Is support access to customer data controlled?**
Status: `Partially implemented`
Answer: A support bundle tool with redaction, a verification self-test, an explicit consent/transfer procedure and a rule not to request credentials, raw prompts or customer files in the first ticket exist. No active support route, access approval workflow or transfer/deletion receipts exist.
Evidence: `scripts/support-bundle.mjs`, `scripts/verify-support-bundle.mjs`, `docs/runbooks/support-bundle.md`, `docs/runbooks/support-v7.md`.

---

## 8. Subprocessors and third parties

**SUB-01. Is there a list of subprocessors and a change-notification process?**
Status: `Not yet — owner action: Privacy/DPO and Legal`
Answer: The repository identifies likely providers by function (Supabase for database/Auth/Storage/Edge Functions, Cloudflare for the Worker/edge proxy and its challenge widget (per the CSP), Stripe or other billing providers if enabled, SMTP provider, optional Sentry, Slack/webhook destinations, S3-compatible backup storage chosen by the operator, GitHub for CI) but marks subprocessor as `unknown` in the matrix and has no approved list, contracts or notice process. Do not publish the function list as the subprocessor list.
Evidence: `docs/production-readiness/privacy-data-flow-matrix.json`, `deploy/cloudflare/wrangler.jsonc`, `supabase/config.toml`, `docs/production-readiness/com-011-region-residency-audit-2026-09-23.md`.

**SUB-02. Are vendor security reviews and contracts in place for third parties with access to data?**
Status: `Not yet — owner action: Legal / Procurement / Security Lead`
Answer: No vendor assessments or contracts are in the repository.
Evidence: none.

**SUB-03. Do third-party components in the product have known provenance?**
Status: `Partially implemented`
Answer: The AIDR/AI Infra Guard vendor source is tracked under `vendor/ai-infra-guard/` with a verification script and an upstream Supabase self-hosting baseline pinned to a commit; the Python runtime lock is hash-pinned. Image-specific SBOM and licence notices are not bound to a candidate.
Evidence: `scripts/verify-aig-source.mjs`, `deploy/README.md` (Supabase `self-hosted/v0.8.1`, commit `8c7a4d9d…`), `docs/production-readiness/com-002-license-audit-2026-09-23.md`.

**SUB-04. Are payment details handled by the vendor?**
Status: `Not applicable`
Answer: The product does not store card data; billing is delegated to an external provider through hosted checkout. Direct-sale billing automation is excluded from the current evaluation scope; self-service billing endpoints are gated off by default.
Evidence: `supabase/functions/billing-checkout/`, `docs/runbooks/secrets-management.md`, `docs/production-readiness/first-customer-ready.md` (scope exclusions).

---

## 9. Vulnerability and patch management

**VUL-01. How are vulnerabilities in dependencies detected and tracked?**
Status: `Implemented (verified in code)`
Answer: See SDL-05 (production and build dependency audits that fail on new advisories, `pip-audit`), weekly Dependabot with grouped updates, and SAST in SDL-03. A CVE checker module exists for installed packages/plugins on the endpoint.
Evidence: `.github/dependabot.yml`, `scripts/audit-production-deps.mjs`, `packages/core/src/cve-checker.ts`.

**VUL-02. Is there a published vulnerability disclosure channel?**
Status: `Partially implemented`
Answer: `SECURITY.md` points to GitHub private security advisories for authorized collaborators in a private repository and states that **an approved, monitored external security-contact route is required before supported customer use**. Acknowledgement and remediation targets are explicitly "not yet approved or staffed".
Evidence: `SECURITY.md` ("Reporting Vulnerabilities"). Owner action: Security Lead to publish a monitored external route (security contact address and, ideally, `security.txt`).

**VUL-03. What are the remediation timelines for vulnerabilities by severity?**
Status: `Not yet — owner action: Security Lead / Legal`
Answer: Internal triage targets exist (SEV1 under 15 minutes, SEV2 under 4 hours, SEV3 under 24 hours) but are labeled internal, not staffed and not customer commitments. Supported and security-only version ranges and end-of-life notice periods have not been approved.
Evidence: `docs/runbooks/incident-response.md` (header), `SECURITY.md` ("Supported Versions"), `docs/runbooks/support-v7.md`.

**VUL-04. How are patches and updates delivered to endpoints and self-hosted deployments?**
Status: `Partially implemented`
Answer: Signed release verification with anti-rollback state, a documented self-hosted upgrade runbook (exact current and target manifests, same baseline, migrations only appended, checksums verified, advisory lock), rollback/yank workflows and an offline air-gap image verifier exist. Automatic version checks are off by default and updating is operator-driven. The upgrade and fleet delivery paths are exercised by local scripts; no field acceptance is recorded.
Evidence: `deploy/UPGRADE.md`, `scripts/deployment-upgrade.mjs`, `scripts/verify-deployment-upgrade.mjs`, `scripts/release-verify.mjs`, `.github/workflows/release-promote.yml`, `deploy/fleet/`.

**VUL-05. Are threat-detection rules updated and signed?**
Status: `Partially implemented`
Answer: Detection patterns are data (YAML under `threats/`, 23 rule files; community and AIG-derived rules sync through scripts). Premium packs are Ed25519-signed and AES-256-GCM encrypted. Rule updates for the open rule set rely on release signing and the rule-sync tooling; effectiveness and false-positive rates are not claimed.
Evidence: `threats/`, `packages/core/src/threat-loader.ts`, `packages/core/src/rule-sync.ts`, `scripts/sync-aig-threats.mjs`, `docs/operations/threat-sync.md`, `scripts/sign-intel-pack-manifest.mjs`.

---

## 10. Business continuity and disaster recovery

**BCP-01. Are backups taken, encrypted, stored off-site and monitored (self-hosted)?**
Status: `Partially implemented`
Answer: Cold encrypted backups of PostgreSQL, object storage and installation volumes, offsite upload with post-download verification, retention dry-run by default, systemd units and a health receipt consumed by `/readyz` exist. Nothing has been accepted: independent offsite durability, recovery-key custody, schedule/alert activation and restore on a second failure-domain host are marked `BLOCKED_EXTERNAL`.
Evidence: `deploy/backup/README.md`, `deploy/backup/aidr-backup-offsite.service`, `deploy/backup/aidr-backup-offsite.timer`, `scripts/deployment-backup.mjs`, `scripts/deployment-backup-offsite.mjs`, `docs/production-readiness/backup-restore-v6.md`.

**BCP-02. Are restore drills performed, and are RPO/RTO measured?**
Status: `Partially implemented`
Answer: A restore-drill tool downloads the newest eligible backup into a new work directory, verifies hashes and tags, restores to isolated containers, reads critical tables and records evidence with explicit RPO minutes and RTO seconds (schema v2, targets must be supplied by the operator); a weekly timer template exists. The only recorded run (13 September 2026) was a same-host, legacy-format local rehearsal that cannot satisfy the current verifier. **No RPO or RTO value is approved or claimed.**
Evidence: `scripts/deployment-restore-drill.mjs`, `deploy/backup/aidr-restore-drill.timer`, `deploy/backup/aidr-restore-drill.env.example`, `docs/production-readiness/backup-restore-v6.md`. Owner action: Operations to execute and record an independent-host drill.

**BCP-03. How is the managed cloud service (Supabase and Cloudflare) recovered?**
Status: `Not yet — owner action: Operations`
Answer: The repository defines a four-part recovery contract (database, Storage object bytes, signed dashboard/Worker/Edge release, Auth/secrets/routes/DNS/jobs) but states that the self-hosted tool does not cover managed cloud and that a synthetic-data drill in a separate recovery project has not been completed. Provider backup availability is preparation only.
Evidence: `docs/production-readiness/backup-restore-v6.md` ("Managed cloud recovery contract").

**BCP-04. Is a high-availability architecture or availability SLA offered?**
Status: `Not yet — owner action: Operations / Product (decision and field evidence)`
Answer: The shipped self-hosted baseline is a single host; two HA reference topologies (self-hosted and managed-cloud) are decision templates; the load harness always records `production_sla_proven` and `ha_proven` as false. A 99.9% figure appears only in a draft support schedule and must not be quoted.
Evidence: `deploy/README.md`, `deploy/ha/README.md`, `deploy/ha/topology.managed-cloud.reference.yaml`, `deploy/ha/topology.self-hosted.reference.yaml`, `docs/runbooks/support-v7.md`.

**BCP-05. How does endpoint protection behave when the control plane is unavailable?**
Status: `Implemented (verified in code)`
Answer: Local-mode evaluation needs no network. For an enrolled install, entitlement uses a configurable grace period (`control_plane.grace_period_hours`) and a customer deployment also requires a fresh central policy: cached policy expires separately and, after `remote_policy_offline_grace_seconds` (3,600 by default), protected operations block until policy refresh succeeds. This is a design property; it has not been measured in a field outage.
Evidence: `docs/device-auth.md` ("Offline behavior"), `packages/core/src/remote-policy.ts`, `packages/core/src/managed.ts`.

**BCP-06. Is there a business continuity plan, tested in production, with defined roles?**
Status: `Not yet — owner action: executive sponsor / Operations`
Answer: No business continuity or crisis-management plan, tabletop exercise record or named alternate staff exist in the repository.
Evidence: none (see also `docs/runbooks/support-v7.md` named-roles table, unfilled).

---

## 11. Incident response

**INC-01. Is there a documented incident response process?**
Status: `Partially implemented`
Answer: A runbook defines severity levels, a detection–triage–containment–investigation flow and a support/security escalation path that restricts the record for suspected tenant-boundary failure or compromised signer. It is explicitly an operating draft with unstaffed coverage and no named responders or paging route.
Evidence: `docs/runbooks/incident-response.md`, `docs/runbooks/support-v7.md` ("Receive, triage, and escalate a case"), `docs/runbooks/alerting.md`.

**INC-02. Will customers be notified of a security incident, and within what time?**
Status: `Not yet — owner action: Legal / Privacy-DPO / Security Lead`
Answer: The notice route, audience, deadline and cadence are listed as required fields in the support activation record but are unfilled. Privacy/Legal, not Support, decides notification obligations. No contractual breach-notification window is defined.
Evidence: `docs/runbooks/support-v7.md` (activation table), `docs/production-readiness/support-sla-template.md`.

**INC-03. Is there a 24x7 security on-call, incident-response retainer or forensic partner?**
Status: `Not yet — owner action: Security Lead / Finance`
Answer: `deploy/monitoring/oncall-ownership.yml.example` is a template; no staffed rota, retainer or forensic partner contract exists in the repository.
Evidence: `deploy/monitoring/oncall-ownership.yml.example`, `docs/runbooks/support-v7.md`.

**INC-04. Can the product's own response actions be audited and rolled back?**
Status: `Partially implemented`
Answer: Response actions (quarantine, rollback, containment) record to a response audit, rollback refuses to overwrite files changed after the snapshot, quarantine does not follow symlinks and records failed deletes (per the engineering log). Automated response is policy-controlled; do not describe any response action as automatic unless the customer's enabled policy is documented and tested.
Evidence: `packages/core/src/response-actions.ts`, `packages/core/src/rollback.ts`, `packages/core/src/quarantine.ts`, `packages/core/src/response-audit.ts`, `docs/operations/response-playbooks.md`.

---

## 12. Deployment models

**DEP-01. What deployment models are available?**
Status: `Partially implemented`
Answer: Two control-plane profiles are in scope in the support matrix: managed cloud (Supabase plus Cloudflare Worker) and customer self-hosted (generated Docker Compose stack on the reviewed Supabase self-hosting baseline); the endpoint detection engine also runs in local mode with no control plane. Each is prepared by repository tooling; none is accepted, and the current decision is NO-GO for a live offer.
Evidence: `deploy/README.md`, `deploy/native/support-matrix.json` (`soldDeploymentProfiles`), `packages/core/src/types.ts` (`mode` default `local`), `docs/production-readiness/first-customer-ready.md`.

**DEP-02. Can the product run fully air-gapped?**
Status: `Partially implemented`
Answer: Local-mode detection, offline signed-release verification, offline intel-pack loading with signature check, and an air-gap container-image bundle builder and verifier exist. The bundle verifier proves file integrity and plan completeness only (not publisher identity); air-gap delivery is excluded from the first-customer scope unless separately proven; features needing outbound services (reputation, managed telemetry, version check, Sentry) must stay disabled.
Evidence: `scripts/build-airgap-images.mjs` (header "Boundary"), `scripts/airgap-images.test.mjs`, `docs/integrity.md`, `docs/privacy.md`, `docs/production-readiness/first-customer-ready.md`.

**DEP-03. Who operates and secures a self-hosted deployment?**
Status: `Implemented (verified in code)`
Answer: The customer. The tooling generates pinned configuration, checks migrations by SHA-256 under an advisory lock, binds ports to loopback so ingress is an explicit customer decision, and provides a doctor that treats a healthy container as insufficient (`/readyz` must pass). Customer responsibilities (hardening, TLS, SMTP/IdP, key custody, backups) are listed in the prerequisites.
Evidence: `deploy/README.md`, `scripts/deployment-prepare.mjs`, `scripts/deployment-doctor.mjs`, `scripts/deployment-migrate.mjs`, `deploy/FIRST_CUSTOMER.md`.

**DEP-04. Is infrastructure defined as code, and are configuration changes controlled?**
Status: `Partially implemented`
Answer: Compose generation, migration manifests, Worker configuration (`wrangler.jsonc`) and edge-function contract manifests are in the repository and checked by scripts. Provisioning of cloud accounts and production projects is manual and not codified here.
Evidence: `scripts/deployment-prepare.mjs`, `deploy/cloudflare/wrangler.jsonc`, `docs/production-readiness/edge-function-contract-manifest.json`, `scripts/check-supabase-edge-contracts.mjs`, `scripts/check-supabase-migrations.mjs`.

**DEP-05. What is the hardware and capacity requirement?**
Status: `Implemented (verified in code)`
Answer: Resource requirements and sizing guidance exist for the self-hosted stack, with a resource profiler. The capacity figures derive from local host runs and are not a production SLA.
Evidence: `deploy/RESOURCE_REQUIREMENTS.md`, `docs/production-readiness/resource-sizing-v8.md`, `scripts/resource-profile.mjs`.

---

## 13. Endpoint agent security

**END-01. Which AI coding agents are covered?**
Status: `Partially implemented`
Answer: Intended scope: Claude Code, Cursor, VS Code, OpenClaw, OpenCode and Codex connectors on Windows, Linux and macOS (x64, arm64). The support matrix records this as target scope, with an `acceptanceEvidence` field per row; a row without evidence is an open gate and the matrix decision is `NO-GO`. A connector missing a passing real-host row is excluded, not assumed covered.
Evidence: `deploy/native/support-matrix.json`, `deploy/native/run-support-matrix.mjs`, `docs/production-readiness/native-host-matrix-v6.md`.

**END-02. What happens if the detection engine crashes or errors?**
Status: `Implemented (verified in code)`
Answer: Connector entry points fail closed: Claude Code exits 0 and emits an explicit deny on input or hook failure; the OpenClaw and OpenCode handlers block on internal errors; the Cursor/VS Code hook installer marks hooks `failClosed: true`; the Codex connector converts `ask` and internal errors to an explicit deny because Codex otherwise fails open on a crashing hook. Inside the engine, a single failing rule or optional reputation lookup is skipped and logged and must not be reported as a clean result.
Evidence: `packages/claude-code/src/pre-tool-use.ts` (header and lines ~39-70, 173), `packages/openclaw/src/tool-handler.ts` (lines ~133-137), `packages/opencode/src/tool-handler.ts` (lines ~74-76), `packages/extension/src/cursor_hook_installer.ts` (`failClosed: true`), `packages/codex/src/cli.ts` (header), `CLAUDE.md` (Failure policy).

**END-03. Can a user or the agent disable or bypass the guard?**
Status: `Partially implemented`
Answer: The repository states known limits. For Claude Code, the support matrix notes "a disabled hook is fail-open" and behavior when the hook process crashes before a verdict is unverified on the host; known bypass entries are listed per connector. Self-defense rules flag agent attempts to delete or alter AIDR/guardrail configuration and require approval rather than block. There is no kernel-level or MDM-enforced tamper resistance in the repository, and device attestation is an enrollment binding, not a hardware attestation.
Evidence: `deploy/native/support-matrix.json` (`tamperResistance`, `knownBypasses`), `threats/self-defense.yaml`, `packages/core/src/device-attestation.ts` (header).

**END-04. Can an agent approve its own blocked action?**
Status: `Implemented (verified in code)`
Answer: No. An `ask` verdict is a block pending out-of-band human approval, and no connector exposes an approval tool to the agent (a prompt-injected agent could otherwise self-approve). OpenClaw registers only allowlist add/remove tools, and approvals recorded by the operator are checked against the exact artifact.
Evidence: `CLAUDE.md` (Key Conventions, Architecture items 2 and data flow), `packages/openclaw/src/allowlist-tools.ts`, `packages/core/src/approval-store.ts`, `packages/claude-code/src/approval-tracker.ts`. Note: allowlist-add tools remain agent-callable in OpenClaw; confirm their gating before claiming allowlist immutability.

**END-05. Is the endpoint package installed from a verified source?**
Status: `Implemented (verified in code)`
Answer: The endpoint installer verifies a signed package manifest before and after copying, and the Claude plugin archive must come from a publisher-verified release bundle (see SDL-08, SDL-10). Package-install verification runs every packed consumer artifact in CI.
Evidence: `docs/integrity.md`, `scripts/endpoint-install.mjs`, `scripts/verify-package-install.mjs`, `.github/workflows/ci.yml`.

**END-06. What does the endpoint send to the control plane and how is it authenticated?**
Status: `Implemented (verified in code)`
Answer: Events authenticate with a bearer API key (hash-only server-side), are normalized and validated at ingest, pass through the credential scrub described in PRV-03, and use a durable telemetry queue. See PRV-01 for the destination unknowns.
Evidence: `supabase/functions/ingest/index.ts`, `supabase/functions/ingest/events.ts`, `packages/core/src/telemetry-queue.ts`, `packages/core/src/clients/control-plane.ts`.

**END-07. Does the product inspect tool output and supply chain actions, not only commands?**
Status: `Partially implemented`
Answer: Post-tool output inspection, package/supply-chain checks, plugin scanning at session start, MCP inventory/attestation and file-write checks exist in core and connectors. Coverage depends on each host's interception points (recorded per row in the support matrix); gaps are documented, not hidden.
Evidence: `packages/claude-code/src/post-tool-use.ts`, `packages/claude-code/src/output-inspection.ts`, `packages/core/src/package-checker.ts`, `packages/core/src/plugin-scanner.ts`, `packages/core/src/mcp-attestation.ts`, `deploy/native/interception-matrix.json`.

---

## 14. Compliance, certifications and penetration testing

**CMP-01. Does the vendor hold a SOC 2 attestation report?**
Status: `Not yet — owner action: executive sponsor / Security Lead (select auditor, define scope and period)`
Answer: No SOC 2 report exists or is claimed. The claim registry blocks certification wording until counsel-approved scope and independent attestation exist.
Evidence: `docs/production-readiness/commercial-go-evidence-registry.json` (`CLM-BANNED-COMPLIANCE`).

**CMP-02. Does the vendor hold an ISO/IEC 27001 certificate?**
Status: `Not yet — owner action: executive sponsor / Security Lead`
Answer: No ISMS certification exists or is claimed.
Evidence: same as CMP-01.

**CMP-03. Is the vendor aligned to a recognized control framework (NIST CSF, CIS, CSA CCM)?**
Status: `Not yet — owner action: Security Lead`
Answer: No control-framework mapping or gap assessment is in the repository. This sheet is a questionnaire answer, not a mapping.
Evidence: none.

**CMP-04. Is a compliance report available for regulated-data use (HIPAA, PCI, FedRAMP, similar)?**
Status: `Not applicable`
Answer: Not offered. The product is not designed or evaluated for regulated health, card or government workloads, and no such scope is claimed. Customers must not place such data in the service until Legal and Privacy approve a scope.
Evidence: `docs/production-readiness/first-customer-ready.md` ("Enable real customer data … prohibited"), `docs/production-readiness/com-003-privacy-acceptance-2026-09-23.md`.

**CMP-05. Has an independent penetration test or security assessment been completed?**
Status: `Not yet — owner action: Security Lead (engage independent assessor on a frozen signed release candidate)`
Answer: No. SEC-EXT-001 is **OPEN**: no independent assessor has been engaged and no signed assessment or retest report exists. Internal tests and a historical May 2026 source audit are not a penetration test. The scope, evidence manifest format and validator are defined in the repository. Do not hand `docs/audit/security-audit.md` to a customer as a penetration test.
Evidence: `docs/production-readiness/sec-ext-001-assessment-acceptance.md`, `docs/audit/security-audit.md`, `docs/production-readiness/commercial-gate-receipts.json`.

**CMP-06. Does the vendor run a bug bounty or responsible disclosure program?**
Status: `Not yet — owner action: Security Lead`
Answer: Disclosure intake is limited to a private-repository advisory route (VUL-02); no external program exists.
Evidence: `SECURITY.md`.

**CMP-07. Are customer audit rights, right-to-assess and evidence-sharing under NDA supported?**
Status: `Not yet — owner action: Legal`
Answer: Contract terms are not in the repository. Candidate-bound evidence is intended to be kept in restricted evidence storage.
Evidence: `docs/production-readiness/sec-ext-001-assessment-acceptance.md` (restricted evidence storage).

**CMP-08. Is the accessibility, export-control or sanctions status documented?**
Status: `Not applicable`
Answer: Outside the scope of this engineering sheet; refer to Legal for export-control classification.
Evidence: none.

---

## 15. AI-specific questions

**AI-01. Does the product send customer prompts, code or tool inputs to a large language model (LLM) provider?**
Status: `Implemented (verified in code)`
Answer: The detection path does not call an LLM: matching uses YAML threat rules, heuristics, DLP rules, a deterministic local embedding model for similarity ("not calibrated confidence") and a behavioral baseline. A source search of `packages/core/src` found no LLM provider client (only mentions in logger and PII-detector comments). The AI Infra Guard deep-scan bridge is a separate, explicit scan that sends the target to a configured bridge (loopback by default). Third-party LLM vendors used by the customer's own agents are outside the product.
Evidence: `packages/core/src/ml-model.ts` (header), `packages/core/src/ml/embedder.ts`, `packages/core/src/heuristics.ts`, `packages/core/src/aig-scan-client.ts`, `docs/privacy.md` (item 6, AIG deep scan).

**AI-02. Is customer data used to train models?**
Status: `Implemented (verified in code)`
Answer: No model training pipeline exists in the repository; the embedding model is a deterministic hash-based embedder, not a trained network. A federated-learning module and false-positive feedback module exist in core; their use with customer data is not enabled by a default configuration verified here and has not been privacy-reviewed, so no commitment on "never used for improvement" should be made without Privacy/Legal approval.
Evidence: `packages/core/src/ml/embedder.ts`, `packages/core/src/ml-model.ts`, `packages/core/src/federated.ts`, `packages/core/src/false-positive-feedback.ts`. Owner action: Privacy/Legal to approve contractual wording on use of customer data for product improvement.

**AI-03. Does the product detect prompt injection and related agent attacks?**
Status: `Partially implemented`
Answer: A rule file for LLM-targeted threats (`LLM-INJ-*` identifiers, 21 top-level rule entries) plus self-defense rules, tool-output inspection and MCP tool identity/attestation checks exist. Detection is pattern- and heuristic-based; no independent evaluation, detection-rate or false-positive figure exists, and none may be claimed. Dataset-size and quality claims are on the blocked list.
Evidence: `threats/llm-threats.yaml`, `threats/self-defense.yaml`, `packages/claude-code/src/output-inspection.ts`, `packages/core/src/mcp-tool-identity.ts`, `packages/core/src/output-scanner.ts`, `docs/production-readiness/commercial-go-evidence-registry.json` (`CLM-BANNED-AIG-DATA`).

**AI-04. Can a prompt-injected agent disable or approve around the product?**
Status: `Partially implemented`
Answer: Approval is out-of-band by design (END-04) and self-tampering patterns require approval. The residual risks listed in END-03 (disabled hook is fail-open on some hosts) apply.
Evidence: see END-03, END-04.

**AI-05. Are model/rule supply-chain integrity and provenance controlled?**
Status: `Implemented (verified in code)`
Answer: Rule data ships inside signed release artifacts; premium packs are signed and encrypted (CRY-06); AIG-derived rules sync through a verification script against pinned vendor source; commercial builds verify manifests at startup (SDL-10).
Evidence: `scripts/verify-aig-source.mjs`, `scripts/sync-aig-threats.mjs`, `packages/core/src/intel/loader.ts`, `docs/integrity.md`.

**AI-06. Does the product expose an MCP gateway or tool-call mediation, and how is it secured?**
Status: `Partially implemented`
Answer: An MCP gateway package exists (`packages/mcp-gateway`) with approve and stdio entry points and is type/syntax-checked in the `check` script; the first-customer profile excludes the MCP gateway unless separately proven.
Evidence: `package.json` script `check`, `packages/mcp-gateway/src/`, `docs/production-readiness/first-customer-ready.md` (scope exclusions).

---

## 16. Open items by owner

Items below are every `Not yet` and the unresolved parts of `Partially implemented` answers that need an external or human action. IDs refer to the sections above.

### Executive sponsor
- Appoint and record a named Security Lead, Privacy/DPO and Operations owner (GOV-02).
- Approve the information security policy set and review cycle (GOV-01).
- Commission SOC 2 attestation and/or ISO/IEC 27001 certification scoping if the buyer requires it (CMP-01, CMP-02).
- Approve and fund a business continuity plan with exercises (BCP-06).

### Security Lead
- Engage an independent assessor on a frozen signed candidate and close SEC-EXT-001 (CMP-05).
- Sign off the 2 owner-confirm secret-history rows (browser-guard example dataset key) and rerun full-history and current-checkout scans with the pinned official gitleaks on the release candidate (SDL-06).
- Publish a monitored external vulnerability-reporting route and approve remediation targets (VUL-02, VUL-03, CMP-06).
- Define signing-key ceremony, custody (HSM/KMS) and rotation schedule (CRY-05, SDL-09).
- Provide control-framework mapping if required (CMP-03); enforce MFA on operator consoles (IAM-06, IAM-11).
- Staff incident on-call, retainer and forensics partner (INC-03); export repository branch-protection evidence (SDL-01).
- Run training and background screening program with records (GOV-06, with HR).

### Legal and Privacy/DPO
- Execute a DPA with technical and organizational measures annex, customer notice and transfer documentation (PRV-08, PRV-10).
- Approve subprocessor list, change-notice process and vendor contracts (SUB-01, SUB-02).
- Approve retention schedule per data class and DSAR procedure (PRV-04, PRV-07).
- Approve breach-notification window and customer incident notice route (INC-02).
- Approve supported-version and end-of-life policy and customer audit/assessment rights (VUL-03, CMP-07).
- Approve use-of-customer-data-for-improvement wording (AI-02); complete licence review and notices (SDL-12).
- Confirm insurance coverage evidence (GOV-08, with Finance) and NDA/access agreements (GOV-07, with HR).

### Operations / SRE
- Provision and document a production cell: region, Cloudflare custom domain, Edge Function region, log/backup regions (PRV-09, CRY-02).
- Execute an independent-host restore drill, offsite durability and key-custody separation; run the managed-cloud recovery drill (BCP-01, BCP-02, BCP-03).
- Decide and evidence any availability target before quoting one (BCP-04); activate monitoring, status page and paging (LOG-06).
- Record platform log retention and access review (LOG-07).
- Set and document Supabase Auth password, session and CAPTCHA settings per deployment (IAM-10).

### Identity engineering
- Run live Entra ID and Okta SAML plus SCIM acceptance with redacted receipts; implement the audited, dual-approved provider-requirement change operation before any SSO continuity claim (IAM-02, IAM-04).

### Release Engineering
- Produce one signed, candidate-bound release with passing evidence index; verify attestations and publish key fingerprints out-of-band (SDL-08, SDL-11).
- Correct the stale "fail-open" checklist line in `.github/pull_request_template.md` (SDL-01).

### Support / Customer Success
- Stand up and test the ticket route, severity definitions, and diagnostics consent/deletion receipts (PRV-12, INC-01).
- Produce real tenant export and offboarding receipts, including held tenants (PRV-05).
