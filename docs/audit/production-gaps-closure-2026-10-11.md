# AIDR production gaps — closure record (11 October 2026)

**Decision: NO-GO.** This record does not change the decision. `commercial-go-evidence-registry.json` and `commercial-gate-receipts.json` were not modified.

This record follows up the 40 items and 13 enterprise gates in [production-gaps-2026-10-10.md](production-gaps-2026-10-10.md). It records:
- what was fixed in code;
- which tests and observations the fixes rest on;
- what is still open.

Work branch: `claude/focused-gates-0u1is2` (base `f90adfb6`). Landing repo: `SingularityRD/aidr-landing` branch `claude/focused-gates-0u1is2`. "Locally verified" means unit/integration tests and, where named, real PostgreSQL, the real built hook or real host binaries driven by a scripted mock model. It is not production acceptance (see the evidence rules in the 10 October record).

## Code findings (1–20)

| # | Finding | Status | Commit | Verification |
| --- | --- | --- | --- | --- |
| 1 | OIDC secret crossed the tenant boundary | Fixed | 4e4a9013 | Secret only for an operator-bound tenant+issuer; existence leak closed; handler/protocol tests |
| 2 | Workspace retention bypass | Fixed | 4e4a9013, 9c6c4a9e | Owner only, class floors and plan maximum; real PostgreSQL rollback SQL + two-session race 7/7; dashboard control |
| 3 | VS Code native tools | Fixed | 6a71d823 | `runInTerminal`/`createFile`/edit tools mapped to canonical operations; deny in the built hook process. VS Code real-host E2E **not run** (VS Code download blocked by this environment's network policy) |
| 4 | Prompt failure/deadline path | Fixed | 6a71d823, cdf7f634 | Oversize, detector error, tenant load failure and deadline tested separately; built Claude Code hook |
| 5 | Relative path / `process.cwd` | Fixed | 6a71d823 | Host `workingDirectory` used in path resolution and diff reads |
| 6 | XML namespace prefix | Fixed | a6aea1bb | Match on namespace URI + local name; Word/Excel/PowerPoint/ODF |
| 7 | Text file name hid a PDF | Fixed | a6aea1bb, ddc3992e | Content signature wins; content check in monitor mode too |
| 8 | Raw data left in XLSX formulas | Fixed | a6aea1bb | Formula scanned; sensitive formula becomes a masked constant |
| 9 | PDF attachments/XMP | Fixed | a6aea1bb | Attachments scanned or the PDF marked not fully inspected |
| 10 | Codex `structuredContent` label | Fixed | 8b40d2dd | Binary exemption only for real top-level MCP blocks |
| 11 | OpenCode JSONC | Fixed | 8b40d2dd, 6a71d823 | Shared config path helper; core inventory too |
| 12 | OpenCode mixed MCP result | Fixed | 8b40d2dd | Every field next to `output` inspected. Real OpenCode binary E2E: all scenarios PASS (0de5ee14) |
| 13 | Privacy audit key rotation | Fixed | 5815a872 | Key check, dual-signed rotation, segments verify independently |
| 14 | Publish without a NO-GO check | Fixed | ff99b9d7 | `verify-production-go.mjs` exits 1 on the current repo state; workflow ordering test. Workflows have **not run** in GitHub Actions (Actions is disabled) |
| 15 | OIDC save + audit | Fixed | 4e4a9013 | Single-transaction RPC; real PostgreSQL |
| 16 | Truncated diff counted as clean | Fixed | 6a71d823 | Truncation → `ask` |
| 17 | Export stopped at 100k | Fixed | 5815a872 | Paged export; 100,003 records across 101 pages verified |
| 18 | Candidate source mismatch | Fixed | ff99b9d7 | Single source; a different candidate is rejected |
| 19 | Restore drill retention | Fixed | ff99b9d7, 332f2286 | Ownership marker; the bundled CLI side effect also fixed |
| 20 | Short-flag redaction | Fixed | 6a71d823 | Wrapper options and attached forms; 19 forms |

## New finding fixed in this round

**Unsigned commercial artifact (pre-existing on master).**
- **Defect:** with no integrity keys, a commercial install accepted any artifact whose manifest hashes matched. An unsigned commercial build therefore ran with full trust, and every connector failed **open**.
- **Fix (aaf4f0be):** the no-keys path now requires a well-formed manifest signature. Otherwise it logs INTEGRITY-001, enters degraded safe mode and fails closed.
- **How it was found:** the real-host tier on real `claude` 2.1.296, `codex` 0.141.0, `opencode` 1.18.32 and `openclaw` 2026.9.6 binaries.
- **Result:** after the fix, every scenario on all four hosts is PASS, including `internal-error-fails-closed`. Records: [docs/evidence/real-host/](../evidence/real-host/). The scenarios use a scripted mock model, not production acceptance.

## Items 21–40

| # | Status | Detail |
| --- | --- | --- |
| 21 NER quality | **Open** | Needs an annotated corporate TR/EN corpus and model acceptance; not possible in this environment. If not approved, NER must stay out of sale. **Default applied (uncommitted working tree):** NER and OCR are `not-sold` in `FEATURE_INVENTORY.json#first_release_scope` (FRS-11, FRS-12); the private service still refuses an unqualified manifest (`SERVICE_MODEL_APPROVAL_REQUIRED`), and README, landing page and sales copy now say NER/OCR ships without a model and is outside the first release. |
| 22 Python lock/evidence | Fixed (residual) | c067e47d: the binding verifier reports 0 issues on all five locks; the Linux lock installs offline with hashes and `pip check` is clean. **Residual:** the Windows lock still has setuptools 78.1.0 (CVE-2025-47273). Re-locking needs a host that can download the torch wheel. |
| 23 Privacy quota | Fixed | 5815a872 |
| 24 Browser Guard required NER | Fixed | ddc3992e, 786441e7: managed flag plus a signed dashboard policy field; telemetry kept |
| 25, 26 Capacity/media scope | **Open** | Product decision on the scope sold in the first release. **Conservative, reversible default applied (uncommitted working tree):** `FEATURE_INVENTORY.json#first_release_scope` (generated by `scripts/generate-feature-inventory.mjs`, enforced on claim surfaces by `scripts/check-commercial-readiness.mjs`) lists each capability as supported within bounds, unsupported-refused or not-sold. Fix: an over-capacity or unsupported fingerprint snapshot is now refused before commit (`DSPM_POLICY_CAPACITY`, `INDEX_CAPACITY`, `INDEX_CONTENT_LIMIT`, `CONTENT_LIMIT`) instead of committing and then blocking every send; data routes return the stable refusal reason; remote/URL source roots are refused with `SOURCE_ROOT`. Tests: `packages/privacy/tests/platform/first-release-scope.test.mjs`. Field recall/false-positive acceptance for the supported bounds is still open. |
| 27 Host OS/version acceptance | Partial | linux/x64 real host is PASS (mock model). Windows, macOS, Cursor and VS Code are not run. |
| 28 Corporate directory | **Open** | Needs real Entra/Okta/Clerk |
| 29 Org-wide egress | **Open** | Needs MDM/network deployment |
| 30 Hook latency | Measured | [hook-latency-2026-10-11.md](../production-readiness/hook-latency-2026-10-11.md): Linux 4 vCPU cold p50 506 ms / p95 566 ms (n=40), warm p50 510 ms (n=120), 8x20 concurrent p95 1.55 s, 0 errors in 700 calls (and 700 more under load). Customer hardware, AV, Windows ACL path and DLP/NER not measured. |
| 31 Windows CI process tree | Fixed | ff99b9d7 |
| 32 Live deployment | **Open** | DNS/Worker/deployed revision need operator access. On the landing side, health JSON + `no-store` is verified in the image. |
| 33 Runtime images | Partial | 332f2286: dashboard and backup helper images 0 CRITICAL / 0 HIGH; AIDR-082 VERIFIED_CLOSED. Landing image (aidr-landing PR #1) 13/168 → 0/1; the remaining HIGH is grpc-js, which Firebase pins. Upstream Supabase images are open (AIDR-080). |
| 34 Backup/legal hold | **Open** | Needs a separate host, offsite storage and RPO/RTO |
| 35 Full test/evidence | Partial | See the gate table below. Signed candidate, SBOM and provenance require the publisher key. |
| 36 Field acceptance | **Open** | Needs real consumers |
| 37 Capacity/HA | **Open** | 8-hour soak and failover need real infrastructure |
| 38 Records | Partial | Generated records regenerated deterministically; this closure record added |
| 39 Secret history | Partial | 3a729178: full history scanned, current tree 0 findings, new detections classified as false positives. The two owner-confirm rows await an owner/Security decision and are currently hidden by a value-exact `.gitleaks.toml` allowlist ([2026-10-11 triage](../production-readiness/secret-history-triage-2026-10-11.md)). |
| 40 Security update operations | **Open** | Turning on the repo's automated security fixes setting needs the account owner; Dependabot limits stay 0 until qualification |

Also in this round:
- **Red-team regression corpus** (34f2f02c): 118 malicious and 44 benign cases run through the real evaluator. Initially 27 misses and 3 false positives; now 0/0, with 3 documented gaps. 13 new rules; 507 rules in total.
- **Landing control plane:** the schema-1 revocation list was silently rejected by current connectors. Fixed with a schema-2 tenant binding on landing branch `7900832`.

## Local gate results (11 October, Linux, Node 22.22 / CI-pinned 24.21)

| Check | Result |
| --- | --- |
| `pnpm check`, `pnpm build`, `pnpm lint` (0 errors) | PASS |
| Full unit run | 637 files / 11,650 tests PASS, 14 skipped, 0 failures |
| `pnpm test:privacy` | 1525 PASS / 0 FAIL / 1 skip (real OCR model not present) |
| `pnpm ci:local --keep-going` | 54 PASS. Three real drift failures were fixed and re-run green (d81ba468). The remaining failures are environmental (next row). |
| Environmental failures | Docker Hub/registry data limit (`supabase-postgres`); IPv6 `::1` missing (one case each in `postgres-gates`, `onprem-*`); Alpine mirror unreachable (`aig-bridge-image`); OCR model missing (`privacy-platform` requires 0 skips); Playwright Chromium revision not present (BG E2E — `pnpm test:e2e:browser-guard` passes separately at 29/30) |
| Real-host tier | 4/4 hosts, every scenario PASS |
| Interception matrix | 0 failures; stale VS Code markers corrected |

## Readiness level

- **LOCAL_ENGINEERING_READY:** not yet. Items 21, 25 and 26 need product scope decisions. The Windows setuptools re-lock and the Windows/macOS/Cursor/VS Code host runs are not possible in this environment.
- **RELEASE_CANDIDATE_READY** and **PRODUCTION_SALES_GO:** not met. A signed candidate, the 12 enterprise gates (legal, finance, independent pentest, customer PoV, SLA) and live deployment acceptance can only be closed by named owners.

## Addendum — second local round (11 October 2026)

Done on the same machine at the owner's request. Every item below is local engineering evidence (one Linux host, Docker), not production acceptance. The decision stays **NO-GO**.

| Item | Result | Commit | Record |
| --- | --- | --- | --- |
| Studio on the public API host (AIDR-080 triage) | Public gateway returns 404 for Studio paths; Studio only on an operator listener bound to 127.0.0.1 (SSH tunnel); nginx forwards API paths only; doctor check flags old kits | a94c7e25 | deploy/onprem/README.md |
| Example dataset key (AIDR-070 owner-confirm rows) | Retired and replaced with refused `REPLACE_WITH_` placeholders; allowlist entry removed; the old key and fingerprints are refused by hash at runtime | a94c7e25, 8b261a85 | secret-history-triage-2026-10-11.md addendum |
| PostgreSQL 17.6 → 17.11 | Encrypted backup restored into 17.11: identical row hashes for 157 tables, RLS/grants/storage parity, RTO about 51–57 s; pin moved, upgrade/rollback procedure written | a94c7e25 | postgres-upgrade-restore-drill-2026-10-11.md |
| Vault (pgsodium) root key missing from backups (new finding) | Key carried encrypted in the authenticated manifest and restored before first start; Docker drill shows a Vault secret decrypting after recovery | 15477717 | backup-restore-v6.md addendum |
| Load/soak/failover (AIDR-052, items 36–37) | 3 h soak with a noisy tenant and four injected faults: all recovered unattended; 1.22 M events reconciled exactly once. Fixed: tenant starvation on the admission check (new migration), load-tool recovery measurement | e2224ad9 | load-soak-drill-2026-10-11.md |
| Hook latency (item 30) | Node compile cache in per-call hooks: warm p50 493 → 438 ms; a bundle that fails to load now blocks (exit 2) | a327c4dc, 365da872 | hook-latency-2026-10-11.md addendum |
| Internal adversarial review (not independent) | **HIGH:** the promote job ran RC tag code before the GO gate; fixed (no tag code, verified-tarball staging, hash-chained GO ledger). **Medium:** PDF attachment hidden by object redefinition, and large renamed documents in monitor mode; both fixed. **Low:** retention increase lowering other classes, and a stale OIDC discovery write; both fixed. No exploitable connector bypass found. | 708a0502, 8b261a85, 610c0800 | this record |
| Stale enrollment-admission Postgres suite | Rewritten for the current schema and gated in CI | 7bb86b16 | — |

State after this round:

| Check | Result |
| --- | --- |
| `check`, `build`, `lint` (0 errors) | PASS |
| Unit suite | 11,699 PASS, 0 failures |
| Privacy suite | 1,535 PASS |
| Real-host tier | 4/4 hosts, every scenario PASS |
| Interception matrix | 0 failures |

Still open — these cannot be closed from this machine:

**Needs other environments or access**
- Windows, macOS, Cursor and VS Code host runs (VS Code downloads are blocked here).
- The Windows setuptools re-lock (needs a host that can download the torch wheel).
- Live DNS/deployment.
- Real Entra/Okta.
- HA across failure domains, offsite backup and an 8-hour soak.

**Needs people or a decision**
- Legal, finance, billing, an independent pentest, a customer PoV and a monthly SLA window.
- Overload shedding policy: which tenant's requests are dropped.
- Upstream Supabase vendor fixes and the Security risk acceptance for them.
- Turning on GitHub automated security fixes (repository setting).

## Correction addendum — record status of items 21, 25 and 26 (11 October 2026, later)

The rows above for item 21 (NER quality) and items 25/26 (capacity and media scope) say the default was
applied in an **"uncommitted working tree"**. That was accurate when the rows were written, but it is no
longer the state. The rows stay as written. This addendum corrects their record status only:

- The changes were committed as `a455f3552c28f2e3ab39df673ab8bf44fcb6bf5b` (2026-10-11 02:43 UTC).
  The commit message is "Declare a conservative first-release scope and refuse out-of-scope input safely
  (gaps 21, 25, 26)", and it touches 25 files.
- That commit is an ancestor of `master` @ `eca71088` (the merge of
  [SingularityRD/aidr#145](https://github.com/SingularityRD/aidr/pull/145)).
- The commit contains everything the rows describe:
  - `FEATURE_INVENTORY.json#first_release_scope` and its generator;
  - the `check-commercial-readiness.mjs` scope check;
  - the snapshot refusals before commit (`DSPM_POLICY_CAPACITY`, `INDEX_CAPACITY`, `INDEX_CONTENT_LIMIT`, `CONTENT_LIMIT`, `SOURCE_ROOT`);
  - `packages/privacy/tests/platform/first-release-scope.test.mjs`;
  - the claim-surface edits.

The substance of the items is unchanged. Items 21, 25 and 26 remain **Open**. What is in place is a
conservative, reversible default. NER/OCR qualification on an annotated corpus, field recall and
false-positive acceptance for the supported bounds, and the product owner's scope decision are still
outstanding.

`a455f355` did not re-render the sales PDFs/PNG previews or update feature-guide sections 16 and 20.
That work is tracked separately as `PRODUCTION_READY_PROMPT-2026-10-11.md` A.2. Commit `1b7c5935` later
re-rendered them so that they describe NER/OCR as not sold.
