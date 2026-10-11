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
| 21 NER quality | **Open** | Needs an annotated corporate TR/EN corpus and model acceptance; not possible in this environment. If not approved, NER must stay out of sale. |
| 22 Python lock/evidence | Fixed (residual) | c067e47d: the binding verifier reports 0 issues on all five locks; the Linux lock installs offline with hashes and `pip check` is clean. **Residual:** the Windows lock still has setuptools 78.1.0 (CVE-2025-47273). Re-locking needs a host that can download the torch wheel. |
| 23 Privacy quota | Fixed | 5815a872 |
| 24 Browser Guard required NER | Fixed | ddc3992e, 786441e7: managed flag plus a signed dashboard policy field; telemetry kept |
| 25, 26 Capacity/media scope | **Open** | Product decision on the scope sold in the first release |
| 27 Host OS/version acceptance | Partial | linux/x64 real host is PASS (mock model). Windows, macOS, Cursor and VS Code are not run. |
| 28 Corporate directory | **Open** | Needs real Entra/Okta/Clerk |
| 29 Org-wide egress | **Open** | Needs MDM/network deployment |
| 30 Hook latency | Measured | [hook-latency-2026-10-11.md](../production-readiness/hook-latency-2026-10-11.md): Linux cold p50 468 ms, p95 521 ms. Customer hardware, AV and DLP/NER not measured. |
| 31 Windows CI process tree | Fixed | ff99b9d7 |
| 32 Live deployment | **Open** | DNS/Worker/deployed revision need operator access. On the landing side, health JSON + `no-store` is verified in the image. |
| 33 Runtime images | Partial | 332f2286: dashboard and backup helper images 0 CRITICAL / 0 HIGH; AIDR-082 VERIFIED_CLOSED. Landing image (aidr-landing PR #1) 13/168 → 0/1; the remaining HIGH is grpc-js, which Firebase pins. Upstream Supabase images are open (AIDR-080). |
| 34 Backup/legal hold | **Open** | Needs a separate host, offsite storage and RPO/RTO |
| 35 Full test/evidence | Partial | See the gate table below. Signed candidate, SBOM and provenance require the publisher key. |
| 36 Field acceptance | **Open** | Needs real consumers |
| 37 Capacity/HA | **Open** | 8-hour soak and failover need real infrastructure |
| 38 Records | Partial | Generated records regenerated deterministically; this closure record added |
| 39 Secret history | Partial | 3a729178: full history scanned, current tree 0 findings, new detections classified as false positives. The two owner-confirm rows await an owner/Security decision. |
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
