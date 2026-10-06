# Secret-history triage (AIDR-070 / FCR-05) — 5 October 2026

**Decision: gate stays OPEN.** The official pinned scanner refresh below found 132 historical detections, including the same two owner-confirm items. A named security owner must review them and bind the final full-clone scan to the exact release candidate. Neither the earlier engineering triage nor this refresh establishes that no credential was ever exposed.

## Official scanner refresh — current checkout

- Source tip: `7f3ec0ad009abf5b032b8116b296d8604fee884e` on `master`; non-shallow clone, 793 reachable commits across all refs. Current uncommitted fixes do not change Git history.
- Official Gitleaks **8.30.1**, executable SHA-256 `17157e2ee8b76fc8b1d8bee607a250e34b8a8023c8bc81822d4b5ee4d78fcb7c`, downloaded from the official release and verified before execution. The old Go-installed executable embeds **8.24.2**; the old ledger is not the same scanner run.
- `pnpm verify:secrets:current`: canary/regression tests 5/5; the latest current-checkout scan passed across 8026 tracked or non-ignored files. No suppressions were added in this work.
- `node scripts/scan-history-secrets.mjs` with the pinned executable and `--all --no-textconv`: completed with exit 1, **132 detections, 52 commits, 66 paths**. Fully redacted report SHA-256: `3bbe08432fd67f7b4c5f8bf4c6707dcf207cb4efdef9ffb008699b87ebb98bff`. The report remains outside the repository; the counts-only run log is `.tmp-test/production-hardening-2026-10-05/secrets-history-pinned.log`.
- 131 detections match the old ledger by rule/path/line/commit metadata: 129 previously classified false positives and the same 2 owner-confirm rows. The one unmatched detection is `policy-signature.test.ts:263` at the tip commit. Its historical bytes were checked: deliberately invalid decoded text, not a valid PKCS8 key; the test asserts HTTP 503. The current test now constructs that invalid fixture from readable text and its 18 tests pass. This classification follows the fixture's actual bytes and rejection behavior, not its test-directory location.
- The refreshed engineering dispositions therefore comprise **130 false-positive/invalid-fixture detections and 2 owner-confirm detections**. Metadata matching is not a fresh value-level review or Security-owner approval. Different default-rule versions and reachable history prevent attributing the reduction from 184 to remediation. Preserve the old 184-row ledger as historical evidence.

The final gate still needs the browser-guard dataset-key owner's answer, Security review, any required provider-side rotation evidence, and a scan on the clean exact release candidate. No Git history was rewritten and no finding was bypassed.

## Earlier engineering triage — historical 184-row record

The following record superseded [`secret-history-triage-2026-09-23.md`](./secret-history-triage-2026-09-23.md) for its own source graph and tool. Its counts are preserved for traceability, not presented as the current pinned run.

No secret value appears in this document, in the ledger, or in any log produced by this work. Reports were written fully redacted outside the repository; the per-finding ledger records only rule, path, line, commit, length and an 8-hex-character SHA-256 fingerprint (used to dedupe, not to recover a value).

## Scope and method

| Item | Value |
|---|---|
| Branch / tip scanned | `readiness/enterprise-hardening-sec` (from `377b9c10`) |
| Refs | all refs (`--all`): 751 reachable commits, 618 carry diffs and were scanned |
| Tool | `gitleaks detect` with the repo `.gitleaks.toml` (default rules + narrow allowlists) and `--log-opts="--all --no-textconv"` |
| Binary caveat | A `go install`ed gitleaks, **not** the pinned official 8.30.1 binary that `scripts/scan-current-secrets.mjs` requires (that script correctly refused it). Re-run with the pinned binary for the gate of record. |
| Reproduce | `node scripts/scan-history-secrets.mjs` (exits 2 on any partial scan, 1 on findings, 0 clean; prints only counts) |
| Ledger | [`evidence/secret-history-ledger-2026-10-05.csv`](./evidence/secret-history-ledger-2026-10-05.csv), 184 rows |

### Why the counts differ from 2026-09-23 (296 matches / 998 commits)

1. **Partial-scan trap.** On Windows, gitleaks runs `git log -p`; Git for Windows applies the `astextplain` textconv filter to `*.docx` and fails (`docx2txt.exe: command not found`). Gitleaks then logs `failed to scan Git repository` and `partial scan completed`, **yet still reports a findings count** from the portion it read. A first run of this work reproduced exactly that (180 "leaks" in a partial scan). Any earlier number obtained without `--no-textconv` on such a host must not be treated as a full-history result. The wrapper above refuses partial scans.
2. The repository graph differs from the one scanned on 23 September (this worktree: 751 commits across refs vs. 998), so counts are not comparable one-to-one.

## Result

184 findings, 92 distinct values, 56 commits, 83 paths.

| Disposition | Findings | Meaning |
|---|---:|---|
| False positive / synthetic | 182 | Evidence-based reason recorded per row in the ledger |
| Owner-confirm | 2 | Cannot be proven synthetic from the repository alone |
| Confirmed live credential | 0 | None identified |

By rule: `generic-api-key` 111, `stripe-access-token` 16, `github-pat` 12, `private-key` 8, `gitlab-pat` 8, `curl-auth-header` 8, `aws-access-token` 6, `curl-auth-user` 5, `jwt` 3, and one each of `gcp-api-key`, `slack-webhook-url`, `slack-legacy-workspace-token`, `github-refresh-token`, `github-app-token`, `github-oauth`, `openai-api-key`.

### False-positive groups (182)

| Group | Rows | Evidence for the classification |
|---|---:|---|
| Detector test fixtures under `__tests__/`, `tests/`, `testcase/`, `e2e/` (e.g. `packages/core/src/__tests__/dlp/secret-detector.test.ts`, `credential-threats.test.ts`, `packages/privacy/tests/`) | 125 | Provider-pattern strings that are sequential/placeholder-shaped (`ghp_abcd…`, `AKIAABCD…`, `sk_live_` + 16 chars, `glpat-ab…`); the products under test are secret/PII detectors, so such fixtures are required. Stripe-shaped values are 20–34 characters (real keys are far longer). |
| Vendored AIG docs, rules, testcases (`vendor/ai-infra-guard/**`) | 31 | Documented placeholder/detector examples; already covered by narrow allowlists in `.gitleaks.toml` (those allowlists are path-anchored and therefore do not apply when scanning an extracted tree with `--no-git`). |
| Identifier/prose matches (env-var **names** in `supabase/functions/compliance-report/index.ts` and `approval-requests/index.ts`, a SQL column, a migration filename, a Node `crypto` function name, generated inventory prose, a prose sentence in `retention-holds.md`) | 13 | The matched text is a name, not a value. |
| Recorded evidence/test-run output (`docs/evidence/gate-logs/…`, `…-self-hosted-smoke.json` function digests) and `scripts/deployment-doctor.mjs` (SHA-256 of a documented demo value) | 7 | Hex digests / replayed fixtures, not credentials. |
| Bundled build artifacts `packages/claude-code/dist/*.cjs` (commit `2702b745d5`) | 4 | Minified identifier (`HapiInstrumentation`). `dist/` is no longer tracked (`git ls-files` shows 0 `/dist/` paths). |
| Docs showing `VITE_SUPABASE_ANON_KEY=<truncated>...` (`ZERO_TO_SECURE_SUMMARY.md`, `packages/dashboard/DEPLOYMENT.md`) | 2 | Truncated with `...`, not a usable value. The Supabase anon key is public by design; the docs also name a Supabase project ref, which is an identifier, not a credential. |

Eight PEM-shaped `private-key` findings (privacy/DLP test fixtures and vendored detector docs) were tested with `openssl pkey`; **none parses as a valid private key** (they are random or truncated base64 blocks used for detector/ReDoS tests).

### Owner-confirm items (2) — require a human before the gate can close

| Path | Commit(s) | What is unknown | Owner action |
|---|---|---|---|
| `deploy/browser-guard/chrome-managed-policy.example.json:57` and `…/firefox-policies.example.json:54` (browser-guard has since been removed from the tree) | `c8cabdc2e7`, `7a32a908`, `a190dbf2` (24–25 Sep 2026) | A 32-byte base64 `keyB64` for `datasetId: "crm-customers-example"`. Filename and dataset id say "example", but a dataset fingerprint key is secret if it was ever generated for a real dataset. | Browser-guard owner: confirm the value was generated only for the example (i.e. no real customer/internal dataset was fingerprinted with it). If unsure: treat as compromised, regenerate the dataset key, re-fingerprint the dataset, and redeploy managed policy. Record the answer in the ledger row. |

(The ledger's second `OWNER-CONFIRM` row is the sibling Firefox file for the same value.)

### `.env.aig` (tracked in history until 839f25ce, 24 Sep 2026)

Revisions `626d1931`, `d5e8387a`, `135e94d4` were inspected by key name and value *shape* only (no values printed). At every revision the secret-bearing keys (`BRIDGE_API_KEY`, `BRIDGE_JWT_SECRET`, `AIG_AGENT_SHARED_SECRET`, `AIG_DATASET_*_SHA256`, `BRIDGE_EGRESS_PROXY_URL`) were **empty**; remaining keys are ports, booleans, timezone, log level and paths. Conclusion: no credential material in that file's history. The file is untracked and ignored; `.env.aig.example` is the shipped template. Gitleaks and this review cannot prove the *local, untracked* copy on any developer machine is clean.

### Tracked sensitive-extension files (current tree)

`git ls-files` matches only `*.example` templates and `vendor/ai-infra-guard/frontend/.env*` (Vite config: API base URL, dev proxy target, feature flags; no credentials). No `.pem`, `.key`, `.p12`, `.pfx`, `id_rsa` or `.sqlite` is tracked.

## If a live secret is later confirmed (rotation runbook — owners, not this repo)

Do not rewrite published history or paste the value anywhere as a first response.

1. **Security lead** declares an incident; record only the ledger row (rule, path, commit, fingerprint).
2. **Credential owner of the issuing system** revokes first, then reissues: Stripe dashboard (roll API key / webhook secret); GitHub/GitLab (revoke PAT, review audit log); Supabase (rotate service-role/JWT secret, anon key, and DB password; redeploy Edge secrets); cloud IAM (disable access key, review CloudTrail/activity logs for use since the commit date); Slack (revoke token/webhook); browser-guard dataset key (regenerate and re-fingerprint).
3. **Release engineering** rotates the AIDR signing keys only if a signing/private key is implicated (re-key the release trust policy and publish a revocation entry; `scripts/release-signing-lib.mjs` supports key-id and fingerprint revocation).
4. **Security lead** reviews provider logs from the commit date to now for use; records the result as evidence.
5. Only then decide on history rewrite (coordinated, with all clones/forks/CI caches re-seeded) versus accept-and-rotate. Add a narrowly scoped allowlist entry to `.gitleaks.toml` only for values proven synthetic.

## Closing the gate (owner checklist)

- [ ] Security owner reviews the 2 owner-confirm rows and records disposition (name, date) in the ledger.
- [ ] Re-run with the pinned official gitleaks 8.30.1 (`GITLEAKS_BIN=… node scripts/scan-current-secrets.mjs`, then `node scripts/scan-history-secrets.mjs --gitleaks …`) on the exact release-candidate commit; attach redacted reports and their SHA-256 to the evidence index.
- [ ] Secret-manager inventory and provider-side revocation evidence for any item escalated (not in this repo).
- [ ] Repeat on the CI-provided full clone (shallow clones silently shrink the scan).
