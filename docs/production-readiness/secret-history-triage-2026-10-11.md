# Secret history triage — 2026-10-11 (AIDR-070 / audit item 39)

**Decision: the gate stays OPEN.** No verified live credential was found. The two owner-confirm rows from 2026-10-05 still have no owner or Security disposition. They are now hidden by a value-exact allowlist in the current `.gitleaks.toml` (see [Finding 1](#finding-1--the-owner-confirm-value-is-suppressed-not-decided)). This is an engineering refresh, not Security sign-off.

The machine-readable record is [`evidence/secret-history-scan-2026-10-11.json`](evidence/secret-history-scan-2026-10-11.json). It holds counts, hashes and one row per detection added since 2026-10-05. Secret values appear nowhere in this record, in the JSON, or in any committed log.

Each value is identified only by `value_fingerprint_sha256_8`: the first 8 hex characters of SHA-256 of the gitleaks match. This is the same scheme as [`secret-history-ledger-2026-10-05.csv`](evidence/secret-history-ledger-2026-10-05.csv). On the 78 rows that match by location, 0 fingerprints disagree with that ledger.

The unredacted reports were kept outside the repository only long enough to compute fingerprints, then deleted.

## Scope and method

| Item | Value |
|---|---|
| Source | `786441e7bd49f4931fb9db32f1c3d0ae51727733` (`claude/focused-gates-0u1is2`). The working tree was dirty: another agent was editing `threats/` and `packages/core`. |
| History | The clone was shallow. `git fetch --unshallow origin` succeeded. Result: non-shallow, 7 refs (2 local heads, 2 remote heads, 3 tags), 1132 reachable commits. Gitleaks reported 909 commits scanned (commits with diffs). The 2026-10-05 tip `7f3ec0ad` is an ancestor of HEAD. |
| Scanner | Official gitleaks **8.30.1** linux x64. The archive SHA-256 `551f6fc8…f2470eb` was checked with `sha256sum --check --strict` against the pin in `.github/workflows/ci.yml`. Executable SHA-256: `88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509`. |
| Current config | `.gitleaks.toml`, sha256 `56d1b904…f5b51d`. Last changed in `ec922dc4` (2026-10-07). |
| 2026-10-05 config | `git show 7f3ec0ad:.gitleaks.toml`, sha256 `cc0af202…a37b4d`. Re-run on the same graph for a like-for-like comparison. |
| Current tree | `PATH=<pinned>:$PATH pnpm verify:secrets:current` |
| History | `GITLEAKS_BIN=<pinned> node scripts/scan-history-secrets.mjs --report <outside repo>`. This uses `--all --no-textconv` and rejects partial scans. |

## Results

| Scan | Exit | Findings | Distinct values | Commits | Paths |
|---|---:|---:|---:|---:|---:|
| Current tree, current config (9120 files; scanner tests 11/11 pass) | 0 | 0 | – | – | – |
| Current tree, 2026-10-05 config | 1 | 57 | – | – | – |
| Full history, current config (official wrapper) | 1 | **83** | 47 | 36 | 42 |
| Full history, 2026-10-05 config | 1 | **157** | 84 | 59 | 73 |

- The redacted report from the official wrapper has SHA-256 `71591898f6825c3b9ae3dbff2096a6107b15601c060aa837ebc86310d6014ce5`. It is kept outside the repository.
- No partial-scan marker appeared in either history scan.
- Rules under the current config:
  - `generic-api-key`: 48
  - `stripe-access-token`: 13
  - `curl-auth-header`: 8
  - `curl-auth-user`: 5
  - `jwt`: 2
  - `gitlab-pat`: 2
  - One each: `gcp-api-key`, `slack-webhook-url`, `slack-legacy-workspace-token`, `private-key`, `openai-api-key`

### Reconciliation with 2026-10-05

**The 2026-10-05 result reproduces exactly.** With the 2026-10-05 config, 131 of the 157 detections match the 2026-10-05 ledger on rule, path, line and commit: 129 false positives and the 2 owner-confirm rows. Adding the one `policy-signature.test.ts:263` row that was classified on 2026-10-05 gives the same **132** set that run reported.

**Six location matches have a different fingerprint.** In each case the match was extracted differently: gitleaks 8.24.2 on Windows for the old ledger, 8.30.1 on Linux now. The lengths differ slightly because of CRLF/LF line endings or how much of a PEM block was captured. The rule, path, line and commit are the same, and every one is a test fixture that 2026-10-05 already classified as FP.

**The remaining 25 detections are all in commits dated 2026-10-06 or 2026-10-07,** after the last triage. Under the current config only 4 of them still fire, plus the 2026-10-05 `policy-signature` row. That is why the current-config history has 5 rows that are not in the ledger.

### New detections since 2026-10-05: all false positives

| Group | Rows (2026-10-05 config) | Flagged under current config | Disposition and evidence |
|---|---:|---:|---|
| `packages/core/.aidr-build.lock:1` (`d8a62046`) | 1 | yes | **FP.** This is a `crypto.randomUUID()` process-lock token written by `acquireCoreBuildLock` in `scripts/build-workspace.mjs`, and it grants no access. It was tracked by accident and has been untracked and gitignored since `60e49ffd`. |
| `packages/core/src/__tests__/mcp-aig-categories.test.ts:109` (`cab356cf`, `0303ee2c`) | 2 | yes | **FP.** A 12-character placeholder-shaped `access_token` in a URL fixture for the MCP hardcoded-secret detector. |
| `packages/core/src/__tests__/telemetry-redaction.test.ts:127` (`ae768a50`) | 1 | yes | **FP.** A 32-character keyboard-walk fragment appended to an Anthropic key prefix in a redaction fixture. A real key is about 108 characters. The fixture was split further in `be9951a2`. |
| `supabase/functions/__tests__/policy-signature.test.ts:263` (`7f3ec0ad`) | 1 | yes | **FP-INVALID-FIXTURE.** Already classified on 2026-10-05: the bytes are deliberately invalid PKCS8 and the test asserts HTTP 503. |
| Public SHA-256 digests and a public CPython release-signing GPG fingerprint in `docs/production-readiness/evidence/bridge-high-zero-*-2026-10-06.json`, `packages/privacy/docs/MODEL_CANDIDATE_EVIDENCE.json` and `MODEL_QUALITY_DIAGNOSTICS.json` (`f3f7f7e9`, `1bde0c2f`, `846482e6`) | 21 | no | **FP-PUBLIC-DIGEST.** The values are pure hex: 64 characters for the digests, 40 for the GPG fingerprint. Their keys are `auth.py`, `tokenizer_sha256` and `GPG_KEY`. They have been value-exact allowlisted since 2026-10-07. |

## Finding 1 — the owner-confirm value is suppressed, not decided

The 2026-10-05 owner-confirm rows are `deploy/browser-guard/chrome-managed-policy.example.json:57` and `…/firefox-policies.example.json:54` (commit `c8cabdc2`, fingerprint `6ebab6aa`). They are the 32-byte example dataset HMAC key.

The current config contains an allowlist whose regex is that literal value. It is labelled *"Browser Guard managed-policy examples: documented exact-data HMAC key for the example dataset"*. It was authored in `41410f7d` (2026-09-25) and merged to this line in `ec922dc4` (2026-10-07). The fingerprint was computed by this run and matches. **There is no recorded owner or Security decision behind the allowlist.**

Consequences:

- **The rows no longer show up.** The full-history scan with the current config no longer reports the two owner-confirm rows, so a future "history clean apart from FPs" reading would silently drop them.
- **The value is in six tracked files today.** Browser Guard is back in the tree. The files are `.gitleaks.toml` itself and `deploy/browser-guard/{chrome-managed-policy,firefox-policies,edge-intune}.example.json`, `macos-jamf.example.mobileconfig` and `windows-registry.example.reg`. The last three do not match the gitleaks rule at all.
- **A backlog claim is stale.** The AIDR-070 claim that the current tree passes *"with default rules only and no ignore/allowlist suppressions"* no longer holds. The current-tree PASS depends on the value-exact allowlists added after 2026-10-05: the same tree has **57** findings under the 2026-10-05 config. Those allowlists are narrow (rule + path + exact value) and the values they cover are synthetic fixtures, public digests or identifiers. The one exception is the dataset key, which is awaiting an owner decision.

**Owner action (unchanged):** the Browser Guard owner and Security must confirm that this key was generated only for the example and that no real dataset was fingerprinted with it. If they cannot confirm it, treat the key as compromised: regenerate the dataset key, re-fingerprint, redeploy managed policy and drop the allowlist. Either way, record the decision with a name and date against fingerprint `6ebab6aa`. This record does not remove the allowlist, because doing so would turn the current-tree gate red pending that decision. That trade-off belongs to the owner.

## What this does not close

- Security-owner disposition of the owner-confirm rows, and of the 2026-10-05 engineering classifications. Matching on metadata is not a fresh value-level review.
- Any provider-side rotation or usage-log review.
- A scan bound to the exact signed release candidate on a clean full clone. This run used a dirty development branch.

No history was rewritten, no allowlist was added or removed, and no backlog status was changed.

## Addendum 2026-10-11 — example dataset key retired

The repository owner directed that the Browser Guard example dataset HMAC key (fingerprint `6ebab6aa`, the two owner-confirm rows in Finding 1) be **treated as compromised** rather than waiting for a confirmation that it was never used for a real dataset. What changed in the working tree:

- **Value retired, not rewritten from history.** All five examples (`deploy/browser-guard/{chrome-managed-policy,firefox-policies,edge-intune}.example.json`, `macos-jamf.example.mobileconfig` and `windows-registry.example.reg`) now carry `keyB64: "REPLACE_WITH_DATASET_KEY_FROM_FINGERPRINT_DATASET"` and `fingerprints: ["REPLACE_WITH_FINGERPRINTS_FROM_FINGERPRINT_DATASET"]`. The three fingerprints derived from the retired key were removed as well. The placeholder is not base64, so neither `fingerprint-dataset.mjs` nor the extension can decode it into key bytes, and it fails the `keyB64` pattern in `static/managed_schema.json`. Git history still holds the old value at `c8cabdc2` and later commits. It was deliberately **not** purged: the value is public, and a rewrite would not un-publish it.
- **Runtime refusal.** `packages/browser-guard/src/background/policy.ts` exports `EXACT_DATA_PLACEHOLDER_KEY`. A managed `exactData` value with any dataset whose key or fingerprints start with `REPLACE_WITH_` is ignored as a whole, with the warning `managed: "exactData" still holds the example placeholder key; ignored. Build each dataset with fingerprint-dataset.mjs`. Other managed keys still apply. Tests: `background-policy.test.ts` ("refuses the example placeholder exact-data key by name") and `build-tools.test.ts` ("the example exact-data set is a placeholder, never a usable key", plus a replaced dataset that is accepted).
- **Allowlist removed.** The value-exact `.gitleaks.toml` allowlist for that key is gone. `node scripts/ci-local.mjs --allow-dirty --only secret-scan,repo-hygiene --fetch-tools`: `secret-scan` and `repo-hygiene` PASS with no suppression for this value. The run's only failure was the working-tree guard, caused by an unrelated untracked file from concurrent work in `packages/claude-code`.
- **Not done here.** The extension does not deny-list the retired key by digest. Any installation that copied the old example key verbatim keeps it until its administrator regenerates the dataset (`fingerprint-dataset.mjs` without `--key-file` generates a fresh key) and redeploys managed policy. The Security owner still has to confirm that no real dataset was fingerprinted with the retired key, and must record that confirmation against fingerprint `6ebab6aa` with a name and date. The full-history scan still reports the historical rows. They should now be classified as "retired example key (treated as compromised)" rather than "owner-confirm".
