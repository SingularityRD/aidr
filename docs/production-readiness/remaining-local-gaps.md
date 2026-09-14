# AIDR — remaining local gaps, step by step

Decision at the start of this list: **NO-GO**. Everything below is a *local* gap —
code, artifact or gate that this repository can provide without a customer, a
signature key, a cloud account or a finance approval. Items that need those stay
listed as external and are not attempted.

Status key: `DONE` (committed and verified), `OPEN`, `EXTERNAL` (cannot be closed locally).

## DONE in this session

| # | Gap | Commit |
|---|---|---|
| D1 | The whole v8 commit series built in an order that violated "module lands with its barrel", and one commit mixed scratch cleanup with core code | series replayed (`4703578c`) |
| D2 | Double-encoded Turkish in the gap-audit generator and in the records it generates (59 work packages, 13 gates, agent prompt) | `d05e84d2`, `bb845814`, `af4de6db` |
| D3 | URL reputation reported "no data" as clean (edge + client + evaluator + SDK) | `b9483ce2`, `c8b39138` |
| D4 | Windows AMSI leg failed open invisibly | `e41dab5a` |
| D5 | Provisioned behavioural detector could never return anything but `ask` (no durable baseline, no model) | `4670ebd6`, `a704b372` |
| D6 | Rollback overwrote a file changed after the snapshot; quarantine followed symlinks and forgot failed deletes | `59d16532` |
| D7 | JSONC MCP configs were unreadable and an unreadable file looked like an empty inventory | `5f9e8e20` |
| D8 | Discovery never consulted the signed MCP tool-manifest mechanism | `a4bdaffb` |
| D9 | Delegated-credential verification had no enforcement point in the evaluator | `8740e472` |
| D10 | Supply-chain inspection selected by tool name, so a Codex `apply_patch` routed around it | `6b1f890a` |
| D11 | A role change for a pending invitation minted a second live invitation | `da0330aa` |
| D12 | An empty `it.skip` could disappear with nothing noticing | `a08958c4`, `4bf0a8c4` |
| D13 | Audit-write failures and telemetry loss were invisible | `dc4f6898` |

## Wave A — bounded detection and tenancy safety (10 subagents) — DONE

| # | Gap | Where | Acceptance |
|---|---|---|---|
| A1 | Tenant storage quota, per-tenant response-command depth cap, and the legacy caller-key `increment_rate_limit` still granted to `service_role` | new migration + caller | `tenant-quotas.test.ts` |
| A2 | No gate enumerates Edge routes and fails on a missing identity/API-key guard | `scripts/verify-endpoint-auth-matrix.mjs` | `verify-endpoint-auth-matrix.test.mjs` |
| A3 | DLP exceptions are never pruned, so expired entries fill the cap and suppress findings | `packages/core/src/dlp/policy.ts`, `scanner.ts` | `dlp/custom-policy.test.ts` |
| A4 | SIEM delivery and the retention reaper have no scheduler, so failures are never retried | `deploy/maintenance/*.service|.timer` | `siem-delivery-worker.test.mjs` |
| A5 | No TLS issuance/renewal and no region/residency manifest | `deploy/ingress/*`, `deployment-prepare.mjs` | `deployment-tls-renew.test.mjs` |
| A6 | `deploy/native/support-matrix.json` points at a schema that does not exist; a template-shaped scenario manifest is not refused | `deploy/native/*` | runner test |
| A7 | Codex `cli.ts` has zero test coverage (the fail-closed entry point itself) | `packages/codex/src/__tests__/cli.test.ts` | new suite |
| A8 | Legal holds are not consulted before an audit export; no cache-deletion phase or receipt | `audit-export/index.ts`, new migration | `audit-export-legal-hold.test.ts` |
| A9 | No finance-approval → entitlement transition, no TTL/pruning, no reconciliation view | new RPC + maintenance + dashboard | `billing-*` tests |
| A10 | No incident/evidence view: correlation and receipt output is never rendered | `packages/dashboard/src/enterprise/evidence-view.tsx` | new suite |

## Wave B — operator surface and remaining honesty gaps (10 subagents) — DONE

| # | Gap | Where | Acceptance |
|---|---|---|---|
| B1 | Policy document editor does not dry-run against the server compiler (parity gap) | `policy-editor.tsx` | `policy-parity.test.ts` |
| B2 | DLP has no editor; `ask` must stay out-of-band (no approval action) | `dlp-editor.tsx` | new suite |
| B3 | Output findings observed after consumption are not carried into the persisted transcript; Cursor assistant text emits no coverage record | `openclaw/output-protection.ts`, `extension/aidr-hook.ts` | new cases |
| B4 | Non-Claude connectors cannot be provisioned with a tenant detector policy | core helper + 4 connectors | new cases |
| B5 | No OS secret store and no rotational revocation for the CLI credential | `cli/utils/secret-store.ts` | `secret-store.test.ts` |
| B6 | No CLI uninstall; no local remediation entry point | `cli/commands/uninstall.ts`, fleet scripts | `uninstall.test.ts` |
| B7 | Dashboard cannot satisfy an `aal2` challenge; no session lifetime | `enterprise/auth.tsx`, `lib/supabase.ts` | `identity-mfa.test.tsx` |
| B8 | Device-code/API-key renewal does not exist; verify page never shows expiry | `api-keys`, `enrollment-tokens`, `VerifyPage.tsx` | new suites |
| B9 | Connector-scope claims disagree (README says four, registry five, matrix six) and claim surfaces are unscanned; stale scan digest is not gated | `check-commercial-readiness.mjs`, README | 3 new gate tests |
| B10 | No offline/air-gap image bundle and no release provenance (SLSA/in-toto) | `scripts/build-airgap-images.mjs`, `generate-provenance.mjs` | new suites |

## Wave C — T39 harness and the remaining evidence gates (10 subagents) — DONE LOCALLY

| # | Gap | Where | Acceptance |
|---|---|---|---|
| C1 | T39: no published corpus/observations/attestation schemas; validator literals can drift | `scripts/benchmarks/schemas/*` | `schema-drift.test.mjs` |
| C2 | T39: no reproducible synthetic corpus with a label-leakage check | `generate-corpus.mjs` | `generate-corpus.test.mjs` |
| C3 | T39: the holdout split is hand-declared and unverifiable | `split-corpus.mjs` | `split-corpus.test.mjs` |
| C4 | T39: no per-class metrics (confusion matrix, P/R/F1, score-gated ROC) | `evaluate.mjs` | new cases |
| C5 | T39: competitor cells have no reason-coded `unknown` | `comparison-spec.json`, `evaluate.mjs` | `comparison-matrix.test.mjs` |
| C6 | T39: any self-minted attestation key passes; no trust anchoring | `trusted-keys.json`, `evaluate.mjs` | new cases |
| C7 | T39: no measurement-budget declaration or ceiling enforcement | `evaluate.mjs` | new cases |
| C8 | T39: no canonical report digest, `--reproduce`, or write-once output | `evaluate.mjs` | `reproducibility.test.mjs` |
| C9 | Gate `13-build-release` and `16-support-bundle` are `unknown` for capture reasons only | `--run <gate>` | index regenerated |
| C10 | AIG source pin is stale against the vendored submodule (local, no network) | `verify-aig-source.mjs` | `aig:verify` exits 0 |

## Wave D — evidence refresh and final decision (10 subagents)

| # | Gap |
|---|---|
| D1 | Regenerate every generated record (feature inventory, gap audit, evidence index, agent prompt) against the new tree |
| D2 | Re-run the full matrix on the frozen tree: test:ci, coverage, check, quality:static, audit:prod, supabase:check, enforcement, codex, node contracts |
| D3 | Rebuild the release bundle and customer kit at the new commit; re-verify the kit |
| D4 | Update the candidate record with the new commit, digests and the local/external split |
| D5 | Repin the recorded commit identities in the four provenance records |
| D6 | Verify every recorded commit id resolves; verify the candidate digest is unchanged |
| D7 | Adversarial review: try to falsify each "DONE" claim above and report any that does not hold |
| D8 | Record the external blocker list verbatim (what each needs, from whom) |
| D9 | State the decision with the exact evidence level for each gate |
| D10 | Write the handoff for the next agent |

## EXTERNAL — cannot be closed locally

A named customer on a real host (T01, T39, POV-001, 25-customer-onboarding); an
approved publisher key with custody (T29, DEP-05, COM-001); independent security
assessment (SEC-EXT-001); legal/privacy/residency approval (EVAL-02, COM-003,
COM-011); finance approval and live provider keys (BIL-01/02/03, COM-004);
competitor access and a measurement budget (T39); an MDM test tenant and
notarization (CLI-04, AIDR-050); offsite storage with an independent key
custodian and agreed RPO/RTO (DEP-06, AIDR-044); a live control plane with DNS and
TLS (AIDR-016); IdP/SMTP configuration (TEN-04, T18); 8-hour soak and monthly SLI
(AIDR-052, COM-013). `AIG_RELEASE=true` also needs a manifest signing key.
