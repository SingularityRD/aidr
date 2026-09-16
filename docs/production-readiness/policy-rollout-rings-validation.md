# Ordered policy rings: implementation and validation

## Contract

`policy-management` actions `rollout` / `create_rollout` accept `expected_version`, `expected_revision_version`, a validated runtime `policy`, and ordered `rings`: each ring has contiguous `ring_order` and `batches`; each batch has contiguous `batch_order` and explicit `agent_ids`. IDs cannot repeat within or across cohorts, or overlap another running/paused rollout. The request remains bounded to 64 KiB. SQL also bounds the plan to 100 rings, 1,000 batches and 20,000 targets (200 per batch).

One revision and the complete plan are committed atomically under the existing tenant publication advisory lock. Both published-version and latest-revision CAS must match. Only the first batch is assigned; tenant fallback is unchanged. Owner/admin mutation authority is checked in the handler and SQL; the existing common session/MFA, membership, active-tenant and quota guards run before dispatch.

Receipts must come from a live agent-bound key (including a valid bounded retired-hash overlap), match the canonical policy digest and the exact currently selected revision. Every released cohort must have all targets freshly confirmed before progression. A cached acknowledgement alone, absent receipt, stale timestamp, wrong digest, superseded assignment, missing/deleted target or pending target cannot advance a batch/ring. Fixed initial batch target counts prevent deletion from shrinking the denominator. Completed-cohort receipts can refresh evidence and unblock an active later cohort. Legitimate return to an older tenant fallback after cancellation is accepted; unrelated older receipts remain rejected.

`rollout_progress` returns ordered batch and ring evidence with `targeted`, `current`, `stale`, `outdated`, `unknown`, and observed acknowledgement percentages. The existing `adoption` response adds rollout evidence; unavailable optional storage is explicitly `unavailable`, never fabricated convergence. Completion is historical state, not a guarantee that current receipts stay fresh.

Evidence is **agent-reported policy loaded**, not host enforcement attestation or real fleet convergence. No production agents were enrolled or observed by this work.

## Merge guidance

The isolated branch starts at `ed834bf6`; it does not contain main's later draft CAS or DLP actions. Preserve main's existing policy-management action bodies, draft preconditions, validators and tests. Integrate the additive `_shared/policy-rollout.ts` helper, its import, the guarded dispatch after common authorization/rate limiting, the rate cost entries, and optional adoption evidence. Do **not** replace main's whole handler with this branch's older file. Likewise merge additive ring test cases rather than replacing main's newer contract suite.

The new unshipped migration is `20260916000000_policy_rollout_rings.sql`; no shipped migration was changed. Required schema/function dependencies:

- `20260911000000_runtime_policy.sql`
- `20260911000002_policy_conflict_status.sql`
- `20260911000004_policy_rollout.sql` (agent binding, assignments, receipts, publication cleanup)
- `20260913000002_policy_stage_cas.sql` (six-argument stage CAS RPC)
- `20260915000000_key_rotation_overlap.sql` (API-key retired-hash columns)
- Existing tenant/users/agents/audit schemas, `app` schema and `touch_updated_at`.

The migration injects a cancellation helper call into the original publication and stage functions using checked definition markers. It deliberately fails migration on dependency drift instead of silently losing cancellation, auth or CAS behavior. Revalidate those markers and run this PG harness against the integrated migration chain. Parent-first cancellation closes the resume-versus-stage assignment cleanup race. Do not add the tenant advisory lock inside the row-level resume trigger: that would invert the existing advisory-before-parent receipt order.

SQL canonical JSON matches the current string/list runtime policy vocabulary and is tested with the same real Node SHA-256 digest. New policy numeric encodings or non-ASCII object keys must receive cross-runtime canonicalization tests before rollout use; differing encodings reject receipts rather than claim adoption.

## Local validation

- Own `pnpm install --offline --ignore-scripts`: passed; no shared node_modules junction.
- `pnpm exec vitest run --config supabase/functions/__tests__/policy-rings.vitest.config.ts`: 101 passed, 0 failed, 0 skipped (64 policy-management, 22 policy-ack, 15 API-key-auth). Default Vitest deadlines; no global connector build is required for these injected-client Edge contracts.
- V8 measurement for `_shared/policy-rollout.ts`, `_shared/api-key-auth.ts`, `policy-ack/index.ts`, and `policy-management/index.ts`: 88.01% statements, 82.40% branches, 66.66% functions, 93.51% lines. This restricted measurement is not repository-wide coverage and excludes `policy/index.ts`.
- PostgreSQL regression command: `node scripts/test-policy-rings-postgres.mjs`. The harness uses cached `postgres:17-alpine` with `--pull never --network none`, no published port, ephemeral data and an owned randomly labelled container. It applies the four real unchanged policy dependency migrations then the new rings migration. Its documented minimal base fixture supplies users/tenants/agents/keys/audit schemas, not a full Supabase installation. All tests fail rather than skip; fixed SQL/lock/Docker deadlines are not widened. The owned container is removed in `finally`.

Final PostgreSQL result: **34/34 passed, 0 failed, 0 skipped**, exit 0, 49.5 seconds. The exact migration bytes tested have SHA-256 `1b85d0470912cb2ed38b0a2d6d63cac2337c6a0b664cb9cc8c953805f69ed528`; the owned container was removed. `node --check scripts/test-policy-rings-postgres.mjs` and `git diff --check` also passed. Scenarios cover real competing CAS/receipt transactions, order/assignment/overlap, tenant authority and grants, canonical hashes, unknown/stale/unconfirmed/deleted-target evidence, completed-cohort refresh, direct stale transition and insertion guards, pause/resume, resume-versus-stage cleanup, and cancellation to an older fallback. Concurrent receipt observers verify exactly one batch activation, completion and next-target assignment write, rather than relying only on the final unique row count.

## External limits

No deployed Supabase/Edge runtime, full migration replay on main, production tenant, connector end-to-end exercise, dashboard UI, host attestation, or real fleet convergence was tested. MFA coverage is the real handler driven by an injected Supabase-shaped client; PostgreSQL covers role and membership checks, not live identity-provider assurance. PostgreSQL test evidence is synthetic local database evidence. Re-run integrated handler and migration checks after merging with main's newer CAS/DLP work.
