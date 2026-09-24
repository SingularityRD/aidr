# Gate 19 — release E2E status

**Current decision:** `NO-GO`. The current contract in
`scripts/e2e-release-manifest.json` declares **14 suites and 155 exact
assertions**. No run of that updated contract is bound to an immutable release
candidate. The current release decision is `.release-evidence/v8-evidence-index.json`;
this page is an explanation, not an acceptance receipt.

The latest stored diagnostic run in `.e2e-artifacts/release/summary.json` ended
**2026-09-22T21:38:43Z** with `candidateDigest=null` and
`candidateBoundAt=null`. Only `supabase-migrations` passed in that run. It used
the previous assertion counts (109 total, including 9 for the Supabase contract
and 31 for the AIG bridge), so it **cannot** be reused as a result for today's
manifest. A separate focused Supabase test subsequently passed 19/19; that is
not a candidate-bound release E2E pass.

## Current suite contract and next evidence

| Suite | Exact tests | Latest stored diagnostic / next requirement |
|---|---:|---|
| `claude` | 7 | Blocked: runnable Claude CLI and authorized model credential. |
| `openclaw` | 5 | Blocked: live gateway, token and signed host receipt for the exact candidate. |
| `opencode` | 13 | Blocked: authenticated model provider and native plugin execution. |
| `cursor` | 8 | Blocked: Cursor executable, candidate VSIX and matching SHA-256. |
| `cursor-headless-agent` | 1 | Blocked: authenticated agent CLI and Cursor host. |
| `model-interception-live` | 3 | Stored run exited 2: configured Codex executable did not exist; rerun with a real authenticated host. |
| `vscode` | 8 | Blocked: VS Code executable, candidate VSIX and matching SHA-256. |
| `aig-bridge-contract` | 67 | Stored run's Python lacked pytest; current contract also requires `AIG_BRIDGE_TEST_POSTGRES_DSN` for the live cross-instance race. |
| `aig-live-control-plane` | 4 | Blocked: deployed server/worker, signed dataset and fresh candidate-bound receipt. |
| `supabase-migrations` | 1 | Passed only in the unbound diagnostic run; repeat for the exact candidate. |
| `supabase-control-plane` | 19 | Stored run collected/passed 19 but old manifest expected 9; focused rerun passed 19/19, not a release pass. |
| `supabase-live-control-plane` | 8 | Blocked: isolated deployed control plane, two disposable tenants and fresh candidate-bound receipt. |
| `dashboard-route-smoke` | 1 | Blocked: running candidate dashboard URL and Supabase browser configuration. |
| `dashboard-browser` | 10 | Blocked: deployed candidate, clean browser/accessibility run and fresh receipt. |

External receipts require a matching `AIDR_E2E_RC_DIGEST`, a canonical
`AIDR_E2E_CANDIDATE_BOUND_AT`, fresh timestamps, every declared assertion
passed, redaction and an attestation. A local fixture or a historical host
observation is not a substitute. In particular, this workspace has no AIDR
cloud project, test domain/TLS or independent restore host yet; neither cloud
nor self-hosted deployment acceptance is claimed here.

## Historical engineering observations (2026-09-18)

The previous notes described a narrower, unbound execution. They are retained
for root-cause context only; none of the old pass counts below should be read
as today's Gate 19 decision.

### The Vitest wrapper problem, resolved

Five suites were previously unusable for a reason that was easy to misread. The
Vitest worker fork dies before any test body executes for the extension suites,
and the JSON report still says `success: true` with `numPassedTests: 0` while
counting the test file as failed, with empty stdout and stderr artifacts. A
reader who trusted the aggregate flag would have recorded a **green IDE suite
that ran nothing**, and `dashboard-route-smoke` was in exactly that state: the
smoke test passed against a live dashboard while the gate read 0/1 from a stale
artifact.

Two changes fixed it without weakening anything:

1. **`cursor` and `vscode` run through `scripts/run-ide-host-e2e.mjs`** as
   `command`-kind suites. It drives the vendor's extension host the way the
   Vitest suite does — same suite file, same `AIDR_E2E_*` metadata, same launch
   arguments — reads the per-case JSON, and emits JUnit. Before launch it
   verifies the inventory-bound VSIX digest, installs that exact archive into a
   fresh profile, and verifies every installed `dist` file against its signed
   artifact manifest. A missing case is a failure, a host that exits 0 without
   writing results is eight failures, and a missing host binary exits blocked.
   Eleven regressions pin those refusals, because a silent or stale green report
   is precisely the failure being replaced.
2. **`dashboard-route-smoke` writes its own JUnit** when the gate asks for one
   via `--junit {junit}`, instead of leaving the gate to find a stale report.

The Cursor headless-agent capability moved to its own suite rather than being
dropped, so it is still declared and still reported honestly as blocked.

## Why the external suites cannot be filled in from here

`validateExternalEvidence` requires `schemaVersion`, `suiteId`, `status`,
`redacted`, a `generatedAt` within 24 hours, an `rcDigest` matching the candidate,
exactly `expectedTests` assertions, and a non-empty **`attestation`**. That last
field is a statement by whoever ran the suite. Writing one from inside this
repository would forge a third-party claim about a deployment that does not
exist, which is precisely what the field is there to prevent. The blocker is the
absence of the deployments and the persons, not the schema.

## The one live model turn that did run

A real Codex session, authenticated with an existing account, was driven through
two turns with the packaged AIDR hook registered. A destructive `rm -rf` was
**declined in 0 ms with `blocked by policy`**, and a benign `echo` in the same
session **executed and returned output**. Details and the full transcript are in
`model-driven-interception-first-proof.md`.

That is the first live evidence that AIDR stops a real agent's action rather than
only a fixture payload. It is **not** recorded as gate 19 external evidence: it
is one command class, on one host, on one platform, run by the same person who
wrote the code, and gate 19 exists to require something this is not.
