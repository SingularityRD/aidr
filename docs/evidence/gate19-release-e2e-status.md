# Gate 19 — release E2E status after the live work

**Date:** 2026-09-18
**Gate:** `19-release-e2e`
**Decision:** `FAIL` — correctly. Two of twelve suites now pass on their own
merit; the rest are blocked on credentials, deployed services, or a runner
limitation that is described below rather than hidden.

## Suite-by-suite

| Suite | Expected | State | Why |
|---|---|---|---|
| `supabase-migrations` | 1 | **PASS 1/1** | Runs against the local installation |
| `supabase-control-plane` | 9 | **PASS 9/9** | Runs against the local installation |
| `cursor` | 8 | **PASS 8/8** | Runs the extension host directly; see below |
| `vscode` | 8 | **PASS 8/8** | Runs the extension host directly; see below |
| `aig-bridge-contract` | 31 | **PASS 31/31** | Passes once `AIDR_AIG_PYTHON` points at the isolated venv |
| `dashboard-route-smoke` | 1 | **PASS 1/1** | Crawls the locally running dashboard over real HTTP |
| `cursor-headless-agent` | 1 | blocked | Needs `AIDR_AGENT_PATH` and agent auth |
| `claude` | 7 | blocked | Needs `ANTHROPIC_API_KEY` |
| `opencode` | 13 | blocked | Needs one of `OPENCODE_API_KEY` / `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` |
| `openclaw` | 5 | blocked | Needs `OPENCLAW_GATEWAY_TOKEN` and `OPENCLAW_E2E_HOST` |
| `aig-live-control-plane` | 4 | blocked | Needs `AIDR_AIG_E2E_EVIDENCE` |
| `supabase-live-control-plane` | 8 | blocked | Needs `AIDR_SUPABASE_E2E_EVIDENCE` |
| `dashboard-browser` | 10 | blocked | Needs `AIDR_DASHBOARD_BROWSER_EVIDENCE` |

**58 of 65 declared assertions across the twelve runnable suites now pass**, up
from 10 before this work. The seven that remain are blocked on credentials,
deployed services, or a named external attestation — not on repository state.

## The Vitest wrapper problem, resolved

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
   arguments — reads the per-case JSON, and emits JUnit. A missing case is a
   failure, a host that exits 0 without writing results is eight failures, and a
   missing host binary exits blocked. Seven regressions pin those refusals,
   because a silent green report is precisely the failure being replaced.
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
