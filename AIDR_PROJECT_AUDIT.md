# AIDR Project Audit (historical snapshot)

> **SUPERSEDED — historical record (2026-04-30). Do not use this file to judge
> readiness.**
>
> Superseded by `READINESS_BACKLOG.json`, `RELEASE_READINESS_REPORT.md` and
> `docs/production-readiness/ga-status-2026-08-04.md`. Retained for history.

## Baseline as recorded at the time

| Area | Status then | Evidence then |
|---|---|---|
| Working tree cleanliness | Dirty (large unrelated churn) | `git status --short` |
| Typecheck | Pass | `pnpm check` |
| Build | Pass | `pnpm build` |
| Unit tests | Pass | `pnpm test:unit` — 86 files / 1639 tests |

## What that baseline did not cover

The snapshot asserted typecheck/build/test passes and treated that as the health
signal. The 2026-09-10 audit wave showed why that was insufficient:

- A green unit suite coexisted with a product that **enforced nothing by default**
  (AIDR-015). The tier-2 integration tests had been written to assert the insecure
  behaviour — they asserted an empty `{}` (allow) response for `curl | bash`,
  `rm -rf /` and `.ssh/authorized_keys` writes — so the suite could not detect it.
- "Build passes" was true while `packages/codex` shipped a hook that denies 100% of
  calls and was absent from every build/release/CI gate (AIDR-017).
- Several "remaining blockers" listed here were never closed and are now tracked
  with ids: connector-wide output scanning (the module has no importers),
  the MCP semantic policy model, and repository hygiene.

## Lesson preserved

Passing tests are only evidence about the behaviour the tests assert. A test that
asserts a threat is allowed is not a test of detection. The current backlog records
for each finding the acceptance criteria and the exact verification method, and
`RELEASE_READINESS_REPORT.md` separates "verified" from "assumed".
