---
name: typescript-fix-worker
description: Fixes TypeScript type errors in core packages, handling strict null checks, API mismatches, and type compatibility issues.
---

# TypeScript Fix Worker

## When to Use This Skill

This skill is used for features that fix TypeScript compilation errors, including:
- OpenTelemetry API version mismatches
- Strict null check errors (undefined access)
- Type compatibility issues between modules
- Missing method implementations that cause type errors

## Required Skills

None — standard TypeScript tooling and knowledge.

## Work Procedure

### 1. Analyze Error Patterns
- Read the specific file(s) mentioned in the feature
- Run `pnpm check` to confirm current error count
- Understand the root cause of each error category

### 2. Implement Fixes
For each error:
- Apply the minimal fix that resolves the type error
- Prefer `?.` optional chaining and `??` nullish coalescing for undefined access
- Fix API mismatches by using correct imports or types
- For missing methods, implement the required functionality

### 3. Write/Update Tests
- Write failing tests FIRST for any new methods or behavior
- Ensure existing tests still pass
- Add specific tests for edge cases that triggered type errors

### 4. Verify
- Run `pnpm check` until zero errors
- Run `pnpm test` to ensure no regressions
- Run `pnpm lint` to ensure code style compliance

### 5. Document Changes
- Note any API changes in the handoff
- Document any patterns workers should follow for similar fixes

## Example Handoff

```json
{
  "salientSummary": "Fixed 34 TypeScript errors in packages/core. Resolved OpenTelemetry API mismatches in tracing.ts, implemented missing downloadRule() method in rule-sync.ts, and added null-safety checks across ML and behavioral modules. All tests pass with no regressions.",
  "whatWasImplemented": "Fixed TypeScript compilation errors:\n- tracing.ts: Fixed OpenTelemetry imports (propagation and createTraceState from @opentelemetry/api, not @opentelemetry/core). Fixed TimeInput type mismatch for span end time.\n- rule-sync.ts: Implemented missing downloadRule() method that fetches single rule by ID from CDN with proper error handling.\n- ml/embedder.ts: Added non-null assertions for Float32Array access with strict null checks.\n- ml/similarity.ts: Fixed vector undefined checks before cosine similarity calculations.\n- novelty-detection.ts: Added null checks for Map iteration in getTopKeys() and getPeakHours().\n- audit.ts: Fixed string|undefined type mismatches with proper nullish coalescing.\n- health.ts: Corrected VerdictCache constructor call argument count.\n- metrics.ts: Added undefined checks for label value access.",
  "whatWasLeftUndone": "",
  "verification": {
    "commandsRun": [
      {"command": "pnpm check", "exitCode": 0, "observation": "Zero TypeScript errors"},
      {"command": "pnpm test -- packages/core", "exitCode": 0, "observation": "All 52 core tests pass"},
      {"command": "pnpm lint", "exitCode": 0, "observation": "No lint warnings"}
    ],
    "interactiveChecks": []
  },
  "tests": {
    "added": [
      {"file": "packages/core/src/__tests__/rule-sync.test.ts", "cases": [
        {"name": "downloadRule fetches single rule by ID", "verifies": "RuleSync.downloadRule() method works correctly"},
        {"name": "downloadRule handles 404 errors", "verifies": "Graceful error handling for missing rules"}
      ]}
    ]
  },
  "discoveredIssues": []
}
```

## When to Return to Orchestrator

- If fixing one error causes cascading errors in other files
- If the fix requires significant architectural changes beyond simple type fixes
- If external API changes require coordination with other packages
- If errors are in generated/auto-generated code that shouldn't be manually edited
