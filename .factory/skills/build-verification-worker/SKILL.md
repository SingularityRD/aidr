---
name: build-verification-worker
description: Verifies complete build pipeline, runs all quality gates, and ensures production readiness.
---

# Build Verification Worker

## When to Use This Skill

This skill is used for the final build verification feature that:
- Runs complete build pipeline
- Executes all quality gates (lint, typecheck, test, coverage)
- Verifies bundle size constraints
- Confirms all artifacts are generated correctly

## Required Skills

None — standard build tooling knowledge.

## Work Procedure

### 1. Run Complete Quality Gates
Execute in sequence:
1. `pnpm lint` - Code style and formatting
2. `pnpm check` - TypeScript type checking
3. `pnpm test` - Unit and integration tests
4. `pnpm test:coverage` - Coverage verification
5. `pnpm build:release` - Production build

### 2. Verify Artifacts
- Check all dist/ directories are generated
- Verify bundle sizes are within constraints
- Confirm no source maps in production builds (per check-no-sourcemaps.mjs)
- Verify no leaky paths in binaries

### 3. Document Results
- Record final metrics (test count, coverage %, bundle sizes)
- Note any warnings or non-blocking issues
- Confirm all success criteria are met

## Example Handoff

```json
{
  "salientSummary": "Completed full build verification. All quality gates pass: 0 lint errors, 0 TypeScript errors, 70 tests passing, >90% coverage, and successful production build. Bundle sizes within constraints. Ready for v2.0 release.",
  "whatWasImplemented": "Executed complete quality gate pipeline:\n- pnpm lint: 0 errors, 0 warnings\n- pnpm check: 0 TypeScript errors across all packages\n- pnpm test: 70 tests passing (52 core, 6 claude-code, 5 openclaw, etc.)\n- pnpm test:coverage: 91% lines, 88% functions, 85% branches (exceeds 70% threshold)\n- pnpm build:release: All packages built successfully\n\nArtifacts verified:\n- packages/core/dist/ - ES modules and types\n- packages/claude-code/dist/ - CJS bundles for hooks\n- packages/extension/dist/ - VSIX ready for publishing\n- packages/openclaw/dist/ - Plugin bundle\n- packages/opencode/dist/ - Plugin bundle\n\nBundle sizes:\n- Core: ~45KB (target <5MB) ✓\n- Claude Code hooks: ~12KB each\n- Extensions: ~180KB",
  "whatWasLeftUndone": "",
  "verification": {
    "commandsRun": [
      {"command": "pnpm lint", "exitCode": 0, "observation": "No errors or warnings"},
      {"command": "pnpm check", "exitCode": 0, "observation": "Zero TypeScript errors"},
      {"command": "pnpm test", "exitCode": 0, "observation": "70 tests passing"},
      {"command": "pnpm test:coverage", "exitCode": 0, "observation": "Coverage >90%"},
      {"command": "pnpm build:release", "exitCode": 0, "observation": "All packages built successfully"}
    ],
    "interactiveChecks": []
  },
  "tests": {
    "added": []
  },
  "discoveredIssues": []
}
```

## When to Return to Orchestrator

- If any quality gate fails and requires fixes in other features
- If bundle sizes exceed constraints and require optimization
- If coverage thresholds are not met
