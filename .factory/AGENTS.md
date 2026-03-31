# AGENTS.md — Singularity AIDR v2.0 Mission

## Mission Boundaries (NEVER VIOLATE)

**Package Scope:**
- Work within `packages/core/`, `packages/sdk/`, `packages/claude-code/`, `packages/openclaw/`, `packages/opencode/`, `packages/extension/`
- DO NOT modify `packages/dashboard/` unless explicitly instructed
- DO NOT touch `threats/` directory (data files, not code)
- DO NOT touch `allowlists/` directory (data files)

**External Services:**
- CI/CD workflows use existing infrastructure (GitHub Actions)
- No new external service dependencies without orchestrator approval

**Off-Limits:**
- `/data` directory - do not read or modify
- Production CDN endpoints for rule sync (use mock/test URLs)

## Coding Conventions

**TypeScript:**
- Strict mode enabled
- Use `?.` and `??` for null-safety (preferred over non-null assertions where possible)
- Naming: `camelCase` for TS, `snake_case` for YAML/JSON data
- Prefer explicit return types on public APIs

**Error Handling:**
- Fail-open: internal errors return `allow` verdict
- Use `logger` from `types.ts` for structured logging
- Never expose secrets in logs or error messages

**Testing:**
- Write tests BEFORE implementation (TDD)
- Mock external services (CDN, Sentry, OTel) in tests
- Use `test-helper.ts` utilities where available

## Testing & Validation Guidance

**For TypeScript Fixes:**
- Run `pnpm check` to verify zero errors
- Run `pnpm test` to ensure no regressions
- Fix one category of errors at a time

**For CI/CD:**
- Validate YAML syntax with `pnpm lint`
- Ensure workflow commands work locally
- Document required secrets in workflow comments

**For Build Verification:**
- Run full quality gate: `pnpm quality:gate`
- Check coverage thresholds (70% minimum)
- Verify bundle sizes in dist/ output

## Mission Context

This mission brings Singularity AIDR to production-ready v2.0:
- 34 TypeScript errors to fix (packages/core)
- Complete Real-Time Rule Sync implementation
- CI/CD pipeline finalization
- Build verification and documentation

**Key Files:**
- `packages/core/src/tracing.ts` — OpenTelemetry (API mismatch)
- `packages/core/src/rule-sync.ts` — Needs downloadRule() method
- `packages/core/src/ml/` — Strict null check fixes
- `packages/core/src/novelty-detection.ts` — Map iteration fixes
