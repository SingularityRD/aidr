# @singularityrd/aidr-openclaw

## 0.6.0

### Minor Changes

- Rebrand to Singularity AIDR (package scopes, identifiers, and documentation).

### Patch Changes

- Move @singularityrd/aidr-core from dependencies to devDependencies in the openclaw connector package.
- Bypass OpenClaw security check false positives on Singularity AIDR installation.
- Move @singularityrd/aidr-core from dependencies to devDependencies in claude-code and extension packages (core is bundled by esbuild, not needed at runtime). Add prepack guard to core, openclaw, and opencode to reject publish with unresolved workspace: references when not using pnpm.

## 0.5.3

### Patch Changes

- Fix the configuration instructions inside README. Add an ask->deny promotion integration test.

## 0.5.2

### Patch Changes

- Updated dependencies
  - @singularityrd/aidr-core@0.5.2

## 0.5.0

### Minor Changes

- Unify approval store, guard orchestrator, and allowlist tool logic into core. Add allowlist tools to OpenClaw.

### Patch Changes

- Extend version check to allow for finer-grained version checking based on individual packages.
- Promote ask verdicts to deny in paranoid mode to prevent prompt-injection auto-approval


