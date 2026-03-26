# @singularityrd/aidr-opencode

## 0.6.0

### Minor Changes

- Rebrand to Singularity AIDR (package scopes, identifiers, and documentation).

### Patch Changes

- Move @singularityrd/aidr-core from dependencies to devDependencies in claude-code and extension packages (core is bundled by esbuild, not needed at runtime). Add prepack guard to core, openclaw, and opencode to reject publish with unresolved workspace: references when not using pnpm.
- Updated dependencies [e4616d8]
  - @singularityrd/aidr-core@0.6.0

## 0.5.2

### Patch Changes

- Updated dependencies
  - @singularityrd/aidr-core@0.5.2

## 0.5.0

### Minor Changes

- OpenCode connector, co-authored by FeiyouG
- Unify approval store, guard orchestrator, and allowlist tool logic into core. Fix OpenCode pendingFindings race condition.

### Patch Changes

- Extend version check to allow for finer-grained version checking based on individual packages.
- Promote ask verdicts to deny in paranoid mode to prevent prompt-injection auto-approval


