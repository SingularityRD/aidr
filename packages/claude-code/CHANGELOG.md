# @singularityrd/aidr-claude-code

## 0.6.0

### Minor Changes

- Rebrand to Singularity AIDR (package scopes, identifiers, and documentation).

### Patch Changes

- Extract command artifacts from JS/TS plugin files using regex-based detection of Node.js/Bun/zx command execution APIs. Add .mjs/.mts to scannable extensions.
- Move @singularityrd/aidr-core from dependencies to devDependencies in claude-code and extension packages (core is bundled by esbuild, not needed at runtime). Add prepack guard to core, openclaw, and opencode to reject publish with unresolved workspace: references when not using pnpm.

## 0.5.2

### Patch Changes

- Updated dependencies
  - @singularityrd/aidr-core@0.5.2

## 0.5.1

### Patch Changes

- Updated dependencies
  - @singularityrd/aidr-core@0.5.1

## 0.5.0

### Minor Changes

- Intercept Read tool for security checks (Claude Code, VS Code)

### Patch Changes

- Extend version check to allow for finer-grained version checking based on individual packages.


