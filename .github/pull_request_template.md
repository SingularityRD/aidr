## Description
<!-- Describe your changes in detail -->

## Type of Change
<!-- Mark relevant items with [x] -->
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Threat rule addition/update
- [ ] Performance improvement
- [ ] Code refactoring

## Testing
<!-- Describe the tests you ran and how to reproduce them -->
- [ ] Unit tests pass (`pnpm test`)
- [ ] Integration tests pass (if applicable)
- [ ] E2E tests pass (`pnpm test:e2e:claude` for Claude Code changes)
- [ ] Tested manually on [platform]

## Pre-PR Checklist
<!-- All items must be checked before submitting -->
- [ ] I have run `pnpm test` and all tests pass
- [ ] I have run `pnpm check` and type checking passes
- [ ] I have run `pnpm lint` and linting passes
- [ ] I have added a changeset if this PR modifies any package (`pnpm changeset`)
- [ ] I have updated CLAUDE.md if needed
- [ ] I have run the code-simplifier subagent on changed files (if applicable)
- [ ] My code follows the project's naming conventions (snake_case for YAML/JSON, camelCase for TypeScript)
- [ ] I have verified the per-layer failure policy in CLAUDE.md: connector entry points and security controls fail closed (deny/block on internal error); only optional detection signals (e.g. a reputation lookup) are skipped and logged

## Related Issues
<!-- Link to related issues using #issue_number -->
Fixes #
Closes #
Relates to #

## Screenshots (if applicable)
<!-- For UI changes in dashboard or extension -->

## Security Considerations
<!-- For security-related changes -->
- [ ] This change does not introduce new attack vectors
- [ ] Threat detection rules follow the YAML schema
- [ ] No sensitive data is logged without redaction
