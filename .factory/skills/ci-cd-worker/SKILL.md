---
name: ci-cd-worker
description: Sets up and validates CI/CD pipelines, GitHub Actions workflows, and pre-commit hooks for quality gates.
---

# CI/CD Worker

## When to Use This Skill

This skill is used for features that:
- Create or modify GitHub Actions workflows (ci.yml, release.yml)
- Configure pre-commit hooks (.pre-commit-config.yaml)
- Set up quality gates and automated checks
- Configure build and release pipelines

## Required Skills

None — standard YAML and GitHub Actions knowledge.

## Work Procedure

### 1. Assess Current State
- Read existing workflow files (.github/workflows/*.yml)
- Read pre-commit configuration (.pre-commit-config.yaml)
- Identify gaps between current state and requirements

### 2. Implement Changes
- Create or modify workflow files with proper syntax
- Configure pre-commit hooks with correct stages
- Ensure workflows use correct pnpm/Node.js setup
- Add any required secrets or environment variables documentation

### 3. Validate Locally
- Test pre-commit hooks with `pre-commit run --all-files` (if pre-commit is installed)
- Validate YAML syntax
- Ensure commands referenced in workflows work locally

### 4. Document
- Update any documentation about CI/CD setup
- Note required secrets or environment variables

## Example Handoff

```json
{
  "salientSummary": "Created release.yml workflow for automated npm publishing with changesets. Enhanced pre-commit hooks with typecheck and test stages properly configured. CI pipeline now includes E2E test jobs for main branch.",
  "whatWasImplemented": "\n- Created .github/workflows/release.yml with changesets-based automated versioning and npm publish\n- Enhanced .github/workflows/ci.yml with E2E test jobs for Claude Code, OpenClaw, and Cursor\n- Fixed .pre-commit-config.yaml hook stages:\n  - pre-commit stage: gitleaks, detect-private-key, lint, typecheck, test\n  - pre-push stage: knip (dead code detection), jscpd (duplicates), build, changeset-check\n- Added proper job dependencies (launch-gate → e2e tests)\n- Configured concurrency controls for release workflow\n- Added conditional execution for E2E tests based on secret availability",
  "whatWasLeftUndone": "",
  "verification": {
    "commandsRun": [
      {"command": "pnpm lint", "exitCode": 0, "observation": "No YAML lint errors"},
      {"command": "pnpm check", "exitCode": 0, "observation": "TypeScript clean"}
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

- If workflow requires secrets that need user setup
- If significant changes to existing workflow structure are needed
- If changes affect multiple repositories or require cross-repo coordination
