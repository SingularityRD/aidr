---
name: documentation-worker
description: Creates and updates documentation including API docs, deployment guides, and README files.
---

# Documentation Worker

## When to Use This Skill

This skill is used for features that:
- Create API documentation (docs/api/*.md)
- Write deployment guides (docs/deployment.md)
- Update README files with setup/run/test instructions
- Document configuration options and environment variables

## Required Skills

None — standard technical writing and markdown knowledge.

## Work Procedure

### 1. Research
- Read existing documentation structure (docs/ directory)
- Review source code for API surface and configuration options
- Check existing README for gaps

### 2. Create Documentation
- Write clear, concise documentation
- Include code examples where appropriate
- Document all environment variables and configuration options
- Add setup, run, and test instructions

### 3. Validate
- Ensure markdown renders correctly
- Verify all links work
- Check that documented commands actually work

## Example Handoff

```json
{
  "salientSummary": "Created comprehensive API documentation for SDK adapters and deployment guide for self-hosting. Updated README with accurate setup instructions and environment variable reference.",
  "whatWasImplemented": "\n- Created docs/api/sdk.md with:\n  - Universal SDK usage examples\n  - LangChain adapter documentation\n  - LlamaIndex adapter documentation\n  - AutoGen adapter documentation\n  - CrewAI adapter documentation\n  - Configuration options and middleware usage\n\n- Created docs/deployment.md with:\n  - Self-hosting instructions\n  - Docker deployment steps\n  - Environment variable configuration\n  - Monitoring setup with OpenTelemetry and Sentry\n\n- Updated README.md with:\n  - Quick start guide\n  - Environment setup instructions\n  - Test commands\n  - CI/CD status badges",
  "whatWasLeftUndone": "",
  "verification": {
    "commandsRun": [
      {"command": "pnpm lint", "exitCode": 0, "observation": "No markdown lint errors"}
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

- If documentation requires information from unfinished features
- If external dependencies need to be documented but aren't finalized
