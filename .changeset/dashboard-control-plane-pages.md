---
"@singularityrd/aidr-dashboard": minor
---

New control-plane pages:

- `/downloads` and a "Download & connect" onboarding step, driven by a validated release manifest (SHA-256, signatures, per-runtime install and enrollment steps).
- `/privacy-guard` shows counts-only Browser Guard privacy telemetry.
- `/posture` shows CVEs, MCP inventory risks and skill/plugin findings.
- Settings gains Workspace and Profile sections.
- The Billing page shows the current plan, usage and a plan picker. `/pricing` renders from the plan catalog.
- The landing page reads its countable facts (rule count, site adapters, prices) from one module.
