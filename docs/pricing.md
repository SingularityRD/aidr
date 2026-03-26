# Pricing (Proposed)

Goal: make Singularity AIDR easy to adopt (1 agent free) while aligning revenue to the value driver (number of protected agents/installations).

## Definitions

- **Agent** = one unique Singularity AIDR installation id (`iid`) connected to the control plane under a customer account.
- **Metering unit** = active agents in the current billing month.

## Plans

### Free

- **$0**
- **1 agent included**
- Dashboard + telemetry for that 1 agent (optional opt-in)
- Local detection features always available

### Pro (per agent)

- **$19 / agent / month**
- Includes all cloud features (telemetry dashboards, longer retention, policy distribution)
- Volume discounts (applied automatically):
  - 10–49 agents: **$15 / agent / month**
  - 50–199 agents: **$12 / agent / month**
  - 200+ agents: contact sales

### Enterprise (custom)

- Everything in Pro
- SSO/SAML, SCIM, org-wide policies, audit exports, on-prem / VPC deployment options
- Dedicated support + SLAs

## Rationale (cost + value alignment)

- Cost drivers scale with event volume and storage, but agent count is the simplest, most predictable proxy.
- Per-agent pricing maps to security outcomes: each additional agent increases attack surface and protection value.
- 1 free agent removes friction and enables individual developers to validate value before expanding.

