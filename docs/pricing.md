# Pricing (Historical Proposal — Not an Offer)

This $2-per-additional-agent draft is superseded. It is not an approved price,
SKU, trial, licence, quote, or entitlement schedule. The current intended
metering unit is a connected protected-agent installation, but no price book
has been approved. See the [Commercial Release Manifest](production-readiness/commercial-release-manifest-template.md)
and [COM-001](production-readiness/commercial-go-evidence-registry.json) before
making any customer offer. The proposal below is retained only as history.

Goal: make Singularity AIDR easy to adopt (1 agent free) while aligning revenue to the value driver (number of protected agents/installations).

## Definitions

- **Agent** = one unique Singularity AIDR installation id (`iid`) connected to the control plane under a customer account.
- **Metering unit** = active agents in the current billing month.

## Plans

### Free

- **$0**
- **1 agent included**
- Dashboard access for that 1 agent (when control plane is enabled)
- Local detection features always available

### Pro (additional agents)

- **$2 / additional agent / month**
- Metered by unique installation id (`iid`) connected under a customer account

### Enterprise (custom)

- Everything in Pro
- Org-wide policy distribution, audit exports, and larger fleets
- Dedicated support + SLAs

## Rationale (cost + value alignment)

- Agent count is the simplest proxy for fleet risk and management value.
- 1 free agent removes friction and enables individual developers to validate value before expanding.
