# AIDR: market-informed delivery and acceptance plan

Reviewed 2026-09-11. Product pages establish advertised capability categories,
not comparative efficacy. No evidence currently establishes that AIDR is the
best product in the market. The engineering objective is measurable coverage,
enforcement, reliability and operator usability on an explicitly supported scope.

## Reference capabilities

| Primary source | Capability signal | AIDR response in this change | Remaining work |
|---|---|---|---|
| [Palo Alto Prisma AIRS](https://www.paloaltonetworks.com/ai-security/prisma-airs) and [agent discovery documentation](https://docs.paloaltonetworks.com/ai-runtime-security/administration/agent-discovery) | Agent discovery, runtime protection and AI application security | Local MCP discovery and infrastructure posture connected to policy/session startup | Organization-wide inventory, cloud collectors, identity graph, continuous discovery |
| [Cisco AI Defense data sheet](https://www.cisco.com/c/en/us/products/collateral/security/ai-defense/ai-defense-ds.html) and [agent security](https://blogs.cisco.com/ai/securing-ai-agents-with-cisco-ai-defense) | AI discovery, validation and runtime controls | Tenant runtime policy publication/fetch, explicit degraded evidence, tool policy enforcement | Predeployment adversarial evaluation, identity-aware restrictions and validated inline response control |
| [Prompt Security agentic governance](https://prompt.security/solutions/agentic-ai-security-and-governance) and [SentinelOne Prompt](https://www.sentinelone.com/platform/securing-ai-prompt/) | Visibility and controls over agent/tool interactions | MCP server/tool controls and bounded Claude output inspection | Cross-connector output pipeline, tool manifest attestation, credential scope and lineage |

AIDR's implemented additions address these capability categories. They do not
establish feature parity. In particular, configuration fingerprints are not
tool-description attestation; a local inventory is not shadow-agent discovery;
PostToolUse feedback is not inline prevention. Claude's
[hook reference](https://code.claude.com/docs/en/hooks) distinguishes the
post-execution hook from pre-execution control.

## What must close before an enterprise production release

The row-level inventory is [FEATURE_INVENTORY.json](../../FEATURE_INVENTORY.json).
The existing commercial registry remains authoritative for external approval.
Every acceptance item below must refer to the same immutable release candidate.

| Priority | Deliverable | Completion evidence | Owner / dependency |
|---|---|---|---|
| P0 | Supported host and OS envelope | Native Claude, editor, OpenClaw, OpenCode, Codex and SDK scenario results; blocked side-effect checks; benign controls; hook-disabled/crash/timeout behavior | Engineering + customer staging hosts |
| P0 | Customer/cloud installation | Fresh install, authenticated onboarding, enrollment, policy denial, telemetry, upgrade and uninstall on each sold deployment model | Engineering + approved domains/project/SMTP/IdP |
| P0 | Scope and tenant isolation | Cross-tenant and role matrix across every exposed route, expired/revoked identities, privilege escalation, invitation replay, API-key/entitlement revocation | Security + independent assessment |
| P0 | Operations and recovery | Encrypted off-host DB/object backups; restore into new environment; measured RPO/RTO; key rotation and offboarding; bounded retention/deletion | Operations + customer policy |
| P0 | Release delivery | Signed candidate, SBOM/provenance, license review, private registry consumer install and rollback; no unpublished credentials or placeholders | Release engineering + Legal + registry/signer |
| P0 | Commercial delivery | Approved SKU/order, invoice-to-entitlement rehearsal, support escalation, data-flow/residency terms and agreed limitations | Finance/Sales + Legal + Support |
| P1 | Policy adoption and failover | Per-agent applied-version receipts, stale/offline posture, rollout rings and rollback; ensure an unavailable policy service cannot create an unreported policy downgrade | Engineering |
| P1 | Output and MCP trust | Inline response inspection where supported; description/schema drift quarantine; operator approval; no agent-issued self approval | Engineering + native protocol tests |
| P1 | Inventory and identity | Fleet MCP/agent discovery, resource and credential lineage, least privilege and short-lived delegated tokens | Engineering + cloud/IdP integrations |
| P1 | Investigation and export | Cursor-based complete export, retention job, SIEM delivery acknowledgment, causal cross-agent investigation | Engineering + customer SIEM |
| P2 | Product depth | Continuous red-team validation, policy simulation, richer benign baselines and customer-specific detectors | Detection engineering + evaluation corpus |

## Proposed benchmark protocol

These are acceptance targets to agree with the customer, not measured claims:

1. Split attack families and benign tasks into development and blind holdout
   sets. Include direct/indirect injection, MCP description drift, credential
   exfiltration, shell obfuscation, package tampering, malicious outputs and
   excessive delegated authority. Record per-family coverage and unsupported
   paths; do not average uncovered attack surfaces into a reassuring score.
2. For every mandatory scenario, require the expected deny/approval and prove
   the protected side effect did not occur. Independently record host bypass and
   hook outage. An emitted deny JSON is insufficient when the host still runs
   the action.
3. Run at least 1000 representative benign tool calls per supported connector
   and report the observed false-block/approval rates with confidence intervals.
   A proposed starting target is less than 1% false blocks on that agreed corpus.
4. Measure added p50/p95/p99 latency separately for cold/warm local evaluation,
   remote reputation, policy refresh and output inspection; publish workload,
   hardware, rule version and timeout counts. Set latency budgets from the
   customer's workflows before acceptance rather than inventing a benchmark.
5. Exercise concurrency, telemetry bursts, unavailable DB/storage, expired
   policy, revoked credentials and process restarts. Define fleet size, event
   rate and observation window before any availability/scale promise.
6. Produce an immutable index of source revision, artifact hashes, scenario
   manifest, evidence files, exceptions and evaluator signoff. Local automated
   regressions and the development Docker smoke are engineering evidence only.

## Current boundaries worth preserving

- Both self-hosted and cloud are supported preparation targets; the current
  running evidence is the isolated self-hosted rehearsal.
- The default commercial flow remains invoice-based. Optional Stripe checkout
  is server-created with authenticated tenant/price binding; live checkout,
  webhook delivery and reconciliation still require provider configuration.
  The implementation follows the separate session/subscription metadata fields
  in [Stripe's Checkout API](https://docs.stripe.com/api/checkout/sessions/create).
- The 13 external evidence gates remain open. Source changes cannot supply a
  customer's acceptance, legal approval, independent penetration test, registry
  custody, region decision or measured monthly SLA.
