# Enterprise Order Form and Entitlement — Template

Status: **DRAFT / NOT APPROVED**
Use with the Commercial Release Manifest for an invoice-based direct-GA sale.

## Order Form

| Field | Customer/AIDR value |
|---|---|
| Customer legal entity, billing address, tax ID | |
| Order Form ID / effective date / term / renewal notice | |
| SKU / protected-agent quantity / metering unit | |
| Connector scope and supported host versions | Claude Code / Cursor / VS Code / OpenClaw / OpenCode |
| Deployment mode | Hybrid |
| Tenant region | EU / US / APAC |
| Private-registry organization and download identities | |
| Price, currency, tax, invoice cadence, payment terms | **Not held** |
| Availability target and exclusions | 99.9% monthly target; exclusions **not held** |
| Support tier/hours/channel/severity | **Not held** |
| Data categories, retention, deletion/export | **Not held** |
| Subprocessors, region and transfer terms | **Not held** |
| Licence rights, seat limits, backup, attribution, resale restrictions | **Not held** |
| MSA / DPA / TOM / SCC / SLA versions | **Not held** |
| Cancellation, suspension, revocation, offboarding | **Not held** |
| Customer acceptance authority | |
| Customer signature / AIDR signature / Legal + Finance approval | **Not held** |

## Entitlement record

```text
entitlement_id: <immutable id>
customer_id: <tenant/legal entity id>
order_form_id: <signed order id>
release_candidate: <commit + manifest hash>
status: pending | active | suspended | expired | revoked
regions: [EU | US | APAC]
connectors: [claude-code, cursor, vscode, openclaw, opencode]
protected_agent_limit: <signed quantity>
registry_scopes: [cli, sdk, connector, plugin, dashboard]
features: <approved flags only>
effective_at: <RFC3339>
expires_at: <RFC3339>
invoice_reference: <finance source of truth>
revocation_reason: <required when suspended/revoked>
audit_event_ids: [provision, change, revoke, export, delete]
```

## Required rehearsals

- Provision from an approved invoice without SQL/manual database edits.
- Increase/decrease protected-agent quantity and test over-limit behavior.
- Install a signed artifact from the private registry and verify tenant entitlement.
- Revoke registry access and runtime entitlement; preserve audit evidence.
- Cancel, export, delete and produce a customer-visible deletion receipt.
