# Enterprise Order Form and Entitlement — Template

Status: **DRAFT / NOT APPROVED**
Source inventory updated: **2026-10-06**. No customer, monetary terms or
signatory is supplied. Review before an actual order is negotiated.
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

## Source-known onboarding and handoff

1. Choose managed Clerk/Firestore/Polar or self-hosted Supabase, one exact
   candidate and supported host/OS versions. Select the actual tenant region;
   EU/US/APAC are intent until deployed evidence exists.
2. For managed organizations, use trusted-operator binding to the existing
   tenant/storage anchor. Verify two distinct current `org:admin` users can
   approve policy publication and removed roles lose access. Native Clerk SSO
   requires configured provider acceptance; Supabase SCIM does not establish a
   managed SCIM service.
3. For self-hosted invoices, authorize Finance through
   `invoice_finance_operators` and provision using `invoice-entitlement`;
   a quote, invoice request or manual SQL edit is not settlement. Use
   `invoice-finance-authority.md`.
4. Verify the signed delivery envelope with independently obtained signer
   policy before install. Enroll the approved tenant and installation ID;
   ambiguous enrollment requires stop/revoke/repair in `docs/device-auth.md`.
5. Record malicious-fixture side-effect prevention and a benign twin, managed
   policy/event acknowledgement, outage, update/rollback and consent-gated
   support ticket. Use the existing PoV run sheet and native matrix.
6. At cancellation, record provider/registry revocation and runtime expiry,
   audit export, legal-hold check, offboarding phase receipts and backup expiry
   separately. Application deletion does not certify provider physical erasure.

Remaining order inputs: legal/billing identity, agreed SKU/quantity, provider
catalogue or invoice authority, price/currency/tax, payment/renewal terms,
service/support schedule, actual region/subprocessors, data-processing terms,
retention/hold handling, usage/distribution rights and named signatories.
Hash signed records to the candidate; source behaviour supplies no approval.
