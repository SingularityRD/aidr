# Cloud (SaaS) deployment

In the cloud option SingularityRD operates the AIDR control plane: the dashboard, the
Supabase database and the Edge Functions that handle enrollment, policy, ingest and
audit export. Enforcement never moves to the cloud. Agent connectors and Browser Guard
evaluate on the endpoint; the control plane manages policy and receives the
redacted events they send.

> **Status.** The hosted service is not accepted for customer use today. The selected
> app hostname does not resolve yet and the cloud path still has to pass the FCR-03
> installation journey and the commercial gates in
> [first-customer-ready.md](../production-readiness/first-customer-ready.md). Use this
> page to plan an evaluation, not as a live-service description.

## What the cloud control plane provides

| Capability | Where it lives |
| --- | --- |
| Tenants, members and roles, row-level security on every tenant table | `supabase/migrations/` (`app.is_tenant_member`) |
| Sign-in: email, Microsoft Entra ID (OAuth), SAML via the identity worker | `supabase/functions/oauth-callback`, `deploy/saml-config.mjs` |
| SCIM user and group provisioning | `supabase/functions/scim`, `scim-admin` |
| Device enrollment by short-lived device code (start, verify, poll) | `supabase/functions/device-start`, `device-verify`, `device-poll` |
| Tenant API keys, stored as hashes only | `supabase/functions/api-keys` |
| Signed runtime policy for agent connectors, with staged rollout and acknowledgement | `supabase/functions/policy`, `policy-management`, `policy-ack`; dashboard `src/enterprise/policy-rollout.tsx` |
| Signed Browser Guard policy: Shadow AI allow/block decisions from the dashboard (needs the policy signing key; extensions pin its public key in managed `dashboardPolicy`) | `supabase/functions/browser-guard-policy`; dashboard Browser Privacy Guard → Shadow AI |
| Signed rule and intel packs | `supabase/functions/packs-manifest`, `packs-download` |
| Event ingest for agent verdicts, and Browser Guard `privacy_scan` counts per the [telemetry contract](../contracts/privacy-telemetry.md) | `supabase/functions/ingest` |
| Incidents, response playbooks and AutoSecOps views | dashboard `/incidents`, `/autosecops` |
| Audit export (JSONL/CSV) | `supabase/functions/audit-export` |
| SIEM delivery in a portable `aidr.siem.event/v1` schema | `packages/core/src/siem-delivery.ts` |
| Tenant DLP policy authoring | dashboard `/policies`, `tenant_dlp_policies` |

## Onboarding flow

1. **Trial.** A verified sign-up starts a 14-day trial for one agent. Paid cloud plans
   have no trial cap. Admission, legal-document acceptance and seats are recorded per
   tenant.
2. **Enroll endpoints.** From `/onboarding`, an administrator enrolls a device with the
   device-code flow. The endpoint receives a signed `managed.json` bound to the tenant.
   Endpoints never receive the artifact-signing private key.
3. **Deploy connectors.** Install the approved connector packages
   ([Package Installation](../package-installation.md)). Each connector keeps enforcing
   locally with signed cached state if the service is unreachable.
4. **Browser Guard.** Push the extension and its managed policy through Chrome/Edge/Firefox
   enterprise policy. Set `controlPlaneUrl` and a tenant API key there to enable
   counts-only telemetry ([contract](../contracts/privacy-telemetry.md)).
5. **Policy and review.** Publish policy from `/policies`, review events in `/events`
   and `/incidents`, and export audit records for your SIEM.

## Data in the cloud

- **Agent verdict events** cross a mandatory credential-redaction boundary before they
  leave the endpoint. The default `redact_mode: "hash"` replaces tool summaries and
  artifacts with SHA-256 digests. See [privacy.md](../privacy.md).
- **Browser Guard events** carry site, action, channel and per-type counts only: no
  prompt text, masked text, values or page URLs.
- **Not sent:** source code, file contents and prompts. Optional reputation lookups
  (URLs, package names, file hashes) are separate, opt-in flows.

## Regions and availability

The commercial decision covers EU, US and APAC regions, recorded in
[`deploy/regions.manifest.json`](../../deploy/regions.manifest.json) as declarations
only. A region counts as available when its hosted project, residency terms and
subprocessor list have been approved (COM-011). A 99.9% monthly availability target has
been chosen for contract discussion; it is not an SLA until the contract evidence is
approved. Nothing here is a service-level commitment.

## Billing

Orders currently go through an approved written quote and invoice. Online checkout is
built but disabled until the payment provider, entitlement reconciliation and Finance
approval are accepted. Payment never grants admission on its own. Plans and list
prices are in [pricing.md](../sales/pricing.md) and are subject to COM-001 approval.

## Operator references

- [deploy/README.md](../../deploy/README.md), "Cloud deployment preparation"
- [deploy/cloudflare/README.md](../../deploy/cloudflare/README.md) (pilot Worker)
- [docs/control-plane.md](../control-plane.md) and [docs/device-auth.md](../device-auth.md)
- [docs/operations/admission-operators.md](../operations/admission-operators.md)
- [Security FAQ](../sales/security-faq.md)
