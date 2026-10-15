# Editions — plan catalog (quote-based pricing)

**Status:** prices are **not published**. Product-owner decision (2026-09-25):
no customer-facing surface (dashboard, website, README, product docs, sales
collateral) shows a price, currency or per-seat / per-month figure. Every paid
edition is sold by written quote; request one from
[anil@singularityrd.com](mailto:anil@singularityrd.com). A signed quote or order
governs every sale, and **final SKU approval is COM-001** in the
[commercial evidence registry](production-readiness/commercial-go-evidence-registry.json).
See the [Commercial Release Manifest](production-readiness/commercial-release-manifest-template.md)
before making a customer offer.

The catalog has one source of truth and one mirror:

| Where | What |
|---|---|
| `supabase/migrations/20260925000010_plan_catalog.sql` | `public.plans` table and seed (authoritative) |
| `packages/dashboard/src/billing/plans.ts` | price-free static mirror used by the public `/pricing` route (titled **Editions**) and the Billing plan picker |
| `packages/dashboard/src/__tests__/plan-catalog-drift.test.ts` | fails when the mirror and the seed disagree, or when a price field reaches the mirror |
| `packages/dashboard/src/__tests__/public-pages-no-prices.test.tsx` | renders every public route and fails on any price or currency text |

## Unit of sale

- **Seat** = one protected developer. Each purchased seat admits
  `included_agents` protected agent installations (`iid`); every plan admits one
  agent per seat today.
- **Agent** = one AIDR installation id connected to the control plane. The
  control plane enforces the admitted agent count at enrollment and ingest.
- Local detection runs on the developer machine on every plan and does not
  depend on a plan or an account.

## Editions

| Edition | Minimum | Deployment | Event retention | Billing intervals offered | Purchase |
|---|---|---|---|---|---|
| **Free** | 1 agent | Cloud | 7 days | — | Sign up |
| **Team** | 3 developers | Cloud | 90 days | Monthly or annual | Quote; self-serve card checkout only in a self-service build |
| **Business** | 25 developers | Cloud or on-premises | 365 days | Annual | Sales-assisted quote and invoice |
| **Enterprise** | By agreement | On-premises or air-gapped | Contractual | By agreement | Sales-assisted quote and invoice |

Paid editions are quoted per developer seat for the customer's seats and
deployment. The amount of a card checkout is set by the Stripe price that
`AIDR_STRIPE_PRICE_MAP` names and is shown only on Stripe's checkout page; the
dashboard never renders an amount it did not read from a recorded order or
ledger row.

Catalog features (each plan includes the ones above it):

- **Free** — local detection engine and the control-plane dashboard for one agent.
- **Team** — adds Browser Guard and Microsoft Entra ID single sign-on.
- **Business** — adds SIEM export, SCIM provisioning and AI security posture.
- **Enterprise** — adds air-gapped deployment and dedicated support.

A feature listed here still needs its own release acceptance before it is sold
as supported; the catalog does not assert readiness. The hosted service is not
live yet (no hosted region is deployed), so the cloud rows, the Free sign-up and
the 14-day trial below cannot be used today; local detection and the on-premises
control plane are the evaluation paths.

## Catalog columns

| Column | Meaning |
|---|---|
| `id` | `free`, `team`, `business`, `enterprise` |
| `included_agents` | protected agents admitted per purchased seat |
| `min_seats` | smallest purchasable seat quantity |
| `price_monthly_cents` | internal per-seat reference for monthly billing; `null` = monthly not offered. Server-side only: never mirrored to the dashboard bundle or shown in any UI; the mirror carries only whether the interval is offered |
| `price_yearly_cents` | internal per-seat reference for annual billing; `null` = quote only. Server-side only, as above |
| `currency` | internal reference currency of the two columns above; not displayed |
| `features` | feature keys (labels live in the dashboard mirror) |
| `self_serve` | may be bought by card in a self-service build (Free and Team only) |
| `deployment` | `cloud`, `onprem`, `air-gapped` |
| `retention_days` | list event-retention term (`null` = contractual) |
| `active` | shown and purchasable |

Signed-in users can read active catalog rows (RLS `plans_select_authenticated`);
nobody but a migration writes them. The public Editions page reads only the
price-free static mirror. The price columns are reference data for Finance and
quoting, not a published price list; checkout amounts come from Stripe.

## How a plan becomes active

A catalog row never grants anything. The tenant's admitted plan and agent
capacity change only through one of these audited paths (see
[billing.md](billing.md)):

1. **Verified trial** — one seat for 14 days (`start_verified_trial`).
2. **Operator licence** — an approved invoice/order is applied by an admission
   operator (`grant_licensed_tenant_admission`).
3. **Card subscription** — a signed Stripe subscription event whose price is
   mapped in `AIDR_STRIPE_PRICE_MAP` grants a licensed admission through
   `apply_stripe_plan_subscription`, bound to `stripe:<subscription id>`.

`public.get_tenant_plan(tenant)` is the member-only projection the Billing page
uses to show the current plan, admission and usage against admitted agents.

## Server-side feature enforcement

Catalog features are enforced by the control plane, not only displayed
(`20261007130000_plan_retention_and_feature_gating.sql`,
`supabase/functions/_shared/plan-entitlements.ts`). One resolver,
`app.tenant_plan_entitlements`, decides the effective edition:

1. a granted Stripe subscription bound to the tenant's active licensed admission;
2. otherwise the billing-managed team label, honoured only while the tenant holds
   an active licensed admission or an approved pilot (a lapsed licence is Free,
   `plan_source: admission_inactive`);
3. an active verified trial evaluates **Team**;
4. everything else is **Free**.

| Feature | From | Enforced at |
|---|---|---|
| Browser Guard (`browser_privacy_guard`) | Team | `ingest` with an `ingest:browser_guard` key, the signed `browser-guard-policy` document |
| Entra / OIDC / SAML SSO administration (`entra_sso`) | Team | `oidc-sso` admin actions, `identity-security` SAML policy actions, `azure-ad-groups` (sign-in itself is never gated) |
| SIEM / audit export (`siem_export`) | Business | `audit-export` |
| SCIM (`scim`) | Business | `scim`, `scim-admin` |
| AI Security Posture (`ai_security_posture`) | Business | posture uploads to `ingest`, `posture_findings` reads (restrictive RLS) |
| Air-gapped deployment (`air_gapped_deployment`) | Enterprise | `scripts/license-verify.mjs` / `license-issue.mjs` refuse an `airgap` licence below Enterprise |

A refusal is `402 {"error":"plan_feature_required","feature",...,"required_plan"}`;
an unreadable plan is `503 plan_entitlement_unavailable` (fail closed). Local
detection and the connector ingest of verdicts are never plan-gated. The
dashboard shows an upgrade notice on gated pages using the same resolver
(`get_tenant_plan_entitlements`); the server stays authoritative.

**Event retention.** The effective telemetry retention is
`min(tenant setting, plan term)`; a tenant that never set a value gets the plan
term (Free 7, Team 90, Business 365 days; Enterprise is contractual and keeps the
tenant setting). The telemetry reaper and `retention-admin` use the same rule,
and a setting above the plan term is refused with `retention_days_exceeds_plan`.

## History

An earlier draft priced each additional agent on top of one free agent, and a
later revision showed list prices on the public `/pricing` page. Both are
superseded: prices are quote-based and not published, and neither was ever an
offer.
