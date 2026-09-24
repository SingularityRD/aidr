# Pricing — plan catalog (list prices)

**Status:** list prices recorded in the plan catalog. They are not yet an
approved SKU or price book: **final SKU approval is COM-001** in the
[commercial evidence registry](production-readiness/commercial-go-evidence-registry.json),
and a signed quote or order governs every sale. See the
[Commercial Release Manifest](production-readiness/commercial-release-manifest-template.md)
before making a customer offer.

The catalog has one source of truth and one mirror:

| Where | What |
|---|---|
| `supabase/migrations/20260925000010_plan_catalog.sql` | `public.plans` table and seed (authoritative) |
| `packages/dashboard/src/billing/plans.ts` | static mirror used by the public `/pricing` page |
| `packages/dashboard/src/__tests__/plan-catalog-drift.test.ts` | fails when the mirror and the seed disagree |

## Unit of sale

- **Seat** = one protected developer. Each purchased seat admits
  `included_agents` protected agent installations (`iid`); every plan admits one
  agent per seat today.
- **Agent** = one AIDR installation id connected to the control plane. The
  control plane enforces the admitted agent count at enrollment and ingest.
- Local detection runs on the developer machine on every plan and does not
  depend on a plan or an account.

## Plans

All prices are USD, per developer seat, before tax.

| Plan | Monthly billing | Annual billing | Minimum | Deployment | Event retention | Purchase |
|---|---|---|---|---|---|---|
| **Free** | $0 | $0 | 1 agent | Cloud | 7 days | Sign up |
| **Team** | $24 / developer / month | $20 / developer / month ($240 / year) | 3 developers | Cloud | 90 days | Self-serve card checkout when enabled, otherwise invoice |
| **Business** | — (annual only) | $45 / developer / month ($540 / year) | 25 developers | Cloud or on-premises | 365 days | Sales-assisted; invoice |
| **Enterprise** | Custom | Custom | By agreement | On-premises or air-gapped | Contractual | Sales-assisted; invoice |

Catalog features (each plan includes the ones above it):

- **Free** — local detection engine and the control-plane dashboard for one agent.
- **Team** — adds Browser Privacy Guard and Microsoft Entra ID single sign-on.
- **Business** — adds SIEM export, SCIM provisioning and AI security posture.
- **Enterprise** — adds air-gapped deployment and dedicated support.

A feature listed here still needs its own release acceptance before it is sold
as supported; the catalog does not assert readiness.

## Catalog columns

| Column | Meaning |
|---|---|
| `id` | `free`, `team`, `business`, `enterprise` |
| `included_agents` | protected agents admitted per purchased seat |
| `min_seats` | smallest purchasable seat quantity |
| `price_monthly_cents` | per-seat price for one month on monthly billing (`null` = not offered monthly / custom) |
| `price_yearly_cents` | per-seat price for one year on annual billing (`null` = custom quote) |
| `currency` | always `USD` |
| `features` | feature keys (labels live in the dashboard mirror) |
| `self_serve` | may be bought by card in a self-service build (Free and Team only) |
| `deployment` | `cloud`, `onprem`, `air-gapped` |
| `retention_days` | list event-retention term (`null` = contractual) |
| `active` | shown and purchasable |

Signed-in users can read active catalog rows (RLS `plans_select_authenticated`);
nobody but a migration writes them. The public pricing page reads only the
static mirror.

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

## History

An earlier draft priced "$2 per additional agent per month" on top of one free
agent. It is superseded by the per-developer catalog above and was never an
offer.
